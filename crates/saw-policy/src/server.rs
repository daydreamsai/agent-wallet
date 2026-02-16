//! WebSocket server: accepts connections from saw-daemon, handles sign requests.
//!
//! Protocol flow per sign request:
//! 1. saw-daemon sends WireMessage::SignRequest
//! 2. saw-policy evaluates policy → sends WireMessage::PolicyDecision
//! 3. If approved, both sides exchange WireMessage::Mpc messages (MPC signing)
//! 4. Connection stays open for subsequent requests

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use cggmp21::round_based::{Incoming, MessageDestination, MessageType, Outgoing};
use saw_mpc::error::MpcError;
use saw_mpc::protocol::{Decision, MpcWireMessage, SessionId, WireMessage};
use saw_mpc::signing::{self, PresignaturePool};
use saw_mpc::transport::DeliveryError;
use saw_mpc::types::{PARTY_DAEMON, PARTY_POLICY};
use saw_mpc::{KeyShare, Secp256k1};

use crate::policy::{self, PolicyConfig, PolicyState};

/// Run the saw-policy WebSocket server.
pub async fn run(
    listen_addr: &str,
    key_share: KeyShare<Secp256k1>,
    policy_config: PolicyConfig,
) -> Result<(), MpcError> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| MpcError::Transport(format!("bind {listen_addr}: {e}")))?;

    tracing::info!(listen = %listen_addr, "saw-policy server listening");

    let key_share = Arc::new(key_share);
    let policy_config = Arc::new(policy_config);

    loop {
        let (tcp_stream, addr) = listener
            .accept()
            .await
            .map_err(|e| MpcError::Transport(format!("accept: {e}")))?;

        tracing::info!(%addr, "daemon connected");

        let ks = key_share.clone();
        let pc = policy_config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(tcp_stream, ks, pc).await {
                tracing::error!(%addr, error = %e, "connection handler failed");
            }
            tracing::info!(%addr, "daemon disconnected");
        });
    }
}

/// Handle a single persistent WebSocket connection from saw-daemon.
async fn handle_connection(
    tcp_stream: tokio::net::TcpStream,
    key_share: Arc<KeyShare<Secp256k1>>,
    policy_config: Arc<PolicyConfig>,
) -> Result<(), MpcError> {
    let ws_stream = tokio_tungstenite::accept_async(tcp_stream)
        .await
        .map_err(|e| MpcError::Transport(format!("ws handshake: {e}")))?;

    let (ws_tx, mut ws_rx) = ws_stream.split();
    let ws_tx = Arc::new(Mutex::new(ws_tx));
    let mut policy_state = PolicyState::new();
    let mut presig_pool = PresignaturePool::new(10, 2);

    loop {
        let wire = match read_next_wire(&mut ws_rx).await {
            Ok(msg) => msg,
            Err(_) => break,
        };

        match wire {
            // ---- Presignature generation (background) ----
            WireMessage::PresignRequest(presign_req) => {
                let presig_index = presign_req.presig_index;
                tracing::info!(presig_index, "presignature generation requested");

                type SignMsg = cggmp21::signing::msg::Msg<Secp256k1, sha2::Sha256>;
                let (incoming_tx, incoming_rx) =
                    mpsc::unbounded::<Result<Incoming<SignMsg>, DeliveryError>>();
                let (outgoing_tx, mut outgoing_rx) =
                    mpsc::unbounded::<Outgoing<SignMsg>>();

                let eid_bytes: Vec<u8> = format!("presign-{presig_index}").into_bytes();
                let signers = vec![PARTY_DAEMON, PARTY_POLICY];
                let sid = presign_req.session_id.clone();

                // Outgoing: MPC → WS
                let ws_tx_c = ws_tx.clone();
                let sid_out = sid.clone();
                let out_task = tokio::spawn(async move {
                    while let Some(outgoing) = outgoing_rx.next().await {
                        let to = match outgoing.recipient {
                            MessageDestination::AllParties => None,
                            MessageDestination::OneParty(p) => Some(p),
                        };
                        let data = match serde_json::to_vec(&outgoing.msg) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };
                        let wire = WireMessage::Mpc(MpcWireMessage {
                            session_id: sid_out.clone(),
                            from: PARTY_POLICY,
                            to,
                            data,
                        });
                        let json = match serde_json::to_vec(&wire) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };
                        let mut tx = ws_tx_c.lock().await;
                        if tx.send(WsMessage::Binary(json.into())).await.is_err() {
                            break;
                        }
                    }
                });

                // Presign task
                let ks = key_share.clone();
                let presign_task = tokio::spawn(async move {
                    let eid = cggmp21::ExecutionId::new(&eid_bytes);
                    signing::generate_presignature(eid, 1, &signers, &ks, (incoming_rx, outgoing_tx))
                        .await
                });

                // Feed MPC messages
                let counter = AtomicU64::new(0);
                let sid_in = sid;

                loop {
                    if presign_task.is_finished() {
                        break;
                    }
                    let msg = tokio::time::timeout(
                        std::time::Duration::from_millis(50),
                        ws_rx.next(),
                    )
                    .await;

                    let item = match msg {
                        Ok(Some(item)) => item,
                        Ok(None) => {
                            let _ = incoming_tx.unbounded_send(Err(DeliveryError("ws ended".into())));
                            break;
                        }
                        Err(_timeout) => continue,
                    };

                    let raw = match item {
                        Ok(WsMessage::Binary(d)) => d.to_vec(),
                        Ok(WsMessage::Text(t)) => t.into_bytes(),
                        Ok(WsMessage::Ping(d)) => {
                            let mut tx = ws_tx.lock().await;
                            let _ = tx.send(WsMessage::Pong(d)).await;
                            continue;
                        }
                        Ok(WsMessage::Pong(_)) => continue,
                        Ok(WsMessage::Close(_)) => {
                            let _ = incoming_tx.unbounded_send(Err(DeliveryError("ws closed".into())));
                            break;
                        }
                        Err(e) => {
                            let _ = incoming_tx.unbounded_send(Err(DeliveryError(format!("{e}"))));
                            break;
                        }
                        _ => continue,
                    };

                    if let Ok(WireMessage::Mpc(mpc_msg)) = serde_json::from_slice::<WireMessage>(&raw) {
                        if mpc_msg.session_id == sid_in {
                            if let Ok(msg) = serde_json::from_slice(&mpc_msg.data) {
                                let msg_type = if mpc_msg.to.is_some() {
                                    MessageType::P2P
                                } else {
                                    MessageType::Broadcast
                                };
                                let incoming = Incoming {
                                    id: counter.fetch_add(1, Ordering::Relaxed),
                                    sender: mpc_msg.from,
                                    msg_type,
                                    msg,
                                };
                                if incoming_tx.unbounded_send(Ok(incoming)).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }

                match presign_task.await {
                    Ok(Ok(presignature)) => {
                        presig_pool.add(presig_index, presignature);
                        tracing::info!(presig_index, avail = presig_pool.available(), "presignature stored");
                        let ready = WireMessage::PresignReady(saw_mpc::protocol::PresignReady {
                            presig_index,
                        });
                        let _ = send_wire(&ws_tx, &ready).await;
                    }
                    Ok(Err(e)) => tracing::error!(presig_index, error = %e, "presign MPC failed"),
                    Err(e) => tracing::error!(presig_index, error = %e, "presign task panic"),
                }
                out_task.abort();
            }

            // ---- Fast path: partial signature exchange ----
            WireMessage::PartialSignRequest(partial_req) => {
                tracing::info!(
                    request_id = %partial_req.request_id,
                    presig_index = partial_req.presig_index,
                    "partial sign request (fast path)"
                );

                // Build a SignRequest for policy evaluation
                let sign_req = saw_mpc::protocol::SignRequest {
                    request_id: partial_req.request_id.clone(),
                    session_id: SessionId::random(),
                    wallet: partial_req.wallet.clone(),
                    action: partial_req.action.clone(),
                    tx_details: partial_req.tx_details.clone(),
                    message_hash: partial_req.message_hash.clone(),
                };

                let decision = policy::evaluate(&policy_config, &mut policy_state, &sign_req);

                if decision.decision != Decision::Approve {
                    let resp = WireMessage::PartialSignResponse(saw_mpc::protocol::PartialSignResponse {
                        request_id: partial_req.request_id,
                        decision: decision.decision,
                        matched_rule: decision.matched_rule,
                        reason: decision.reason,
                        partial_signature: None,
                    });
                    let _ = send_wire(&ws_tx, &resp).await;
                    continue;
                }

                // Take presignature from pool
                let presig = presig_pool.take(partial_req.presig_index);
                if presig.is_none() {
                    tracing::error!(presig_index = partial_req.presig_index, "presignature not found");
                    let resp = WireMessage::PartialSignResponse(saw_mpc::protocol::PartialSignResponse {
                        request_id: partial_req.request_id,
                        decision: Decision::Deny,
                        matched_rule: None,
                        reason: Some("presignature not found — index mismatch".into()),
                        partial_signature: None,
                    });
                    let _ = send_wire(&ws_tx, &resp).await;
                    continue;
                }

                // Parse message hash
                let hash_hex = partial_req.message_hash.trim_start_matches("0x");
                let hash_bytes = match hex::decode(hash_hex) {
                    Ok(b) if b.len() == 32 => {
                        let mut h = [0u8; 32];
                        h.copy_from_slice(&b);
                        h
                    }
                    _ => {
                        let resp = WireMessage::PartialSignResponse(saw_mpc::protocol::PartialSignResponse {
                            request_id: partial_req.request_id,
                            decision: Decision::Deny,
                            matched_rule: None,
                            reason: Some("invalid message hash".into()),
                            partial_signature: None,
                        });
                        let _ = send_wire(&ws_tx, &resp).await;
                        continue;
                    }
                };

                // Issue partial signature locally
                let partial = signing::issue_partial_signature(presig.unwrap(), &hash_bytes);
                let partial_bytes = match serde_json::to_vec(&partial) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to serialize partial signature");
                        continue;
                    }
                };

                let resp = WireMessage::PartialSignResponse(saw_mpc::protocol::PartialSignResponse {
                    request_id: partial_req.request_id,
                    decision: Decision::Approve,
                    matched_rule: decision.matched_rule,
                    reason: None,
                    partial_signature: Some(partial_bytes),
                });
                send_wire(&ws_tx, &resp).await?;
                tracing::info!("partial signature sent (fast path complete)");
            }

            // ---- Full MPC signing (slow path) ----
            WireMessage::SignRequest(sign_req) => {
                tracing::info!(
                    request_id = %sign_req.request_id,
                    wallet = %sign_req.wallet,
                    "evaluating sign request"
                );

                let decision =
                    policy::evaluate(&policy_config, &mut policy_state, &sign_req);

                tracing::info!(
                    request_id = %sign_req.request_id,
                    decision = ?decision.decision,
                    "policy decision"
                );

                send_wire(&ws_tx, &WireMessage::PolicyDecision(decision.clone())).await?;

                if decision.decision != Decision::Approve {
                    continue;
                }

                // Parse message hash
                let hash_bytes = hex::decode(
                    sign_req.message_hash.trim_start_matches("0x"),
                )
                .map_err(|_| MpcError::Signing("bad hash hex".into()))?;
                if hash_bytes.len() != 32 {
                    tracing::error!("hash not 32 bytes");
                    continue;
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hash_bytes);

                // MPC signing — build channel-based delivery
                // The signing message type for cggmp21
                type SignMsg = cggmp21::signing::msg::Msg<Secp256k1, sha2::Sha256>;
                let (incoming_tx, incoming_rx) =
                    mpsc::unbounded::<Result<Incoming<SignMsg>, DeliveryError>>();
                let (outgoing_tx, mut outgoing_rx) =
                    mpsc::unbounded::<Outgoing<SignMsg>>();

                let eid_bytes: Vec<u8> = format!("sign-{}", sign_req.request_id).into_bytes();
                let signers = vec![PARTY_DAEMON, PARTY_POLICY];
                let sid = sign_req.session_id.clone();

                // Outgoing task: MPC → WS
                let ws_tx_c = ws_tx.clone();
                let sid_out = sid.clone();
                let out_task = tokio::spawn(async move {
                    while let Some(outgoing) = outgoing_rx.next().await {
                        let to = match outgoing.recipient {
                            MessageDestination::AllParties => None,
                            MessageDestination::OneParty(p) => Some(p),
                        };
                        let data = match serde_json::to_vec(&outgoing.msg) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };
                        let wire = WireMessage::Mpc(MpcWireMessage {
                            session_id: sid_out.clone(),
                            from: PARTY_POLICY,
                            to,
                            data,
                        });
                        let json = match serde_json::to_vec(&wire) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };
                        let mut tx = ws_tx_c.lock().await;
                        if tx.send(WsMessage::Binary(json.into())).await.is_err() {
                            break;
                        }
                    }
                });

                // Sign task
                let ks = key_share.clone();
                let sign_task = tokio::spawn(async move {
                    let eid = cggmp21::ExecutionId::new(&eid_bytes);
                    signing::sign_full(eid, 1, &signers, &ks, &hash, (incoming_rx, outgoing_tx))
                        .await
                });

                // Feed MPC messages from WS → incoming channel until sign completes
                let counter = AtomicU64::new(0);
                let sid_in = sid;

                loop {
                    if sign_task.is_finished() {
                        break;
                    }

                    // Use a timeout so we periodically check if sign_task finished
                    let msg = tokio::time::timeout(
                        std::time::Duration::from_millis(50),
                        ws_rx.next(),
                    )
                    .await;

                    let item = match msg {
                        Ok(Some(item)) => item,
                        Ok(None) => {
                            let _ = incoming_tx.unbounded_send(Err(DeliveryError(
                                "ws ended".into(),
                            )));
                            break;
                        }
                        Err(_timeout) => continue,
                    };

                    let raw = match item {
                        Ok(WsMessage::Binary(d)) => d.to_vec(),
                        Ok(WsMessage::Text(t)) => t.into_bytes(),
                        Ok(WsMessage::Ping(d)) => {
                            let mut tx = ws_tx.lock().await;
                            let _ = tx.send(WsMessage::Pong(d)).await;
                            continue;
                        }
                        Ok(WsMessage::Pong(_)) => continue,
                        Ok(WsMessage::Close(_)) => {
                            let _ = incoming_tx.unbounded_send(Err(DeliveryError(
                                "ws closed".into(),
                            )));
                            break;
                        }
                        Err(e) => {
                            let _ = incoming_tx.unbounded_send(Err(DeliveryError(
                                format!("{e}"),
                            )));
                            break;
                        }
                        _ => continue,
                    };

                    if let Ok(WireMessage::Mpc(mpc_msg)) = serde_json::from_slice::<WireMessage>(&raw) {
                        if mpc_msg.session_id == sid_in {
                            if let Ok(msg) = serde_json::from_slice(&mpc_msg.data) {
                                let msg_type = if mpc_msg.to.is_some() {
                                    MessageType::P2P
                                } else {
                                    MessageType::Broadcast
                                };
                                let incoming = Incoming {
                                    id: counter.fetch_add(1, Ordering::Relaxed),
                                    sender: mpc_msg.from,
                                    msg_type,
                                    msg,
                                };
                                if incoming_tx.unbounded_send(Ok(incoming)).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }

                // Collect result
                let result = sign_task
                    .await
                    .map_err(|e| MpcError::Signing(format!("task panic: {e}")))?;
                out_task.abort();

                let (success, error) = match result {
                    Ok(_) => {
                        tracing::info!(request_id = %sign_req.request_id, "signing ok");
                        (true, None)
                    }
                    Err(ref e) => {
                        tracing::error!(request_id = %sign_req.request_id, error = %e, "signing failed");
                        (false, Some(e.to_string()))
                    }
                };

                let complete = WireMessage::SigningComplete(saw_mpc::protocol::SigningComplete {
                    request_id: sign_req.request_id.clone(),
                    success,
                    error,
                });
                send_wire(&ws_tx, &complete).await?;
            }
            WireMessage::Ping => {
                send_wire(&ws_tx, &WireMessage::Pong).await?;
            }
            _ => {}
        }
    }

    Ok(())
}

// Helpers

async fn read_next_wire<S>(
    rx: &mut futures::stream::SplitStream<tokio_tungstenite::WebSocketStream<S>>,
) -> Result<WireMessage, MpcError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        match rx.next().await {
            Some(Ok(WsMessage::Binary(d))) => {
                return serde_json::from_slice(&d).map_err(MpcError::Serde);
            }
            Some(Ok(WsMessage::Text(t))) => {
                return serde_json::from_str(&t).map_err(MpcError::Serde);
            }
            Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => continue,
            Some(Ok(WsMessage::Close(_))) => {
                return Err(MpcError::Transport("closed".into()));
            }
            Some(Err(e)) => return Err(MpcError::Transport(format!("{e}"))),
            None => return Err(MpcError::Transport("ended".into())),
            _ => continue,
        }
    }
}

async fn send_wire<S>(
    tx: &Arc<Mutex<futures::stream::SplitSink<tokio_tungstenite::WebSocketStream<S>, WsMessage>>>,
    msg: &WireMessage,
) -> Result<(), MpcError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let data = serde_json::to_vec(msg).map_err(MpcError::Serde)?;
    let mut guard = tx.lock().await;
    guard
        .send(WsMessage::Binary(data.into()))
        .await
        .map_err(|e| MpcError::Transport(format!("{e}")))?;
    Ok(())
}
