//! Threshold signing client for saw-daemon (Share 1).
//!
//! Manages a persistent WebSocket connection to saw-policy, a background
//! presignature pool, and two signing paths:
//!
//! - **Fast path** (presignature available): local partial sig + exchange
//!   with policy → sub-50ms signing latency
//! - **Slow path** (pool empty): full inline MPC signing (fallback)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use cggmp21::round_based::{Incoming, MessageDestination, MessageType, Outgoing};
use saw_mpc::protocol::*;
use saw_mpc::signing::{self, PresignaturePool};
use saw_mpc::transport::DeliveryError;
use saw_mpc::types::{PARTY_DAEMON, PARTY_POLICY};
use saw_mpc::{KeyShare, Secp256k1};

/// Default pool target size and refill threshold.
const DEFAULT_POOL_SIZE: usize = 5;
const DEFAULT_REFILL_THRESHOLD: usize = 2;

/// Persistent connection to saw-policy for threshold signing.
pub struct ThresholdClient {
    key_share: KeyShare<Secp256k1>,
    policy_url: String,
    /// Presignature pool (shared with background refill task).
    pool: Arc<Mutex<PresignaturePool>>,
}

impl ThresholdClient {
    pub fn new(key_share: KeyShare<Secp256k1>, policy_url: String) -> Self {
        Self {
            key_share,
            policy_url,
            pool: Arc::new(Mutex::new(PresignaturePool::new(
                DEFAULT_POOL_SIZE,
                DEFAULT_REFILL_THRESHOLD,
            ))),
        }
    }

    /// Get the shared public key from the key share.
    pub fn public_key(&self) -> generic_ec::Point<cggmp21::supported_curves::Secp256k1> {
        *self.key_share.shared_public_key
    }

    /// Start the background presignature refill loop.
    /// Call once after constructing the client. Runs until dropped.
    pub fn start_presign_refill(&self) -> tokio::task::JoinHandle<()> {
        let pool = self.pool.clone();
        let key_share = self.key_share.clone();
        let policy_url = self.policy_url.clone();

        tokio::spawn(async move {
            loop {
                // Check if pool needs refill
                let count = {
                    let p = pool.lock().await;
                    if p.needs_refill() {
                        p.refill_count()
                    } else {
                        0
                    }
                };

                if count > 0 {
                    eprintln!("presignature pool low, generating {count}");
                    for _ in 0..count {
                        match generate_one_presignature(&pool, &key_share, &policy_url).await {
                            Ok(idx) => {
                                let avail = pool.lock().await.available();
                                eprintln!("presignature ready: index={idx} available={avail}");
                            }
                            Err(e) => {
                                eprintln!("presignature generation failed: {e}, will retry");
                                // Back off before retrying on error
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                break;
                            }
                        }
                    }
                }

                // Sleep before checking again
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        })
    }

    /// Sign a message hash via threshold signing.
    ///
    /// Fast path: uses a presignature from the pool (partial sig exchange).
    /// Slow path: falls back to full MPC signing if pool is empty.
    pub async fn sign(
        &self,
        wallet: &str,
        action: SignAction,
        tx_details: TxDetails,
        message_hash: &[u8; 32],
    ) -> Result<ThresholdSignResult, ThresholdError> {
        // Try fast path first
        let presig_entry = {
            let mut pool = self.pool.lock().await;
            pool.take_next()
        };

        if let Some((presig_index, presignature)) = presig_entry {
            eprintln!("using presignature {presig_index} (fast path)");
            return self
                .sign_with_presignature(wallet, action, tx_details, message_hash, presig_index, presignature)
                .await;
        }

        // Slow path: full MPC signing
        eprintln!("no presignatures available, falling back to full MPC signing");
        self.sign_full_mpc(wallet, action, tx_details, message_hash).await
    }

    /// Fast path: sign using a pre-generated presignature.
    async fn sign_with_presignature(
        &self,
        wallet: &str,
        action: SignAction,
        tx_details: TxDetails,
        message_hash: &[u8; 32],
        presig_index: u64,
        presignature: signing::Presignature<Secp256k1>,
    ) -> Result<ThresholdSignResult, ThresholdError> {
        let request_id = generate_request_id();

        // Connect to policy
        let (ws_stream, _) = tokio_tungstenite::connect_async(&self.policy_url)
            .await
            .map_err(|e| ThresholdError::PolicyUnavailable(format!("connect: {e}")))?;

        let (mut ws_tx, mut ws_rx) = ws_stream.split();

        // Issue our partial signature locally (no network!)
        let our_partial = signing::issue_partial_signature(presignature, message_hash);
        let our_partial_bytes = serde_json::to_vec(&our_partial)
            .map_err(|e| ThresholdError::Mpc(format!("serialize partial: {e}")))?;

        // Send partial sign request to policy
        let req = WireMessage::PartialSignRequest(PartialSignRequest {
            request_id: request_id.clone(),
            presig_index,
            wallet: wallet.to_string(),
            action,
            tx_details,
            message_hash: format!("0x{}", hex::encode(message_hash)),
        });
        let data = serde_json::to_vec(&req)
            .map_err(|e| ThresholdError::Transport(format!("serialize: {e}")))?;
        ws_tx
            .send(WsMessage::Binary(data.into()))
            .await
            .map_err(|e| ThresholdError::Transport(format!("send: {e}")))?;

        // Wait for policy's partial signature response
        let resp = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match read_ws_msg(&mut ws_rx).await? {
                    WireMessage::PartialSignResponse(r) if r.request_id == request_id => {
                        return Ok::<_, ThresholdError>(r);
                    }
                    _ => continue,
                }
            }
        })
        .await
        .map_err(|_| ThresholdError::PolicyUnavailable("partial sign timeout (5s)".into()))??;

        if resp.decision != Decision::Approve {
            return Err(match resp.decision {
                Decision::Deny => ThresholdError::PolicyDenied {
                    rule: resp.matched_rule,
                    reason: resp.reason,
                },
                Decision::Escalate => ThresholdError::Escalated {
                    rule: resp.matched_rule,
                    reason: resp.reason,
                },
                Decision::Approve => unreachable!(),
            });
        }

        // Deserialize policy's partial signature
        let policy_partial_bytes = resp
            .partial_signature
            .ok_or_else(|| ThresholdError::Mpc("no partial signature in response".into()))?;
        let policy_partial: cggmp21::PartialSignature<Secp256k1> =
            serde_json::from_slice(&policy_partial_bytes)
                .map_err(|e| ThresholdError::Mpc(format!("deserialize partial: {e}")))?;

        // Combine partials → complete signature
        let signature = signing::combine_partial_signatures(&[our_partial, policy_partial])
            .map_err(|e| ThresholdError::Mpc(format!("{e}")))?;

        Ok(ThresholdSignResult {
            request_id,
            signature,
            matched_rule: resp.matched_rule,
        })
    }

    /// Slow path: full inline MPC signing (original behavior).
    async fn sign_full_mpc(
        &self,
        wallet: &str,
        action: SignAction,
        tx_details: TxDetails,
        message_hash: &[u8; 32],
    ) -> Result<ThresholdSignResult, ThresholdError> {
        let request_id = generate_request_id();
        let session_id = SessionId::random();

        // Connect to policy agent
        let (ws_stream, _) = tokio_tungstenite::connect_async(&self.policy_url)
            .await
            .map_err(|e| ThresholdError::PolicyUnavailable(format!("connect: {e}")))?;

        let (ws_tx, mut ws_rx) = ws_stream.split();
        let ws_tx = Arc::new(Mutex::new(ws_tx));

        // Send sign request
        let sign_req = WireMessage::SignRequest(SignRequest {
            request_id: request_id.clone(),
            session_id: session_id.clone(),
            wallet: wallet.to_string(),
            action,
            tx_details,
            message_hash: format!("0x{}", hex::encode(message_hash)),
        });

        send_ws(&ws_tx, &sign_req).await?;

        // Wait for policy decision (with timeout)
        let decision = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match read_ws_msg(&mut ws_rx).await? {
                    WireMessage::PolicyDecision(d) if d.request_id == request_id => {
                        return Ok::<_, ThresholdError>(d);
                    }
                    _ => continue,
                }
            }
        })
        .await
        .map_err(|_| ThresholdError::PolicyUnavailable("decision timeout (5s)".into()))??;

        match decision.decision {
            Decision::Deny => {
                return Err(ThresholdError::PolicyDenied {
                    rule: decision.matched_rule,
                    reason: decision.reason,
                });
            }
            Decision::Escalate => {
                return Err(ThresholdError::Escalated {
                    rule: decision.matched_rule,
                    reason: decision.reason,
                });
            }
            Decision::Approve => {}
        }

        // MPC signing
        type SignMsg = cggmp21::signing::msg::Msg<Secp256k1, sha2::Sha256>;
        let (incoming_tx, incoming_rx) =
            mpsc::unbounded::<Result<Incoming<SignMsg>, DeliveryError>>();
        let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded::<Outgoing<SignMsg>>();

        let eid_bytes: Vec<u8> = format!("sign-{request_id}").into_bytes();
        let signers = vec![PARTY_DAEMON, PARTY_POLICY];

        // Outgoing: MPC → WS
        let ws_tx_c = ws_tx.clone();
        let sid_out = session_id.clone();
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
                    from: PARTY_DAEMON,
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
        let ks = self.key_share.clone();
        let hash = *message_hash;
        let sign_task = tokio::spawn(async move {
            let eid = cggmp21::ExecutionId::new(&eid_bytes);
            signing::sign_full(eid, 0, &signers, &ks, &hash, (incoming_rx, outgoing_tx)).await
        });

        // Feed incoming MPC messages from WS
        let counter = AtomicU64::new(0);
        let sid_in = session_id;

        loop {
            if sign_task.is_finished() {
                break;
            }

            let msg = tokio::time::timeout(Duration::from_millis(50), ws_rx.next()).await;

            let item = match msg {
                Ok(Some(item)) => item,
                Ok(None) => {
                    let _ = incoming_tx.unbounded_send(Err(DeliveryError("ws ended".into())));
                    break;
                }
                Err(_) => continue,
            };

            let raw = match item {
                Ok(WsMessage::Binary(d)) => d.to_vec(),
                Ok(WsMessage::Text(t)) => t.into_bytes(),
                Ok(WsMessage::Ping(_) | WsMessage::Pong(_)) => continue,
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

        let result = sign_task
            .await
            .map_err(|e| ThresholdError::Mpc(format!("task panic: {e}")))?
            .map_err(|e| ThresholdError::Mpc(format!("{e}")))?;

        out_task.abort();

        Ok(ThresholdSignResult {
            request_id,
            signature: result,
            matched_rule: decision.matched_rule,
        })
    }
}

/// Generate one presignature via MPC with the policy server.
async fn generate_one_presignature(
    pool: &Arc<Mutex<PresignaturePool>>,
    key_share: &KeyShare<Secp256k1>,
    policy_url: &str,
) -> Result<u64, ThresholdError> {
    let presig_index = {
        let mut p = pool.lock().await;
        p.reserve_index()
    };

    let session_id = SessionId::random();

    // Connect to policy
    let (ws_stream, _) = tokio_tungstenite::connect_async(policy_url)
        .await
        .map_err(|e| ThresholdError::PolicyUnavailable(format!("connect: {e}")))?;

    let (ws_tx, mut ws_rx) = ws_stream.split();
    let ws_tx = Arc::new(Mutex::new(ws_tx));

    // Send presign request
    let req = WireMessage::PresignRequest(PresignRequest {
        session_id: session_id.clone(),
        presig_index,
        wallet: String::new(), // Background presign doesn't need wallet context
    });
    send_ws(&ws_tx, &req).await?;

    // Run presignature generation MPC
    type SignMsg = cggmp21::signing::msg::Msg<Secp256k1, sha2::Sha256>;
    let (incoming_tx, incoming_rx) =
        mpsc::unbounded::<Result<Incoming<SignMsg>, DeliveryError>>();
    let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded::<Outgoing<SignMsg>>();

    let eid_bytes: Vec<u8> = format!("presign-{presig_index}").into_bytes();
    let signers = vec![PARTY_DAEMON, PARTY_POLICY];

    // Outgoing: MPC → WS
    let ws_tx_c = ws_tx.clone();
    let sid_out = session_id.clone();
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
                from: PARTY_DAEMON,
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
        signing::generate_presignature(eid, 0, &signers, &ks, (incoming_rx, outgoing_tx)).await
    });

    // Feed incoming MPC messages
    let counter = AtomicU64::new(0);
    let sid_in = session_id;

    loop {
        if presign_task.is_finished() {
            break;
        }

        let msg = tokio::time::timeout(Duration::from_millis(50), ws_rx.next()).await;

        let item = match msg {
            Ok(Some(item)) => item,
            Ok(None) => {
                let _ = incoming_tx.unbounded_send(Err(DeliveryError("ws ended".into())));
                break;
            }
            Err(_) => continue,
        };

        let raw = match item {
            Ok(WsMessage::Binary(d)) => d.to_vec(),
            Ok(WsMessage::Text(t)) => t.into_bytes(),
            Ok(WsMessage::Ping(_) | WsMessage::Pong(_)) => continue,
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

    let presignature = presign_task
        .await
        .map_err(|e| ThresholdError::Mpc(format!("task panic: {e}")))?
        .map_err(|e| ThresholdError::Mpc(format!("{e}")))?;

    out_task.abort();

    // Store in pool
    pool.lock().await.add(presig_index, presignature);

    Ok(presig_index)
}

/// Result of a successful threshold signing operation.
pub struct ThresholdSignResult {
    pub request_id: String,
    pub signature: signing::CggmpSignature<Secp256k1>,
    pub matched_rule: Option<String>,
}

/// Errors specific to threshold signing.
#[derive(Debug)]
pub enum ThresholdError {
    /// Policy agent unreachable or timed out
    PolicyUnavailable(String),
    /// Policy denied the request
    PolicyDenied {
        rule: Option<String>,
        reason: Option<String>,
    },
    /// Policy escalated — requires human cosigner
    Escalated {
        rule: Option<String>,
        reason: Option<String>,
    },
    /// MPC protocol error
    Mpc(String),
    /// Transport error
    Transport(String),
}

impl std::fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolicyUnavailable(e) => write!(f, "policy_unavailable: {e}"),
            Self::PolicyDenied { rule, reason } => {
                write!(f, "policy_denied")?;
                if let Some(r) = rule {
                    write!(f, " (rule: {r})")?;
                }
                if let Some(r) = reason {
                    write!(f, ": {r}")?;
                }
                Ok(())
            }
            Self::Escalated { rule, reason } => {
                write!(f, "escalated")?;
                if let Some(r) = rule {
                    write!(f, " (rule: {r})")?;
                }
                if let Some(r) = reason {
                    write!(f, ": {r}")?;
                }
                Ok(())
            }
            Self::Mpc(e) => write!(f, "mpc_error: {e}"),
            Self::Transport(e) => write!(f, "transport_error: {e}"),
        }
    }
}

impl std::error::Error for ThresholdError {}

// Helpers

fn generate_request_id() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

async fn send_ws<S>(
    tx: &Arc<Mutex<futures::stream::SplitSink<tokio_tungstenite::WebSocketStream<S>, WsMessage>>>,
    msg: &WireMessage,
) -> Result<(), ThresholdError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let data = serde_json::to_vec(msg).map_err(|e| ThresholdError::Transport(format!("{e}")))?;
    let mut guard = tx.lock().await;
    guard
        .send(WsMessage::Binary(data.into()))
        .await
        .map_err(|e| ThresholdError::Transport(format!("{e}")))?;
    Ok(())
}

async fn read_ws_msg<S>(
    rx: &mut futures::stream::SplitStream<tokio_tungstenite::WebSocketStream<S>>,
) -> Result<WireMessage, ThresholdError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        match rx.next().await {
            Some(Ok(WsMessage::Binary(d))) => {
                return serde_json::from_slice(&d)
                    .map_err(|e| ThresholdError::Transport(format!("{e}")));
            }
            Some(Ok(WsMessage::Text(t))) => {
                return serde_json::from_str(&t)
                    .map_err(|e| ThresholdError::Transport(format!("{e}")));
            }
            Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => continue,
            Some(Ok(WsMessage::Close(_))) => {
                return Err(ThresholdError::Transport("ws closed".into()));
            }
            Some(Err(e)) => {
                return Err(ThresholdError::Transport(format!("{e}")));
            }
            None => {
                return Err(ThresholdError::Transport("ws ended".into()));
            }
            _ => continue,
        }
    }
}
