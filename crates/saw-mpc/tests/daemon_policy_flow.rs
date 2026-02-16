//! End-to-end integration test: saw-daemon ThresholdClient → saw-policy server.
//!
//! 1. Generate key shares (in-memory, 2-of-3)
//! 2. Start saw-policy server with share 1 + permissive policy
//! 3. ThresholdClient (share 0) sends sign request
//! 4. Policy approves → MPC signing → verified ECDSA signature

// This test lives in saw-mpc to avoid circular deps, but tests the full flow
// by directly using saw_daemon::threshold and saw_policy server internals.
// In a real deploy, these are separate binaries on separate machines.

// NOTE: This test cannot import saw-policy (binary crate) or saw-daemon (has
// Unix-specific deps). Instead we test the WebSocket transport + MPC flow
// end-to-end using just saw-mpc primitives — simulating what daemon and policy do.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use cggmp21::round_based::{Incoming, MessageDestination, MessageType, Outgoing};
use saw_mpc::error::MpcError;
use saw_mpc::keygen;
use saw_mpc::protocol::*;
use saw_mpc::signing;
use saw_mpc::transport::DeliveryError;
use saw_mpc::types::{PARTY_DAEMON, PARTY_POLICY};
use saw_mpc::{KeyShare, Secp256k1};

type SignMsg = cggmp21::signing::msg::Msg<Secp256k1, sha2::Sha256>;

#[tokio::test]
async fn full_daemon_policy_flow() {
    let _ = tracing_subscriber::fmt::try_init();

    let n: u16 = 3;
    let t: u16 = 2;

    // --- Keygen ---
    let primes: Vec<_> = (0..n).map(|_| keygen::pregenerate_primes()).collect();

    let aux_eid = cggmp21::ExecutionId::new(b"flow-aux");
    let aux_deliveries = saw_mpc::transport::in_memory_delivery(n);
    let mut aux_handles = Vec::new();
    for (i, (delivery, prime)) in aux_deliveries.into_iter().zip(primes).enumerate() {
        let eid = aux_eid.clone();
        aux_handles.push(tokio::spawn(async move {
            keygen::generate_aux_info(eid, i as u16, n, prime, delivery).await
        }));
    }
    let mut aux_infos = Vec::new();
    for h in aux_handles {
        aux_infos.push(h.await.unwrap().unwrap());
    }

    let keygen_eid = cggmp21::ExecutionId::new(b"flow-keygen");
    let keygen_deliveries = saw_mpc::transport::in_memory_delivery(n);
    let mut keygen_handles = Vec::new();
    for (i, delivery) in keygen_deliveries.into_iter().enumerate() {
        let eid = keygen_eid.clone();
        keygen_handles.push(tokio::spawn(async move {
            keygen::generate_key(eid, i as u16, n, t, delivery).await
        }));
    }
    let mut key_shares = Vec::new();
    for h in keygen_handles {
        key_shares.push(h.await.unwrap().unwrap());
    }
    let mut complete_shares = Vec::new();
    for (inc, aux) in key_shares.into_iter().zip(aux_infos) {
        complete_shares.push(keygen::complete_key_share(inc, aux).unwrap().key_share);
    }

    let ks_daemon = complete_shares[PARTY_DAEMON as usize].clone();
    let ks_policy = complete_shares[PARTY_POLICY as usize].clone();

    println!("Keygen done, testing full daemon→policy flow over WebSocket...");

    // --- Set up WS server (policy side) ---
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ws_url = format!("ws://{addr}");

    let message_hash = [0xBEu8; 32];

    // Policy server task
    let hash_p = message_hash;
    let policy_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        let (ws_tx, mut ws_rx) = ws.split();
        let ws_tx = Arc::new(Mutex::new(ws_tx));

        // 1. Read SignRequest
        let raw = loop {
            if let Some(Ok(WsMessage::Binary(d))) = ws_rx.next().await {
                break d.to_vec();
            }
        };
        let wire: WireMessage = serde_json::from_slice(&raw).unwrap();
        let sign_req = match wire {
            WireMessage::SignRequest(r) => r,
            _ => panic!("expected SignRequest"),
        };

        // 2. Send Approve decision
        let decision = PolicyDecision {
            request_id: sign_req.request_id.clone(),
            decision: Decision::Approve,
            matched_rule: Some("test-allow-all".into()),
            reason: None,
        };
        let data = serde_json::to_vec(&WireMessage::PolicyDecision(decision)).unwrap();
        ws_tx.lock().await.send(WsMessage::Binary(data.into())).await.unwrap();

        // 3. MPC signing
        let (incoming_tx, incoming_rx) = mpsc::unbounded::<Result<Incoming<SignMsg>, DeliveryError>>();
        let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded::<Outgoing<SignMsg>>();

        let eid_bytes: Vec<u8> = format!("sign-{}", sign_req.request_id).into_bytes();
        let signers = vec![PARTY_DAEMON, PARTY_POLICY];
        let sid = sign_req.session_id.clone();

        // Outgoing router
        let ws_tx_c = ws_tx.clone();
        let sid_out = sid.clone();
        tokio::spawn(async move {
            while let Some(out) = outgoing_rx.next().await {
                let to = match out.recipient {
                    MessageDestination::AllParties => None,
                    MessageDestination::OneParty(p) => Some(p),
                };
                let data = serde_json::to_vec(&out.msg).unwrap();
                let wire = WireMessage::Mpc(MpcWireMessage {
                    session_id: sid_out.clone(),
                    from: PARTY_POLICY,
                    to,
                    data,
                });
                let json = serde_json::to_vec(&wire).unwrap();
                let mut tx = ws_tx_c.lock().await;
                let _ = tx.send(WsMessage::Binary(json.into())).await;
            }
        });

        // Sign task
        let sign_task = tokio::spawn(async move {
            let eid = cggmp21::ExecutionId::new(&eid_bytes);
            signing::sign_full(eid, 1, &signers, &ks_policy, &hash_p, (incoming_rx, outgoing_tx)).await
        });

        // Incoming router
        let counter = AtomicU64::new(0);
        let sid_in = sid;
        loop {
            if sign_task.is_finished() { break; }
            let msg = tokio::time::timeout(std::time::Duration::from_millis(50), ws_rx.next()).await;
            match msg {
                Ok(Some(Ok(WsMessage::Binary(d)))) => {
                    if let Ok(WireMessage::Mpc(m)) = serde_json::from_slice::<WireMessage>(&d) {
                        if m.session_id == sid_in {
                            if let Ok(msg) = serde_json::from_slice::<SignMsg>(&m.data) {
                                let mt = if m.to.is_some() { MessageType::P2P } else { MessageType::Broadcast };
                                let _ = incoming_tx.unbounded_send(Ok(Incoming {
                                    id: counter.fetch_add(1, Ordering::Relaxed),
                                    sender: m.from, msg_type: mt, msg,
                                }));
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        sign_task.await.unwrap().unwrap()
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // --- Daemon client side ---
    let hash_d = message_hash;
    let daemon_task = tokio::spawn(async move {
        let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
        let (ws_tx, mut ws_rx) = ws.split();
        let ws_tx = Arc::new(Mutex::new(ws_tx));

        let request_id = "test-req-001".to_string();
        let session_id = SessionId::from_str("test-session-001");

        // 1. Send SignRequest
        let req = WireMessage::SignRequest(SignRequest {
            request_id: request_id.clone(),
            session_id: session_id.clone(),
            wallet: "test-wallet".into(),
            action: SignAction::EvmTx,
            tx_details: TxDetails {
                chain_id: Some(1),
                to: Some("0x0000000000000000000000000000000000000001".into()),
                value: Some("0".into()),
                data_len: 0,
                is_contract_call: false,
            },
            message_hash: format!("0x{}", hex::encode(hash_d)),
        });
        let data = serde_json::to_vec(&req).unwrap();
        ws_tx.lock().await.send(WsMessage::Binary(data.into())).await.unwrap();

        // 2. Read PolicyDecision
        let decision = loop {
            if let Some(Ok(WsMessage::Binary(d))) = ws_rx.next().await {
                if let Ok(WireMessage::PolicyDecision(dec)) = serde_json::from_slice(&d) {
                    break dec;
                }
            }
        };
        assert_eq!(decision.decision, Decision::Approve);
        println!("Policy approved! Starting MPC...");

        // 3. MPC signing
        let (incoming_tx, incoming_rx) = mpsc::unbounded::<Result<Incoming<SignMsg>, DeliveryError>>();
        let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded::<Outgoing<SignMsg>>();

        let eid_bytes: Vec<u8> = format!("sign-{request_id}").into_bytes();
        let signers = vec![PARTY_DAEMON, PARTY_POLICY];
        let sid = session_id.clone();

        let ws_tx_c = ws_tx.clone();
        let sid_out = sid.clone();
        tokio::spawn(async move {
            while let Some(out) = outgoing_rx.next().await {
                let to = match out.recipient {
                    MessageDestination::AllParties => None,
                    MessageDestination::OneParty(p) => Some(p),
                };
                let data = serde_json::to_vec(&out.msg).unwrap();
                let wire = WireMessage::Mpc(MpcWireMessage {
                    session_id: sid_out.clone(),
                    from: PARTY_DAEMON,
                    to,
                    data,
                });
                let json = serde_json::to_vec(&wire).unwrap();
                let mut tx = ws_tx_c.lock().await;
                let _ = tx.send(WsMessage::Binary(json.into())).await;
            }
        });

        let sign_task = tokio::spawn(async move {
            let eid = cggmp21::ExecutionId::new(&eid_bytes);
            signing::sign_full(eid, 0, &signers, &ks_daemon, &hash_d, (incoming_rx, outgoing_tx)).await
        });

        let counter = AtomicU64::new(0);
        let sid_in = sid;
        loop {
            if sign_task.is_finished() { break; }
            let msg = tokio::time::timeout(std::time::Duration::from_millis(50), ws_rx.next()).await;
            match msg {
                Ok(Some(Ok(WsMessage::Binary(d)))) => {
                    if let Ok(WireMessage::Mpc(m)) = serde_json::from_slice::<WireMessage>(&d) {
                        if m.session_id == sid_in {
                            if let Ok(msg) = serde_json::from_slice::<SignMsg>(&m.data) {
                                let mt = if m.to.is_some() { MessageType::P2P } else { MessageType::Broadcast };
                                let _ = incoming_tx.unbounded_send(Ok(Incoming {
                                    id: counter.fetch_add(1, Ordering::Relaxed),
                                    sender: m.from, msg_type: mt, msg,
                                }));
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        sign_task.await.unwrap().unwrap()
    });

    let (sig_policy, sig_daemon) = tokio::join!(policy_task, daemon_task);
    let sig_policy = sig_policy.unwrap();
    let sig_daemon = sig_daemon.unwrap();

    assert_eq!(sig_policy, sig_daemon);

    // Verify
    let data = cggmp21::DataToSign::from_scalar(
        generic_ec::Scalar::from_be_bytes_mod_order(&message_hash),
    );
    sig_daemon
        .verify(&complete_shares[0].shared_public_key, &data)
        .expect("verification failed");

    println!("✓ Full daemon→policy signing flow verified!");
}
