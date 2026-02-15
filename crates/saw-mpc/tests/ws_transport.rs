//! Integration test: 2-party signing over WebSocket transport.
//!
//! Runs keygen in-memory (fast, already tested), then does signing
//! over a real WebSocket connection between two tasks.

use saw_mpc::keygen;
use saw_mpc::signing;
use saw_mpc::transport;
use saw_mpc::protocol::SessionId;
use saw_mpc::types::{PARTY_DAEMON, PARTY_POLICY};

use sha2::Digest;

#[tokio::test]
async fn sign_over_websocket() {
    let _ = tracing_subscriber::fmt::try_init();

    let n: u16 = 3;
    let t: u16 = 2;

    // --- Keygen in-memory (reuse proven path) ---
    let primes: Vec<_> = (0..n).map(|_| keygen::pregenerate_primes()).collect();

    let aux_eid = cggmp21::ExecutionId::new(b"ws-test-aux");
    let aux_deliveries = transport::in_memory_delivery(n);
    let mut aux_handles = Vec::new();
    for (i, (delivery, prime)) in aux_deliveries.into_iter().zip(primes).enumerate() {
        let eid = aux_eid.clone();
        aux_handles.push(tokio::spawn(async move {
            keygen::generate_aux_info(eid, i as u16, n, prime, delivery).await
        }));
    }
    let mut aux_infos = Vec::new();
    for h in aux_handles {
        aux_infos.push(h.await.unwrap().expect("aux info failed"));
    }

    let keygen_eid = cggmp21::ExecutionId::new(b"ws-test-keygen");
    let keygen_deliveries = transport::in_memory_delivery(n);
    let mut keygen_handles = Vec::new();
    for (i, delivery) in keygen_deliveries.into_iter().enumerate() {
        let eid = keygen_eid.clone();
        keygen_handles.push(tokio::spawn(async move {
            keygen::generate_key(eid, i as u16, n, t, delivery).await
        }));
    }
    let mut key_shares = Vec::new();
    for h in keygen_handles {
        let incomplete = h.await.unwrap().expect("keygen failed");
        key_shares.push(incomplete);
    }
    let mut complete_shares = Vec::new();
    for (inc, aux) in key_shares.into_iter().zip(aux_infos) {
        let out = keygen::complete_key_share(inc, aux).expect("complete failed");
        complete_shares.push(out.key_share);
    }

    println!("Keygen done, starting WebSocket signing test...");

    // --- Signing over WebSocket ---
    let message_hash = [0xABu8; 32];
    let signers_at_keygen: Vec<u16> = vec![PARTY_DAEMON, PARTY_POLICY];
    let session_id = SessionId::random();

    // Bind a TCP listener on a random port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind failed");
    let addr = listener.local_addr().unwrap();
    let ws_url = format!("ws://{addr}");

    let ks_daemon = complete_shares[PARTY_DAEMON as usize].clone();
    let ks_policy = complete_shares[PARTY_POLICY as usize].clone();
    let signers_d = signers_at_keygen.clone();
    let signers_p = signers_at_keygen.clone();
    let sid_d = session_id.clone();
    let sid_p = session_id.clone();
    let hash_d = message_hash;
    let hash_p = message_hash;

    // Server side (saw-policy, party 1)
    let server_handle = tokio::spawn(async move {
        let conn = transport::ws_accept(&listener, PARTY_POLICY, PARTY_DAEMON, n)
            .await
            .expect("ws accept failed");

        let delivery = conn.into_delivery(sid_p);

        signing::sign_full(
            cggmp21::ExecutionId::new(b"ws-test-sign"),
            1, // party index in signing group
            &signers_p,
            &ks_policy,
            &hash_p,
            delivery,
        )
        .await
        .expect("policy signing failed")
    });

    // Small delay to let server bind
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Client side (saw-daemon, party 0)
    let client_handle = tokio::spawn(async move {
        let conn = transport::ws_connect(&ws_url, PARTY_DAEMON, PARTY_POLICY, n)
            .await
            .expect("ws connect failed");

        let delivery = conn.into_delivery(sid_d);

        signing::sign_full(
            cggmp21::ExecutionId::new(b"ws-test-sign"),
            0, // party index in signing group
            &signers_d,
            &ks_daemon,
            &hash_d,
            delivery,
        )
        .await
        .expect("daemon signing failed")
    });

    let (sig_policy, sig_daemon) = tokio::join!(server_handle, client_handle);
    let sig_policy = sig_policy.unwrap();
    let sig_daemon = sig_daemon.unwrap();

    assert_eq!(sig_policy, sig_daemon, "both parties should produce same signature");

    // Verify
    let data = cggmp21::DataToSign::from_digest(
        sha2::Sha256::new_with_prefix(&message_hash),
    );
    sig_daemon
        .verify(&complete_shares[0].shared_public_key, &data)
        .expect("signature verification failed");

    println!("✓ WebSocket signing verified!");
}
