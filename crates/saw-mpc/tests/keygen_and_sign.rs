//! Integration test: run a full 2-of-3 keygen ceremony followed by
//! presignature generation and signing, all in-memory.

use saw_mpc::keygen;
use saw_mpc::signing;
use saw_mpc::transport;

#[tokio::test]
async fn keygen_2of3_and_sign() {
    let _ = tracing_subscriber::fmt::try_init();

    let n: u16 = 3;
    let t: u16 = 2;

    // --- Phase 1: Aux info generation ---
    // Each party needs Paillier primes (slow, do in parallel)
    let primes: Vec<_> = (0..n).map(|_| keygen::pregenerate_primes()).collect();

    let aux_eid = cggmp21::ExecutionId::new(b"test-aux-info-001");
    let aux_deliveries = transport::in_memory_delivery(n);

    let mut aux_handles = Vec::new();
    for (i, (delivery, prime)) in aux_deliveries.into_iter().zip(primes).enumerate() {
        let eid = aux_eid.clone();
        aux_handles.push(tokio::spawn(async move {
            keygen::generate_aux_info(eid, i as u16, n, prime, delivery).await
        }));
    }

    let mut aux_infos = Vec::new();
    for handle in aux_handles {
        let aux = handle.await.unwrap().expect("aux info gen failed");
        aux_infos.push(aux);
    }

    // --- Phase 2: Key generation ---
    let keygen_eid = cggmp21::ExecutionId::new(b"test-keygen-001");
    let keygen_deliveries = transport::in_memory_delivery(n);

    let mut keygen_handles = Vec::new();
    for (i, delivery) in keygen_deliveries.into_iter().enumerate() {
        let eid = keygen_eid.clone();
        keygen_handles.push(tokio::spawn(async move {
            keygen::generate_key(eid, i as u16, n, t, delivery).await
        }));
    }

    let mut incomplete_shares = Vec::new();
    for handle in keygen_handles {
        let share = handle.await.unwrap().expect("keygen failed");
        incomplete_shares.push(share);
    }

    // --- Phase 3: Complete key shares ---
    let mut key_shares = Vec::new();
    let mut address = String::new();
    for (incomplete, aux) in incomplete_shares.into_iter().zip(aux_infos) {
        let output = keygen::complete_key_share(incomplete, aux)
            .expect("complete key share failed");
        if address.is_empty() {
            address = output.address.clone();
        } else {
            // All parties should derive the same address
            assert_eq!(address, output.address, "address mismatch between parties");
        }
        key_shares.push(output.key_share);
    }

    println!("Generated wallet address: {address}");
    assert!(address.starts_with("0x"));
    assert_eq!(address.len(), 42); // 0x + 40 hex chars

    // --- Phase 4: Signing (parties 0 and 1, i.e., daemon + policy) ---
    let message_hash = [0x42u8; 32]; // test message

    // For 2-of-3, parties 0 and 1 sign. Their indices in the signing
    // group are 0 and 1, but their keygen indices are also 0 and 1.
    let signers_at_keygen: Vec<u16> = vec![0, 1];
    let sign_eid = cggmp21::ExecutionId::new(b"test-sign-001");
    let sign_deliveries = transport::in_memory_delivery(t);

    let mut sign_handles = Vec::new();
    for (i, delivery) in sign_deliveries.into_iter().enumerate() {
        let eid = sign_eid.clone();
        let ks = key_shares[i].clone();
        let signers = signers_at_keygen.clone();
        let hash = message_hash;
        sign_handles.push(tokio::spawn(async move {
            signing::sign_full(eid, i as u16, &signers, &ks, &hash, delivery).await
        }));
    }

    let mut signatures = Vec::new();
    for handle in sign_handles {
        let sig = handle.await.unwrap().expect("signing failed");
        signatures.push(sig);
    }

    // Both parties should produce the same signature
    assert_eq!(signatures[0], signatures[1], "signatures should match");
    println!("Signature: r={:?}, s={:?}", signatures[0].r, signatures[0].s);

    // Verify the signature against the public key
    let data = cggmp21::DataToSign::from_digest(
        sha2::Sha256::new_with_prefix(&message_hash),
    );
    signatures[0]
        .verify(&key_shares[0].shared_public_key, &data)
        .expect("signature verification failed");

    println!("✓ Signature verified successfully!");
}

use sha2::Digest;
