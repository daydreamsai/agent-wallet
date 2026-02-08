use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

fn temp_root() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("saw-test-{}-{}-{}", std::process::id(), nanos, counter));
    fs::create_dir_all(&path).expect("create temp root");
    path
}

fn read_response(mut stream: UnixStream) -> serde_json::Value {
    let mut buf = String::new();
    stream.read_to_string(&mut buf).expect("read response");
    serde_json::from_str(&buf).expect("valid json response")
}

fn start_server(root: PathBuf, socket_path: PathBuf) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        saw_daemon::serve_n(&socket_path, &root, 1).expect("serve n");
    })
}

#[test]
fn sign_sol_tx_returns_signature_and_signed_tx() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    let secret = [7u8; 32];
    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();
    let mut key_bytes = Vec::with_capacity(64);
    key_bytes.extend_from_slice(&secret);
    key_bytes.extend_from_slice(verifying_key.as_bytes());

    let keys_dir = root.join("keys").join("sol");
    fs::create_dir_all(&keys_dir).expect("create keys dir");
    fs::write(keys_dir.join("treasury.key"), &key_bytes).expect("write key");

    fs::write(
        root.join("policy.yaml"),
        "wallets:\n  treasury:\n    chain: sol\n",
    )
    .expect("write policy");

    let handle = start_server(root.clone(), socket_path.clone());

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let message = b"hello-solana";
    let message_b64 = general_purpose::STANDARD.encode(message);
    let request = format!(
        "{{\"request_id\":\"1\",\"action\":\"sign_sol_tx\",\"wallet\":\"treasury\",\"payload\":{{\"message_base64\":\"{}\"}}}}",
        message_b64
    );

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    stream.write_all(request.as_bytes()).expect("write request");
    stream.shutdown(std::net::Shutdown::Write).ok();

    let response = read_response(stream);
    assert_eq!(response["status"], "approved");

    let signature_b58 = response["result"]["signature"].as_str().expect("sig");
    let signed_tx_b64 = response["result"]["signed_tx_base64"].as_str().expect("signed tx");

    let sig_bytes = bs58::decode(signature_b58)
        .into_vec()
        .expect("sig b58");
    let signature = Signature::from_slice(&sig_bytes).expect("sig");

    let verify_key = VerifyingKey::from(&signing_key);
    verify_key.verify_strict(message, &signature).expect("verify");

    let signed_bytes = general_purpose::STANDARD
        .decode(signed_tx_b64)
        .expect("signed tx b64");
    assert_eq!(signed_bytes[0], 1, "signature count");
    assert_eq!(signed_bytes[1..65], sig_bytes[..]);
    assert_eq!(&signed_bytes[65..], message);

    handle.join().expect("server join");
}
