use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use saw::{gen_key, Chain};

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

fn start_server(root: PathBuf, socket_path: PathBuf, count: usize) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        saw_daemon::serve_n(&socket_path, &root, count).expect("serve n");
    })
}

fn send_request(socket_path: &PathBuf, request: &str) -> serde_json::Value {
    let mut stream = UnixStream::connect(socket_path).expect("connect");
    stream.write_all(request.as_bytes()).expect("write request");
    stream.shutdown(std::net::Shutdown::Write).ok();
    read_response(stream)
}

#[test]
fn audit_log_records_approved_tx_without_payload() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    gen_key(Chain::Evm, "main", &root).expect("gen key");

    let policy = "wallets:\n  main:\n    chain: evm\n    allowed_chains: [1]\n    allowlist_addresses:\n      - \"0x1111111111111111111111111111111111111111\"\n";
    fs::write(root.join("policy.yaml"), policy).expect("write policy");

    let handle = start_server(root.clone(), socket_path.clone(), 1);

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let request = "{\"request_id\":\"1\",\"action\":\"sign_evm_tx\",\"wallet\":\"main\",\"payload\":{\"chain_id\":1,\"nonce\":0,\"to\":\"0x1111111111111111111111111111111111111111\",\"value\":\"0x0\",\"gas_limit\":21000,\"max_fee_per_gas\":\"0x3b9aca00\",\"max_priority_fee_per_gas\":\"0x3b9aca00\",\"data\":\"0x\"}}";
    let response = send_request(&socket_path, request);

    assert_eq!(response["status"], "approved");

    handle.join().expect("server join");

    let audit = fs::read_to_string(root.join("audit.log")).expect("audit log");
    assert!(audit.contains("wallet=main"));
    assert!(audit.contains("action=sign_evm_tx"));
    assert!(audit.contains("status=approved"));
    assert!(audit.contains("tx_hash=0x"));
    assert!(!audit.contains("payload"));
    assert!(!audit.contains("max_fee_per_gas"));
}

#[test]
fn audit_log_records_denied_request() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    gen_key(Chain::Evm, "main", &root).expect("gen key");

    let policy = "wallets:\n  main:\n    chain: evm\n    allowlist_addresses:\n      - \"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n";
    fs::write(root.join("policy.yaml"), policy).expect("write policy");

    let handle = start_server(root.clone(), socket_path.clone(), 1);

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let request = "{\"request_id\":\"2\",\"action\":\"sign_evm_tx\",\"wallet\":\"main\",\"payload\":{\"chain_id\":1,\"nonce\":0,\"to\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"value\":\"0x0\",\"gas_limit\":21000,\"max_fee_per_gas\":\"0x3b9aca00\",\"max_priority_fee_per_gas\":\"0x3b9aca00\",\"data\":\"0x\"}}";
    let response = send_request(&socket_path, request);

    assert_eq!(response["status"], "denied");

    handle.join().expect("server join");

    let audit = fs::read_to_string(root.join("audit.log")).expect("audit log");
    assert!(audit.contains("wallet=main"));
    assert!(audit.contains("action=sign_evm_tx"));
    assert!(audit.contains("status=denied"));
}
