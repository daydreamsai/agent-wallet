use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rlp::Rlp;
use saw::{gen_key, Chain};
use sha3::{Digest, Keccak256};

fn temp_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let mut path = std::env::temp_dir();
    path.push(format!("saw-test-{}", nanos));
    fs::create_dir_all(&path).expect("create temp root");
    path
}

fn read_response(mut stream: UnixStream) -> serde_json::Value {
    let mut buf = String::new();
    stream.read_to_string(&mut buf).expect("read response");
    serde_json::from_str(&buf).expect("valid json response")
}

fn write_policy(root: &Path, policy: &str) {
    fs::write(root.join("policy.yaml"), policy).expect("write policy");
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
fn sign_evm_tx_happy_path() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    gen_key(Chain::Evm, "main", &root).expect("gen key");

    let policy = "wallets:\n  main:\n    chain: evm\n    allowed_chains: [1]\n    max_tx_value_eth: 1.0\n    allow_contract_calls: false\n    allowlist_addresses:\n      - \"0x1111111111111111111111111111111111111111\"\n    rate_limit_per_minute: 10\n";
    write_policy(&root, policy);

    let handle = start_server(root.clone(), socket_path.clone(), 1);

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let request = "{\"request_id\":\"1\",\"action\":\"sign_evm_tx\",\"wallet\":\"main\",\"payload\":{\"chain_id\":1,\"nonce\":0,\"to\":\"0x1111111111111111111111111111111111111111\",\"value\":\"0x38d7ea4c68000\",\"gas_limit\":21000,\"max_fee_per_gas\":\"0x3b9aca00\",\"max_priority_fee_per_gas\":\"0x3b9aca00\",\"data\":\"0x\"}}";
    let response = send_request(&socket_path, request);

    assert_eq!(response["status"], "approved");
    let raw_tx = response["result"]["raw_tx"].as_str().expect("raw_tx");
    let tx_hash = response["result"]["tx_hash"].as_str().expect("tx_hash");

    let raw_bytes = hex::decode(raw_tx.trim_start_matches("0x")).expect("raw tx hex");
    assert_eq!(raw_bytes[0], 0x02);

    let mut hasher = Keccak256::new();
    hasher.update(&raw_bytes);
    let expected_hash = format!("0x{}", hex::encode(hasher.finalize()));
    assert_eq!(tx_hash, expected_hash);

    let rlp = Rlp::new(&raw_bytes[1..]);
    assert_eq!(rlp.item_count().unwrap_or(0), 12);
    assert_eq!(rlp.val_at::<u64>(0).unwrap(), 1);
    assert_eq!(rlp.val_at::<u64>(1).unwrap(), 0);
    assert_eq!(rlp.val_at::<u64>(4).unwrap(), 21000);
    let to = rlp.val_at::<Vec<u8>>(5).unwrap();
    assert_eq!(hex::encode(to), "1111111111111111111111111111111111111111");

    handle.join().expect("server join");
}

#[test]
fn sign_evm_tx_denies_chain_id() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    gen_key(Chain::Evm, "main", &root).expect("gen key");

    let policy = "wallets:\n  main:\n    chain: evm\n    allowed_chains: [1]\n";
    write_policy(&root, policy);

    let handle = start_server(root.clone(), socket_path.clone(), 1);

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let request = "{\"request_id\":\"2\",\"action\":\"sign_evm_tx\",\"wallet\":\"main\",\"payload\":{\"chain_id\":2,\"nonce\":0,\"to\":\"0x1111111111111111111111111111111111111111\",\"value\":\"0x0\",\"gas_limit\":21000,\"max_fee_per_gas\":\"0x3b9aca00\",\"max_priority_fee_per_gas\":\"0x3b9aca00\",\"data\":\"0x\"}}";
    let response = send_request(&socket_path, request);

    assert_eq!(response["status"], "denied");

    handle.join().expect("server join");
}

#[test]
fn sign_evm_tx_denies_allowlist() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    gen_key(Chain::Evm, "main", &root).expect("gen key");

    let policy = "wallets:\n  main:\n    chain: evm\n    allowlist_addresses:\n      - \"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n";
    write_policy(&root, policy);

    let handle = start_server(root.clone(), socket_path.clone(), 1);

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let request = "{\"request_id\":\"3\",\"action\":\"sign_evm_tx\",\"wallet\":\"main\",\"payload\":{\"chain_id\":1,\"nonce\":0,\"to\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"value\":\"0x0\",\"gas_limit\":21000,\"max_fee_per_gas\":\"0x3b9aca00\",\"max_priority_fee_per_gas\":\"0x3b9aca00\",\"data\":\"0x\"}}";
    let response = send_request(&socket_path, request);

    assert_eq!(response["status"], "denied");

    handle.join().expect("server join");
}

#[test]
fn sign_evm_tx_denies_contract_call() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    gen_key(Chain::Evm, "main", &root).expect("gen key");

    let policy = "wallets:\n  main:\n    chain: evm\n    allow_contract_calls: false\n";
    write_policy(&root, policy);

    let handle = start_server(root.clone(), socket_path.clone(), 1);

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let request = "{\"request_id\":\"4\",\"action\":\"sign_evm_tx\",\"wallet\":\"main\",\"payload\":{\"chain_id\":1,\"nonce\":0,\"to\":\"0x1111111111111111111111111111111111111111\",\"value\":\"0x0\",\"gas_limit\":21000,\"max_fee_per_gas\":\"0x3b9aca00\",\"max_priority_fee_per_gas\":\"0x3b9aca00\",\"data\":\"0xdeadbeef\"}}";
    let response = send_request(&socket_path, request);

    assert_eq!(response["status"], "denied");

    handle.join().expect("server join");
}

#[test]
fn sign_evm_tx_denies_max_value() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    gen_key(Chain::Evm, "main", &root).expect("gen key");

    let policy = "wallets:\n  main:\n    chain: evm\n    max_tx_value_eth: 0.001\n";
    write_policy(&root, policy);

    let handle = start_server(root.clone(), socket_path.clone(), 1);

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let request = "{\"request_id\":\"5\",\"action\":\"sign_evm_tx\",\"wallet\":\"main\",\"payload\":{\"chain_id\":1,\"nonce\":0,\"to\":\"0x1111111111111111111111111111111111111111\",\"value\":\"0x470de4df820000\",\"gas_limit\":21000,\"max_fee_per_gas\":\"0x3b9aca00\",\"max_priority_fee_per_gas\":\"0x3b9aca00\",\"data\":\"0x\"}}";
    let response = send_request(&socket_path, request);

    assert_eq!(response["status"], "denied");

    handle.join().expect("server join");
}

#[test]
fn sign_evm_tx_enforces_rate_limit() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    gen_key(Chain::Evm, "main", &root).expect("gen key");

    let policy = "wallets:\n  main:\n    chain: evm\n    rate_limit_per_minute: 1\n";
    write_policy(&root, policy);

    let handle = start_server(root.clone(), socket_path.clone(), 2);

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let request = "{\"request_id\":\"6\",\"action\":\"sign_evm_tx\",\"wallet\":\"main\",\"payload\":{\"chain_id\":1,\"nonce\":0,\"to\":\"0x1111111111111111111111111111111111111111\",\"value\":\"0x0\",\"gas_limit\":21000,\"max_fee_per_gas\":\"0x3b9aca00\",\"max_priority_fee_per_gas\":\"0x3b9aca00\",\"data\":\"0x\"}}";
    let first = send_request(&socket_path, request);
    let second = send_request(&socket_path, request);

    assert_eq!(first["status"], "approved");
    assert_eq!(second["status"], "denied");

    handle.join().expect("server join");
}
