use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ethereum_types::U256;
use saw::{gen_key, Chain};
use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1};
use sha3::{Digest, Keccak256};

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

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn pad_u256(value: U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    value.to_big_endian(&mut out);
    out
}

fn pad_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr);
    out
}

fn parse_address(value: &str) -> [u8; 20] {
    let normalized = value.trim_start_matches("0x");
    let bytes = hex::decode(normalized).expect("valid address hex");
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    out
}

fn hash_domain(name: &str, version: &str, chain_id: u64, verifying_contract: &[u8; 20]) -> [u8; 32] {
    let type_hash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let name_hash = keccak256(name.as_bytes());
    let version_hash = keccak256(version.as_bytes());

    let mut encoded = Vec::with_capacity(32 * 5);
    encoded.extend_from_slice(&type_hash);
    encoded.extend_from_slice(&name_hash);
    encoded.extend_from_slice(&version_hash);
    encoded.extend_from_slice(&pad_u256(U256::from(chain_id)));
    encoded.extend_from_slice(&pad_address(verifying_contract));

    keccak256(&encoded)
}

fn hash_permit(
    owner: &[u8; 20],
    spender: &[u8; 20],
    value: U256,
    nonce: U256,
    deadline: U256,
) -> [u8; 32] {
    let type_hash =
        keccak256(b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    let mut encoded = Vec::with_capacity(32 * 6);
    encoded.extend_from_slice(&type_hash);
    encoded.extend_from_slice(&pad_address(owner));
    encoded.extend_from_slice(&pad_address(spender));
    encoded.extend_from_slice(&pad_u256(value));
    encoded.extend_from_slice(&pad_u256(nonce));
    encoded.extend_from_slice(&pad_u256(deadline));

    keccak256(&encoded)
}

fn eip712_digest(domain_separator: [u8; 32], struct_hash: [u8; 32]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(2 + 32 + 32);
    encoded.extend_from_slice(b"\x19\x01");
    encoded.extend_from_slice(&domain_separator);
    encoded.extend_from_slice(&struct_hash);
    keccak256(&encoded)
}

fn recover_address(signature: &str, digest: [u8; 32]) -> String {
    let sig_bytes = hex::decode(signature.trim_start_matches("0x")).expect("sig hex");
    assert_eq!(sig_bytes.len(), 65, "signature length");

    let rec_id = (sig_bytes[64] - 27) as i32;
    let rec_id = secp256k1::ecdsa::RecoveryId::from_i32(rec_id).expect("recovery id");
    let sig = RecoverableSignature::from_compact(&sig_bytes[0..64], rec_id).expect("sig");

    let msg = Message::from_digest_slice(&digest).expect("message");
    let secp = Secp256k1::new();
    let pubkey = secp.recover_ecdsa(&msg, &sig).expect("recover");
    let pubkey_bytes = pubkey.serialize_uncompressed();

    let hash = keccak256(&pubkey_bytes[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

#[test]
fn sign_eip2612_permit_happy_path() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    let key_result = gen_key(Chain::Evm, "main", &root).expect("gen key");
    let owner = key_result.address;

    let token = "0x1111111111111111111111111111111111111111";
    let spender = "0x2222222222222222222222222222222222222222";

    let policy = "wallets:\n  main:\n    chain: evm\n    allowed_chains: [1]\n    allowlist_addresses:\n      - \"0x1111111111111111111111111111111111111111\"\n      - \"0x2222222222222222222222222222222222222222\"\n";
    write_policy(&root, policy);

    let handle = start_server(root.clone(), socket_path.clone(), 1);

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let request = format!(
        "{{\"request_id\":\"1\",\"action\":\"sign_eip2612_permit\",\"wallet\":\"main\",\"payload\":{{\"chain_id\":1,\"token\":\"{}\",\"name\":\"USD Coin\",\"version\":\"2\",\"spender\":\"{}\",\"value\":\"1000000\",\"nonce\":\"0\",\"deadline\":\"9999999999\",\"owner\":\"{}\"}}}}",
        token, spender, owner
    );

    let response = send_request(&socket_path, &request);

    assert_eq!(response["status"], "approved");
    let signature = response["result"]["signature"].as_str().expect("signature");
    assert!(signature.starts_with("0x"));
    assert_eq!(signature.len(), 132);

    let owner_addr = parse_address(&owner);
    let spender_addr = parse_address(spender);
    let token_addr = parse_address(token);

    let domain = hash_domain("USD Coin", "2", 1, &token_addr);
    let permit = hash_permit(
        &owner_addr,
        &spender_addr,
        U256::from_dec_str("1000000").expect("value"),
        U256::from_dec_str("0").expect("nonce"),
        U256::from_dec_str("9999999999").expect("deadline"),
    );
    let digest = eip712_digest(domain, permit);

    let recovered = recover_address(signature, digest);
    assert_eq!(recovered.to_lowercase(), owner.to_lowercase());

    handle.join().expect("server join");
}

#[test]
fn sign_eip2612_permit_denies_chain_id() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    let key_result = gen_key(Chain::Evm, "main", &root).expect("gen key");
    let owner = key_result.address;

    let policy = "wallets:\n  main:\n    chain: evm\n    allowed_chains: [1]\n";
    write_policy(&root, policy);

    let handle = start_server(root.clone(), socket_path.clone(), 1);

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let request = format!(
        "{{\"request_id\":\"2\",\"action\":\"sign_eip2612_permit\",\"wallet\":\"main\",\"payload\":{{\"chain_id\":5,\"token\":\"0x1111111111111111111111111111111111111111\",\"name\":\"USD Coin\",\"version\":\"2\",\"spender\":\"0x2222222222222222222222222222222222222222\",\"value\":\"1000000\",\"nonce\":\"0\",\"deadline\":\"9999999999\",\"owner\":\"{}\"}}}}",
        owner
    );

    let response = send_request(&socket_path, &request);
    assert_eq!(response["status"], "denied");

    handle.join().expect("server join");
}

#[test]
fn sign_eip2612_permit_denies_allowlist() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    let key_result = gen_key(Chain::Evm, "main", &root).expect("gen key");
    let owner = key_result.address;

    let policy = "wallets:\n  main:\n    chain: evm\n    allowed_chains: [1]\n    allowlist_addresses:\n      - \"0x1111111111111111111111111111111111111111\"\n";
    write_policy(&root, policy);

    let handle = start_server(root.clone(), socket_path.clone(), 1);

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let request = format!(
        "{{\"request_id\":\"3\",\"action\":\"sign_eip2612_permit\",\"wallet\":\"main\",\"payload\":{{\"chain_id\":1,\"token\":\"0x1111111111111111111111111111111111111111\",\"name\":\"USD Coin\",\"version\":\"2\",\"spender\":\"0x2222222222222222222222222222222222222222\",\"value\":\"1000000\",\"nonce\":\"0\",\"deadline\":\"9999999999\",\"owner\":\"{}\"}}}}",
        owner
    );

    let response = send_request(&socket_path, &request);
    assert_eq!(response["status"], "denied");

    handle.join().expect("server join");
}

#[test]
fn sign_eip2612_permit_denies_owner_mismatch() {
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

    let request = "{\"request_id\":\"4\",\"action\":\"sign_eip2612_permit\",\"wallet\":\"main\",\"payload\":{\"chain_id\":1,\"token\":\"0x1111111111111111111111111111111111111111\",\"name\":\"USD Coin\",\"version\":\"2\",\"spender\":\"0x2222222222222222222222222222222222222222\",\"value\":\"1000000\",\"nonce\":\"0\",\"deadline\":\"9999999999\",\"owner\":\"0x3333333333333333333333333333333333333333\"}}";

    let response = send_request(&socket_path, request);
    assert_eq!(response["status"], "denied");

    handle.join().expect("server join");
}

#[test]
fn sign_eip2612_permit_denies_invalid_owner_address() {
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

    let request = "{\"request_id\":\"5\",\"action\":\"sign_eip2612_permit\",\"wallet\":\"main\",\"payload\":{\"chain_id\":1,\"token\":\"0x1111111111111111111111111111111111111111\",\"name\":\"USD Coin\",\"version\":\"2\",\"spender\":\"0x2222222222222222222222222222222222222222\",\"value\":\"1000000\",\"nonce\":\"0\",\"deadline\":\"9999999999\",\"owner\":\"0x1\"}}";

    let response = send_request(&socket_path, request);
    assert_eq!(response["status"], "denied");
    assert_eq!(response["error"], "invalid owner address");

    handle.join().expect("server join");
}
