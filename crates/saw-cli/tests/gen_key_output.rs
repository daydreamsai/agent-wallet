use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use saw::{gen_key, Chain};

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

#[test]
fn gen_key_evm_returns_address_and_public_key() {
    let root = temp_root();

    let result = gen_key(Chain::Evm, "main", &root).expect("gen_key succeeds");

    assert!(result.address.starts_with("0x"));
    assert_eq!(result.address.len(), 42);
    assert!(result.public_key.starts_with("0x"));
    assert_eq!(result.public_key.len(), 132);
}

#[test]
fn gen_key_sol_returns_address_and_public_key() {
    let root = temp_root();

    let result = gen_key(Chain::Sol, "treasury", &root).expect("gen_key succeeds");

    let address_bytes = bs58::decode(result.address)
        .into_vec()
        .expect("address base58");
    assert_eq!(address_bytes.len(), 32);

    let public_bytes = bs58::decode(result.public_key)
        .into_vec()
        .expect("public key base58");
    assert_eq!(public_bytes.len(), 32);
}
