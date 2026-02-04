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
fn gen_key_sol_creates_key_and_policy_stub() {
    let root = temp_root();

    let result = gen_key(Chain::Sol, "treasury", &root);
    assert!(result.is_ok(), "gen_key should succeed");

    let key_path = root.join("keys").join("sol").join("treasury.key");
    let key_meta = fs::metadata(&key_path).expect("key file exists");
    assert_eq!(key_meta.len(), 64, "Solana key must be 64 bytes");

    let policy_path = root.join("policy.yaml");
    let policy = fs::read_to_string(&policy_path).expect("policy.yaml exists");
    assert!(policy.contains("wallets:"));
    assert!(policy.contains("treasury:"));
    assert!(policy.contains("chain: sol"));
}
