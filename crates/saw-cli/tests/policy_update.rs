use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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

#[test]
fn gen_key_updates_policy_without_overwriting_existing_wallets() {
    let root = temp_root();

    let policy_path = root.join("policy.yaml");
    let initial = "wallets:\n  existing:\n    chain: evm\n";
    fs::write(&policy_path, initial).expect("write initial policy");

    gen_key(Chain::Sol, "treasury", &root).expect("gen_key succeeds");

    let policy = fs::read_to_string(&policy_path).expect("read policy");
    assert!(policy.contains("existing:"));
    assert!(policy.contains("chain: evm"));
    assert!(policy.contains("treasury:"));
    assert!(policy.contains("chain: sol"));
}
