use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
fn policy_validate_accepts_minimal_stub() {
    let root = temp_root();
    let policy_path = root.join("policy.yaml");
    fs::write(
        &policy_path,
        "wallets:\n  main:\n    chain: evm\n",
    )
    .expect("write policy");

    let output = saw::cli::run([
        "policy",
        "validate",
        "--root",
        root.to_str().expect("root path utf8"),
    ])
    .expect("validate should succeed");

    assert!(output.contains("ok"));
}

#[test]
fn policy_validate_rejects_unknown_field() {
    let root = temp_root();
    let policy_path = root.join("policy.yaml");
    fs::write(
        &policy_path,
        "wallets:\n  main:\n    chain: evm\n    mystery: true\n",
    )
    .expect("write policy");

    let result = saw::cli::run([
        "policy",
        "validate",
        "--root",
        root.to_str().expect("root path utf8"),
    ]);

    assert!(result.is_err());
}

#[test]
fn policy_add_wallet_inserts_stub() {
    let root = temp_root();
    let policy_path = root.join("policy.yaml");
    fs::write(&policy_path, "wallets:\n  existing:\n    chain: evm\n")
        .expect("write policy");

    let output = saw::cli::run([
        "policy",
        "add-wallet",
        "--wallet",
        "treasury",
        "--chain",
        "sol",
        "--root",
        root.to_str().expect("root path utf8"),
    ])
    .expect("add-wallet should succeed");

    assert!(output.contains("added"));

    let policy = fs::read_to_string(&policy_path).expect("read policy");
    assert!(policy.contains("existing:"));
    assert!(policy.contains("treasury:"));
    assert!(policy.contains("chain: sol"));
}

#[test]
fn policy_add_wallet_fails_if_exists() {
    let root = temp_root();
    let policy_path = root.join("policy.yaml");
    fs::write(&policy_path, "wallets:\n  main:\n    chain: evm\n")
        .expect("write policy");

    let result = saw::cli::run([
        "policy",
        "add-wallet",
        "--wallet",
        "main",
        "--chain",
        "evm",
        "--root",
        root.to_str().expect("root path utf8"),
    ]);

    assert!(result.is_err());
}
