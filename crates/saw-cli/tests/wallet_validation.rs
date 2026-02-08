use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use saw::Chain;

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
fn gen_key_rejects_path_traversal_wallet_name() {
    let root = temp_root();
    let outside = root.parent().expect("has parent").join("escaped.key");
    if outside.exists() {
        fs::remove_file(&outside).expect("remove stale outside file");
    }

    let result = saw::gen_key(Chain::Evm, "../../../escaped", &root);

    assert!(result.is_err(), "gen_key must reject path traversal wallet names");
    assert!(
        !outside.exists(),
        "gen_key must not create key files outside the configured root"
    );
}

#[test]
fn cli_rejects_invalid_wallet_name_for_gen_key() {
    let root = temp_root();

    let result = saw::cli::run([
        "gen-key",
        "--chain",
        "evm",
        "--wallet",
        "../main",
        "--root",
        root.to_str().expect("root path utf8"),
    ]);

    let err = result.expect_err("invalid wallet name should be rejected");
    assert!(
        format!("{err}").contains("invalid wallet"),
        "error should clearly indicate invalid wallet name"
    );
}

#[test]
fn cli_rejects_invalid_wallet_name_for_policy_add_wallet() {
    let root = temp_root();

    let result = saw::cli::run([
        "policy",
        "add-wallet",
        "--wallet",
        "bad/name",
        "--chain",
        "evm",
        "--root",
        root.to_str().expect("root path utf8"),
    ]);

    let err = result.expect_err("invalid wallet name should be rejected");
    assert!(
        format!("{err}").contains("invalid wallet"),
        "error should clearly indicate invalid wallet name"
    );
}
