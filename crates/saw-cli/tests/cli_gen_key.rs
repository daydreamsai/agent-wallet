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
fn cli_gen_key_outputs_address_and_public_key() {
    let root = temp_root();

    let output = saw::cli::run([
        "gen-key",
        "--chain",
        "evm",
        "--wallet",
        "main",
        "--root",
        root.to_str().expect("root path utf8"),
    ])
    .expect("cli gen-key succeeds");

    assert!(output.contains("address:"));
    assert!(output.contains("public_key:"));

    let key_path = root.join("keys").join("evm").join("main.key");
    assert!(key_path.exists(), "key file created");
}
