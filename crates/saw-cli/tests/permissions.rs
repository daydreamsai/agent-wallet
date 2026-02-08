use std::fs;
use std::os::unix::fs::PermissionsExt;
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

fn mode(path: &PathBuf) -> u32 {
    fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn gen_key_sets_permissions_for_keys_and_keyfile() {
    let root = temp_root();

    gen_key(Chain::Evm, "main", &root).expect("gen_key succeeds");

    let keys_dir = root.join("keys");
    let chain_dir = root.join("keys").join("evm");
    let key_path = root.join("keys").join("evm").join("main.key");

    assert_eq!(mode(&keys_dir), 0o700, "keys dir mode");
    assert_eq!(mode(&chain_dir), 0o700, "chain dir mode");
    assert_eq!(mode(&key_path), 0o600, "key file mode");
}
