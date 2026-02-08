use std::fs;
use std::os::unix::fs::PermissionsExt;
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

fn mode(path: &PathBuf) -> u32 {
    fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn cli_install_creates_layout_with_permissions() {
    let root = temp_root();

    let output = saw::cli::run(["install", "--root", root.to_str().unwrap()])
        .expect("install should succeed");
    assert!(output.contains("installed"));

    let keys_dir = root.join("keys");
    let policy_path = root.join("policy.yaml");
    let audit_path = root.join("audit.log");

    assert!(keys_dir.exists());
    assert!(policy_path.exists());
    assert!(audit_path.exists());

    assert_eq!(mode(&root), 0o750);
    assert_eq!(mode(&keys_dir), 0o700);
    assert_eq!(mode(&policy_path), 0o640);
    assert_eq!(mode(&audit_path), 0o640);
}
