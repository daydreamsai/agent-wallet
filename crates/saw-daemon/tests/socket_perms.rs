use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
fn socket_permissions_are_restricted() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    let server_root = root.clone();
    let server_socket = socket_path.clone();
    let handle = thread::spawn(move || {
        saw_daemon::serve_n(&server_socket, &server_root, 1).expect("serve n");
    });

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(mode(&socket_path), 0o660);

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    stream.write_all(b"{\"request_id\":\"1\",\"action\":\"get_address\",\"wallet\":\"missing\"}")
        .expect("write request");
    stream.shutdown(std::net::Shutdown::Write).ok();

    handle.join().expect("server join");
}
