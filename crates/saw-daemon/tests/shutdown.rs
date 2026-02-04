use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
fn serve_forever_stops_on_flag() {
    let root = temp_root();
    let socket_path = root.join("shutdown.sock");
    let stop = Arc::new(AtomicBool::new(false));

    let stop_flag = stop.clone();
    let server_root = root.clone();
    let server_socket = socket_path.clone();
    let handle = thread::spawn(move || {
        saw_daemon::serve_forever_with_shutdown(&server_socket, &server_root, stop_flag)
            .expect("serve with shutdown");
    });

    for _ in 0..20 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    stop.store(true, Ordering::Relaxed);

    handle.join().expect("server join");
    assert!(!socket_path.exists());
}
