use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn read_response_with_timeout(stream: &mut UnixStream) -> serde_json::Value {
    stream
        .set_read_timeout(Some(Duration::from_millis(800)))
        .expect("set read timeout");
    let mut buf = String::new();
    stream.read_to_string(&mut buf).expect("read response");
    serde_json::from_str(&buf).expect("valid json response")
}

#[test]
fn daemon_recovers_after_partial_request_stall() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    gen_key(Chain::Evm, "main", &root).expect("gen key");

    let server_root = root.clone();
    let server_socket = socket_path.clone();
    let handle = thread::spawn(move || {
        saw_daemon::serve_n(&server_socket, &server_root, 2).expect("serve two requests");
    });

    for _ in 0..20 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let mut stalled = UnixStream::connect(&socket_path).expect("connect stalled client");
    stalled
        .write_all(b"{\"request_id\":\"1\",\"action\":\"get_address\",\"wallet\":\"main\"")
        .expect("write partial request");

    thread::sleep(Duration::from_millis(250));

    let mut legit = UnixStream::connect(&socket_path).expect("connect legit client");
    legit
        .write_all(b"{\"request_id\":\"2\",\"action\":\"get_address\",\"wallet\":\"main\"}")
        .expect("write legit request");
    legit.shutdown(std::net::Shutdown::Write).ok();

    let response = read_response_with_timeout(&mut legit);
    assert_eq!(response["status"], "approved");

    stalled.shutdown(std::net::Shutdown::Both).ok();
    handle.join().expect("server join");
}
