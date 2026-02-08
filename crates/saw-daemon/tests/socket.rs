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

fn read_response(mut stream: UnixStream) -> serde_json::Value {
    let mut buf = String::new();
    stream.read_to_string(&mut buf).expect("read response");
    serde_json::from_str(&buf).expect("valid json response")
}

#[test]
fn daemon_get_address_evm() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    let result = gen_key(Chain::Evm, "main", &root).expect("gen key");

    let server_root = root.clone();
    let server_socket = socket_path.clone();
    let handle = thread::spawn(move || {
        saw_daemon::serve_once(&server_socket, &server_root).expect("serve once");
    });

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    let request = "{\"request_id\":\"1\",\"action\":\"get_address\",\"wallet\":\"main\"}\n";
    stream.write_all(request.as_bytes()).expect("write request");
    stream.shutdown(std::net::Shutdown::Write).ok();

    let response = read_response(stream);

    assert_eq!(response["request_id"], "1");
    assert_eq!(response["status"], "approved");
    assert_eq!(response["result"]["address"], result.address);
    assert_eq!(response["result"]["public_key"], result.public_key);
    assert_eq!(response["result"]["chain"], "evm");

    handle.join().expect("server join");
}

#[test]
fn daemon_denies_missing_wallet() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    let server_root = root.clone();
    let server_socket = socket_path.clone();
    let handle = thread::spawn(move || {
        saw_daemon::serve_once(&server_socket, &server_root).expect("serve once");
    });

    for _ in 0..10 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    let request = "{\"request_id\":\"2\",\"action\":\"get_address\",\"wallet\":\"missing\"}\n";
    stream.write_all(request.as_bytes()).expect("write request");
    stream.shutdown(std::net::Shutdown::Write).ok();

    let response = read_response(stream);

    assert_eq!(response["request_id"], "2");
    assert_eq!(response["status"], "denied");
    assert!(response["error"].as_str().unwrap_or("").contains("wallet"));

    handle.join().expect("server join");
}
