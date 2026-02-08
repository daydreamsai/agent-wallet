use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use saw::{gen_key, Chain};

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

fn read_response(mut stream: UnixStream) -> serde_json::Value {
    let mut buf = String::new();
    stream.read_to_string(&mut buf).expect("read response");
    serde_json::from_str(&buf).expect("valid json response")
}

#[test]
fn audit_log_single_line_per_request_under_action_injection() {
    let root = temp_root();
    let socket_path = root.join("saw.sock");

    gen_key(Chain::Evm, "main", &root).expect("gen key");

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
    let request = "{\"request_id\":\"1\",\"action\":\"bad\\ninjected\",\"wallet\":\"main\"}";
    stream.write_all(request.as_bytes()).expect("write request");
    stream.shutdown(std::net::Shutdown::Write).ok();
    let response = read_response(stream);
    assert_eq!(response["status"], "denied");

    handle.join().expect("server join");

    let audit = fs::read_to_string(root.join("audit.log")).expect("audit log");
    let lines: Vec<&str> = audit.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "a single request should produce exactly one audit log line"
    );
}
