use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
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

fn read_response(mut stream: UnixStream) -> serde_json::Value {
    let mut buf = String::new();
    stream.read_to_string(&mut buf).expect("read response");
    serde_json::from_str(&buf).expect("valid json response")
}

#[test]
fn denies_request_too_large() {
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

    let big_payload = "a".repeat(100_000);
    let request = format!("{{\"request_id\":\"1\",\"action\":\"get_address\",\"wallet\":\"main\",\"payload\":\"{}\"}}", big_payload);

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    stream.write_all(request.as_bytes()).expect("write request");
    stream.shutdown(std::net::Shutdown::Write).ok();

    let response = read_response(stream);
    assert_eq!(response["status"], "denied");
    assert!(response["error"].as_str().unwrap_or("").contains("too large"));

    handle.join().expect("server join");
}
