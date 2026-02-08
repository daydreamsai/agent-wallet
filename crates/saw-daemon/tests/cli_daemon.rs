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
fn cli_runs_with_socket_and_root() {
    let root = temp_root();
    let socket_path = root.join("daemon.sock");

    gen_key(Chain::Evm, "main", &root).expect("gen key");

    let args = vec![
        "--socket".to_string(),
        socket_path.to_str().expect("socket path").to_string(),
        "--root".to_string(),
        root.to_str().expect("root path").to_string(),
    ];

    let handle = thread::spawn(move || {
        saw_daemon::cli::run(args, Some(1)).expect("cli run");
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
    assert_eq!(response["status"], "approved");

    handle.join().expect("server join");
}
