//! A request the server does not finish (its deadline runs out, or the client goes away)
//! must leave one line in the server's own log: the client sees a typed refusal it may
//! never read, or nothing. Real `oncl-server` binary, real socket, real stderr.
#[path = "server_support/mod.rs"]
mod support;

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    time::Duration,
};

fn server() -> support::Process {
    support::Process::configured("127.0.0.1:0", |root| {
        format!(
            "scratch_directory = {}\noperation_timeout_ms = 1500\nheader_timeout_ms = 1000",
            support::toml_path(&root.join("scratch")),
        )
    })
}

/// Stops the server and returns what it wrote to stderr.
fn stop(mut process: support::Process) -> String {
    process
        .child
        .stdin
        .take()
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    process.child.wait().unwrap();
    let mut stderr = String::new();
    process
        .child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    stderr
}

fn head(process: &support::Process, path: &str, content_type: &str, length: usize) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n",
        process.address,
        process.token.as_str(),
    )
}

fn hash_head(process: &support::Process, length: usize) -> String {
    head(process, "/v1/hash", "application/octet-stream", length)
}

fn fields(line: &str) -> BTreeMap<&str, &str> {
    line.split(' ')
        .skip(3)
        .map(|pair| pair.split_once('=').expect("key=value"))
        .collect()
}

/// The only line of `stderr`, as its fields.
fn only_line(stderr: &str) -> BTreeMap<&str, &str> {
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "exactly one line per aborted request: {stderr:?}"
    );
    assert!(
        lines[0].starts_with("oncl-server: request aborted: "),
        "{stderr:?}"
    );
    fields(lines[0])
}

/// RED before the change: the server wrote nothing.
#[test]
fn a_client_that_goes_away_mid_upload_is_logged() {
    let process = server();
    {
        let mut stream = std::net::TcpStream::connect(process.address).unwrap();
        stream
            .write_all(hash_head(&process, 1_000_000).as_bytes())
            .unwrap();
        stream.write_all(&[7u8; 100]).unwrap();
        std::thread::sleep(Duration::from_millis(300));
    }
    // The server notices the closed connection and ends the request.
    std::thread::sleep(Duration::from_millis(500));
    let stderr = stop(process);
    let fields = only_line(&stderr);
    assert_eq!(fields["route"], "hash", "{stderr:?}");
    assert_eq!(fields["reason"], "client_disconnected", "{stderr:?}");
    fields["elapsed_ms"].parse::<u64>().unwrap();
    assert_eq!(fields.len(), 3, "no field beyond the documented ones");
}

/// RED before the change: the client got a 504, and the server wrote nothing.
#[test]
fn a_deadline_that_ends_an_upload_is_logged() {
    let process = server();
    let mut stream = std::net::TcpStream::connect(process.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .write_all(hash_head(&process, 1_000_000).as_bytes())
        .unwrap();
    stream.write_all(&[7u8; 100]).unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 504 "), "{response}");
    assert!(response.contains("DeadlineExceeded"), "{response}");
    let stderr = stop(process);
    let fields = only_line(&stderr);
    assert_eq!(fields["route"], "hash", "{stderr:?}");
    assert_eq!(fields["reason"], "deadline_exceeded", "{stderr:?}");
    let elapsed: u64 = fields["elapsed_ms"].parse().unwrap();
    assert!(elapsed >= 1000, "{elapsed} ms before the 1500 ms deadline");
}

/// The batch route reports its own name.
#[test]
fn a_batch_upload_that_hits_the_deadline_names_its_route() {
    let process = server();
    let mut stream = std::net::TcpStream::connect(process.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .write_all(
            head(
                &process,
                "/v1/batch",
                "multipart/form-data; boundary=b",
                1_000_000,
            )
            .as_bytes(),
        )
        .unwrap();
    stream
        .write_all(b"--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{\"items\":")
        .unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let stderr = stop(process);
    let fields = only_line(&stderr);
    assert_eq!(fields["route"], "batch", "{stderr:?}");
    assert_eq!(fields["reason"], "deadline_exceeded", "{stderr:?}");
}

/// The line is built from numbers and closed names only: the token, the peer's address, the
/// actor, the operator's paths and the bytes of the request never reach the log.
#[test]
fn the_abort_line_carries_no_user_data() {
    let process = server();
    let token = process.token.to_string();
    let address = process.address.to_string();
    let mut stream = std::net::TcpStream::connect(process.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .write_all(hash_head(&process, 1_000_000).as_bytes())
        .unwrap();
    stream
        .write_all(b"CANARY citizen IIN 900101300123")
        .unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let stderr = stop(process);
    assert!(!stderr.is_empty(), "the abort must be logged at all");
    for canary in [
        token.as_str(),
        address.as_str(),
        "127.0.0.1",
        "CANARY",
        "900101300123",
        "synthetic-actor",
        "scratch",
        "audit",
        "/v1/hash",
    ] {
        assert!(
            !stderr.contains(canary),
            "{canary:?} leaked into {stderr:?}"
        );
    }
    assert!(
        stderr.trim_end().bytes().all(|b| b == b' '
            || b == b':'
            || b == b'-'
            || b == b'='
            || b == b'_'
            || b.is_ascii_alphanumeric()),
        "only closed names and numbers: {stderr:?}"
    );
}

/// A request that completes writes nothing.
#[test]
fn a_completed_request_logs_nothing() {
    let process = server();
    let mut stream = std::net::TcpStream::connect(process.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(hash_head(&process, 3).as_bytes()).unwrap();
    stream.write_all(b"abc").unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    assert_eq!(stop(process), "");
}
