//! Process-level tests of `magicrun-jail-egress-forwarder`. The forwarder is
//! the Linux in-jail stage, but its relay and exit semantics are plain Unix
//! and are exercised here on any Unix host, outside a jail.
#![cfg(unix)]

use std::{
    io::{Read, Write},
    net::TcpListener,
    os::unix::{net::UnixListener, process::ExitStatusExt},
    path::Path,
    process::{Command, Output},
    sync::{Arc, Mutex},
    thread,
};

const FORWARDER: &str = env!("CARGO_BIN_EXE_magicrun-jail-egress-forwarder");
const BODY: &str = "relayed-through-unix-socket";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn read_head(stream: &mut impl Read) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).ok()? == 0 {
            return None;
        }
        head.push(byte[0]);
    }
    String::from_utf8(head).ok()
}

/// A CONNECT broker on a unix socket that tunnels to a canned response.
fn start_unix_broker(path: &Path) -> Arc<Mutex<Vec<String>>> {
    let listener = UnixListener::bind(path).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let recorded = Arc::clone(&recorded);
            thread::spawn(move || {
                let Some(head) = read_head(&mut stream) else {
                    return;
                };
                recorded
                    .lock()
                    .unwrap()
                    .push(head.lines().next().unwrap_or_default().to_owned());
                let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                if read_head(&mut stream).is_some() {
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
                            BODY.len()
                        )
                        .as_bytes(),
                    );
                }
            });
        }
    });
    requests
}

fn forward(port: u16, socket: &Path, child: &[&str], environment: &[(&str, String)]) -> Output {
    let mut command = Command::new(FORWARDER);
    command
        .env_clear()
        .arg("--magicrun-jail-egress-forwarder-v1")
        .arg(port.to_string())
        .arg(socket)
        .arg("--")
        .args(child);
    for (name, value) in environment {
        command.env(name, value);
    }
    command.output().unwrap()
}

#[test]
fn relays_a_proxied_client_to_the_unix_socket_broker() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("broker.sock");
    let requests = start_unix_broker(&socket);
    let port = free_port();
    let proxy = format!("http://127.0.0.1:{port}");
    let output = forward(
        port,
        &socket,
        &[
            "/usr/bin/curl",
            "-sS",
            "--proxytunnel",
            "http://allowed.example/",
        ],
        &[("http_proxy", proxy)],
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), BODY);
    assert_eq!(
        requests.lock().unwrap().clone(),
        vec!["CONNECT allowed.example:80 HTTP/1.1"]
    );
}

#[test]
fn mirrors_the_child_exit_code_and_signal() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("unused.sock");
    let output = forward(free_port(), &socket, &["/bin/sh", "-c", "exit 7"], &[]);
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let output = forward(
        free_port(),
        &socket,
        &["/bin/sh", "-c", "kill -TERM $$"],
        &[],
    );
    assert_eq!(output.status.signal(), Some(libc_sigterm()));
}

#[test]
fn refuses_a_malformed_invocation_without_running_anything() {
    let marker = tempfile::tempdir().unwrap();
    let path = marker.path().join("ran");
    let output = Command::new(FORWARDER)
        .args(["--wrong-protocol", "3128", "/s", "--", "/usr/bin/touch"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    assert!(!path.exists());
}

#[test]
fn a_spawn_failure_exits_127() {
    let directory = tempfile::tempdir().unwrap();
    let output = forward(
        free_port(),
        &directory.path().join("s"),
        &["/nonexistent/program"],
        &[],
    );
    assert_eq!(output.status.code(), Some(127));
}

const fn libc_sigterm() -> i32 {
    15
}
