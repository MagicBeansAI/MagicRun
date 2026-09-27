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
    time::{Duration, Instant},
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

/// Run the forwarder to completion on a fresh port, retrying while it fails
/// to bind (exit 125 with no output): a port probed free can be taken again,
/// for example as another test's ephemeral source port, before the forwarder
/// binds it. `environment` receives the port actually used.
fn forward(
    socket: &Path,
    child: &[&str],
    environment: impl Fn(u16) -> Vec<(&'static str, String)>,
) -> Output {
    for _ in 0..5 {
        let port = free_port();
        let mut command = Command::new(FORWARDER);
        command
            .env_clear()
            .arg("--magicrun-jail-egress-forwarder-v1")
            .arg(port.to_string())
            .arg(socket)
            .arg("--")
            .args(child);
        for (name, value) in environment(port) {
            command.env(name, value);
        }
        let output = command.output().unwrap();
        if output.status.code() != Some(125) || !output.stdout.is_empty() || !output.stderr.is_empty() {
            return output;
        }
    }
    panic!("the forwarder never bound a free port");
}

#[test]
fn relays_a_proxied_client_to_the_unix_socket_broker() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("broker.sock");
    let requests = start_unix_broker(&socket);
    let output = forward(
        &socket,
        &[
            "/usr/bin/curl",
            "-sS",
            "--proxytunnel",
            "http://allowed.example/",
        ],
        |port| vec![("http_proxy", format!("http://127.0.0.1:{port}"))],
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
    let output = forward(&socket, &["/bin/sh", "-c", "exit 7"], |_| Vec::new());
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let output = forward(&socket, &["/bin/sh", "-c", "kill -TERM $$"], |_| Vec::new());
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
    let output = forward(&directory.path().join("s"), &["/nonexistent/program"], |_| Vec::new());
    assert_eq!(output.status.code(), Some(127));
}

const fn libc_sigterm() -> i32 {
    15
}

const PERL: &str = "/usr/bin/perl";
const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

fn perl_available() -> bool {
    if Path::new(PERL).is_file() {
        return true;
    }
    eprintln!("SKIP: {PERL} is not installed");
    false
}

/// A unix-socket broker running `serve` on every accepted stream.
fn start_broker(path: &Path, serve: fn(std::os::unix::net::UnixStream)) {
    let listener = UnixListener::bind(path).unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            thread::spawn(move || serve(stream));
        }
    });
}

fn forwarder_command(port: u16, socket: &Path, child: &[&str]) -> Command {
    let mut command = Command::new(FORWARDER);
    command
        .env_clear()
        .arg("--magicrun-jail-egress-forwarder-v1")
        .arg(port.to_string())
        .arg(socket)
        .arg("--")
        .args(child)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());
    command
}

/// Wait for the forwarder with a bound; reap it with `wait4` so its own CPU
/// time (and its reaped child's) is known. `None` if it did not exit.
fn wait_bounded(mut child: std::process::Child, seconds: u64) -> Option<(i32, Duration, String)> {
    use std::os::unix::process::ExitStatusExt as _;

    let mut stdout = child.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    let pid = child.id() as libc::pid_t;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        let mut status = 0;
        // SAFETY: an all-zero `rusage` is valid output storage.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: `pid` is this test's own unreaped child; `WNOHANG` never blocks.
        let reaped = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, &mut usage) };
        if reaped == pid {
            let cpu = |time: libc::timeval| {
                Duration::from_secs(time.tv_sec as u64) + Duration::from_micros(time.tv_usec as u64)
            };
            let code = std::process::ExitStatus::from_raw(status).code().unwrap_or(-1);
            std::mem::forget(child);
            return Some((code, cpu(usage.ru_utime) + cpu(usage.ru_stime), reader.join().unwrap()));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Run the forwarder with `child` plus the listen port as its last argument,
/// retrying on a fresh port while it fails to bind (exit 125): a port probed
/// free can be taken again, for example as any client's ephemeral source
/// port, before the forwarder binds it.
fn run_forwarder(socket: &Path, child: &[&str], seconds: u64) -> Option<(i32, Duration, String)> {
    run_forwarder_with(socket, child, seconds, |_| {})
}

fn run_forwarder_with(
    socket: &Path,
    child: &[&str],
    seconds: u64,
    prepare: impl Fn(&mut Command),
) -> Option<(i32, Duration, String)> {
    for _ in 0..5 {
        let port = free_port();
        let port_argument = port.to_string();
        let mut arguments = child.to_vec();
        arguments.push(&port_argument);
        let mut command = forwarder_command(port, socket, &arguments);
        prepare(&mut command);
        let result = wait_bounded(command.spawn().unwrap(), seconds)?;
        if result.0 != 125 {
            return Some(result);
        }
    }
    panic!("the forwarder never bound a free port");
}

/// A fire-and-forget upload: the child writes a request body and exits at
/// once. Bytes it already handed to the forwarder still reach the broker.
#[test]
fn bytes_sent_before_the_child_exits_still_reach_the_broker() {
    if !perl_available() {
        return;
    }
    const BODY_BYTES: usize = 1024 * 1024;
    static RECEIVED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("broker.sock");
    start_broker(&socket, |mut stream| {
        if read_head(&mut stream).is_none() {
            return;
        }
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    RECEIVED.fetch_add(read, std::sync::atomic::Ordering::SeqCst);
                },
            }
        }
        DONE.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let script = format!(
        "use IO::Socket::INET; my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $ARGV[0]) or die; \
         print $s \"CONNECT upload.example:80 HTTP/1.1\\r\\n\\r\\n\"; print $s ('x' x {BODY_BYTES}); close($s); exit 0;"
    );
    let (code, _, _) = run_forwarder(&socket, &[PERL, "-e", &script], 20).expect("forwarder exits");
    assert_eq!(code, 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !DONE.load(std::sync::atomic::Ordering::SeqCst) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(RECEIVED.load(std::sync::atomic::Ordering::SeqCst), BODY_BYTES);
}

/// The broker sends a large reply and hangs up while the client still reads
/// it slowly. The reply arrives whole, and the forwarder does not spin on the
/// broker's hang-up (Linux reports `POLLHUP` on every poll).
#[test]
fn a_broker_hang_up_with_buffered_reply_neither_truncates_nor_spins() {
    if !perl_available() {
        return;
    }
    const REPLY_BYTES: usize = 2 * 1024 * 1024;
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("broker.sock");
    start_broker(&socket, |mut stream| {
        if read_head(&mut stream).is_none() {
            return;
        }
        let _ = stream.write_all(ESTABLISHED);
        let _ = stream.write_all(&vec![b'y'; REPLY_BYTES]);
    });
    let script = "use IO::Socket::INET; use Time::HiRes qw(sleep); \
         my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $ARGV[0]) or die; \
         syswrite($s, \"CONNECT slow.example:80 HTTP/1.1\\r\\n\\r\\n\"); sleep(1.0); \
         my ($total, $buffer) = (0, ''); \
         while (1) { my $n = sysread($s, $buffer, 65536); last if !defined($n) || $n == 0; $total += $n; sleep(0.02); } \
         print \"$total\\n\"; exit 0;";
    let (code, cpu, stdout) = run_forwarder(&socket, &[PERL, "-e", script], 30).expect("forwarder exits");
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), (ESTABLISHED.len() + REPLY_BYTES).to_string());
    assert!(cpu < Duration::from_millis(800), "forwarder and child used {cpu:?} of CPU");
}

/// A unix stream socket marked close-on-exec at once, so forwarders other
/// tests spawn concurrently do not inherit it.
fn cloexec_unix_socket() -> libc::c_int {
    // SAFETY: plain socket creation and `F_SETFD` on the new descriptor.
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        assert!(fd >= 0);
        assert_eq!(libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC), 0);
        fd
    }
}

/// Start a non-blocking unix connect from the test; `None` once the broker's
/// backlog refuses more.
fn try_connect_nonblocking(path: &Path) -> Option<std::os::fd::OwnedFd> {
    use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};

    let bytes = path.as_os_str().as_bytes();
    // SAFETY: an all-zero `sockaddr_un` is a valid empty address.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    let fd = cloexec_unix_socket();
    // SAFETY: `fd` is a fresh descriptor owned by nothing else.
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    // SAFETY: `fcntl` on the descriptor owned above.
    unsafe { libc::fcntl(fd, libc::F_SETFL, libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK) };
    // SAFETY: `address` is a live `sockaddr_un` of the given size.
    let result = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    (result == 0).then_some(owned)
}

/// A broker whose backlog is full never stalls the forwarder: the client is
/// closed at once and the forwarder still exits with its child.
#[test]
fn a_full_broker_backlog_closes_the_client_instead_of_blocking() {
    use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};

    if !perl_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("full.sock");
    // A listener with the smallest backlog that never accepts.
    let bytes = socket.as_os_str().as_bytes();
    // SAFETY: as above.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    let fd = cloexec_unix_socket();
    // SAFETY: bind and listen on a fresh descriptor this test owns.
    let listener = unsafe {
        assert_eq!(
            libc::bind(
                fd,
                (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            ),
            0
        );
        assert_eq!(libc::listen(fd, 0), 0);
        std::os::fd::OwnedFd::from_raw_fd(fd)
    };
    let mut queued = Vec::new();
    while queued.len() < 256 {
        match try_connect_nonblocking(&socket) {
            Some(connection) => queued.push(connection),
            None => break,
        }
    }
    assert!(queued.len() < 256, "the backlog never filled");
    let script = "use IO::Socket::INET; my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $ARGV[0]) or die; \
         syswrite($s, \"CONNECT full.example:80 HTTP/1.1\\r\\n\\r\\n\"); my $buffer = ''; \
         my $n = sysread($s, $buffer, 1024); print defined($n) && $n > 0 ? \"data\\n\" : \"closed\\n\"; exit 0;";
    let (code, _, stdout) = run_forwarder(&socket, &[PERL, "-e", script], 15)
        .expect("the forwarder must not block on a full backlog");
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), "closed");
    drop(listener);
}

/// At the smallest descriptor budget a brokered jail accepts, the forwarder
/// clamps itself to one relay and serves concurrent clients in turn.
#[test]
fn the_minimum_descriptor_budget_serves_concurrent_clients_in_turn() {
    use std::os::unix::process::CommandExt;

    if !perl_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("broker.sock");
    start_broker(&socket, |mut stream| {
        if read_head(&mut stream).is_some() {
            let _ = stream.write_all(ESTABLISHED);
        }
    });
    let script = "use IO::Socket::INET; my @s = map { IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $ARGV[0]) or die } 1..3; \
         syswrite($_, \"CONNECT turn.example:80 HTTP/1.1\\r\\n\\r\\n\") for @s; my $ok = 0; \
         for my $s (@s) { my ($all, $b) = ('', ''); while (1) { my $n = sysread($s, $b, 1024); if (!defined($n)) { $all .= \"[error $!]\"; last; } last if $n == 0; $all .= $b; } if ($all =~ /^HTTP\\/1.1 200/) { $ok++ } else { print STDERR \"bad reply: [$all]\\n\" } close($s); } \
         print \"$ok\\n\"; exit 0;";
    // The forwarder gets a soft limit of 8 (the smallest a brokered jail
    // takes); its child raises its own soft limit again, since Perl needs
    // more descriptors to load its modules.
    let child = [
        "/bin/sh",
        "-c",
        "ulimit -n 64 && exec /usr/bin/perl -e \"$1\" \"$2\"",
        "sh",
        script,
    ];
    let (code, cpu, stdout) = run_forwarder_with(
        &socket,
        &child,
        30,
        |command| {
            // SAFETY: `setrlimit` is async-signal-safe and touches only the
            // forwarder child.
            unsafe {
                command.pre_exec(|| {
                    let limit = libc::rlimit {
                        rlim_cur: 8,
                        rlim_max: 256,
                    };
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        },
    )
    .expect("forwarder exits");
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), "3");
    assert!(cpu < Duration::from_millis(800), "used {cpu:?} of CPU");
}

fn exec_shim(arguments: &[&str]) -> Output {
    Command::new(FORWARDER)
        .env_clear()
        .arg("--magicrun-jail-exec-v1")
        .args(arguments)
        .output()
        .unwrap()
}

/// The exec shim without a ceiling only execs: same exit status, no output
/// of its own.
#[test]
fn the_exec_shim_without_a_ceiling_only_execs() {
    let output = exec_shim(&["-", "-", "--", "/bin/sh", "-c", "echo ran; exit 7"]);
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ran\n");
    assert!(output.stderr.is_empty());
}

/// A requested ceiling outside a user namespace of the jail's own would
/// count every task of the UID on the host: the shim refuses (126) and runs
/// nothing.
#[test]
fn the_exec_shim_refuses_a_ceiling_in_the_host_user_namespace() {
    let host = std::fs::read_link("/proc/self/ns/user")
        .ok()
        .and_then(|target| {
            tool_runtime_core::governed_process_jail::egress_forwarder::parse_user_namespace_link(
                &target,
            )
        })
        .unwrap_or(1)
        .to_string();
    let marker = tempfile::tempdir().unwrap();
    let path = marker.path().join("ran");
    let output = exec_shim(&["64", &host, "--", "/usr/bin/touch", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(126));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        tool_runtime_core::governed_process_jail::egress_forwarder::JAIL_EXEC_REFUSAL_MARKER
    );
    assert!(output.stdout.is_empty());
    assert!(!path.exists());
    // Malformed: refused before anything runs.
    let output = exec_shim(&["64", "-", "--", "/usr/bin/touch", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(125));
    assert!(!path.exists());
}

/// Linux: in a (here: claimed) different user namespace the shim sets
/// `RLIMIT_NPROC` soft and hard to the ceiling before exec.
#[cfg(target_os = "linux")]
#[test]
fn the_exec_shim_sets_the_task_ceiling_before_exec() {
    // `/bin/cat` reads its own limits; dash (Ubuntu's /bin/sh) has no `ulimit -u`.
    let output = exec_shim(&["4242", "1", "--", "/bin/cat", "/proc/self/limits"]);
    assert_eq!(output.status.code(), Some(0), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let limits = String::from_utf8_lossy(&output.stdout);
    let processes = limits
        .lines()
        .find(|line| line.starts_with("Max processes"))
        .expect("a Max processes line")
        .split_whitespace()
        .skip(2)
        .take(2)
        .collect::<Vec<_>>();
    assert_eq!(processes, ["4242", "4242"], "{limits}");
}
