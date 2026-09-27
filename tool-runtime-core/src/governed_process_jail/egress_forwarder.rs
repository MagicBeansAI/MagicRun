//! In-jail egress forwarder for the Linux brokered-egress jail.
//!
//! Bubblewrap runs the admitted executable inside an unshared network
//! namespace whose only interface is `lo`, so a host TCP proxy is unreachable
//! and ordinary HTTP clients cannot speak to a unix-socket proxy. This small
//! stage runs first inside the jail: it listens on `127.0.0.1:<port>` in that
//! namespace, starts the exact executable as its only child, and relays each
//! accepted connection byte-for-byte to the broker's unix socket, which is
//! bind-mounted read-only into the jail. It adds no authority: the child could
//! connect to the same socket itself, and the broker remains the sole policy
//! point for destinations, name resolution and metering.
//!
//! The forwarder never writes to stdout or stderr (they belong to the child),
//! never resolves names, is single-threaded (one task beside the child under
//! the jail's process ceiling), and exits with the child's exact status. It
//! is invoked as:
//!
//! ```text
//! magicrun-jail-egress-forwarder --magicrun-jail-egress-forwarder-v1 <port> <socket> -- <program> [args...]
//! ```
//!
//! The same trusted binary is the Linux jail's exec shim in every mode. It is
//! the first program bubblewrap runs, after the jail's namespaces exist:
//!
//! ```text
//! magicrun-jail-egress-forwarder --magicrun-jail-exec-v1 <tasks|-> <host-userns|-> <status-fd> -- <program> [args...]
//! ```
//!
//! With a task ceiling it first proves it runs in a user namespace other than
//! the host's (`/proc/self/ns/user` differs from `<host-userns>`) and that
//! it does not run as root (whose tasks Linux never holds to `RLIMIT_NPROC`),
//! then sets `RLIMIT_NPROC` (soft and hard) to `<tasks>` and execs
//! `<program>`. Linux charges `RLIMIT_NPROC` to the (user namespace, UID)
//! pair of the forking task, so inside the jail's own new user namespace it
//! counts only the jail's tasks, threads included: an exact per-jail bound.
//! Outside a new user namespace the same limit would count every task of the
//! UID on the host, so the shim refuses rather than apply a meaningless or
//! starving bound. With `- -` it only execs.
//!
//! `<status-fd>` is the inherited write end of the runner's exec-status pipe.
//! On a refusal, or any failure before the program runs (`setrlimit`, exec),
//! the shim writes [`JAIL_EXEC_REFUSED`] there and exits 126. Before a
//! successful exec it marks the descriptor close-on-exec, so the program
//! never holds it: nothing the program does can report a refusal. (bubblewrap
//! closes inherited descriptors in its in-jail init; only the shim and the
//! outer monitor, outside the jail's pid namespace, hold it.) It never forks
//! and never writes to stdio.

use std::{ffi::OsString, path::PathBuf};

/// Exit status for a malformed invocation or a listener that cannot bind.
pub const FORWARDER_EXIT_USAGE: i32 = 125;
/// Exit status when the child cannot be started.
pub const FORWARDER_EXIT_SPAWN: i32 = 127;
/// Exec shim: exit status after a refusal or a failure before exec. Only the
/// status pipe, never this code, tells the runner that nothing ran.
pub const JAIL_EXEC_EXIT_REFUSED: i32 = 126;
/// The byte the exec shim writes to the status pipe when the program never
/// ran.
pub const JAIL_EXEC_REFUSED: u8 = b'R';
/// argv marker of the in-jail exec-shim protocol.
pub const GOVERNED_JAIL_EXEC_PROTOCOL_V1: &str = "--magicrun-jail-exec-v1";
/// Concurrent relayed connections; further connections wait in the listen
/// backlog. The forwarder clamps this to what its `RLIMIT_NOFILE` allows (see
/// [`connection_capacity_for`]).
pub const MAX_FORWARDER_CONNECTIONS: usize = 16;
/// Descriptors the forwarder needs besides its relays: stdio (3), the
/// listener (1) and the child spawn's error pipe (2).
const FORWARDER_FIXED_DESCRIPTORS: u64 = 6;
/// The smallest `RLIMIT_NOFILE` that fits the fixed descriptors plus one
/// relay (client and broker sockets). A brokered Linux jail refuses a lower
/// `max_open_files`.
pub const FORWARDER_MIN_OPEN_FILES: u64 = FORWARDER_FIXED_DESCRIPTORS + 2;
#[cfg(unix)]
const RELAY_BUFFER_BYTES: usize = 16 * 1024;
#[cfg(unix)]
const POLL_INTERVAL_MS: i32 = 50;
/// Bound on a non-blocking broker connect that is still in progress.
#[cfg(unix)]
const CONNECT_TIMEOUT_MS: u64 = 2_000;
/// After the child exits, bytes it already sent are still delivered to the
/// broker for at most this long.
#[cfg(unix)]
const EXIT_DRAIN_MS: u64 = 1_000;
/// After an accept failure the next poll would repeat (descriptor
/// exhaustion), the listener is left out of the poll set for this long or
/// until a relay closes.
#[cfg(unix)]
const ACCEPT_PAUSE_MS: u64 = 250;
/// Read/write rounds per direction per wake-up, so one busy relay cannot
/// starve the others or the child's exit check.
#[cfg(unix)]
const PUMP_ROUNDS: usize = 16;

/// Concurrent relays that fit a soft `RLIMIT_NOFILE` of `soft` when `open`
/// descriptors (stdio, the listener, anything inherited) are already in use:
/// two each after those and the spawn pipe, at least one and at most
/// [`MAX_FORWARDER_CONNECTIONS`].
pub fn connection_capacity_for(soft: u64, open: u64) -> usize {
    let reserved = open.max(FORWARDER_FIXED_DESCRIPTORS - 2).saturating_add(2);
    let relays = soft.saturating_sub(reserved) / 2;
    usize::try_from(relays)
        .unwrap_or(usize::MAX)
        .clamp(1, MAX_FORWARDER_CONNECTIONS)
}

/// A parsed forwarder invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwarderInvocation {
    pub port: u16,
    pub socket: PathBuf,
    pub program: OsString,
    pub arguments: Vec<OsString>,
}

/// Parse the argument vector after argv[0]. Anything but the exact protocol
/// layout is refused.
pub fn parse_forwarder_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Option<ForwarderInvocation> {
    let mut arguments = arguments.into_iter();
    if arguments.next()? != super::GOVERNED_JAIL_EGRESS_FORWARDER_PROTOCOL_V1 {
        return None;
    }
    let port = arguments.next()?.to_str()?.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    let socket = PathBuf::from(arguments.next()?);
    if !socket.is_absolute() || arguments.next()? != "--" {
        return None;
    }
    let program = arguments.next()?;
    if program.is_empty() {
        return None;
    }
    Some(ForwarderInvocation {
        port,
        socket,
        program,
        arguments: arguments.collect(),
    })
}

/// A parsed exec-shim invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JailExecInvocation {
    /// `RLIMIT_NPROC` to apply, and the host user-namespace inode the shim
    /// must differ from; `None` for `- -` (exec only).
    pub task_ceiling: Option<(u64, u64)>,
    /// Write end of the runner's exec-status pipe (at least 3).
    pub status_fd: i32,
    pub program: OsString,
    pub arguments: Vec<OsString>,
}

/// Parse the exec-shim argument vector after argv[0]. Anything but the
/// exact layout is refused: both values numeric (ceiling at least 1) or both
/// `-`, a status descriptor of at least 3, then `--` and an absolute program.
pub fn parse_exec_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Option<JailExecInvocation> {
    let mut arguments = arguments.into_iter();
    if arguments.next()? != GOVERNED_JAIL_EXEC_PROTOCOL_V1 {
        return None;
    }
    let tasks = arguments.next()?;
    let namespace = arguments.next()?;
    let task_ceiling = match (tasks.to_str()?, namespace.to_str()?) {
        ("-", "-") => None,
        (tasks, namespace) => {
            let tasks = tasks.parse::<u64>().ok().filter(|tasks| *tasks > 0)?;
            let namespace = namespace.parse::<u64>().ok()?;
            Some((tasks, namespace))
        },
    };
    let status_fd = arguments.next()?.to_str()?.parse::<i32>().ok().filter(|fd| *fd >= 3)?;
    if arguments.next()? != "--" {
        return None;
    }
    let program = arguments.next()?;
    if !std::path::Path::new(&program).is_absolute() {
        return None;
    }
    Some(JailExecInvocation {
        task_ceiling,
        status_fd,
        program,
        arguments: arguments.collect(),
    })
}

/// The inode of a `user:[N]` namespace link target.
pub fn parse_user_namespace_link(target: &std::path::Path) -> Option<u64> {
    target
        .to_str()?
        .strip_prefix("user:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Process entry point of `magicrun-jail-egress-forwarder`. Runs the relay
/// until the child exits, then exits with the child's status (re-raising a
/// terminating signal); or, in exec-shim mode, applies the task ceiling and
/// execs. Never returns.
#[cfg(unix)]
pub fn forwarder_main(arguments: impl IntoIterator<Item = OsString>) -> ! {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if arguments.first().is_some_and(|first| first == GOVERNED_JAIL_EXEC_PROTOCOL_V1) {
        let Some(invocation) = parse_exec_arguments(arguments) else {
            std::process::exit(FORWARDER_EXIT_USAGE);
        };
        std::process::exit(unix::exec_shim(&invocation));
    }
    let Some(invocation) = parse_forwarder_arguments(arguments) else {
        std::process::exit(FORWARDER_EXIT_USAGE);
    };
    match unix::run(&invocation) {
        Ok(status) => unix::exit_like(status),
        Err(code) => std::process::exit(code),
    }
}

#[cfg(unix)]
mod unix {
    use std::{
        io::{self, ErrorKind, Read, Write},
        net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream},
        os::{
            fd::{AsRawFd, FromRawFd, RawFd},
            unix::{ffi::OsStrExt, net::UnixStream, process::ExitStatusExt},
        },
        path::Path,
        process::{Command, ExitStatus},
        time::{Duration, Instant},
    };

    use super::{
        connection_capacity_for, ForwarderInvocation, ACCEPT_PAUSE_MS, CONNECT_TIMEOUT_MS,
        EXIT_DRAIN_MS, FORWARDER_EXIT_SPAWN, FORWARDER_EXIT_USAGE, POLL_INTERVAL_MS, PUMP_ROUNDS,
        RELAY_BUFFER_BYTES,
    };

    /// Apply the task ceiling (only inside a user namespace of the jail's
    /// own) and exec the program. Returns only on failure, with the exit code.
    pub(super) fn exec_shim(invocation: &super::JailExecInvocation) -> i32 {
        use std::os::unix::process::CommandExt;

        let status = invocation.status_fd;
        // Report on the status pipe that the program never ran.
        let refuse = || {
            let byte = [super::JAIL_EXEC_REFUSED];
            // SAFETY: writes one byte from a live buffer to a descriptor
            // number; a closed or foreign number fails harmlessly.
            let _ = unsafe { libc::write(status, byte.as_ptr().cast(), 1) };
            super::JAIL_EXEC_EXIT_REFUSED
        };
        // SAFETY: `F_GETFD` only queries the descriptor number.
        if unsafe { libc::fcntl(status, libc::F_GETFD) } < 0 {
            return FORWARDER_EXIT_USAGE;
        }
        if let Some((tasks, host_namespace)) = invocation.task_ceiling {
            let own = std::fs::read_link("/proc/self/ns/user")
                .ok()
                .and_then(|target| super::parse_user_namespace_link(&target));
            // bubblewrap keeps the caller's UID inside the sandbox (no
            // `--uid`), so UID 0 here means the service runs as host root.
            // `/proc/self/uid_map` cannot tell: to mount devpts, unprivileged
            // bubblewrap nests the sandbox namespace in one that maps the
            // caller to 0, so the map is relative to that intermediate one.
            // SAFETY: `getuid` has no preconditions and cannot fail.
            let root = unsafe { libc::getuid() } == 0;
            if own.is_none() || own == Some(host_namespace) || root {
                return refuse();
            }
            // `rlim_t` is 64-bit on every supported target.
            let value = tasks as libc::rlim_t;
            let limit = libc::rlimit {
                rlim_cur: value,
                rlim_max: value,
            };
            // SAFETY: `setrlimit` reads only the live `limit`.
            if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &limit) } != 0 {
                return refuse();
            }
        }
        // The program must never hold the status pipe.
        // SAFETY: `F_SETFD` on the inherited descriptor checked above.
        if unsafe { libc::fcntl(status, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return refuse();
        }
        // `exec` replaces this process and returns only on failure (the
        // descriptor is then still open). No PATH search: the program is
        // absolute.
        let _error = Command::new(&invocation.program)
            .args(&invocation.arguments)
            .exec();
        refuse()
    }

    pub(super) fn run(invocation: &ForwarderInvocation) -> Result<ExitStatus, i32> {
        // Bind before the child exists so its first connection cannot race
        // the listener. Rust opens it close-on-exec; the child never holds it.
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, invocation.port))
            .map_err(|_| FORWARDER_EXIT_USAGE)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| FORWARDER_EXIT_USAGE)?;
        let capacity = connection_capacity(&listener);
        let mut command = Command::new(&invocation.program);
        command.args(&invocation.arguments);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            // SAFETY: `prctl(PR_SET_PDEATHSIG)` is async-signal-safe and only
            // touches the calling (post-fork, pre-exec) child.
            unsafe {
                command.pre_exec(|| {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = command.spawn().map_err(|_| FORWARDER_EXIT_SPAWN)?;
        let mut connections: Vec<Connection> = Vec::new();
        let mut accept_paused_until: Option<Instant> = None;
        loop {
            if accept_paused_until.is_some_and(|until| Instant::now() >= until) {
                accept_paused_until = None;
            }
            let listening = connections.len() < capacity && accept_paused_until.is_none();
            if !poll_round(listening.then_some(&listener), &mut connections, false, POLL_INTERVAL_MS) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(FORWARDER_EXIT_USAGE);
            }
            if let Some(status) = child.try_wait().map_err(|_| FORWARDER_EXIT_USAGE)? {
                drain_outbound(&listener, &invocation.socket, &mut connections, capacity);
                return Ok(status);
            }
            if listening
                && accept_pending(&listener, &invocation.socket, &mut connections, capacity).is_err()
            {
                accept_paused_until = Some(Instant::now() + Duration::from_millis(ACCEPT_PAUSE_MS));
            }
            for connection in &mut connections {
                connection.pump();
            }
            let open = connections.len();
            connections.retain(|connection| !connection.finished());
            if connections.len() < open {
                accept_paused_until = None;
            }
        }
    }

    /// Relays that fit this process's descriptor limit, counting the
    /// descriptors actually open now (the listener included), so inherited
    /// descriptors cannot push a relay into `EMFILE`.
    fn connection_capacity(listener: &TcpListener) -> usize {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` writes only the provided, live `rlimit`.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return 1;
        }
        let soft = u64::from(limit.rlim_cur);
        let highest = soft.min(4096).max(listener.as_raw_fd() as u64 + 1);
        let open = (0..highest)
            // SAFETY: `F_GETFD` only queries a descriptor number; an unused
            // number fails with `EBADF`.
            .filter(|fd| unsafe { libc::fcntl(*fd as RawFd, libc::F_GETFD) } != -1)
            .count() as u64;
        connection_capacity_for(soft, open)
    }

    /// Poll the listener (when given) and every relay, then hand each relay
    /// its events. A descriptor whose peer is gone and that has nothing left
    /// to transfer is left out: `poll` reports hang-up even with no requested
    /// events, and keeping it would wake every round and spin. `false` on a
    /// poll failure other than an interruption.
    fn poll_round(
        listener: Option<&TcpListener>,
        connections: &mut [Connection],
        outbound_only: bool,
        timeout_ms: i32,
    ) -> bool {
        let mut descriptors = Vec::with_capacity(1 + connections.len() * 2);
        if let Some(listener) = listener {
            descriptors.push(libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        for connection in connections.iter() {
            let (client, upstream) = connection.interest(outbound_only);
            let client_fd = if connection.client_gone && client == 0 {
                -1
            } else {
                connection.client.as_raw_fd()
            };
            let upstream_fd = if connection.upstream_gone && upstream == 0 {
                -1
            } else {
                connection.upstream.as_raw_fd()
            };
            descriptors.push(libc::pollfd {
                fd: client_fd,
                events: client,
                revents: 0,
            });
            descriptors.push(libc::pollfd {
                fd: upstream_fd,
                events: upstream,
                revents: 0,
            });
        }
        // SAFETY: `descriptors` is a live, initialized pollfd slice for the
        // duration of the call and its length is passed exactly. Negative
        // descriptors are ignored by `poll` and get no events.
        let ready = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                timeout_ms,
            )
        };
        if ready < 0 {
            return io::Error::last_os_error().kind() == ErrorKind::Interrupted;
        }
        if ready > 0 {
            let offset = usize::from(listener.is_some());
            for (connection, pair) in connections
                .iter_mut()
                .zip(descriptors[offset..].chunks_exact(2))
            {
                connection.observe(pair[0].revents, pair[1].revents);
            }
        }
        true
    }

    /// The child has exited: deliver what it already sent to the broker, for
    /// at most `EXIT_DRAIN_MS`, so a fire-and-forget upload is not cut short.
    /// A connection the child completed just before exiting may still sit in
    /// the listen queue (Linux reports a fully closed client only once its
    /// peer closes), so the queue is accepted once, at exit, while under
    /// capacity. Never again afterwards: a descendant that outlives the child
    /// must not open new brokered connections during the drain.
    fn drain_outbound(
        listener: &TcpListener,
        socket: &Path,
        connections: &mut Vec<Connection>,
        capacity: usize,
    ) {
        let deadline = Instant::now() + Duration::from_millis(EXIT_DRAIN_MS);
        let _ = accept_pending(listener, socket, connections, capacity);
        loop {
            for connection in connections.iter_mut() {
                connection.pump_outbound();
            }
            connections.retain(|connection| !connection.outbound_settled());
            let now = Instant::now();
            if connections.is_empty() || now >= deadline {
                return;
            }
            let remaining = (deadline - now).as_millis().clamp(1, POLL_INTERVAL_MS as u128) as i32;
            if !poll_round(None, connections, true, remaining) {
                return;
            }
        }
    }

    /// Accept until the listen queue is empty or `capacity` is reached. A
    /// client whose broker connection cannot start at once is closed rather
    /// than stalling every other relay. `Err` when accepting failed in a way
    /// the next poll would repeat (descriptor exhaustion and the like).
    fn accept_pending(
        listener: &TcpListener,
        socket: &Path,
        connections: &mut Vec<Connection>,
        capacity: usize,
    ) -> Result<(), ()> {
        while connections.len() < capacity {
            let client = match listener.accept() {
                Ok((client, _)) => client,
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(error)
                    if error.kind() == ErrorKind::Interrupted
                        || error.raw_os_error() == Some(libc::ECONNABORTED) =>
                {
                    continue
                },
                Err(_) => return Err(()),
            };
            if client.set_nonblocking(true).is_err() || client.set_nodelay(true).is_err() {
                continue;
            }
            let Ok((upstream, connected)) = connect_nonblocking(socket) else {
                continue;
            };
            connections.push(Connection {
                client,
                upstream,
                outbound: Pipe::new(),
                inbound: Pipe::new(),
                connecting: (!connected)
                    .then(|| Instant::now() + Duration::from_millis(CONNECT_TIMEOUT_MS)),
                client_gone: false,
                upstream_gone: false,
                failed: false,
            });
        }
        Ok(())
    }

    /// Start a non-blocking connection to the broker socket: `(stream, true)`
    /// when connected, `(stream, false)` while in progress. A full broker
    /// backlog (`EAGAIN`) or a refusal is an error; nothing blocks.
    fn connect_nonblocking(path: &Path) -> io::Result<(UnixStream, bool)> {
        let bytes = path.as_os_str().as_bytes();
        // SAFETY: an all-zero `sockaddr_un` is a valid (empty) address.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
            return Err(ErrorKind::InvalidInput.into());
        }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
            *slot = *byte as libc::c_char;
        }
        let length = std::mem::size_of::<libc::sockaddr_un>();
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        {
            address.sun_len = length as u8;
        }
        // SAFETY: plain socket creation; the descriptor is owned below.
        let fd: RawFd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh socket owned by nothing else; the stream
        // closes it on every path from here.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        // The child was spawned before any relay exists, so this cannot race
        // an exec; close-on-exec keeps the invariant explicit anyway.
        // SAFETY: `fcntl(F_SETFD)` on a descriptor this function owns.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        stream.set_nonblocking(true)?;
        // SAFETY: `address` is a live, initialized `sockaddr_un` of `length`
        // bytes whose path is NUL-terminated by the zeroed tail.
        let result = unsafe {
            libc::connect(
                fd,
                (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
                length as libc::socklen_t,
            )
        };
        if result == 0 {
            return Ok((stream, true));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINPROGRESS) {
            return Ok((stream, false));
        }
        Err(error)
    }

    struct Pipe {
        buffer: Box<[u8]>,
        start: usize,
        end: usize,
        source_closed: bool,
        sink_shut: bool,
    }

    impl Pipe {
        fn new() -> Self {
            Self {
                buffer: vec![0; RELAY_BUFFER_BYTES].into_boxed_slice(),
                start: 0,
                end: 0,
                source_closed: false,
                sink_shut: false,
            }
        }

        fn wants_read(&self) -> bool {
            !self.source_closed && self.end < self.buffer.len()
        }

        fn has_data(&self) -> bool {
            self.start < self.end
        }

        fn drained(&self) -> bool {
            self.source_closed && !self.has_data() && self.sink_shut
        }

        /// Move what is available without blocking, for a bounded number of
        /// rounds. A read error ends the source like EOF (bytes already read
        /// are still delivered). `Err` means the sink can take no more.
        fn pump(
            &mut self,
            source: &mut impl Read,
            sink: &mut impl Write,
            shut_sink: impl FnOnce() -> io::Result<()>,
        ) -> Result<(), ()> {
            for _ in 0..PUMP_ROUNDS {
                let mut progressed = false;
                if self.wants_read() {
                    match source.read(&mut self.buffer[self.end..]) {
                        Ok(0) => self.source_closed = true,
                        Ok(read) => {
                            self.end += read;
                            progressed = true;
                        },
                        Err(error) if would_block(&error) => {},
                        Err(_) => self.source_closed = true,
                    }
                }
                while self.has_data() {
                    match sink.write(&self.buffer[self.start..self.end]) {
                        Ok(0) => return Err(()),
                        Ok(written) => {
                            self.start += written;
                            progressed = true;
                        },
                        Err(error) if would_block(&error) => break,
                        Err(_) => return Err(()),
                    }
                }
                if !self.has_data() {
                    self.start = 0;
                    self.end = 0;
                }
                if !progressed {
                    break;
                }
            }
            if self.source_closed && !self.has_data() && !self.sink_shut {
                self.sink_shut = true;
                // The peer may already be gone; half-close is best effort.
                let _ = shut_sink();
            }
            Ok(())
        }
    }

    fn would_block(error: &io::Error) -> bool {
        matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted)
    }

    struct Connection {
        client: TcpStream,
        upstream: UnixStream,
        /// client -> broker
        outbound: Pipe,
        /// broker -> client
        inbound: Pipe,
        /// Deadline of a broker connect still in progress.
        connecting: Option<Instant>,
        /// The client hung up or errored: nothing more can be delivered to
        /// it, but what it already sent is still read and relayed.
        client_gone: bool,
        /// The broker hung up, errored or refused a write: nothing more can
        /// be sent to it, but what it already sent is still delivered.
        upstream_gone: bool,
        failed: bool,
    }

    impl Connection {
        fn interest(&self, outbound_only: bool) -> (libc::c_short, libc::c_short) {
            if self.connecting.is_some() {
                return (0, libc::POLLOUT);
            }
            let mut client = 0;
            let mut upstream = 0;
            if !self.upstream_gone {
                if self.outbound.wants_read() {
                    client |= libc::POLLIN;
                }
                if self.outbound.has_data() {
                    upstream |= libc::POLLOUT;
                }
            }
            if !self.client_gone && !outbound_only {
                if self.inbound.has_data() {
                    client |= libc::POLLOUT;
                }
                if self.inbound.wants_read() {
                    upstream |= libc::POLLIN;
                }
            }
            (client, upstream)
        }

        /// Record hang-ups and errors once per peer. Linux reports `POLLHUP`
        /// for a closed AF_UNIX peer on every poll, requested or not; the
        /// peer is then marked gone and its descriptor leaves the poll set
        /// as soon as nothing is left to read from it.
        fn observe(&mut self, client: libc::c_short, upstream: libc::c_short) {
            if (client | upstream) & libc::POLLNVAL != 0 {
                self.failed = true;
                return;
            }
            if self.connecting.is_some() {
                if client & (libc::POLLHUP | libc::POLLERR) != 0 {
                    self.failed = true;
                } else if upstream & (libc::POLLOUT | libc::POLLHUP | libc::POLLERR) != 0 {
                    match self.upstream.take_error() {
                        Ok(None) => self.connecting = None,
                        _ => self.failed = true,
                    }
                }
                return;
            }
            if upstream & (libc::POLLHUP | libc::POLLERR) != 0 {
                self.upstream_gone = true;
            }
            if client & (libc::POLLHUP | libc::POLLERR) != 0 {
                self.client_gone = true;
            }
        }

        /// `true` while the connection may move bytes.
        fn ready(&mut self) -> bool {
            if self.failed {
                return false;
            }
            if let Some(deadline) = self.connecting {
                if Instant::now() >= deadline {
                    self.failed = true;
                }
                return false;
            }
            true
        }

        fn pump_outbound(&mut self) {
            if !self.ready() || self.upstream_gone {
                return;
            }
            let upstream = &self.upstream;
            if self
                .outbound
                .pump(&mut &self.client, &mut &self.upstream, || {
                    upstream.shutdown(Shutdown::Write)
                })
                .is_err()
            {
                self.upstream_gone = true;
            }
        }

        fn pump(&mut self) {
            self.pump_outbound();
            if !self.ready() || self.client_gone {
                return;
            }
            let client = &self.client;
            if self
                .inbound
                .pump(&mut &self.upstream, &mut &self.client, || {
                    client.shutdown(Shutdown::Write)
                })
                .is_err()
            {
                self.client_gone = true;
            }
        }

        fn outbound_settled(&self) -> bool {
            self.failed || self.upstream_gone || self.outbound.drained()
        }

        fn finished(&self) -> bool {
            self.failed
                || (self.outbound_settled() && (self.client_gone || self.inbound.drained()))
        }
    }

    /// Exit exactly like the child: same code, or the same terminating signal.
    pub(super) fn exit_like(status: ExitStatus) -> ! {
        if let Some(code) = status.code() {
            std::process::exit(code);
        }
        if let Some(signal) = status.signal() {
            // SAFETY: restoring the default disposition and raising a signal
            // on this single-threaded process has no memory-safety preconditions.
            unsafe {
                libc::signal(signal, libc::SIG_DFL);
                libc::raise(signal);
            }
            std::process::exit(128 + signal);
        }
        std::process::exit(FORWARDER_EXIT_USAGE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn capacity_fits_the_descriptor_limit() {
        assert_eq!(FORWARDER_MIN_OPEN_FILES, 8);
        // stdio and the listener open.
        assert_eq!(connection_capacity_for(FORWARDER_MIN_OPEN_FILES, 4), 1);
        assert_eq!(connection_capacity_for(0, 4), 1);
        assert_eq!(connection_capacity_for(12, 4), 3);
        assert_eq!(connection_capacity_for(38, 4), 16);
        assert_eq!(connection_capacity_for(64, 4), MAX_FORWARDER_CONNECTIONS);
        assert_eq!(connection_capacity_for(u64::MAX, 4), MAX_FORWARDER_CONNECTIONS);
        // Inherited descriptors reduce the relays that fit.
        assert_eq!(connection_capacity_for(12, 8), 1);
        assert_eq!(connection_capacity_for(16, 6), 4);
        // Never fewer reserved than stdio plus the listener.
        assert_eq!(connection_capacity_for(12, 0), 3);
    }

    #[test]
    fn exec_shim_parses_only_the_exact_layout() {
        let parsed = parse_exec_arguments(args(&[
            "--magicrun-jail-exec-v1",
            "258",
            "4026531837",
            "9",
            "--",
            "/app/tool",
            "--flag",
        ]))
        .unwrap();
        assert_eq!(parsed.task_ceiling, Some((258, 4026531837)));
        assert_eq!(parsed.status_fd, 9);
        assert_eq!(parsed.program, OsString::from("/app/tool"));
        assert_eq!(parsed.arguments, args(&["--flag"]));
        let exec_only =
            parse_exec_arguments(args(&["--magicrun-jail-exec-v1", "-", "-", "3", "--", "/app/tool"])).unwrap();
        assert_eq!(exec_only.task_ceiling, None);
        for refused in [
            &["--magicrun-jail-exec-v1", "0", "1", "9", "--", "/app/tool"][..],
            &["--magicrun-jail-exec-v1", "8", "-", "9", "--", "/app/tool"],
            &["--magicrun-jail-exec-v1", "-", "1", "9", "--", "/app/tool"],
            &["--magicrun-jail-exec-v1", "8", "1", "9", "/app/tool"],
            &["--magicrun-jail-exec-v1", "8", "1", "9", "--", "relative"],
            &["--magicrun-jail-exec-v1", "8", "1", "9", "--"],
            &["--magicrun-jail-exec-v1", "8", "1", "--", "/app/tool"],
            &["--magicrun-jail-exec-v1", "8", "1", "2", "--", "/app/tool"],
            &["--magicrun-jail-exec-v1", "8", "1", "x", "--", "/app/tool"],
            &["--magicrun-jail-egress-forwarder-v1", "8", "1", "9", "--", "/app/tool"],
        ] {
            assert_eq!(parse_exec_arguments(args(refused)), None, "{refused:?}");
        }
        assert_eq!(
            parse_user_namespace_link(std::path::Path::new("user:[4026531837]")),
            Some(4026531837)
        );
        for refused in ["pid:[1]", "user:[x]", "user:4026531837"] {
            assert_eq!(parse_user_namespace_link(std::path::Path::new(refused)), None);
        }
    }

    #[test]
    fn parses_only_the_exact_protocol_layout() {
        let parsed = parse_forwarder_arguments(args(&[
            "--magicrun-jail-egress-forwarder-v1",
            "3128",
            "/run/magicrun/egress.sock",
            "--",
            "/app/tool",
            "--flag",
            "",
        ]))
        .unwrap();
        assert_eq!(parsed.port, 3128);
        assert_eq!(parsed.socket, PathBuf::from("/run/magicrun/egress.sock"));
        assert_eq!(parsed.program, OsString::from("/app/tool"));
        assert_eq!(parsed.arguments, args(&["--flag", ""]));

        for refused in [
            &["--other", "3128", "/s", "--", "/app/tool"][..],
            &[
                "--magicrun-jail-egress-forwarder-v1",
                "0",
                "/s",
                "--",
                "/app/tool",
            ],
            &[
                "--magicrun-jail-egress-forwarder-v1",
                "70000",
                "/s",
                "--",
                "/app/tool",
            ],
            &[
                "--magicrun-jail-egress-forwarder-v1",
                "3128",
                "relative",
                "--",
                "/app/tool",
            ],
            &[
                "--magicrun-jail-egress-forwarder-v1",
                "3128",
                "/s",
                "/app/tool",
            ],
            &["--magicrun-jail-egress-forwarder-v1", "3128", "/s", "--"],
            &[
                "--magicrun-jail-egress-forwarder-v1",
                "3128",
                "/s",
                "--",
                "",
            ],
        ] {
            assert_eq!(
                parse_forwarder_arguments(args(refused)),
                None,
                "{refused:?}"
            );
        }
    }
}
