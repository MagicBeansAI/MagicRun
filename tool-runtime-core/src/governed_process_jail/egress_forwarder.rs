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

use std::{ffi::OsString, path::PathBuf};

/// Exit status for a malformed invocation or a listener that cannot bind.
pub const FORWARDER_EXIT_USAGE: i32 = 125;
/// Exit status when the child cannot be started.
pub const FORWARDER_EXIT_SPAWN: i32 = 127;
/// Concurrent relayed connections; further connections wait in the listen
/// backlog. Two descriptors each plus stdio and the listener stay well under
/// the jail's `RLIMIT_NOFILE` ceiling (`MAX_GOVERNED_JAIL_OPEN_FILES`).
pub const MAX_FORWARDER_CONNECTIONS: usize = 16;
#[cfg(unix)]
const RELAY_BUFFER_BYTES: usize = 16 * 1024;
#[cfg(unix)]
const POLL_INTERVAL_MS: i32 = 50;

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

/// Process entry point of `magicrun-jail-egress-forwarder`. Runs the relay
/// until the child exits, then exits with the child's status (re-raising a
/// terminating signal). Never returns.
#[cfg(unix)]
pub fn forwarder_main(arguments: impl IntoIterator<Item = OsString>) -> ! {
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
            fd::AsRawFd,
            unix::{net::UnixStream, process::ExitStatusExt},
        },
        path::Path,
        process::{Command, ExitStatus},
    };

    use super::{
        ForwarderInvocation, FORWARDER_EXIT_SPAWN, FORWARDER_EXIT_USAGE, MAX_FORWARDER_CONNECTIONS,
        POLL_INTERVAL_MS, RELAY_BUFFER_BYTES,
    };

    pub(super) fn run(invocation: &ForwarderInvocation) -> Result<ExitStatus, i32> {
        // Bind before the child exists so its first connection cannot race
        // the listener. Rust opens it close-on-exec; the child never holds it.
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, invocation.port))
            .map_err(|_| FORWARDER_EXIT_USAGE)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| FORWARDER_EXIT_USAGE)?;
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
        loop {
            let mut descriptors = Vec::with_capacity(1 + connections.len() * 2);
            if connections.len() < MAX_FORWARDER_CONNECTIONS {
                descriptors.push(libc::pollfd {
                    fd: listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            for connection in &connections {
                let (client, upstream) = connection.interest();
                descriptors.push(libc::pollfd {
                    fd: connection.client.as_raw_fd(),
                    events: client,
                    revents: 0,
                });
                descriptors.push(libc::pollfd {
                    fd: connection.upstream.as_raw_fd(),
                    events: upstream,
                    revents: 0,
                });
            }
            // SAFETY: `descriptors` is a live, initialized pollfd slice for
            // the duration of the call and its length is passed exactly.
            let ready = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as libc::nfds_t,
                    POLL_INTERVAL_MS,
                )
            };
            if ready < 0 && io::Error::last_os_error().kind() != ErrorKind::Interrupted {
                let _ = child.kill();
                let _ = child.wait();
                return Err(FORWARDER_EXIT_USAGE);
            }
            if let Some(status) = child.try_wait().map_err(|_| FORWARDER_EXIT_USAGE)? {
                return Ok(status);
            }
            accept_pending(&listener, &invocation.socket, &mut connections);
            for connection in &mut connections {
                connection.pump();
            }
            connections.retain(|connection| !connection.finished());
        }
    }

    fn accept_pending(listener: &TcpListener, socket: &Path, connections: &mut Vec<Connection>) {
        while connections.len() < MAX_FORWARDER_CONNECTIONS {
            let client = match listener.accept() {
                Ok((client, _)) => client,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return,
            };
            let Ok(upstream) = UnixStream::connect(socket) else {
                continue;
            };
            if client.set_nonblocking(true).is_err()
                || upstream.set_nonblocking(true).is_err()
                || client.set_nodelay(true).is_err()
            {
                continue;
            }
            connections.push(Connection {
                client,
                upstream,
                outbound: Pipe::new(),
                inbound: Pipe::new(),
                failed: false,
            });
        }
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

        /// Move what is available without blocking. `Err` ends the connection.
        fn pump(
            &mut self,
            source: &mut impl Read,
            sink: &mut impl Write,
            shut_sink: impl FnOnce() -> io::Result<()>,
        ) -> io::Result<()> {
            if self.wants_read() {
                match source.read(&mut self.buffer[self.end..]) {
                    Ok(0) => self.source_closed = true,
                    Ok(read) => self.end += read,
                    Err(error) if would_block(&error) => {}
                    Err(error) => return Err(error),
                }
            }
            while self.has_data() {
                match sink.write(&self.buffer[self.start..self.end]) {
                    Ok(0) => return Err(ErrorKind::WriteZero.into()),
                    Ok(written) => self.start += written,
                    Err(error) if would_block(&error) => break,
                    Err(error) => return Err(error),
                }
            }
            if !self.has_data() {
                self.start = 0;
                self.end = 0;
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
        failed: bool,
    }

    impl Connection {
        fn interest(&self) -> (libc::c_short, libc::c_short) {
            let mut client = 0;
            let mut upstream = 0;
            if self.outbound.wants_read() {
                client |= libc::POLLIN;
            }
            if self.inbound.has_data() {
                client |= libc::POLLOUT;
            }
            if self.inbound.wants_read() {
                upstream |= libc::POLLIN;
            }
            if self.outbound.has_data() {
                upstream |= libc::POLLOUT;
            }
            (client, upstream)
        }

        fn pump(&mut self) {
            if self.failed {
                return;
            }
            let upstream = &self.upstream;
            let client = &self.client;
            let outbound = self
                .outbound
                .pump(&mut &self.client, &mut &self.upstream, || {
                    upstream.shutdown(Shutdown::Write)
                });
            let inbound = self
                .inbound
                .pump(&mut &self.upstream, &mut &self.client, || {
                    client.shutdown(Shutdown::Write)
                });
            if outbound.is_err() || inbound.is_err() {
                self.failed = true;
            }
        }

        fn finished(&self) -> bool {
            self.failed || (self.outbound.drained() && self.inbound.drained())
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
