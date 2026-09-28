//! Real-jail tests of the brokered-egress mode. They launch the platform
//! launcher (`sandbox-exec` / `bwrap`) and skip only when it is unavailable.

use std::{
    collections::BTreeSet,
    io::{Read, Write},
    net::{Shutdown, TcpListener},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
};

use super::*;
use crate::{
    credential_injection::{ChildEnvironmentBaseline, ChildEnvironmentVariable},
    credential_materialization::ChildEnvironmentValues,
    governed_batch_process::{
        GovernedBatchCancellation, GovernedBatchExecutor, GovernedBatchProcess,
        GovernedBatchProcessErrorCode,
    },
    governed_execution::{
        GovernedExecutionContract, GovernedExecutionPolicy, GovernedExecutionRequest,
        GovernedExecutionTerminal,
    },
    governed_execution_authority::{
        GovernedExecutionAuthority, GovernedExecutionAuthorityErrorCode,
        GovernedExpectedExecutableDigest,
    },
    manifest::{
        AuthContract, CliInteraction, PolicyFloor, RuntimeLimits, RuntimeProtocol,
        RuntimeRequirements, SkillRuntimeContract, SkillRuntimeContractVersion, StdinContract,
        StdinMode, WorkingDirectoryContract,
    },
    manifest_validation::validate_skill_runtime_contract,
};

/// Real jails spawn real processes; keep them serial like the batch tests.
pub(super) static JAIL_PROCESS_BUDGET: Mutex<()> = Mutex::new(());

pub(super) const TUNNEL_BODY: &str = "tunnel-relayed-body";

/// Minimal HTTP CONNECT test broker (loopback TCP, the macOS endpoint). It records every request line, tunnels
/// `allowed.example:80` to a canned HTTP response and refuses anything else
/// with 403, like the real broker's allowlist.
#[cfg(target_os = "macos")]
pub(super) struct TestBroker {
    pub(super) port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

#[cfg(target_os = "macos")]
impl TestBroker {
    pub(super) fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let recorded = Arc::clone(&recorded);
                thread::spawn(move || serve_connect(stream, &recorded));
            }
        });
        Self { port, requests }
    }

    pub(super) fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

fn read_head(stream: &mut impl Read) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).ok()? == 0 || head.len() > 16 * 1024 {
            return None;
        }
        head.push(byte[0]);
    }
    String::from_utf8(head).ok()
}

pub(super) fn serve_connect<S: Read + Write>(mut stream: S, recorded: &Mutex<Vec<String>>) {
    let Some(head) = read_head(&mut stream) else {
        return;
    };
    let line = head.lines().next().unwrap_or_default().to_owned();
    recorded.lock().unwrap().push(line.clone());
    if line != "CONNECT allowed.example:80 HTTP/1.1" {
        let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
    if read_head(&mut stream).is_none() {
        return;
    }
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{TUNNEL_BODY}",
            TUNNEL_BODY.len()
        )
        .as_bytes(),
    );
}

/// A host listener that must never see a jailed connection.
pub(super) struct Tripwire {
    pub(super) port: u16,
    pub(super) hits: Arc<AtomicUsize>,
}

impl Tripwire {
    pub(super) fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&hits);
        thread::spawn(move || {
            for stream in listener.incoming() {
                counted.fetch_add(1, Ordering::SeqCst);
                if let Ok(stream) = stream {
                    let _ = stream.shutdown(Shutdown::Both);
                }
            }
        });
        Self { port, hits }
    }
}

pub(super) struct JailedRun {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(super) terminal: GovernedExecutionTerminal,
    pub(super) exit_code: Option<i32>,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

/// A skipped real-jail test says so on stderr. On a Linux host that sets
/// `MAGICRUN_REQUIRE_LINUX_JAIL=1` (CI with `bwrap`, the forwarder and a
/// trusted python3 installed) a skip is a failure instead.
pub(crate) fn skip(reason: &str) {
    if cfg!(target_os = "linux") && std::env::var_os("MAGICRUN_REQUIRE_LINUX_JAIL").is_some_and(|value| value == "1") {
        panic!("MAGICRUN_REQUIRE_LINUX_JAIL=1 but the real-jail test would skip: {reason}");
    }
    eprintln!("SKIP: {reason}");
}

/// Why a governed jailed run was refused before or at dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JailRunError {
    Authority(GovernedExecutionAuthorityErrorCode),
    Batch(GovernedBatchProcessErrorCode),
}

/// Run `bin` (resolved from `/usr/bin:/bin`) with `arguments` inside `jail`
/// through the same governed batch path Magician uses.
fn run_in_jail(jail: GovernedProcessJail, bin: &str, arguments: &[&str]) -> JailedRun {
    run_in_jail_with_environment(jail, bin, arguments, &[])
}

/// As [`run_in_jail`], with package-authored fixed environment pairs carried
/// through the same authorized child-environment vector as credential
/// injections.
fn run_in_jail_with_environment(
    jail: GovernedProcessJail,
    bin: &str,
    arguments: &[&str],
    fixed: &[(&str, &str)],
) -> JailedRun {
    try_run_in_jail(jail, "/usr/bin:/bin", bin, arguments, fixed, None).unwrap()
}

/// The governed batch path with a caller `PATH` for resolution and an
/// optional install-review executable digest. Refusals keep their code.
pub(super) fn try_run_in_jail(
    jail: GovernedProcessJail,
    search_path: &str,
    bin: &str,
    arguments: &[&str],
    fixed: &[(&str, &str)],
    expected_executable: Option<[u8; 32]>,
) -> Result<JailedRun, JailRunError> {
    let authored = SkillRuntimeContract {
        schema_version: SkillRuntimeContractVersion::v1(),
        requires: RuntimeRequirements {
            bins: BTreeSet::from([bin.to_owned()]),
            entrypoint: Default::default(),
            environment: fixed
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        },
        runtime: RuntimeProtocol::Cli {
            command_prefix: Vec::new(),
            interaction: CliInteraction::Batch,
            stdin: StdinContract {
                mode: StdinMode::Denied,
                sensitivity: Default::default(),
            },
            working_directory: WorkingDirectoryContract {
                mode: WorkingDirectoryMode::Workspace,
            },
            limits: RuntimeLimits {
                timeout_secs: Some(20),
                stdin_bytes: None,
                stdout_bytes: Some(64 * 1024),
                stderr_bytes: Some(64 * 1024),
                memory_bytes: None,
            },
        },
        auth: AuthContract::default(),
        policy_floor: PolicyFloor::default(),
    };
    let contract = GovernedExecutionContract::compile(
        validate_skill_runtime_contract(&authored).unwrap(),
        GovernedExecutionPolicy::new(20, 20, 1024, 64 * 1024, 64 * 1024).unwrap(),
    )
    .unwrap();
    let intent = contract
        .admit(GovernedExecutionRequest::new(
            arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
            None,
            None,
            Some(20),
        ))
        .unwrap();
    let baseline = ChildEnvironmentBaseline::path_only();
    let mut values = ChildEnvironmentValues::new(&baseline);
    values
        .provide(ChildEnvironmentVariable::Path, search_path.as_bytes().to_vec())
        .unwrap();
    for (name, value) in fixed {
        values
            .provide_fixed(*name, value.as_bytes().to_vec())
            .unwrap();
    }
    let root = jail
        .working_directory_root(WorkingDirectoryMode::Workspace)
        .unwrap();
    let authority = match expected_executable {
        None => GovernedExecutionAuthority::bind(intent, &baseline, values, Some(root)),
        Some(digest) => GovernedExecutionAuthority::bind_expected_executable(
            intent,
            &baseline,
            values,
            Some(root),
            GovernedExpectedExecutableDigest::from_blake3(digest),
        ),
    }
    .map_err(|error| JailRunError::Authority(error.code))?;
    let parts = authority.into_parts();
    let mut environment = parts
        .environment
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Vec<_>>();
    environment.sort_by(|left, right| left.0.cmp(&right.0));
    let process = GovernedBatchProcess::from_authorized_parts_in_jail(parts, environment, jail)
        .map_err(|error| JailRunError::Batch(error.code))?;
    let result = GovernedBatchExecutor::execute(process, &GovernedBatchCancellation::new())
        .map_err(|error| JailRunError::Batch(error.code))?;
    let terminal = result.terminal().terminal();
    let exit_code = result.exit_code();
    let parts = result.into_parts();
    Ok(JailedRun {
        terminal,
        exit_code,
        stdout: String::from_utf8_lossy(&parts.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&parts.stderr).into_owned(),
    })
}

#[cfg(target_os = "macos")]
mod macos {
    use std::time::Duration;

    use super::*;

    fn brokered(port: u16) -> Option<GovernedProcessJail> {
        match GovernedProcessJail::strict_app_with_brokered_egress(
            GovernedProcessJailLimits::default(),
            GovernedEgressBrokerEndpoint::LoopbackTcp {
                port: NonZeroU16::new(port).unwrap(),
            },
        ) {
            Ok(jail) => Some(jail),
            Err(error) if error.code == GovernedProcessJailErrorCode::LauncherUnavailable => None,
            Err(error) => panic!("unexpected brokered jail setup failure: {error}"),
        }
    }

    /// A file staged before launch is readable by the jailed child by its
    /// plain name, relative to the private workdir.
    #[test]
    fn a_staged_input_file_is_readable_by_the_child() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Ok(jail) = GovernedProcessJail::strict_app(GovernedProcessJailLimits::default()) else {
            return;
        };
        let name = jail.stage_input_file("input.txt", b"staged-content").unwrap();
        let run = run_in_jail(jail, "cat", &[&name]);
        assert_eq!(run.exit_code, Some(0), "stderr={}", run.stderr);
        assert_eq!(run.stdout, "staged-content");
    }

    /// (a) A standard CLI reaches the broker through the proxy environment
    /// alone, and bytes are tunnelled end to end.
    #[test]
    fn child_reaches_the_broker_through_the_proxy_environment() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let broker = TestBroker::start();
        let Some(jail) = brokered(broker.port) else {
            return;
        };
        let audit = jail.audit();
        let egress = audit
            .egress
            .expect("brokered audit carries egress evidence");
        assert_eq!(egress.broker_port, Some(broker.port));
        assert_eq!(egress.proxy_port, broker.port);
        let run = run_in_jail(
            jail,
            "curl",
            &["-sS", "--proxytunnel", "http://allowed.example/"],
        );
        assert_eq!(
            run.terminal,
            GovernedExecutionTerminal::Success,
            "stderr={}",
            run.stderr
        );
        assert_eq!(run.stdout, TUNNEL_BODY, "stderr={}", run.stderr);
        assert_eq!(
            broker.requests(),
            vec!["CONNECT allowed.example:80 HTTP/1.1"]
        );
    }

    /// (a') HTTPS uses CONNECT through `HTTPS_PROXY`; the name is never
    /// resolved in the jail and the trust store is readable (curl reaches the
    /// broker instead of failing on its CA file or on DNS).
    #[test]
    fn https_request_is_sent_to_the_broker_as_connect() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let broker = TestBroker::start();
        let Some(jail) = brokered(broker.port) else {
            return;
        };
        let run = run_in_jail(jail, "curl", &["-sS", "https://refused.example/"]);
        assert_ne!(run.exit_code, Some(0));
        assert_eq!(
            broker.requests(),
            vec!["CONNECT refused.example:443 HTTP/1.1"]
        );
        assert!(!run.stderr.contains("resolve"), "stderr={}", run.stderr);
    }

    /// (b) A child that ignores the proxy cannot reach any other loopback
    /// port, nor a remote address.
    #[test]
    fn direct_connections_bypassing_the_broker_are_refused() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let broker = TestBroker::start();
        let tripwire = Tripwire::start();
        let Some(jail) = brokered(broker.port) else {
            return;
        };
        let target = format!("http://127.0.0.1:{}/", tripwire.port);
        let run = run_in_jail(jail, "curl", &["-sS", "--noproxy", "*", &target]);
        assert_eq!(run.exit_code, Some(7), "stderr={}", run.stderr);
        let Some(jail) = brokered(broker.port) else {
            return;
        };
        let run = run_in_jail(
            jail,
            "curl",
            &[
                "-sS",
                "--noproxy",
                "*",
                "--connect-timeout",
                "3",
                "http://1.1.1.1/",
            ],
        );
        assert_eq!(run.exit_code, Some(7), "stderr={}", run.stderr);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(tripwire.hits.load(Ordering::SeqCst), 0);
        assert!(broker.requests().is_empty());
    }

    /// The broker port admits IPv4 TCP only: a listener another process
    /// binds on the same port over IPv6 loopback stays unreachable.
    #[test]
    fn the_broker_port_over_ipv6_loopback_is_refused() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let broker = TestBroker::start();
        let Ok(listener) = TcpListener::bind(("::1", broker.port)) else {
            return;
        };
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&hits);
        thread::spawn(move || {
            for stream in listener.incoming() {
                counted.fetch_add(1, Ordering::SeqCst);
                if let Ok(stream) = stream {
                    let _ = stream.shutdown(Shutdown::Both);
                }
            }
        });
        let Some(jail) = brokered(broker.port) else {
            return;
        };
        let target = format!("http://[::1]:{}/", broker.port);
        let run = run_in_jail(jail, "curl", &["-sS", "--noproxy", "*", &target]);
        assert_eq!(run.exit_code, Some(7), "stderr={}", run.stderr);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        assert!(broker.requests().is_empty());
    }

    /// (c) Name resolution is impossible inside the jail.
    #[test]
    fn dns_resolution_fails_inside_the_jail() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let broker = TestBroker::start();
        let Some(jail) = brokered(broker.port) else {
            return;
        };
        let run = run_in_jail(
            jail,
            "curl",
            &["-sS", "--noproxy", "*", "http://example.com/"],
        );
        // CURLE_COULDNT_RESOLVE_HOST
        assert_eq!(run.exit_code, Some(6), "stderr={}", run.stderr);
        assert!(broker.requests().is_empty());
    }

    /// (d) The strict profile still denies the broker port itself.
    #[test]
    fn strict_jail_still_cannot_reach_a_broker() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let broker = TestBroker::start();
        let jail = match GovernedProcessJail::strict_app(GovernedProcessJailLimits::default()) {
            Ok(jail) => jail,
            Err(error) if error.code == GovernedProcessJailErrorCode::LauncherUnavailable => return,
            Err(error) => panic!("unexpected strict jail setup failure: {error}"),
        };
        let proxy = format!("http://127.0.0.1:{}", broker.port);
        let run = run_in_jail(
            jail,
            "curl",
            &[
                "-sS",
                "--proxy",
                &proxy,
                "--proxytunnel",
                "http://allowed.example/",
            ],
        );
        // The strict profile does not even expose the trust store curl loads
        // at start-up; whichever check fails first, nothing reaches the broker.
        assert_ne!(run.exit_code, Some(0), "stderr={}", run.stderr);
        assert!(broker.requests().is_empty());
    }

    /// Caller-authorized environment pairs (the channel credential
    /// injections use) reach the jailed child beside the fixed proxy overlay,
    /// and a package value cannot re-point the broker.
    #[test]
    fn authorized_environment_and_proxy_overlay_reach_the_child() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let broker = TestBroker::start();
        let Some(jail) = brokered(broker.port) else {
            return;
        };
        let run =
            run_in_jail_with_environment(jail, "env", &[], &[("SKILL_MARKER", "authorized-value")]);
        assert_eq!(
            run.terminal,
            GovernedExecutionTerminal::Success,
            "stderr={}",
            run.stderr
        );
        let lines = run.stdout.lines().collect::<BTreeSet<_>>();
        let proxy = format!("http://127.0.0.1:{}", broker.port);
        assert!(
            lines.contains("SKILL_MARKER=authorized-value"),
            "{}",
            run.stdout
        );
        for name in GOVERNED_JAIL_EGRESS_PROXY_VARIABLES {
            assert!(
                lines.contains(format!("{name}={proxy}").as_str()),
                "{name}: {}",
                run.stdout
            );
        }
        assert!(lines.contains("NO_PROXY=") && lines.contains("no_proxy="));
    }

    #[test]
    fn macos_refuses_a_unix_socket_broker() {
        let error = GovernedProcessJail::strict_app_with_brokered_egress(
            GovernedProcessJailLimits::default(),
            GovernedEgressBrokerEndpoint::UnixSocket {
                path: PathBuf::from("/private/tmp/broker.sock"),
            },
        )
        .err()
        .expect("unix-socket broker is unsupported on macOS");
        assert!(matches!(
            error.code,
            GovernedProcessJailErrorCode::UnsupportedEgressBroker
                | GovernedProcessJailErrorCode::LauncherUnavailable
        ));
    }
}

/// NOT EXECUTED on macOS development hosts. These need `bwrap` and the
/// forwarder installed root-owned at one of
/// `GOVERNED_JAIL_EGRESS_FORWARDER_PATHS`; they skip otherwise.
#[cfg(target_os = "linux")]
pub(super) mod linux {
    use std::os::unix::net::UnixListener;

    use super::*;

    /// A system tool (snapshotted `/usr/bin/jq`, dynamically linked) runs in
    /// the strict jail on a file staged before launch: the base library
    /// binds are enough and staging reaches the child's `/work`.
    #[test]
    fn a_system_tool_reads_a_staged_input_in_the_strict_jail() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if !Path::new("/usr/bin/jq").exists() {
            skip("no /usr/bin/jq on this host");
            return;
        }
        let jail = match GovernedProcessJail::strict_app(GovernedProcessJailLimits::default()) {
            Ok(jail) => jail,
            Err(error) => {
                skip(&format!("no Linux strict jail on this host: {error}"));
                return;
            },
        };
        let name = jail.stage_input_file("in-data.json", br#"{"items":[1,2,3]}"#).unwrap();
        let run = run_in_jail(jail, "jq", &[".items | length", &name]);
        assert_eq!(run.exit_code, Some(0), "stderr={}", run.stderr);
        assert_eq!(run.stdout.trim(), "3");
    }

    pub(in crate::governed_process_jail) struct UnixBroker {
        _directory: tempfile::TempDir,
        path: PathBuf,
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl UnixBroker {
        pub(in crate::governed_process_jail) fn start() -> Self {
            let directory = tempfile::tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let path = fs::canonicalize(directory.path())
                .unwrap()
                .join("broker.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&requests);
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { return };
                    let recorded = Arc::clone(&recorded);
                    thread::spawn(move || serve_connect(stream, &recorded));
                }
            });
            Self {
                _directory: directory,
                path,
                requests,
            }
        }
    }

    pub(in crate::governed_process_jail) fn brokered(broker: &UnixBroker) -> Option<GovernedProcessJail> {
        match GovernedProcessJail::strict_app_with_brokered_egress(
            GovernedProcessJailLimits::default(),
            GovernedEgressBrokerEndpoint::UnixSocket {
                path: broker.path.clone(),
            },
        ) {
            Ok(jail) => Some(jail),
            Err(error)
                if matches!(
                    error.code,
                    GovernedProcessJailErrorCode::LauncherUnavailable
                        | GovernedProcessJailErrorCode::EgressForwarderUnavailable
                ) =>
            {
                skip(&format!("no Linux brokered jail on this host: {error}"));
                None
            }
            Err(error) => panic!("unexpected brokered jail setup failure: {error}"),
        }
    }

    #[test]
    fn linux_child_reaches_the_broker_through_the_in_jail_forwarder() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let broker = UnixBroker::start();
        let Some(jail) = brokered(&broker) else {
            return;
        };
        let run = run_in_jail(
            jail,
            "curl",
            &["-sS", "--proxytunnel", "http://allowed.example/"],
        );
        assert_eq!(run.stdout, TUNNEL_BODY, "stderr={}", run.stderr);
        assert_eq!(
            broker.requests.lock().unwrap().clone(),
            vec!["CONNECT allowed.example:80 HTTP/1.1"]
        );
    }

    #[test]
    fn linux_direct_connections_and_dns_fail() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let broker = UnixBroker::start();
        let tripwire = Tripwire::start();
        let Some(jail) = brokered(&broker) else {
            return;
        };
        let target = format!("http://127.0.0.1:{}/", tripwire.port);
        let run = run_in_jail(jail, "curl", &["-sS", "--noproxy", "*", &target]);
        assert_eq!(run.exit_code, Some(7), "stderr={}", run.stderr);
        let Some(jail) = brokered(&broker) else {
            return;
        };
        let run = run_in_jail(
            jail,
            "curl",
            &["-sS", "--noproxy", "*", "http://example.com/"],
        );
        assert_eq!(run.exit_code, Some(6), "stderr={}", run.stderr);
        assert_eq!(tripwire.hits.load(Ordering::SeqCst), 0);
    }

    /// The jailed command's own descriptor table, as `find` reads it: one
    /// `(fd, readlink target)` pair per entry of `/proc/self/fd`.
    fn descriptors_seen_by(run: &JailedRun) -> Vec<(u32, String)> {
        assert_eq!(run.exit_code, Some(0), "stdout={} stderr={}", run.stdout, run.stderr);
        eprintln!("jailed descriptors: {}", run.stdout.trim().replace('\n', "; "));
        run.stdout
            .lines()
            .map(|line| {
                let (fd, target) = line
                    .split_once(' ')
                    .unwrap_or_else(|| panic!("unexpected listing line: {line:?}"));
                (fd.parse().unwrap(), target.to_owned())
            })
            .collect()
    }

    /// List `/proc/self/fd` from inside `jail` with `find`, which resolves
    /// every link (`%l` is its `readlink`). `find` holds a few directory
    /// descriptors of its own while it walks.
    fn list_descriptors_in(jail: GovernedProcessJail) -> Vec<(u32, String)> {
        let run = run_in_jail(
            jail,
            "find",
            &["/proc/self/fd/", "-mindepth", "1", "-maxdepth", "1", "-printf", "%f %l\\n"],
        );
        descriptors_seen_by(&run)
    }

    /// Descriptors above 2 that this test process holds without
    /// close-on-exec, by `readlink` target (`pipe:[inode]`, `socket:[inode]`,
    /// a path). Under GitHub Actions the runner's own channel pipes are among
    /// them. The runner marks them close-on-exec before it execs the jail
    /// launcher, so the jailed command must hold none of them.
    pub(in crate::governed_process_jail) fn inherited_host_descriptors() -> BTreeSet<String> {
        let mut inherited = BTreeSet::new();
        for entry in fs::read_dir("/proc/self/fd").unwrap() {
            let entry = entry.unwrap();
            let Some(fd) = entry.file_name().to_str().and_then(|name| name.parse::<i32>().ok()) else {
                continue;
            };
            // SAFETY: `F_GETFD` only queries a descriptor number; one closed
            // meanwhile (this listing's own) fails with `EBADF`.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if fd <= 2 || flags < 0 || flags & libc::FD_CLOEXEC != 0 {
                continue;
            }
            if let Ok(target) = fs::read_link(entry.path()) {
                inherited.insert(target.to_string_lossy().into_owned());
            }
        }
        eprintln!("host descriptors without close-on-exec: {inherited:?}");
        inherited
    }

    /// A pipe this test process holds with close-on-exec deliberately
    /// cleared on its write end, as a stray host descriptor would be, until
    /// dropped. Both ends are created close-on-exec (`pipe2(O_CLOEXEC)`);
    /// only the write end is then made inheritable. That end is inheritable
    /// process-wide for as long as the value lives: any child this test
    /// process spawns meanwhile, from any thread, would inherit it unless its
    /// launch marks it close-on-exec. So open it right before the run, drop
    /// it right after, and hold `JAIL_PROCESS_BUDGET` meanwhile. No test ever
    /// writes to it (or to any descriptor it did not create).
    pub(in crate::governed_process_jail) struct StrayHostPipe {
        _read: std::os::fd::OwnedFd,
        write: std::os::fd::OwnedFd,
        /// `pipe:[inode]`, as `readlink` shows it in any process.
        pub(in crate::governed_process_jail) target: String,
    }

    impl StrayHostPipe {
        pub(in crate::governed_process_jail) fn open() -> Self {
            use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

            let mut fds = [0; 2];
            // SAFETY: `pipe2` writes two fresh descriptors into the live array.
            assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            // SAFETY: both descriptors are fresh and owned by nothing else.
            let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
            // SAFETY: flag change on a descriptor this struct owns.
            assert_eq!(unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETFD, 0) }, 0);
            let target = fs::read_link(format!("/proc/self/fd/{}", write.as_raw_fd()))
                .unwrap()
                .to_string_lossy()
                .into_owned();
            assert!(target.starts_with("pipe:["), "{target}");
            Self {
                _read: read,
                write,
                target,
            }
        }

        /// Positive control: the host process does hold it across exec.
        pub(in crate::governed_process_jail) fn assert_inheritable(&self) {
            use std::os::fd::AsRawFd;

            // SAFETY: `F_GETFD` only queries a descriptor this struct owns.
            let flags = unsafe { libc::fcntl(self.write.as_raw_fd(), libc::F_GETFD) };
            assert_eq!(flags & libc::FD_CLOEXEC, 0, "the stray pipe must lack close-on-exec");
            assert!(inherited_host_descriptors().contains(&self.target));
        }
    }

    /// The jailed command holds stdio and nothing else. Stdio is `/dev/null`
    /// and two pipes, never a socket (the exec-status channel is a Unix
    /// socket pair). Above 2 the only descriptors allowed are directories
    /// the lister opened itself (a path), when `lister_directories` is set;
    /// none of them may be one this test process holds without close-on-exec
    /// (`inherited`, by target, so by pipe or socket inode). The status
    /// channel's `socket:[inode]` is never a path, so if the helper did not
    /// mark it close-on-exec before exec this fails too.
    pub(in crate::governed_process_jail) fn assert_only_stdio(
        entries: &[(u32, String)],
        inherited: &BTreeSet<String>,
        lister_directories: bool,
    ) {
        for fd in 0..=2 {
            let target = entries
                .iter()
                .find(|(seen, _)| *seen == fd)
                .map(|(_, target)| target)
                .unwrap_or_else(|| panic!("the listing must show fd {fd}: {entries:?}"));
            assert!(!target.starts_with("socket:"), "stdio fd {fd} is a socket: {entries:?}");
        }
        for (fd, target) in entries.iter().filter(|(fd, _)| *fd > 2) {
            assert!(
                !inherited.contains(target),
                "fd {fd} ({target}) is a host descriptor inherited into the jail: {entries:?}"
            );
            assert!(
                lister_directories && target.starts_with('/'),
                "fd {fd} ({target}) is not the lister's own; nothing above stdio may be \
                 inherited: {entries:?}"
            );
        }
    }

    /// Strict mode: the helper execs the command directly. It holds stdio
    /// alone: neither the status channel's write end nor any host
    /// descriptor.
    #[test]
    fn the_status_channel_is_absent_inside_the_strict_jail() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let jail = match GovernedProcessJail::strict_app(GovernedProcessJailLimits::default()) {
            Ok(jail) => jail,
            Err(error) => {
                skip(&format!("no Linux strict jail on this host: {error}"));
                return;
            },
        };
        let inherited = inherited_host_descriptors();
        assert_only_stdio(&list_descriptors_in(jail), &inherited, true);
    }

    /// Brokered mode: the helper execs the forwarder, which spawns the
    /// command. The forwarder's own sockets (its listener, its relays) are
    /// close-on-exec and the channel was closed when the helper exec'd, so
    /// the command inherits stdio alone: it reaches the broker through the
    /// proxy environment, not through any descriptor.
    #[test]
    fn the_status_channel_is_absent_from_the_brokered_child() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let broker = UnixBroker::start();
        let Some(jail) = brokered(&broker) else {
            return;
        };
        let inherited = inherited_host_descriptors();
        assert_only_stdio(&list_descriptors_in(jail), &inherited, true);
        assert!(broker.requests.lock().unwrap().is_empty());
    }

    /// A pipe the host process holds without close-on-exec does not reach
    /// the jailed command, in the strict jail (helper, then the command) or
    /// the brokered jail (helper, forwarder, then the command). Before
    /// `0.1.79` bubblewrap passed it through.
    #[test]
    fn a_stray_host_pipe_is_absent_inside_strict_and_brokered_jails() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let strict = match GovernedProcessJail::strict_app(GovernedProcessJailLimits::default()) {
            Ok(jail) => jail,
            Err(error) => {
                skip(&format!("no Linux strict jail on this host: {error}"));
                return;
            },
        };
        let broker = UnixBroker::start();
        let Some(brokered) = brokered(&broker) else {
            return;
        };
        let stray = StrayHostPipe::open();
        stray.assert_inheritable();
        let inherited = inherited_host_descriptors();
        for (mode, jail) in [("strict", strict), ("brokered", brokered)] {
            let entries = list_descriptors_in(jail);
            assert!(
                entries.iter().all(|(_, target)| *target != stray.target),
                "{mode}: the stray host pipe {} reached the jailed command: {entries:?}",
                stray.target
            );
            assert_only_stdio(&entries, &inherited, true);
        }
    }

    #[test]
    fn linux_refuses_a_loopback_tcp_broker() {
        let error = GovernedProcessJail::strict_app_with_brokered_egress(
            GovernedProcessJailLimits::default(),
            GovernedEgressBrokerEndpoint::LoopbackTcp {
                port: NonZeroU16::new(8080).unwrap(),
            },
        )
        .err()
        .expect("loopback broker is unreachable from an unshared netns");
        assert!(matches!(
            error.code,
            GovernedProcessJailErrorCode::UnsupportedEgressBroker
                | GovernedProcessJailErrorCode::LauncherUnavailable
        ));
    }
}
