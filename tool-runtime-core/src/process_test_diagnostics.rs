//! Debug-only observation for one synchronous synthetic invocation. Not a Cargo
//! feature, runtime option, callback, log or agent API. Normal builds omit this
//! module and every hook. Standard release compilation rejects the custom cfg.
use std::{
    cell::RefCell,
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
};

const MAX_CAPTURES: usize = 16;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    static CURRENT: RefCell<Option<Snapshot>> = const { RefCell::new(None) };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    Kill,
    Terminate,
    Abort,
    SegmentationFault,
    BusError,
    IllegalInstruction,
    Pipe,
    Interrupt,
    Hangup,
    Quit,
    Trap,
    CpuLimit,
    FileLimit,
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitCode {
    Exited,
    Killed,
    Dumped,
    Stopped,
    Trapped,
    Continued,
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalResult {
    Delivered,
    NoSuchProcess,
    Denied,
    OtherError,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitObservation {
    pub owned_child: bool,
    pub child_notification: bool,
    pub code: WaitCode,
    pub signal: Option<Signal>,
    pub normal_success: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitReason {
    Observed(OsReason),
    NoReason,
    Denied,
    NoSuchProcess,
    Unsupported,
    InvalidSize,
    OtherError,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OsReason {
    Signal(Signal),
    Jetsam,
    CodesigningInvalidSignature,
    CodesigningInvalidPage,
    CodesigningTaskAccessPort,
    CodesigningLaunchConstraint,
    CodesigningOther,
    Exec(ExecReason),
    DynamicLoader,
    PrivacyControl,
    Watchdog,
    Guard,
    Sandbox,
    Security,
    EndpointSecurity,
    InvalidNamespace,
    HangTracer,
    Test,
    LibXpc,
    Objc,
    SpringBoard,
    ReportCrash,
    CoreAnimation,
    Aggregated,
    RunningBoard,
    Skywalk,
    Settings,
    LibSystem,
    Foundation,
    Metal,
    WatchKit,
    Analytics,
    PacException,
    BluetoothChip,
    PortSpace,
    WebKit,
    BacklightServices,
    Media,
    Rosetta,
    LibIgnition,
    BootMount,
    RealityKit,
    Audio,
    WakeBoard,
    CoreRc,
    SelfRestrict,
    ArKit,
    Camera,
    BackBoard,
    PowerExceptions,
    SecInit,
    OtherNamespace,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecReason {
    BadMachO,
    SugidFailure,
    ActivateThreadState,
    StackAllocation,
    AppleStringInit,
    CopyoutStrings,
    CopyoutDynamicLinker,
    SecurityPolicy,
    TaskgatedOther,
    FairplayDecrypt,
    Decrypt,
    Upx,
    No32BitExec,
    WrongPlatform,
    MainFdAllocation,
    CopyoutRosetta,
    SetDyldInfo,
    MachineThread,
    BadSpawnAttributes,
    NoX86Exec,
    MapExecFailure,
    Other,
}

/// Closed categories only: no PIDs, raw exit codes, paths, argv, streams,
/// environment, credentials or arbitrary strings. Deliberately not Serialize.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub spawned_children: u32,
    pub spawn_group_owned: Option<bool>,
    pub wait_polls: u32,
    pub wait_interruptions: u32,
    pub wait_errors: u32,
    pub nonzero_waits: u32,
    pub last_wait: Option<WaitObservation>,
    pub os_exit_reason: Option<ExitReason>,
    pub cleanup_before_reap: bool,
    pub termination_cleanup: bool,
    pub group_term_attempts: u32,
    pub group_kill_attempts: u32,
    pub last_group_term: Option<SignalResult>,
    pub last_group_kill: Option<SignalResult>,
    pub reaped_normal_success: Option<bool>,
    pub reaped_signal: Option<Signal>,
    pub child_wait_error: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StartError {
    AlreadyActive,
    Capacity,
}

fn reserve(counter: &AtomicUsize) -> Result<(), StartError> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < MAX_CAPTURES).then_some(n + 1)
        })
        .map(|_| ())
        .map_err(|_| StartError::Capacity)
}

/// Must be created, observed and dropped on the invocation's blocking thread.
/// No capture is inherited by worker threads or unrelated invocations.
pub struct Capture(PhantomData<Rc<()>>);
impl Capture {
    pub fn start() -> Result<Self, StartError> {
        CURRENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_some() {
                return Err(StartError::AlreadyActive);
            }
            reserve(&ACTIVE)?;
            *slot = Some(Snapshot::default());
            Ok(Self(PhantomData))
        })
    }
    pub fn snapshot(&self) -> Snapshot {
        CURRENT.with(|slot| slot.borrow().expect("active diagnostic capture"))
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        CURRENT.with(|slot| {
            slot.borrow_mut().take();
        });
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}
fn update(f: impl FnOnce(&mut Snapshot)) {
    CURRENT.with(|slot| {
        if let Some(snapshot) = slot.borrow_mut().as_mut() {
            f(snapshot);
        }
    });
}

#[cfg(unix)]
fn signal(value: i32) -> Signal {
    match value {
        libc::SIGKILL => Signal::Kill,
        libc::SIGTERM => Signal::Terminate,
        libc::SIGABRT => Signal::Abort,
        libc::SIGSEGV => Signal::SegmentationFault,
        libc::SIGBUS => Signal::BusError,
        libc::SIGILL => Signal::IllegalInstruction,
        libc::SIGPIPE => Signal::Pipe,
        libc::SIGINT => Signal::Interrupt,
        libc::SIGHUP => Signal::Hangup,
        libc::SIGQUIT => Signal::Quit,
        libc::SIGTRAP => Signal::Trap,
        libc::SIGXCPU => Signal::CpuLimit,
        libc::SIGXFSZ => Signal::FileLimit,
        _ => Signal::Other,
    }
}
pub(crate) fn spawned(pid: u32) {
    update(|s| {
        s.spawned_children = s.spawned_children.saturating_add(1);
        #[cfg(unix)]
        {
            // SAFETY: read-only query of the newly spawned, unreaped owned child.
            let group = unsafe { libc::getpgid(pid as libc::pid_t) };
            s.spawn_group_owned = (group > 0).then_some(group as u32 == pid);
        }
        #[cfg(not(unix))]
        let _ = pid;
    });
}
#[cfg(unix)]
pub(crate) fn wait_observation(pid: libc::id_t, info: &libc::siginfo_t) {
    update(|s| {
        s.wait_polls = s.wait_polls.saturating_add(1);
        // SAFETY: caller supplies an initialized siginfo from successful waitid.
        let observed_pid = unsafe { info.si_pid() };
        if observed_pid == 0 {
            return;
        }
        let code = match info.si_code {
            libc::CLD_EXITED => WaitCode::Exited,
            libc::CLD_KILLED => WaitCode::Killed,
            libc::CLD_DUMPED => WaitCode::Dumped,
            libc::CLD_STOPPED => WaitCode::Stopped,
            libc::CLD_TRAPPED => WaitCode::Trapped,
            libc::CLD_CONTINUED => WaitCode::Continued,
            _ => WaitCode::Other,
        };
        let status = unsafe { info.si_status() };
        s.nonzero_waits = s.nonzero_waits.saturating_add(1);
        let observation = WaitObservation {
            owned_child: observed_pid as libc::id_t == pid,
            child_notification: info.si_signo == libc::SIGCHLD,
            code,
            signal: matches!(
                code,
                WaitCode::Killed | WaitCode::Dumped | WaitCode::Stopped | WaitCode::Trapped
            )
            .then(|| signal(status)),
            normal_success: (code == WaitCode::Exited).then_some(status == 0),
        };
        s.last_wait = Some(observation);
        record_exit_reason(s, pid, observation, query_exit_reason);
    });
}

// Called only inside an active capture, after successful WNOWAIT observation.
// The owned unreaped child pins its identity. Never query normal exits, other
// processes or repeated observations; the snapshot stores no PID or raw code.
#[cfg(unix)]
fn record_exit_reason(
    snapshot: &mut Snapshot,
    pid: libc::id_t,
    observation: WaitObservation,
    query: impl FnOnce(libc::pid_t) -> ExitReason,
) {
    if snapshot.os_exit_reason.is_some()
        || !observation.owned_child
        || !observation.child_notification
        || !matches!(observation.code, WaitCode::Killed | WaitCode::Dumped)
    {
        return;
    }
    if let Ok(pid) = libc::pid_t::try_from(pid) {
        if pid > 0 {
            snapshot.os_exit_reason = Some(query(pid));
        }
    }
}
#[cfg(all(unix, not(target_os = "macos")))]
fn query_exit_reason(_: libc::pid_t) -> ExitReason {
    ExitReason::Unsupported
}
#[cfg(target_os = "macos")]
fn query_exit_reason(pid: libc::pid_t) -> ExitReason {
    macos_exit_reason::query(pid)
}

#[cfg(target_os = "macos")]
mod macos_exit_reason {
    use super::{signal, ExecReason, ExitReason, OsReason, Signal};

    // XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea:
    // bsd/sys/proc_info_private.h (flavor), proc_info.h (packed ABI), reason.h
    // (namespace/code), bsd/kern/proc_info.c (parent-only zombie lookup).
    // Private flavor: diagnostics only. No dependency on it in normal builds.
    const FLAVOR: libc::c_int = 25; // PROC_PIDEXITREASONBASICINFO, never full INFO.
    const SIZE: usize = 24;

    pub(super) fn query(pid: libc::pid_t) -> ExitReason {
        // Packed ABI: u32 namespace, u64 code, u64 flags, u32 payload size.
        // A byte buffer avoids unaligned Rust field references. Do not request
        // or follow a payload pointer; flags and payload length are discarded.
        let mut bytes = [0u8; SIZE];
        // SAFETY: caller has just observed this exact owned child with WNOWAIT
        // and has not reaped it. Kernel writes at most the supplied 24 bytes.
        let count =
            unsafe { libc::proc_pidinfo(pid, FLAVOR, 0, bytes.as_mut_ptr().cast(), SIZE as i32) };
        let errno = if count <= 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        decode(count, errno, &bytes)
    }

    fn decode(count: i32, errno: Option<i32>, bytes: &[u8; SIZE]) -> ExitReason {
        if count <= 0 {
            return match errno {
                Some(libc::ENOENT) => ExitReason::NoReason,
                Some(libc::EACCES | libc::EPERM) => ExitReason::Denied,
                Some(libc::ESRCH) => ExitReason::NoSuchProcess,
                Some(libc::EINVAL | libc::ENOTSUP | libc::ENOSYS) => ExitReason::Unsupported,
                _ => ExitReason::OtherError,
            };
        }
        if count != SIZE as i32 {
            return ExitReason::InvalidSize;
        }
        let namespace = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        let code = u64::from_ne_bytes(bytes[4..12].try_into().unwrap());
        let reason = match namespace {
            1 => OsReason::Jetsam,
            2 => OsReason::Signal(i32::try_from(code).map(signal).unwrap_or(Signal::Other)),
            3 => match code {
                1 => OsReason::CodesigningInvalidSignature,
                2 => OsReason::CodesigningInvalidPage,
                3 => OsReason::CodesigningTaskAccessPort,
                4 => OsReason::CodesigningLaunchConstraint,
                _ => OsReason::CodesigningOther,
            },
            6 => OsReason::DynamicLoader,
            9 => OsReason::Exec(match code {
                1 => ExecReason::BadMachO,
                2 => ExecReason::SugidFailure,
                3 => ExecReason::ActivateThreadState,
                4 => ExecReason::StackAllocation,
                5 => ExecReason::AppleStringInit,
                6 => ExecReason::CopyoutStrings,
                7 => ExecReason::CopyoutDynamicLinker,
                8 => ExecReason::SecurityPolicy,
                9 => ExecReason::TaskgatedOther,
                10 => ExecReason::FairplayDecrypt,
                11 => ExecReason::Decrypt,
                12 => ExecReason::Upx,
                13 => ExecReason::No32BitExec,
                14 => ExecReason::WrongPlatform,
                15 => ExecReason::MainFdAllocation,
                16 => ExecReason::CopyoutRosetta,
                17 => ExecReason::SetDyldInfo,
                18 => ExecReason::MachineThread,
                19 => ExecReason::BadSpawnAttributes,
                20 => ExecReason::NoX86Exec,
                21 => ExecReason::MapExecFailure,
                _ => ExecReason::Other,
            }),
            11 => OsReason::PrivacyControl,
            20 => OsReason::Watchdog,
            23 => OsReason::Guard,
            25 => OsReason::Sandbox,
            26 => OsReason::Security,
            27 => OsReason::EndpointSecurity,
            0 => OsReason::InvalidNamespace,
            4 => OsReason::HangTracer,
            5 => OsReason::Test,
            7 => OsReason::LibXpc,
            8 => OsReason::Objc,
            10 => OsReason::SpringBoard,
            12 => OsReason::ReportCrash,
            13 => OsReason::CoreAnimation,
            14 => OsReason::Aggregated,
            15 => OsReason::RunningBoard,
            16 => OsReason::Skywalk,
            17 => OsReason::Settings,
            18 => OsReason::LibSystem,
            19 => OsReason::Foundation,
            21 => OsReason::Metal,
            22 => OsReason::WatchKit,
            24 => OsReason::Analytics,
            28 => OsReason::PacException,
            29 => OsReason::BluetoothChip,
            30 => OsReason::PortSpace,
            31 => OsReason::WebKit,
            32 => OsReason::BacklightServices,
            33 => OsReason::Media,
            34 => OsReason::Rosetta,
            35 => OsReason::LibIgnition,
            36 => OsReason::BootMount,
            38 => OsReason::RealityKit,
            39 => OsReason::Audio,
            40 => OsReason::WakeBoard,
            41 => OsReason::CoreRc,
            42 => OsReason::SelfRestrict,
            43 => OsReason::ArKit,
            44 => OsReason::Camera,
            45 => OsReason::BackBoard,
            46 => OsReason::PowerExceptions,
            47 => OsReason::SecInit,
            _ => OsReason::OtherNamespace,
        };
        ExitReason::Observed(reason)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn fixture(namespace: u32, code: u64) -> [u8; SIZE] {
            let mut bytes = [0xff; SIZE]; // flags/payload size must be ignored.
            bytes[..4].copy_from_slice(&namespace.to_ne_bytes());
            bytes[4..12].copy_from_slice(&code.to_ne_bytes());
            bytes
        }
        #[test]
        fn packed_bytes_are_classified_without_retaining_raw_codes_or_payloads() {
            for (namespace, code, reason) in [
                (2, libc::SIGKILL as u64, OsReason::Signal(Signal::Kill)),
                (
                    2,
                    (1u64 << 32) + libc::SIGKILL as u64,
                    OsReason::Signal(Signal::Other),
                ),
                (3, 1, OsReason::CodesigningInvalidSignature),
                (3, 2, OsReason::CodesigningInvalidPage),
                (3, 3, OsReason::CodesigningTaskAccessPort),
                (3, 4, OsReason::CodesigningLaunchConstraint),
                (3, u64::MAX, OsReason::CodesigningOther),
                (9, 8, OsReason::Exec(ExecReason::SecurityPolicy)),
                (9, 21, OsReason::Exec(ExecReason::MapExecFailure)),
                (9, u64::MAX, OsReason::Exec(ExecReason::Other)),
                (u32::MAX, u64::MAX, OsReason::OtherNamespace),
            ] {
                assert_eq!(
                    decode(SIZE as i32, None, &fixture(namespace, code)),
                    ExitReason::Observed(reason)
                );
            }
        }
        #[test]
        fn every_defined_namespace_is_named_and_unknown_values_stay_closed() {
            // Complete namespace set from the pinned Apple reason.h, including
            // INVALID and the ASSERTIOND/RUNNINGBOARD alias. 37 is not defined.
            for (namespace, expected) in [
                (0, OsReason::InvalidNamespace),
                (1, OsReason::Jetsam),
                (2, OsReason::Signal(Signal::Other)),
                (3, OsReason::CodesigningOther),
                (4, OsReason::HangTracer),
                (5, OsReason::Test),
                (6, OsReason::DynamicLoader),
                (7, OsReason::LibXpc),
                (8, OsReason::Objc),
                (9, OsReason::Exec(ExecReason::Other)),
                (10, OsReason::SpringBoard),
                (11, OsReason::PrivacyControl),
                (12, OsReason::ReportCrash),
                (13, OsReason::CoreAnimation),
                (14, OsReason::Aggregated),
                (15, OsReason::RunningBoard),
                (16, OsReason::Skywalk),
                (17, OsReason::Settings),
                (18, OsReason::LibSystem),
                (19, OsReason::Foundation),
                (20, OsReason::Watchdog),
                (21, OsReason::Metal),
                (22, OsReason::WatchKit),
                (23, OsReason::Guard),
                (24, OsReason::Analytics),
                (25, OsReason::Sandbox),
                (26, OsReason::Security),
                (27, OsReason::EndpointSecurity),
                (28, OsReason::PacException),
                (29, OsReason::BluetoothChip),
                (30, OsReason::PortSpace),
                (31, OsReason::WebKit),
                (32, OsReason::BacklightServices),
                (33, OsReason::Media),
                (34, OsReason::Rosetta),
                (35, OsReason::LibIgnition),
                (36, OsReason::BootMount),
                (38, OsReason::RealityKit),
                (39, OsReason::Audio),
                (40, OsReason::WakeBoard),
                (41, OsReason::CoreRc),
                (42, OsReason::SelfRestrict),
                (43, OsReason::ArKit),
                (44, OsReason::Camera),
                (45, OsReason::BackBoard),
                (46, OsReason::PowerExceptions),
                (47, OsReason::SecInit),
            ] {
                assert_eq!(
                    decode(SIZE as i32, None, &fixture(namespace, u64::MAX)),
                    ExitReason::Observed(expected)
                );
            }
            for namespace in [37, 48, u32::MAX] {
                assert_eq!(
                    decode(SIZE as i32, None, &fixture(namespace, u64::MAX)),
                    ExitReason::Observed(OsReason::OtherNamespace)
                );
            }
        }
        #[test]
        fn unavailable_and_malformed_results_never_decode_stale_bytes() {
            let bytes = fixture(2, libc::SIGKILL as u64);
            for (errno, expected) in [
                (libc::ENOENT, ExitReason::NoReason),
                (libc::EACCES, ExitReason::Denied),
                (libc::EPERM, ExitReason::Denied),
                (libc::ESRCH, ExitReason::NoSuchProcess),
                (libc::EINVAL, ExitReason::Unsupported),
                (libc::ENOTSUP, ExitReason::Unsupported),
                (libc::ENOSYS, ExitReason::Unsupported),
                (libc::EIO, ExitReason::OtherError),
                (libc::EINTR, ExitReason::OtherError), // no retry
            ] {
                for count in [0, -1] {
                    assert_eq!(decode(count, Some(errno), &bytes), expected);
                }
            }
            for count in [1, 12, 23, 25, i32::MAX] {
                assert_eq!(decode(count, None, &bytes), ExitReason::InvalidSize);
            }
            assert_eq!(decode(0, None, &bytes), ExitReason::OtherError);
        }
    }
}
pub(crate) fn wait_error(interrupted: bool) {
    update(|s| {
        if interrupted {
            s.wait_interruptions = s.wait_interruptions.saturating_add(1);
        } else {
            s.wait_errors = s.wait_errors.saturating_add(1);
        }
    });
}
pub(crate) fn cleanup(before_reap: bool) {
    update(|s| {
        if before_reap {
            s.cleanup_before_reap = true;
        } else {
            s.termination_cleanup = true;
        }
    });
}
#[cfg(unix)]
pub(crate) fn group_signal(kill: bool, result: libc::c_int) {
    // Capture errno before borrowing the observer or doing any other work.
    let outcome = if result == 0 {
        SignalResult::Delivered
    } else {
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => SignalResult::NoSuchProcess,
            Some(libc::EPERM) => SignalResult::Denied,
            _ => SignalResult::OtherError,
        }
    };
    update(|s| {
        if kill {
            s.group_kill_attempts = s.group_kill_attempts.saturating_add(1);
            s.last_group_kill = Some(outcome);
        } else {
            s.group_term_attempts = s.group_term_attempts.saturating_add(1);
            s.last_group_term = Some(outcome);
        }
    });
}
pub(crate) fn reaped(result: &std::io::Result<std::process::ExitStatus>) {
    update(|s| match result {
        Ok(status) => {
            s.reaped_normal_success = status.code().map(|code| code == 0);
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                s.reaped_signal = status.signal().map(signal);
            }
        }
        Err(_) => s.child_wait_error = true,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    static_assertions::assert_not_impl_any!(Capture: Send, Sync, Clone);
    #[cfg(unix)]
    #[test]
    fn exit_reason_queries_require_an_owned_signal_exit_and_are_bounded() {
        let observed = WaitObservation {
            owned_child: true,
            child_notification: true,
            code: WaitCode::Killed,
            signal: Some(Signal::Kill),
            normal_success: None,
        };
        let mut snapshot = Snapshot::default();
        for rejected in [
            WaitObservation {
                owned_child: false,
                ..observed
            },
            WaitObservation {
                child_notification: false,
                ..observed
            },
            WaitObservation {
                code: WaitCode::Exited,
                ..observed
            },
            WaitObservation {
                code: WaitCode::Stopped,
                ..observed
            },
            WaitObservation {
                code: WaitCode::Continued,
                ..observed
            },
        ] {
            record_exit_reason(&mut snapshot, 1, rejected, |_| {
                panic!("query outside scope")
            });
        }
        record_exit_reason(&mut snapshot, 0, observed, |_| panic!("zero PID"));
        record_exit_reason(&mut snapshot, u32::MAX, observed, |_| {
            panic!("unrepresentable PID")
        });
        assert_eq!(snapshot.os_exit_reason, None);
        record_exit_reason(&mut snapshot, 1, observed, |_| ExitReason::Denied);
        record_exit_reason(&mut snapshot, 1, observed, |_| {
            panic!("query repeated after denial")
        });
        assert_eq!(snapshot.os_exit_reason, Some(ExitReason::Denied));
        let mut dumped = Snapshot::default();
        record_exit_reason(
            &mut dumped,
            1,
            WaitObservation {
                code: WaitCode::Dumped,
                ..observed
            },
            |_| ExitReason::NoReason,
        );
        assert_eq!(dumped.os_exit_reason, Some(ExitReason::NoReason));
    }
    #[test]
    fn thread_scope_refuses_nesting_and_does_not_keep_unregistered_work() {
        update(|_| panic!("uncaptured work must not run an observer query"));
        update(|s| s.spawned_children = 99);
        let first = Capture::start().unwrap();
        assert_eq!(first.snapshot(), Snapshot::default());
        assert!(matches!(Capture::start(), Err(StartError::AlreadyActive)));
        std::thread::spawn(|| {
            update(|s| s.spawned_children = 99);
            let second = Capture::start().unwrap();
            update(|s| s.spawned_children = 2);
            assert_eq!(second.snapshot().spawned_children, 2);
        })
        .join()
        .unwrap();
        assert_eq!(first.snapshot(), Snapshot::default());
        drop(first);
        assert_eq!(Capture::start().unwrap().snapshot(), Snapshot::default());
    }
    #[test]
    fn global_budget_is_bounded() {
        let counter = AtomicUsize::new(0);
        for _ in 0..MAX_CAPTURES {
            reserve(&counter).unwrap();
        }
        assert_eq!(reserve(&counter), Err(StartError::Capacity));
        assert_eq!(counter.load(Ordering::Acquire), MAX_CAPTURES);
        counter.fetch_sub(1, Ordering::AcqRel);
        reserve(&counter).unwrap();
    }
}
