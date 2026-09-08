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
        s.last_wait = Some(WaitObservation {
            owned_child: observed_pid as libc::id_t == pid,
            child_notification: info.si_signo == libc::SIGCHLD,
            code,
            signal: matches!(
                code,
                WaitCode::Killed | WaitCode::Dumped | WaitCode::Stopped | WaitCode::Trapped
            )
            .then(|| signal(status)),
            normal_success: (code == WaitCode::Exited).then_some(status == 0),
        });
    });
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
    #[test]
    fn thread_scope_refuses_nesting_and_does_not_keep_unregistered_work() {
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
