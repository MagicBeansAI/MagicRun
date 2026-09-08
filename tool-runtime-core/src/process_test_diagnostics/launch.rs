//! macOS-only synthetic launch observation. No descriptor, child-side logging,
//! allocation, TLS access, lock, callback to a consumer or credential data.
use super::{update, PreExecStage};
use std::{
    ptr::NonNull,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
};

const NOT_ENTERED: u8 = 0;
const ENTERED: u8 = 1;
const COMPLETED: u8 = 2;
const LENGTH: usize = std::mem::size_of::<AtomicU8>();

pub(crate) struct Probe(NonNull<AtomicU8>);

// SAFETY: the anonymous shared mapping has one initialized atomic byte. All
// access is atomic; the last parent Arc owns munmap. Child hooks only borrow it,
// never clone/drop an Arc, and exec/_exit discard the child's mapping. Command
// retains its Arc throughout spawn, including the pre-exec/error-pipe handshake.
unsafe impl Send for Probe {}
unsafe impl Sync for Probe {}

impl Probe {
    fn allocate() -> Option<Self> {
        // SAFETY: parent-only allocation of an anonymous mapping, no file backing
        // or caller-selected address. The kernel rounds LENGTH to a page.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LENGTH,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_SHARED,
                -1,
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return None;
        }
        let Some(address) = NonNull::new(address.cast::<AtomicU8>()) else {
            // SAFETY: even an unusable null-address mapping must be released.
            unsafe { libc::munmap(address, LENGTH) };
            return None;
        };
        // SAFETY: fresh writable page-aligned mapping, initialized before any
        // fork or shared access. AtomicU8 is lock-free on supported macOS targets.
        unsafe { address.as_ptr().write(AtomicU8::new(NOT_ENTERED)) };
        Some(Self(address))
    }

    // These child-side methods do only a lock-free atomic store. In particular,
    // do not route them through the parent observer's TLS/RefCell update helper.
    pub(crate) fn entered(&self) {
        // SAFETY: the Arc-retained initialized mapping remains valid in child.
        unsafe { self.0.as_ref() }.store(ENTERED, Ordering::SeqCst);
    }

    pub(crate) fn completed(&self) {
        // SAFETY: same lifetime and atomic-only access as entered().
        unsafe { self.0.as_ref() }.store(COMPLETED, Ordering::SeqCst);
    }

    fn stage(&self) -> PreExecStage {
        // SAFETY: parent retains the mapping through this read after spawn.
        decode(unsafe { self.0.as_ref() }.load(Ordering::SeqCst))
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        // SAFETY: unique final parent owner; no other reference can access this
        // mapping. No Rust destructor runs in the post-fork child.
        unsafe { libc::munmap(self.0.as_ptr().cast(), LENGTH) };
    }
}

fn decode(value: u8) -> PreExecStage {
    match value {
        NOT_ENTERED => PreExecStage::CallbackNotEntered,
        ENTERED => PreExecStage::CallbackEntered,
        COMPLETED => PreExecStage::CallbackCompleted,
        _ => PreExecStage::Invalid,
    }
}

fn prepare_with(allocate: impl FnOnce() -> Option<Probe>) -> Option<Arc<Probe>> {
    let mut probe = None;
    update(|snapshot| {
        // Allocation happens only on the captured parent thread. Failure is an
        // observation, never a spawn error or a reason to retry an operation.
        snapshot.pre_exec_stage = Some(PreExecStage::Unavailable);
        probe = allocate().map(Arc::new);
    });
    probe
}

pub(crate) fn prepare() -> Option<Arc<Probe>> {
    prepare_with(Probe::allocate)
}

pub(crate) fn record(probe: Option<&Probe>) {
    if let Some(probe) = probe {
        update(|snapshot| snapshot.pre_exec_stage = Some(probe.stage()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_test_diagnostics::Capture;
    use std::{
        os::unix::process::{CommandExt, ExitStatusExt},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    #[test]
    fn uncaptured_work_never_allocates() {
        assert!(prepare_with(|| panic!("uncaptured allocation")).is_none());
    }

    #[test]
    fn unavailable_and_unknown_bytes_remain_closed_observations() {
        let capture = Capture::start().unwrap();
        assert!(prepare_with(|| None).is_none());
        record(None);
        assert_eq!(
            capture.snapshot().pre_exec_stage,
            Some(PreExecStage::Unavailable)
        );
        for value in 0..=u8::MAX {
            assert_eq!(
                decode(value),
                match value {
                    0 => PreExecStage::CallbackNotEntered,
                    1 => PreExecStage::CallbackEntered,
                    2 => PreExecStage::CallbackCompleted,
                    _ => PreExecStage::Invalid,
                }
            );
        }
    }

    #[test]
    fn shared_child_stages_distinguish_boundaries_without_proving_exec() {
        let root = tempfile::tempdir().unwrap();
        for case in 0..6 {
            let capture = Capture::start().unwrap();
            let probe = prepare().expect("synthetic shared mapping");
            let child_probe = Arc::clone(&probe); // parent-only clone
            let mut command = if case == 4 {
                Command::new(root.path().join("absent-recipient"))
            } else {
                Command::new("/usr/bin/true")
            };
            command
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0);
            // SAFETY: only atomic stores and async-signal-safe own-child kill /
            // _exit. No allocation, assertion, destructor or parent TLS in hook.
            unsafe {
                command.pre_exec(move || {
                    if case == 0 {
                        die();
                    }
                    child_probe.entered();
                    if case == 1 {
                        die();
                    }
                    if case == 5 {
                        return Err(std::io::Error::from_raw_os_error(libc::EPERM));
                    }
                    child_probe.completed();
                    if case == 2 {
                        die();
                    }
                    Ok(())
                });
            }
            let spawned = command.spawn();
            record(Some(&probe));
            if case >= 4 {
                match spawned {
                    Err(error) => assert_eq!(
                        error.kind(),
                        if case == 4 {
                            std::io::ErrorKind::NotFound
                        } else {
                            std::io::ErrorKind::PermissionDenied
                        }
                    ),
                    Ok(mut child) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!("synthetic spawn should fail, case {case}");
                    }
                }
            } else {
                let mut child = spawned.unwrap();
                let deadline = Instant::now() + Duration::from_secs(2);
                let status = loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        break status;
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!("synthetic child exceeded deadline, case {case}");
                    }
                    std::thread::sleep(Duration::from_millis(5));
                };
                assert_eq!(
                    status.signal(),
                    if case < 3 { Some(libc::SIGKILL) } else { None }
                );
                assert_eq!(status.success(), case == 3);
            }
            assert_eq!(
                capture.snapshot().pre_exec_stage,
                Some(match case {
                    0 => PreExecStage::CallbackNotEntered,
                    1 | 5 => PreExecStage::CallbackEntered,
                    _ => PreExecStage::CallbackCompleted,
                }),
                "synthetic case {case}"
            );
            // Command's Arc keeps the mapping valid after the observer's owner
            // is dropped; dropping Command releases the last parent reference.
            let retained = Arc::downgrade(&probe);
            drop(probe);
            assert!(retained.upgrade().is_some());
            drop(command);
            assert!(retained.upgrade().is_none());
        }
    }

    unsafe fn die() -> ! {
        libc::kill(libc::getpid(), libc::SIGKILL);
        libc::_exit(127)
    }
}
