//! Close-on-exec for every descriptor a launch did not deliberately pass.
//!
//! A process that execs a jail launcher (bubblewrap, `sandbox-exec`), a
//! governed command or, in the jail, the command, passes on every descriptor
//! it holds without close-on-exec. The host process can hold such descriptors
//! for reasons that have nothing to do with the launch (a parent's pipes, a
//! library that opened a file without `O_CLOEXEC`), and the child could read
//! or write them. [`InheritedDescriptors::mark_cloexec`] marks every
//! descriptor above stdio close-on-exec, then clears the flag again on exactly
//! the ones the caller passes on. It only sets flags: descriptors the forked
//! child still uses before exec (the standard library's exec-error pipe, the
//! working-directory handle) stay open until exec.
//!
//! [`InheritedDescriptors::prepare`] runs in the parent, before `fork`, and
//! reads the scan bound. `mark_cloexec` runs in the child between `fork` and
//! `exec` and is async-signal-safe: raw system calls on a fixed stack buffer,
//! no allocation, no locks. It tries, in order:
//!
//! 1. Linux: `close_range(3, ~0U, CLOSE_RANGE_CLOEXEC)` (kernel 5.11+). Any
//!    error return (`ENOSYS`, `EINVAL` before 5.11, `EPERM` from a seccomp
//!    filter that predates the call) moves on. A seccomp filter that kills
//!    the process on `close_range` instead of returning an error makes the
//!    launch fail with `SIGSYS`; there is no fallback from that.
//! 2. Linux: the entries of `/proc/self/fd`, read with `getdents64` into a
//!    stack buffer, each marked with `fcntl(F_SETFD)`. Exact, whatever the
//!    descriptor limit. Needs a mounted `/proc`.
//! 3. macOS: `proc_pidinfo(PROC_PIDLISTFDS)` into a stack buffer of
//!    [`MACOS_LISTED_DESCRIPTORS`] entries (8 KiB), each marked. Exact; a
//!    full buffer or an error moves on.
//! 4. Every descriptor number from 3 up to the scan bound. On macOS the
//!    bound is `kern.maxfilesperproc`: no descriptor can be opened at or above
//!    it (`F_DUPFD` fails with `EINVAL`), whatever the soft `RLIMIT_NOFILE`
//!    says (the launching shell's limit, e.g. 1048576 or unlimited;
//!    launchd's default is 256), so this is exact too, even after the soft
//!    limit was lowered below an open descriptor, unless root lowered
//!    `kern.maxfilesperproc` after a higher descriptor was opened; that only
//!    matters when the exact listing also fails. Elsewhere, and if the sysctl cannot be read, the
//!    bound is the soft `RLIMIT_NOFILE`, capped at
//!    [`DESCRIPTOR_SCAN_CEILING`]: exact unless the limit was lowered after a
//!    higher descriptor was opened, or exceeds the cap. On Linux it runs only
//!    when both calls above are unavailable.

use std::{io, os::fd::RawFd};

/// Highest descriptor number (exclusive) the fallback scan visits when it is
/// bounded by `RLIMIT_NOFILE`: 2^20. Linux `fs.nr_open` defaults to the same
/// value, so no descriptor can exceed it unless an administrator raised
/// `fs.nr_open` and the process its limit.
pub(crate) const DESCRIPTOR_SCAN_CEILING: RawFd = 1 << 20;

/// Entries of the macOS descriptor listing buffer: 8 bytes each, 8 KiB in
/// all, on the stack of the forked child, which may be a small thread stack
/// (the spawning thread's). A process holding at least this many
/// descriptors falls back to the scan bounded by `kern.maxfilesperproc`
/// (about 18 ms at 184320); a running Magician holds about 137.
#[cfg(target_os = "macos")]
pub(crate) const MACOS_LISTED_DESCRIPTORS: usize = 1024;

/// Serializes the tests that change this process's `RLIMIT_NOFILE`.
#[cfg(test)]
pub(crate) static FILE_LIMIT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The scan bound, read in the parent before `fork`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InheritedDescriptors {
    scan_end: RawFd,
}

impl InheritedDescriptors {
    /// Parent side: read the scan bound (see the module documentation).
    pub(crate) fn prepare() -> Self {
        #[cfg(target_os = "macos")]
        if let Some(maximum) = macos_max_files_per_process() {
            return Self { scan_end: maximum };
        }
        Self {
            scan_end: soft_limit_scan_end(),
        }
    }

    /// Child side: mark every descriptor from 3 up close-on-exec, then clear
    /// close-on-exec on each descriptor in `keep`, which the caller
    /// deliberately passes across exec. Async-signal-safe. An error means a
    /// descriptor in `keep` could not be kept; the caller must not exec then.
    pub(crate) fn mark_cloexec(self, keep: &[RawFd]) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        let marked = mark_by_close_range() || mark_by_proc_listing();
        #[cfg(target_os = "macos")]
        let marked = mark_by_pid_listing();
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let marked = false;
        if !marked {
            mark_by_scan(self.scan_end);
        }
        keep_across_exec(keep)
    }

    /// The scan bound this preparation read.
    #[cfg(test)]
    pub(crate) fn scan_end(self) -> RawFd {
        self.scan_end
    }
}

/// The soft `RLIMIT_NOFILE`, capped at [`DESCRIPTOR_SCAN_CEILING`].
fn soft_limit_scan_end() -> RawFd {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` writes only the live `limit`.
    let soft = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
        limit.rlim_cur
    } else {
        libc::RLIM_INFINITY
    };
    if soft == libc::RLIM_INFINITY || soft > DESCRIPTOR_SCAN_CEILING as libc::rlim_t {
        DESCRIPTOR_SCAN_CEILING
    } else {
        soft as RawFd
    }
}

/// `kern.maxfilesperproc`, read with `sysctl({CTL_KERN,
/// KERN_MAXFILESPERPROC})`; `None` if unreadable or not positive.
#[cfg(target_os = "macos")]
fn macos_max_files_per_process() -> Option<RawFd> {
    let mut name = [libc::CTL_KERN, libc::KERN_MAXFILESPERPROC];
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>();
    // SAFETY: `sysctl` reads the two-entry name and writes at most `length`
    // bytes into the live `value`.
    let status = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            name.len() as libc::c_uint,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    (status == 0 && length == std::mem::size_of::<libc::c_int>() && value > 0).then_some(value)
}

/// Clear close-on-exec on each descriptor in `keep`.
fn keep_across_exec(keep: &[RawFd]) -> io::Result<()> {
    for &fd in keep {
        // SAFETY: `fcntl(F_SETFD)` only changes a descriptor flag; a closed
        // number fails with `EBADF`, reported to the caller.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// `close_range(3, ~0U, CLOSE_RANGE_CLOEXEC)`; `false` if the kernel (or a
/// seccomp filter) refuses it with an error.
#[cfg(target_os = "linux")]
pub(crate) fn mark_by_close_range() -> bool {
    // SAFETY: `close_range` with `CLOSE_RANGE_CLOEXEC` closes nothing; it
    // only sets close-on-exec on the open descriptors in the range.
    unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3 as libc::c_uint,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        ) == 0
    }
}

/// Mark each entry of `/proc/self/fd` from 3 up; `false` if `/proc` cannot
/// be opened or read to the end, or a record is malformed.
#[cfg(target_os = "linux")]
pub(crate) fn mark_by_proc_listing() -> bool {
    // SAFETY: a NUL-terminated literal path; the descriptor is closed below.
    let directory = unsafe {
        libc::open(
            c"/proc/self/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if directory < 0 {
        return false;
    }
    // `linux_dirent64` records are 8-byte aligned; a `u64` array keeps the
    // buffer aligned for the header reads below.
    let mut buffer = [0_u64; 512];
    let complete = 'listing: loop {
        // SAFETY: `getdents64` writes at most the buffer's byte length into
        // the live buffer.
        let read = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                directory,
                buffer.as_mut_ptr(),
                std::mem::size_of_val(&buffer),
            )
        };
        if read == 0 {
            break true;
        }
        if read < 0 {
            break false;
        }
        let read = read as usize;
        let bytes = buffer.as_ptr().cast::<u8>();
        let mut offset = 0_usize;
        while offset < read {
            // `linux_dirent64`: d_ino (8), d_off (8), d_reclen (2),
            // d_type (1), then the NUL-terminated name.
            if offset + 20 > read {
                break 'listing false;
            }
            // SAFETY: the header lies inside the bytes the kernel wrote; the
            // reclen field is 2-byte aligned.
            let record_length = unsafe { bytes.add(offset + 16).cast::<u16>().read() } as usize;
            // A record that cannot hold its header and a name, or overruns
            // what was read, makes the listing incomplete: the scan follows.
            if record_length < 20 || offset + record_length > read {
                break 'listing false;
            }
            // SAFETY: the name starts inside the record and is NUL-terminated
            // within it.
            let fd = unsafe { parse_descriptor(bytes.add(offset + 19)) };
            if let Some(fd) = fd.filter(|fd| *fd >= 3 && *fd != directory) {
                // SAFETY: flag change only; a descriptor closed meanwhile
                // fails with `EBADF`, which is ignored.
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            }
            offset += record_length;
        }
    };
    // SAFETY: closes the directory descriptor opened above.
    unsafe { libc::close(directory) };
    complete
}

/// Parse a NUL-terminated decimal descriptor name (`.` and `..` are not).
///
/// # Safety
/// `name` must point to a NUL-terminated byte string.
#[cfg(target_os = "linux")]
unsafe fn parse_descriptor(name: *const u8) -> Option<RawFd> {
    let mut value: RawFd = 0;
    let mut digits = 0;
    loop {
        // SAFETY: the caller guarantees a NUL terminator ends the walk.
        let byte = unsafe { name.add(digits).read() };
        if byte == 0 {
            return (digits > 0).then_some(value);
        }
        if !byte.is_ascii_digit() || digits >= 10 {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(RawFd::from(byte - b'0'))?;
        digits += 1;
    }
}

/// Mark each descriptor `proc_pidinfo(PROC_PIDLISTFDS)` lists from 3 up;
/// `false` if the call fails or the buffer may have been too small.
#[cfg(target_os = "macos")]
pub(crate) fn mark_by_pid_listing() -> bool {
    // Uninitialized: no zeroed temporary doubles the stack use in debug
    // builds. Only the entries the kernel writes are read.
    let mut buffer =
        std::mem::MaybeUninit::<[libc::proc_fdinfo; MACOS_LISTED_DESCRIPTORS]>::uninit();
    let size = std::mem::size_of_val(&buffer) as libc::c_int;
    // SAFETY: `getpid` cannot fail; `proc_pidinfo` writes at most `size`
    // bytes into the live buffer.
    let filled = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDLISTFDS,
            0,
            buffer.as_mut_ptr().cast(),
            size,
        )
    };
    if filled <= 0 || filled >= size {
        return false;
    }
    let entries = filled as usize / std::mem::size_of::<libc::proc_fdinfo>();
    let first = buffer.as_ptr().cast::<libc::proc_fdinfo>();
    for index in 0..entries {
        // SAFETY: the kernel wrote `filled` bytes, so the first `entries`
        // records are initialized; `index` stays below that count.
        let entry = unsafe { first.add(index).read() };
        if entry.proc_fd >= 3 {
            // SAFETY: flag change only; a descriptor closed meanwhile fails
            // with `EBADF`, which is ignored.
            unsafe { libc::fcntl(entry.proc_fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
    }
    true
}

/// Mark every descriptor number in `3..end` close-on-exec.
pub(crate) fn mark_by_scan(end: RawFd) {
    for fd in 3..end {
        // SAFETY: flag change only; an unused number fails with `EBADF`,
        // which is ignored.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::process::CommandExt,
        },
        process::Command,
    };

    use super::*;

    /// The descriptor listing the exec'd program sees.
    #[cfg(target_os = "linux")]
    const LISTING: &str = "/proc/self/fd/";
    #[cfg(not(target_os = "linux"))]
    const LISTING: &str = "/dev/fd/";

    /// A fresh pipe, both ends close-on-exec from creation (macOS has no
    /// `pipe2`: the flag is set at once, before anything else runs here).
    fn cloexec_pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        #[cfg(target_os = "linux")]
        // SAFETY: `pipe2` writes two fresh descriptors into the live array.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        #[cfg(not(target_os = "linux"))]
        {
            // SAFETY: `pipe` writes two fresh descriptors into the live array.
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            for fd in fds {
                // SAFETY: flag change on a descriptor this test owns.
                assert_eq!(
                    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                    0
                );
            }
        }
        // SAFETY: both descriptors are fresh and owned by nothing else.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    /// A close-on-exec pipe whose write end sits at a number of at least
    /// `minimum`, so no descriptor the listed program opens itself can take
    /// that number.
    fn high_pipe_end(minimum: RawFd) -> (OwnedFd, OwnedFd) {
        let (read, write) = cloexec_pipe();
        // SAFETY: duplicates a live descriptor, close-on-exec, at >= minimum.
        let high = unsafe { libc::fcntl(write.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
        assert!(high >= minimum, "{}", io::Error::last_os_error());
        // SAFETY: `high` is fresh and owned by nothing else.
        (read, unsafe { OwnedFd::from_raw_fd(high) })
    }

    /// Fork; in the child only, make `stray` and `kept` inheritable (as a
    /// host descriptor without close-on-exec would be), optionally lower the
    /// soft `RLIMIT_NOFILE` to `lowered`, run `mark`, keep `kept`, and exec
    /// `/bin/sh -c 'ls <listing>'`. The descriptor numbers the program sees,
    /// or `None` if `mark` reported the method unavailable.
    fn listing_after(
        mark: impl Fn() -> bool + Send + Sync + 'static,
        stray: RawFd,
        kept: RawFd,
        lowered: Option<libc::rlim_t>,
    ) -> Option<Vec<RawFd>> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &format!("ls {LISTING}")]);
        // SAFETY: only `fcntl`, `getrlimit`/`setrlimit` and the
        // async-signal-safe marking run in the child, on its own state.
        unsafe {
            command.pre_exec(move || {
                for fd in [stray, kept] {
                    if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                if let Some(soft) = lowered {
                    let mut limit = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    limit.rlim_cur = soft;
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                if !mark() {
                    return Err(io::Error::from_raw_os_error(libc::ENOSYS));
                }
                keep_across_exec(&[kept])
            });
        }
        let output = match command.output() {
            Ok(output) => output,
            Err(error) if error.raw_os_error() == Some(libc::ENOSYS) => return None,
            Err(error) => panic!("{error}"),
        };
        assert!(output.status.success(), "{output:?}");
        let listing = String::from_utf8(output.stdout).unwrap();
        eprintln!(
            "descriptors after marking: {}",
            listing.split_whitespace().collect::<Vec<_>>().join(" ")
        );
        Some(
            listing
                .split_whitespace()
                .map(|name| name.parse().unwrap())
                .collect(),
        )
    }

    fn assert_marks(method: &str, mark: impl Fn() -> bool + Send + Sync + 'static) {
        let (_stray_read, stray) = high_pipe_end(200);
        let (_kept_read, kept) = high_pipe_end(240);
        let Some(seen) = listing_after(mark, stray.as_raw_fd(), kept.as_raw_fd(), None) else {
            crate::governed_process_jail::egress_tests::skip(&format!(
                "{method} is unavailable here"
            ));
            return;
        };
        assert!(
            !seen.contains(&stray.as_raw_fd()),
            "{method}: stray fd {} inherited: {seen:?}",
            stray.as_raw_fd()
        );
        assert!(
            seen.contains(&kept.as_raw_fd()),
            "{method}: kept fd {} missing: {seen:?}",
            kept.as_raw_fd()
        );
    }

    /// Positive control: without marking, the listing does show the stray
    /// descriptor, so its absence below is the marking's doing.
    #[test]
    fn an_unmarked_stray_descriptor_is_inherited() {
        let (_stray_read, stray) = high_pipe_end(200);
        let (_kept_read, kept) = high_pipe_end(240);
        let seen = listing_after(|| true, stray.as_raw_fd(), kept.as_raw_fd(), None).unwrap();
        assert!(seen.contains(&stray.as_raw_fd()), "{seen:?}");
        assert!(seen.contains(&kept.as_raw_fd()), "{seen:?}");
    }

    /// The combined helper, as every launch runs it.
    #[test]
    fn marking_hides_a_stray_descriptor_and_keeps_the_passed_one() {
        let descriptors = InheritedDescriptors::prepare();
        assert_marks("the combined helper", move || {
            descriptors.mark_cloexec(&[]).is_ok()
        });
    }

    #[test]
    fn the_bounded_scan_marks_a_stray_descriptor() {
        let end = InheritedDescriptors::prepare().scan_end();
        assert_marks("the bounded scan", move || {
            mark_by_scan(end);
            true
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn close_range_marks_a_stray_descriptor() {
        assert_marks("close_range(CLOSE_RANGE_CLOEXEC)", mark_by_close_range);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_proc_listing_marks_a_stray_descriptor() {
        assert_marks("the /proc/self/fd listing", mark_by_proc_listing);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_pid_listing_marks_a_stray_descriptor() {
        assert_marks("proc_pidinfo(PROC_PIDLISTFDS)", mark_by_pid_listing);
    }

    /// macOS: a process holding more descriptors than the listing buffer
    /// fits gets no listing (`false`), and the combined helper still marks
    /// the stray through the scan. The extra descriptors are close-on-exec
    /// duplicates made in the forked child only (so exec closes them).
    #[cfg(target_os = "macos")]
    #[test]
    fn a_full_pid_listing_falls_back_to_the_scan() {
        let descriptors = InheritedDescriptors::prepare();
        assert_marks("the listing fallback", move || {
            // Room for the duplicates beyond the listing buffer.
            const WANTED: libc::rlim_t = 4096;
            let mut current = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: `getrlimit`/`setrlimit`/`fcntl` are async-signal-safe
            // and touch only this forked child.
            unsafe {
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) != 0 {
                    return false;
                }
                if current.rlim_cur < WANTED {
                    let raised = libc::rlimit {
                        rlim_cur: WANTED.min(current.rlim_max),
                        rlim_max: current.rlim_max,
                    };
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &raised) != 0 {
                        return false;
                    }
                }
                for _ in 0..MACOS_LISTED_DESCRIPTORS + 64 {
                    if libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 300) < 0 {
                        return false;
                    }
                }
            }
            // The listing must report itself incomplete; the helper then
            // scans.
            !mark_by_pid_listing() && descriptors.mark_cloexec(&[]).is_ok()
        });
    }

    /// macOS: the scan bound is `kern.maxfilesperproc`, not the soft limit
    /// (which can be far higher, or lower than an open descriptor).
    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_scan_is_bounded_by_max_files_per_process() {
        let maximum = macos_max_files_per_process().expect("kern.maxfilesperproc");
        assert_eq!(InheritedDescriptors::prepare().scan_end(), maximum);
        let (_read, write) = cloexec_pipe();
        // SAFETY: `F_DUPFD_CLOEXEC` at the bound itself must fail: no
        // descriptor can exist at or above it.
        let beyond = unsafe { libc::fcntl(write.as_raw_fd(), libc::F_DUPFD_CLOEXEC, maximum) };
        assert_eq!(beyond, -1);
    }

    /// Raise this process's soft `RLIMIT_NOFILE` to at least `wanted` (or as
    /// high as allowed); returns the previous limit to restore.
    fn raise_soft_file_limit(wanted: libc::rlim_t) -> libc::rlimit {
        let mut previous = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` writes only the live `previous`.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut previous) },
            0
        );
        if previous.rlim_cur < wanted {
            let raised = libc::rlimit {
                rlim_cur: wanted.min(previous.rlim_max),
                rlim_max: previous.rlim_max,
            };
            // SAFETY: `setrlimit` reads only the live `raised`.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) }, 0);
        }
        previous
    }

    fn restore_file_limit(previous: libc::rlimit) {
        // SAFETY: `setrlimit` reads only the live `previous`.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &previous) },
            0
        );
    }

    /// A descriptor above a soft limit lowered after it was opened is still
    /// marked (the exact listings; on macOS also the scan, bounded by
    /// `kern.maxfilesperproc`). The limit is lowered only in the child.
    #[test]
    fn a_descriptor_above_a_lowered_soft_limit_is_marked() {
        let _limit = FILE_LIMIT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let previous = raise_soft_file_limit(6000);
        let (_stray_read, stray) = high_pipe_end(5000);
        let (_kept_read, kept) = high_pipe_end(40);
        restore_file_limit(previous);
        // Positive control: unmarked, the child does hold the descriptor
        // above its lowered limit.
        let seen = listing_after(|| true, stray.as_raw_fd(), kept.as_raw_fd(), Some(64)).unwrap();
        assert!(seen.contains(&stray.as_raw_fd()), "{seen:?}");
        let descriptors = InheritedDescriptors::prepare();
        let mut methods: Vec<(&str, Marking)> = vec![(
            "the combined helper",
            Box::new(move || descriptors.mark_cloexec(&[]).is_ok()),
        )];
        #[cfg(target_os = "macos")]
        {
            methods.push((
                "proc_pidinfo(PROC_PIDLISTFDS)",
                Box::new(mark_by_pid_listing),
            ));
            let end = descriptors.scan_end();
            methods.push((
                "the scan to kern.maxfilesperproc",
                Box::new(move || {
                    mark_by_scan(end);
                    true
                }),
            ));
        }
        #[cfg(target_os = "linux")]
        {
            methods.push(("close_range", Box::new(mark_by_close_range)));
            methods.push(("the /proc/self/fd listing", Box::new(mark_by_proc_listing)));
        }
        for (method, mark) in methods {
            let seen = listing_after(mark, stray.as_raw_fd(), kept.as_raw_fd(), Some(64))
                .unwrap_or_else(|| panic!("{method} is unavailable here"));
            assert!(
                !seen.contains(&stray.as_raw_fd()),
                "{method}: fd {} above the lowered limit was inherited: {seen:?}",
                stray.as_raw_fd()
            );
            assert!(seen.contains(&kept.as_raw_fd()), "{method}: {seen:?}");
        }
    }

    /// A marking method run in the forked child.
    type Marking = Box<dyn Fn() -> bool + Send + Sync>;

    /// Keeping a descriptor that is not open is an error: the caller must
    /// not exec without the descriptor it meant to pass.
    #[test]
    fn keeping_a_closed_descriptor_fails() {
        // A number no descriptor can have: a closed one could be reused by a
        // concurrent test before the call.
        let error = keep_across_exec(&[RawFd::MAX]).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_names_parse_only_as_plain_decimals() {
        for (name, expected) in [
            (&b"0\0"[..], Some(0)),
            (b"17\0", Some(17)),
            (b"2147483647\0", Some(RawFd::MAX)),
            (b"2147483648\0", None),
            (b".\0", None),
            (b"..\0", None),
            (b"\0", None),
            (b"1a\0", None),
        ] {
            // SAFETY: every case is NUL-terminated.
            assert_eq!(
                unsafe { parse_descriptor(name.as_ptr()) },
                expected,
                "{name:?}"
            );
        }
    }
}
