//! Close-on-exec for every descriptor a jail launch did not deliberately pass.
//!
//! A process that execs a jail launcher (bubblewrap, `sandbox-exec`) or, in
//! the jail, the command, passes on every descriptor it holds without
//! close-on-exec. The host process can hold such descriptors for reasons
//! that have nothing to do with the jail (a parent's pipes, a library that
//! opened a file without `O_CLOEXEC`), and a jailed command could read or
//! write them. [`mark_inherited_descriptors_cloexec`] marks every descriptor
//! above stdio close-on-exec, then clears the flag again on exactly the ones
//! the caller passes on. It only sets flags: descriptors the forked child
//! still uses before exec (the standard library's exec-error pipe, the
//! working-directory handle) stay open until exec.
//!
//! It is async-signal-safe: raw system calls on a fixed stack buffer, no
//! allocation, no locks, so it may run between `fork` and `exec`. It tries,
//! in order:
//!
//! 1. Linux: `close_range(3, ~0U, CLOSE_RANGE_CLOEXEC)` (kernel 5.11+). Any
//!    failure (`ENOSYS`, `EINVAL` before 5.11, `EPERM` from a seccomp filter
//!    that predates the call) moves on.
//! 2. Linux: the entries of `/proc/self/fd`, read with `getdents64` into a
//!    stack buffer, each marked with `fcntl(F_SETFD)`. Exact, whatever the
//!    descriptor limit. Needs a mounted `/proc`.
//! 3. Every descriptor number from 3 up to the soft `RLIMIT_NOFILE`, capped
//!    at [`DESCRIPTOR_SCAN_CEILING`]. No descriptor can be opened at or above
//!    the soft limit, so the scan is exact unless the limit was lowered after
//!    a higher descriptor was opened, or the limit exceeds the cap. On Linux
//!    this runs only when both calls above are unavailable; on macOS, which
//!    has neither, it is the method (the soft limit there is bounded by
//!    `kern.maxfilesperproc`).

use std::{io, os::fd::RawFd};

/// Highest descriptor number (exclusive) the fallback scan visits: 2^20.
/// Linux `fs.nr_open` defaults to the same value, so no descriptor can exceed
/// it unless an administrator raised `fs.nr_open` and the process its limit.
pub(crate) const DESCRIPTOR_SCAN_CEILING: RawFd = 1 << 20;

/// Mark every descriptor from 3 up close-on-exec, then clear close-on-exec
/// on each descriptor in `keep`, which the caller deliberately passes across
/// exec. Async-signal-safe (see the module documentation). An error means
/// a descriptor in `keep` could not be kept; the caller must not exec then.
pub(crate) fn mark_inherited_descriptors_cloexec(keep: &[RawFd]) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    let marked = mark_by_close_range() || mark_by_proc_listing();
    #[cfg(not(target_os = "linux"))]
    let marked = false;
    if !marked {
        mark_by_scan();
    }
    keep_across_exec(keep)
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
/// seccomp filter) refuses it.
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
/// be opened or read to the end.
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
    let complete = loop {
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
        let bytes = buffer.as_ptr().cast::<u8>();
        let mut offset = 0_usize;
        while offset < read as usize {
            // `linux_dirent64`: d_ino (8), d_off (8), d_reclen (2),
            // d_type (1), then the NUL-terminated name.
            // SAFETY: the kernel wrote a whole record at `offset`; the
            // reclen field is inside it and 2-byte aligned.
            let record_length = unsafe { bytes.add(offset + 16).cast::<u16>().read() } as usize;
            if record_length == 0 {
                break;
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

/// Mark every descriptor number from 3 up to the soft `RLIMIT_NOFILE`
/// (at most [`DESCRIPTOR_SCAN_CEILING`]) close-on-exec.
pub(crate) fn mark_by_scan() {
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
    let end = if soft == libc::RLIM_INFINITY || soft > DESCRIPTOR_SCAN_CEILING as libc::rlim_t {
        DESCRIPTOR_SCAN_CEILING
    } else {
        soft as RawFd
    };
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

    /// A fresh close-on-exec pipe end at a number of at least `minimum`, so
    /// no descriptor the listed program opens itself can take that number.
    fn high_pipe_end(minimum: RawFd) -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        // SAFETY: `pipe` writes two fresh descriptors into the live array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: both descriptors are fresh and owned by nothing else.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // SAFETY: duplicates a live descriptor, close-on-exec, at >= minimum.
        let high = unsafe { libc::fcntl(write.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
        assert!(high >= minimum);
        // SAFETY: `high` is fresh and owned by nothing else.
        (read, unsafe { OwnedFd::from_raw_fd(high) })
    }

    /// Fork, make `stray` and `kept` inheritable in the child only (as a
    /// host descriptor without close-on-exec would be), run `mark`, keep
    /// `kept`, and exec `/bin/sh -c 'ls <listing>'`. The descriptor numbers
    /// the program sees, or `None` if `mark` reported the method unavailable.
    fn listing_after(mark: fn() -> bool, stray: RawFd, kept: RawFd) -> Option<Vec<RawFd>> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &format!("ls {LISTING}")]);
        // SAFETY: only `fcntl` and the async-signal-safe marking run in the
        // child, and only on its own copies of the descriptors.
        unsafe {
            command.pre_exec(move || {
                for fd in [stray, kept] {
                    if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
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

    fn assert_marks(method: &str, mark: fn() -> bool) {
        let (_stray_read, stray) = high_pipe_end(200);
        let (_kept_read, kept) = high_pipe_end(240);
        let Some(seen) = listing_after(mark, stray.as_raw_fd(), kept.as_raw_fd()) else {
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
        let seen = listing_after(|| true, stray.as_raw_fd(), kept.as_raw_fd()).unwrap();
        assert!(seen.contains(&stray.as_raw_fd()), "{seen:?}");
        assert!(seen.contains(&kept.as_raw_fd()), "{seen:?}");
    }

    /// The combined helper, as every jail launch runs it.
    #[test]
    fn marking_hides_a_stray_descriptor_and_keeps_the_passed_one() {
        assert_marks("the combined helper", || {
            mark_inherited_descriptors_cloexec(&[]).is_ok()
        });
    }

    #[test]
    fn the_bounded_scan_marks_a_stray_descriptor() {
        assert_marks("the bounded scan", || {
            mark_by_scan();
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
