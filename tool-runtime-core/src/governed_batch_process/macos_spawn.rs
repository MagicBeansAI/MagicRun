//! Non-jailed macOS batch launch without a userspace fork interval. Private to
//! the governed runner: no shell/PATH lookup, callbacks or inherited environment.
use std::{
    fs::File,
    io,
    mem::MaybeUninit,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, process::ExitStatusExt},
    },
    process::{Child as StdChild, ExitStatus},
    sync::OnceLock,
};
use zeroize::Zeroizing;

type AddFchdir =
    unsafe extern "C" fn(*mut libc::posix_spawn_file_actions_t, libc::c_int) -> libc::c_int;

fn add_fchdir() -> Option<AddFchdir> {
    static FUNCTION: OnceLock<Option<AddFchdir>> = OnceLock::new();
    *FUNCTION.get_or_init(|| {
        // SAFETY: fixed public macOS 10.15+ symbol and exact <spawn.h> signature.
        // Resolve dynamically so older systems fail this operation closed rather
        // than preventing library loading or silently falling back to fork.
        let address = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"posix_spawn_file_actions_addfchdir_np".as_ptr(),
            )
        };
        if address.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute::<*mut libc::c_void, AddFchdir>(address) })
        }
    })
}

fn result(code: libc::c_int) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code))
    }
}

struct Actions(libc::posix_spawn_file_actions_t);
impl Actions {
    fn new() -> io::Result<Self> {
        let mut value = MaybeUninit::uninit();
        // SAFETY: init writes the opaque object on success only.
        result(unsafe { libc::posix_spawn_file_actions_init(value.as_mut_ptr()) })?;
        Ok(Self(unsafe { value.assume_init() }))
    }
}
impl Drop for Actions {
    fn drop(&mut self) {
        // SAFETY: exactly one owner of a successfully initialized object.
        unsafe { libc::posix_spawn_file_actions_destroy(&mut self.0) };
    }
}
struct Attributes(libc::posix_spawnattr_t);
impl Attributes {
    fn new() -> io::Result<Self> {
        let mut value = MaybeUninit::uninit();
        // SAFETY: init writes the opaque object on success only.
        result(unsafe { libc::posix_spawnattr_init(value.as_mut_ptr()) })?;
        Ok(Self(unsafe { value.assume_init() }))
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: exactly one owner of a successfully initialized object.
        unsafe { libc::posix_spawnattr_destroy(&mut self.0) };
    }
}

fn duplicate(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    // SAFETY: borrow keeps the source alive. Duplicate above stdio atomically
    // CLOEXEC so file actions cannot clobber another action's source, even when
    // the embedding process has closed descriptors 0, 1 or 2.
    let new_fd = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if new_fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
    }
}
fn above_stdio(fd: OwnedFd) -> io::Result<OwnedFd> {
    if fd.as_raw_fd() >= 3 {
        Ok(fd)
    } else {
        duplicate(fd.as_fd())
    }
}
fn pipe() -> io::Result<(File, File)> {
    let (reader, writer) = io::pipe()?;
    Ok((
        above_stdio(reader.into())?.into(),
        above_stdio(writer.into())?.into(),
    ))
}

fn c_bytes(bytes: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    if bytes.contains(&0) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut value = Zeroizing::new(Vec::with_capacity(bytes.len() + 1));
    value.extend_from_slice(bytes);
    value.push(0);
    Ok(value)
}

/// Owns every file-action source and zeroizing C buffer through the syscall.
/// Preparation is parent-only; the caller revalidates authority/deadline after it.
pub(super) struct Prepared {
    arguments: Vec<Zeroizing<Vec<u8>>>,
    environment: Vec<Zeroizing<Vec<u8>>>,
    actions: Actions,
    attributes: Attributes,
    _sources: Vec<OwnedFd>,
    stdin: Option<File>,
    stdout: File,
    stderr: File,
}
/// Original authorized inputs, never values read back from std Command: Command
/// can substitute invalid C strings while recording an inaccessible error flag.
pub(super) struct Request<'a> {
    pub(super) program: &'a std::path::Path,
    pub(super) arguments: Vec<&'a std::ffi::OsStr>,
    pub(super) environment: Vec<(&'a str, &'a [u8])>,
    pub(super) cwd: Option<BorrowedFd<'a>>,
    pub(super) with_stdin: bool,
}
impl Prepared {
    pub(super) fn new(request: Request<'_>) -> io::Result<Self> {
        if !request.program.is_absolute() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Self::prepare(request, add_fchdir())
    }

    fn prepare(request: Request<'_>, fchdir: Option<AddFchdir>) -> io::Result<Self> {
        // Require the supported backend even without a cwd, never use fork as a
        // compatibility or error fallback. No extra process is created on error.
        let fchdir = fchdir.ok_or_else(|| io::Error::from_raw_os_error(libc::ENOTSUP))?;
        let arguments = std::iter::once(request.program.as_os_str())
            .chain(request.arguments)
            .map(|argument| c_bytes(argument.as_bytes()))
            .collect::<io::Result<Vec<_>>>()?;
        let mut environment = Vec::new();
        let mut previous_name = None;
        for (name, value) in request.environment {
            if previous_name.is_some_and(|previous| previous >= name) {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            previous_name = Some(name);
            let name = name.as_bytes();
            if name.is_empty() || name.contains(&b'=') || name.contains(&0) || value.contains(&0) {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            let mut entry = Zeroizing::new(Vec::with_capacity(name.len() + value.len() + 2));
            entry.extend_from_slice(name);
            entry.push(b'=');
            entry.extend_from_slice(value);
            entry.push(0);
            environment.push(entry);
        }
        let (stdin, input) = if request.with_stdin {
            let (reader, writer) = pipe()?;
            (Some(writer), reader.into())
        } else {
            (None, above_stdio(File::open("/dev/null")?.into())?)
        };
        let (stdout, output) = pipe()?;
        let (stderr, error) = pipe()?;
        let mut sources = vec![input, output.into(), error.into()];
        let mut actions = Actions::new()?;
        for (destination, source) in sources.iter().enumerate() {
            // SAFETY: initialized actions; source FDs stay owned until spawn;
            // distinct sources above stdio prevent dup2 action cycles.
            result(unsafe {
                libc::posix_spawn_file_actions_adddup2(
                    &mut actions.0,
                    source.as_raw_fd(),
                    destination as libc::c_int,
                )
            })?;
        }
        if let Some(cwd) = request.cwd {
            sources.push(duplicate(cwd)?);
            // SAFETY: exact open directory description, not a re-resolved path.
            result(unsafe { fchdir(&mut actions.0, sources.last().unwrap().as_raw_fd()) })?;
        }
        for source in &sources {
            // SAFETY: action ordering is dup2/fchdir then close. No source FD
            // remains available to the recipient, even if an action marks it used.
            result(unsafe {
                libc::posix_spawn_file_actions_addclose(&mut actions.0, source.as_raw_fd())
            })?;
        }
        let mut attributes = Attributes::new()?;
        // SAFETY: initialized attributes and signal set. Match std Command's
        // default SIGPIPE reset and inherited signal mask; own group from birth.
        unsafe {
            let mut defaults = MaybeUninit::<libc::sigset_t>::uninit();
            if libc::sigemptyset(defaults.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut defaults = defaults.assume_init();
            if libc::sigaddset(&mut defaults, libc::SIGPIPE) != 0 {
                return Err(io::Error::last_os_error());
            }
            result(libc::posix_spawnattr_setsigdefault(
                &mut attributes.0,
                &defaults,
            ))?;
            result(libc::posix_spawnattr_setpgroup(&mut attributes.0, 0))?;
            result(libc::posix_spawnattr_setflags(
                &mut attributes.0,
                (libc::POSIX_SPAWN_SETPGROUP
                    | libc::POSIX_SPAWN_SETSIGDEF
                    | libc::POSIX_SPAWN_CLOEXEC_DEFAULT) as libc::c_short,
            ))?;
        }
        Ok(Self {
            arguments,
            environment,
            actions,
            attributes,
            _sources: sources,
            stdin,
            stdout,
            stderr,
        })
    }

    pub(super) fn spawn(self) -> io::Result<Child> {
        let argv: Vec<_> = self
            .arguments
            .iter()
            .map(|a| a.as_ptr().cast::<libc::c_char>().cast_mut())
            .chain(std::iter::once(std::ptr::null_mut()))
            .collect();
        let envp: Vec<_> = self
            .environment
            .iter()
            .map(|a| a.as_ptr().cast::<libc::c_char>().cast_mut())
            .chain(std::iter::once(std::ptr::null_mut()))
            .collect();
        let mut pid = 0;
        // SAFETY: NUL-terminated argv/envp and absolute program, all action FDs
        // and buffers retained for the syscall. macOS returns an error with no
        // child or success with the exact owned PID. No callback/fork/retry.
        result(unsafe {
            libc::posix_spawn(
                &mut pid,
                argv[0],
                &self.actions.0,
                &self.attributes.0,
                argv.as_ptr(),
                envp.as_ptr(),
            )
        })?;
        Ok(Child {
            inner: Inner::Native {
                pid: Some(pid),
                status: None,
            },
            stdin: self.stdin,
            stdout: Some(self.stdout),
            stderr: Some(self.stderr),
        })
    }
}

enum Inner {
    Standard(StdChild),
    Native {
        pid: Option<libc::pid_t>,
        status: Option<ExitStatus>,
    },
}

/// Same collection contract as std Child; native PIDs never outlive their owner
/// unreaped. No public raw-PID construction or diagnostic formatting exists.
pub(super) struct Child {
    inner: Inner,
    pub(super) stdin: Option<File>,
    pub(super) stdout: Option<File>,
    pub(super) stderr: Option<File>,
}
impl From<StdChild> for Child {
    fn from(mut child: StdChild) -> Self {
        Self {
            stdin: child
                .stdin
                .take()
                .map(|pipe| File::from(OwnedFd::from(pipe))),
            stdout: child
                .stdout
                .take()
                .map(|pipe| File::from(OwnedFd::from(pipe))),
            stderr: child
                .stderr
                .take()
                .map(|pipe| File::from(OwnedFd::from(pipe))),
            inner: Inner::Standard(child),
        }
    }
}
impl Child {
    pub(super) fn id(&self) -> u32 {
        match &self.inner {
            Inner::Standard(child) => child.id(),
            Inner::Native { pid, .. } => pid.expect("unreaped native child") as u32,
        }
    }
    pub(super) fn kill(&mut self) -> io::Result<()> {
        match &mut self.inner {
            Inner::Standard(child) => child.kill(),
            Inner::Native { pid, .. } => {
                let pid = pid.ok_or_else(|| io::Error::from_raw_os_error(libc::ESRCH))?;
                // SAFETY: exact owned unreaped child, never a process search.
                if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }
    }
    pub(super) fn wait(&mut self) -> io::Result<ExitStatus> {
        match &mut self.inner {
            Inner::Standard(child) => child.wait(),
            Inner::Native { pid, status } => {
                if let Some(status) = status {
                    return Ok(*status);
                }
                let owned = pid.ok_or_else(|| io::Error::from_raw_os_error(libc::ECHILD))?;
                loop {
                    let mut raw = 0;
                    // SAFETY: wait only for the exact owned PID, no WNOHANG.
                    let waited = unsafe { libc::waitpid(owned, &mut raw, 0) };
                    if waited == owned {
                        let observed = ExitStatus::from_raw(raw);
                        *pid = None; // never signal this identity after reap
                        *status = Some(observed);
                        return Ok(observed);
                    }
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    if error.raw_os_error() == Some(libc::ECHILD) {
                        *pid = None;
                    }
                    return Err(error);
                }
            }
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if let Inner::Native { pid: Some(pid), .. } = &self.inner {
            // SAFETY: fallback for unwinding before ProcessTreeGuard takes over.
            // The unreaped owned leader pins the group identity. Normal cleanup
            // remains in ProcessTreeGuard; a reaped PID is never signalled here.
            unsafe {
                libc::kill(-*pid, libc::SIGKILL);
                libc::kill(*pid, libc::SIGKILL);
            }
            let _ = self.wait();
        }
    }
}

#[cfg(test)]
mod tests;
