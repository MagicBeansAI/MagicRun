use super::*;
use std::{
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

fn shell(body: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .env_clear()
        .args(["-c", body, "synthetic-recipient"]);
    command
}

// Test convenience for valid Command fixtures only. Malformed-input cases below
// deliberately construct Request directly, exactly as production does.
fn request<'a>(command: &'a Command, cwd: Option<BorrowedFd<'a>>, with_stdin: bool) -> Request<'a> {
    Request {
        program: std::path::Path::new(command.get_program()),
        arguments: command.get_args().collect(),
        environment: command
            .get_envs()
            .filter_map(|(name, value)| {
                value.map(|value| (name.to_str().unwrap(), value.as_bytes()))
            })
            .collect(),
        cwd,
        with_stdin,
    }
}
fn prepare(
    command: &Command,
    cwd: Option<BorrowedFd<'_>>,
    with_stdin: bool,
) -> io::Result<Prepared> {
    Prepared::new(request(command, cwd, with_stdin))
}

fn wait(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !super::super::observe_owned_child_exit(Some(child.id())).unwrap() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("synthetic native child exceeded deadline");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    child.wait().unwrap()
}

#[test]
fn exact_arguments_environment_stdin_and_streams_survive_native_spawn() {
    let mut command = shell("printf '<%s>' \"$@\"; printf '|%s|%s|' \"$MV_TOKEN\" \"${HOME-unset}\"; /bin/cat; printf error >&2");
    command
        .args(["spaces $(not-a-command)", "हैलो", ""])
        .env("MV_TOKEN", "synthetic-token");
    let mut child = prepare(&command, None, true).unwrap().spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"input").unwrap();
    assert!(wait(&mut child).success());
    let mut output = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert!(output == "<spaces $(not-a-command)><हैलो><>|synthetic-token|unset|input");
    output.clear();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert_eq!(output, "error");
}

#[test]
fn directory_replacement_after_preparation_cannot_retarget_child() {
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("authorized");
    let retained = root.path().join("retained");
    std::fs::create_dir(&original).unwrap();
    let directory = File::open(&original).unwrap();
    let prepared = prepare(
        &shell("printf owned > marker"),
        Some(directory.as_fd()),
        false,
    )
    .unwrap();
    drop(directory); // Prepared retains an independent, exact descriptor.
    std::fs::rename(&original, &retained).unwrap();
    std::fs::create_dir(&original).unwrap();
    let mut child = prepared.spawn().unwrap();
    assert!(wait(&mut child).success());
    assert_eq!(std::fs::read(retained.join("marker")).unwrap(), b"owned");
    assert!(!original.join("marker").exists());
}

#[test]
fn unsupported_backend_and_malformed_inputs_fail_before_launch() {
    assert_eq!(
        Prepared::prepare(request(&shell("exit 0"), None, false), None)
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ENOTSUP)
    );
    let mut relative = Command::new("sh");
    relative.env_clear();
    assert_eq!(
        prepare(&relative, None, false)
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::EINVAL)
    );
    for malformed in 0..4 {
        let command = shell("exit 0");
        let mut input = request(&command, None, false);
        match malformed {
            0 => {
                input.arguments.push(std::ffi::OsStr::new("nul\0argument"));
            }
            1 => {
                input.environment.push(("BAD=NAME", b"value"));
            }
            2 => {
                input.environment.push(("MV_TOKEN", b"nul\0value"));
            }
            _ => {
                input.environment.extend([
                    ("MV_TOKEN", b"first".as_slice()),
                    ("MV_TOKEN", b"second".as_slice()),
                ]);
            }
        }
        assert_eq!(
            Prepared::new(input).err().unwrap().raw_os_error(),
            Some(libc::EINVAL)
        );
    }
}

#[test]
fn bad_cwd_missing_image_and_nonexecutable_image_have_no_recipient_effect() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("marker");
    let bad_directory = File::create(root.path().join("file-not-directory")).unwrap();
    let mut command = shell("printf effect > \"$1\"");
    command.arg(&marker);
    assert_eq!(
        prepare(&command, Some(bad_directory.as_fd()), false)
            .unwrap()
            .spawn()
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ENOTDIR)
    );
    let mut missing = Command::new(root.path().join("missing"));
    missing.env_clear();
    assert_eq!(
        prepare(&missing, None, false)
            .unwrap()
            .spawn()
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    let image = root.path().join("image");
    std::fs::write(&image, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut denied = Command::new(image);
    denied.env_clear();
    assert_eq!(
        prepare(&denied, None, false)
            .unwrap()
            .spawn()
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::EACCES)
    );
    assert!(!marker.exists());
}

#[test]
fn native_status_is_cached_and_live_child_drop_is_bounded() {
    for (body, success, signal) in [
        ("exit 0", true, None),
        ("exit 17", false, None),
        ("kill -TERM $$", false, Some(libc::SIGTERM)),
    ] {
        let mut child = prepare(&shell(body), None, false).unwrap().spawn().unwrap();
        let status = wait(&mut child);
        assert_eq!(status.success(), success);
        assert_eq!(status.signal(), signal);
        assert_eq!(child.wait().unwrap(), status);
        assert_eq!(child.kill().unwrap_err().raw_os_error(), Some(libc::ESRCH));
    }
    let child = prepare(&shell("exec /bin/sleep 30"), None, false)
        .unwrap()
        .spawn()
        .unwrap();
    let started = Instant::now();
    drop(child); // owner kills the still-unreaped group/leader and reaps it
    assert!(started.elapsed() < Duration::from_secs(2));
}

// Fork handlers and closed process stdio must never alter the main test process.
// A marker proves the exact helper test ran; a zero-test harness is not success.
fn isolated(name: &str) -> bool {
    if std::env::var("MAGICRUN_SPAWN_WORKER").as_deref() == Ok(name) {
        return false;
    }
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("proof");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .env("MAGICRUN_SPAWN_WORKER", name)
        .env("MAGICRUN_SPAWN_PROOF", &marker)
        .args([name, "--exact", "--nocapture"])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("isolated native spawn proof exceeded deadline");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(std::fs::read(marker).unwrap(), b"passed");
    true
}
fn proof() {
    std::fs::write(std::env::var_os("MAGICRUN_SPAWN_PROOF").unwrap(), b"passed").unwrap();
}

#[test]
fn native_launch_does_not_invoke_fork_handlers() {
    const NAME: &str =
        "governed_batch_process::macos_spawn::tests::native_launch_does_not_invoke_fork_handlers";
    if isolated(NAME) {
        return;
    }
    static FORKS: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn parent_fork() {
        FORKS.fetch_add(1, Ordering::SeqCst);
    }
    // SAFETY: isolated process; permanent static callback does one atomic update.
    assert_eq!(
        unsafe { libc::pthread_atfork(None, Some(parent_fork), None) },
        0
    );
    let mut child = prepare(&shell("exit 0"), None, false)
        .unwrap()
        .spawn()
        .unwrap();
    assert!(wait(&mut child).success());
    assert_eq!(FORKS.load(Ordering::SeqCst), 0);
    let mut control = Command::new("/usr/bin/true");
    control.env_clear();
    // SAFETY: positive control's empty hook does no work in the child.
    unsafe {
        control.pre_exec(|| Ok(()));
    }
    let mut child = Child::from(control.spawn().unwrap());
    assert!(wait(&mut child).success());
    assert_eq!(FORKS.load(Ordering::SeqCst), 1);
    proof();
}

#[test]
fn closed_parent_stdio_does_not_corrupt_file_actions() {
    const NAME: &str = "governed_batch_process::macos_spawn::tests::closed_parent_stdio_does_not_corrupt_file_actions";
    if isolated(NAME) {
        return;
    }
    // SAFETY: exact stdio of this dedicated disposable test process, never the
    // caller/test harness's descriptors or a discovered unrelated descriptor.
    unsafe {
        libc::close(0);
        libc::close(1);
        libc::close(2);
    }
    let mut child = prepare(&shell("/bin/cat; printf error >&2"), None, true)
        .unwrap()
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"input").unwrap();
    assert!(wait(&mut child).success());
    let mut output = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert_eq!(output, "input");
    output.clear();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert_eq!(output, "error");
    proof();
}

#[test]
fn unrelated_inheritable_descriptor_is_not_available_to_recipient() {
    const NAME: &str = "governed_batch_process::macos_spawn::tests::unrelated_inheritable_descriptor_is_not_available_to_recipient";
    if std::env::var("MAGICRUN_SPAWN_ROLE").as_deref() == Ok("recipient") {
        let fd: i32 = std::env::var("MAGICRUN_SPAWN_FD").unwrap().parse().unwrap();
        // Exact synthetic sentinel deliberately supplied by our parent, not an
        // enumeration of this process's or any other process's descriptors.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        proof();
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("proof");
    let sentinel = File::create(root.path().join("sentinel")).unwrap();
    // Use a high owned descriptor so the recipient's own std runtime setup does
    // not coincidentally reuse it. Deliberately inheritable; parent keeps owner.
    let fd = unsafe { libc::fcntl(sentinel.as_raw_fd(), libc::F_DUPFD, 200) };
    assert!(fd >= 200);
    let _sentinel = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .env_clear()
        .env("MAGICRUN_SPAWN_ROLE", "recipient")
        .env("MAGICRUN_SPAWN_FD", fd.to_string())
        .env("MAGICRUN_SPAWN_PROOF", &marker)
        .args([NAME, "--exact"]);
    let mut child = prepare(&command, None, false).unwrap().spawn().unwrap();
    assert!(wait(&mut child).success());
    assert_eq!(std::fs::read(marker).unwrap(), b"passed");
    // Parent's descriptor was not closed by a child-side file action.
    assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
}
