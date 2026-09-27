//! Interpreter mode. The profile, argv, identity and trust-check tests run on
//! every host; the live tests launch the real `sandbox-exec` (macOS) or
//! `bwrap` (Linux) with the host's discovered Python 3.

use std::os::unix::fs::PermissionsExt;

use super::egress_tests::{skip, try_run_in_jail, JailedRun, JAIL_PROCESS_BUDGET};
use super::*;
use crate::governed_execution::GovernedExecutionTerminal;

fn macos_grants() -> InterpreterGrants<'static> {
    InterpreterGrants {
        executable: Path::new("/Library/Py.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python"),
        images: vec![Path::new("/Library/Py.framework/Versions/3.9/Py")],
        library_roots: vec![Path::new("/Library/Py.framework/Versions/3.9/lib")],
        denied_roots: vec![Path::new("/Library/Py.framework/Versions/3.9/lib/python3.9/site-packages")],
    }
}

fn linux_grants() -> InterpreterGrants<'static> {
    InterpreterGrants {
        executable: Path::new("/usr/bin/python3.11"),
        images: Vec::new(),
        library_roots: vec![Path::new("/usr/lib/python3.11")],
        denied_roots: Vec::new(),
    }
}

fn strings(args: &[OsString]) -> Vec<&str> {
    args.iter().map(|argument| argument.to_str().unwrap()).collect()
}

/// Golden: the reviewed profile identities consumers fold into lock digests.
/// `0.1.78` deliberately rotated the Linux values: every Linux jail now binds
/// the trusted helper and runs through its exec shim (strict was
/// `blake3:1fc54240…cc61a0`, brokered `blake3:3c4fcba8…e142cc`). `0.1.77` deliberately
/// rotated both macOS values by adding
/// `(deny file-map-executable (subpath "<workdir>"))` to the strict profile:
/// strict was `blake3:e783cb6b…020d31`, brokered `blake3:89b6c07b…2f09f6`.
#[test]
fn profile_identities_match_the_reviewed_goldens() {
    use GovernedProcessJailNetwork::{BrokeredEgress, Denied};
    use GovernedProcessJailPlatform::{LinuxBubblewrap, MacosSandboxExec};
    for (platform, network, expected) in [
        (MacosSandboxExec, Denied, "blake3:8a06b6cf39f973f5e72e7f56919d42e28949205f84f4a1de52f81d383d32dcd2"),
        (MacosSandboxExec, BrokeredEgress, "blake3:97a0d14fc4da175cd3f231dbbfc6ce35f3305052c339f83cc86b65da8860aacb"),
        (LinuxBubblewrap, Denied, "blake3:ab90ccc53ad835dccbbd0893728f73a496386a7ee37a847dd08e5f0580d0fe3c"),
        (LinuxBubblewrap, BrokeredEgress, "blake3:e2822def264dbc69779eff9c0872d67c17f958fcffca9b5c8ac3eaf9fa4fbe8e"),
    ] {
        assert_eq!(
            governed_process_jail_profile_identity(platform, network).to_string(),
            expected,
            "{platform:?} {network:?}"
        );
    }
}

/// Golden: interpreter-mode identities for Python 3.9 and 3.14.
#[test]
fn interpreter_profile_identities_match_the_reviewed_goldens() {
    use GovernedProcessJailNetwork::{BrokeredEgress, Denied};
    use GovernedProcessJailPlatform::{LinuxBubblewrap, MacosSandboxExec};
    for (platform, network, minor, expected) in [
        (MacosSandboxExec, Denied, 9, "blake3:cf6750189aa80f18332c78698ce51576d45aa2dde6a94beb2a2612336d2a7494"),
        (MacosSandboxExec, Denied, 14, "blake3:a47ea4ba6a97e7bb1ef057b346f63c67c749ab33e262e947f59868b9cfcc4ac3"),
        (MacosSandboxExec, BrokeredEgress, 9, "blake3:cc6fa6d8a746bd393d35fe92b8aa090add58f61f0fe45595e31bb365482b4116"),
        (LinuxBubblewrap, Denied, 9, "blake3:87d3b302bdf932bc99dfc927c1e5bf5ac5801e721990c0d782875d085c6002cc"),
        (LinuxBubblewrap, BrokeredEgress, 14, "blake3:d0da12305446bb515d2a86385987f68406b0d08e65d822f1bec446d90690a9da"),
    ] {
        let identity = governed_process_jail_interpreter_profile_identity(
            platform,
            network,
            GovernedJailInterpreterKind::Python3,
            GovernedJailInterpreterVersion { major: 3, minor },
        );
        assert_eq!(identity.to_string(), expected, "{platform:?} {network:?} 3.{minor}");
    }
}

#[test]
fn interpreter_identity_is_distinct_stable_and_binds_the_version() {
    let python = |minor| GovernedJailInterpreterVersion { major: 3, minor };
    let mut seen = std::collections::BTreeSet::new();
    for platform in [
        GovernedProcessJailPlatform::MacosSandboxExec,
        GovernedProcessJailPlatform::LinuxBubblewrap,
    ] {
        for network in [
            GovernedProcessJailNetwork::Denied,
            GovernedProcessJailNetwork::BrokeredEgress,
        ] {
            assert!(seen.insert(governed_process_jail_profile_identity(platform, network).to_string()));
            for minor in [9, 14] {
                let identity = governed_process_jail_interpreter_profile_identity(
                    platform,
                    network,
                    GovernedJailInterpreterKind::Python3,
                    python(minor),
                );
                assert_eq!(
                    identity,
                    governed_process_jail_interpreter_profile_identity(
                        platform,
                        network,
                        GovernedJailInterpreterKind::Python3,
                        python(minor),
                    )
                );
                assert!(seen.insert(identity.to_string()), "{platform:?} {network:?} 3.{minor}");
            }
        }
    }
}

/// Golden of the macOS interpreter profile shape: the strict profile rendered
/// for the interpreter (the only exec literal), then the script literal, the
/// pinned image, the library root and the `site-packages` denial last.
#[test]
fn macos_interpreter_profile_execs_only_the_interpreter() {
    let grants = macos_grants();
    let script = Path::new("/private/tmp/governed-bundle/skill");
    let bundle = Some(Path::new("/private/tmp/governed-bundle"));
    let workdir = Path::new("/private/tmp/private-work");
    let profile = macos_interpreter_profile(&grants, script, bundle, workdir, None).unwrap();
    assert_eq!(
        profile,
        "(version 1)\n\
         (deny default)\n\
         (deny process-fork)\n\
         (allow process-exec (literal \"/Library/Py.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python\"))\n\
         (allow file-read* (literal \"/Library/Py.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python\"))\n\
         (allow file-read-data (literal \"/\"))\n\
         (allow sysctl-read)\n\
         (allow file-read* (subpath \"/System\"))\n\
         (allow file-read* (subpath \"/usr/lib\"))\n\
         (allow file-read* (subpath \"/Library/Apple/System\"))\n\
         (allow file-read* (subpath \"/private/var/db/dyld\"))\n\
         (allow file-read* (literal \"/dev/null\"))\n\
         (allow file-read* (literal \"/dev/random\"))\n\
         (allow file-read* (literal \"/dev/urandom\"))\n\
         (allow file-read* (subpath \"/private/tmp/governed-bundle\"))\n\
         (allow file-read* (subpath \"/private/tmp/private-work\"))\n\
         (allow file-write* (subpath \"/private/tmp/private-work\"))\n\
         (deny file-map-executable (subpath \"/private/tmp/private-work\"))\n\
         (allow file-read* (literal \"/private/tmp/governed-bundle/skill\"))\n\
         (allow file-read* (literal \"/Library/Py.framework/Versions/3.9/Py\"))\n\
         (allow file-read* (subpath \"/Library/Py.framework/Versions/3.9/lib\"))\n\
         (deny file-read* (subpath \"/Library/Py.framework/Versions/3.9/lib/python3.9/site-packages\"))\n"
    );
    assert_eq!(profile.matches("(allow process-exec").count(), 1);
    assert!(!profile.contains("process-exec (literal \"/private/tmp/governed-bundle/skill\")"));
    assert!(!profile.contains("(allow process-fork"));
    for absent in ["mach-lookup", "network", "(allow default)", "file-write* (subpath \"/Library"] {
        assert!(!profile.contains(absent), "{absent}");
    }
    // The brokered variant appends exactly the reviewed egress rules.
    let brokered =
        macos_interpreter_profile(&grants, script, bundle, workdir, Some(("49152", true))).unwrap();
    assert_eq!(
        brokered.strip_prefix(&profile).unwrap(),
        macos_egress_rules("49152", true).unwrap()
    );
    assert!(macos_interpreter_profile(&grants, script, bundle, workdir, Some(("1) (allow default", true))).is_err());
    // The interpreter can never be the script.
    assert!(macos_interpreter_profile(&grants, grants.executable, bundle, workdir, None).is_err());
}

#[test]
fn linux_interpreter_argv_binds_the_interpreter_and_prepends_it() {
    let lib_roots = [Path::new("/lib"), Path::new("/lib64")];
    let bundle = Path::new("/private/bundle");
    let workdir = Path::new("/private/work");
    let script = Path::new("skill");
    let exec = LinuxJailExec {
        helper: Path::new("/usr/libexec/magicrun/magicrun-jail-egress-forwarder"),
        task_ceiling: Some((OsString::from("258"), OsString::from("4026531837"))),
    };
    assert_eq!(
        linux_bwrap_args_with_interpreter(&lib_roots, bundle, workdir, script, &exec, None, None),
        linux_bwrap_args(&lib_roots, bundle, workdir, script, &exec, None)
    );
    let grants = linux_grants();
    let args =
        linux_bwrap_args_with_interpreter(&lib_roots, bundle, workdir, script, &exec, None, Some(&grants));
    let args = strings(&args);
    let has = |window: &[&str]| args.windows(window.len()).any(|pair| pair == window);
    assert!(has(&["--ro-bind", "/usr/bin/python3.11", "/usr/bin/python3.11"]));
    assert!(has(&["--ro-bind", "/usr/lib/python3.11", "/usr/lib/python3.11"]));
    assert!(!args.windows(2).any(|pair| pair[0] == "--bind" && pair[1].starts_with("/usr")));
    assert!(args.contains(&"--unshare-all"));
    let remount = args.iter().position(|arg| *arg == "--remount-ro").unwrap();
    assert!(args.iter().rposition(|arg| *arg == "--ro-bind").unwrap() < remount);
    let separator = args.iter().position(|arg| *arg == "--").unwrap();
    assert_eq!(
        &args[separator..],
        [
            "--",
            LINUX_JAIL_HELPER,
            "--magicrun-jail-exec-v1",
            "258",
            "4026531837",
            "--",
            "/usr/bin/python3.11",
            "-I",
            "-S",
            "-B",
            "/app/skill",
        ]
    );

    let mounts = LinuxEgressMounts {
        socket: Path::new("/run/magician/egress/broker.sock"),
        trust_bundle: None,
        environment: Vec::new(),
    };
    let args = linux_bwrap_args_with_interpreter(
        &lib_roots,
        bundle,
        workdir,
        script,
        &exec,
        Some(&mounts),
        Some(&grants),
    );
    let args = strings(&args);
    let separator = args.iter().position(|arg| *arg == "--").unwrap();
    assert_eq!(
        &args[separator..],
        [
            "--",
            LINUX_JAIL_HELPER,
            "--magicrun-jail-exec-v1",
            "258",
            "4026531837",
            "--",
            LINUX_JAIL_HELPER,
            GOVERNED_JAIL_EGRESS_FORWARDER_PROTOCOL_V1,
            "3128",
            LINUX_JAIL_EGRESS_SOCKET,
            "--",
            "/usr/bin/python3.11",
            "-I",
            "-S",
            "-B",
            "/app/skill",
        ]
    );
}

#[test]
fn python3_version_accepts_only_exact_minor_names() {
    assert_eq!(
        python3_version("python3.9"),
        Some(GovernedJailInterpreterVersion { major: 3, minor: 9 })
    );
    assert_eq!(python3_version("python3.14").unwrap().to_string(), "3.14");
    for refused in ["python3", "python3.", "python3.14t", "python3.9-intel64", "python2.7", "python3.+9", "Python", "python3.1234"] {
        assert_eq!(python3_version(refused), None, "{refused}");
    }
    assert_eq!(
        serde_json::to_value(GovernedJailInterpreterVersion { major: 3, minor: 14 }).unwrap(),
        serde_json::Value::String("3.14".to_owned())
    );
}

/// A user-owned installation with a perfect framework layout is refused, as
/// is a user-owned symlink to a trusted interpreter: nobody but root may
/// choose or alter what the jail runs.
#[test]
fn user_owned_or_symlinked_candidates_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let root_path = fs::canonicalize(root.path()).unwrap();
    let version = root_path.join("Py.framework/Versions/3.9");
    fs::create_dir_all(version.join("bin")).unwrap();
    fs::create_dir_all(version.join("Resources/Python.app/Contents/MacOS")).unwrap();
    fs::create_dir_all(version.join("lib/python3.9/site-packages")).unwrap();
    fs::write(version.join("lib/python3.9/os.py"), b"").unwrap();
    for file in ["bin/python3.9", "Resources/Python.app/Contents/MacOS/Python", "Py"] {
        fs::write(version.join(file), b"#!/bin/false\n").unwrap();
        fs::set_permissions(version.join(file), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let candidate = version.join("bin/python3.9");
    for platform in [
        GovernedProcessJailPlatform::MacosSandboxExec,
        GovernedProcessJailPlatform::LinuxBubblewrap,
    ] {
        assert_eq!(
            python3_candidate(platform, &candidate).err().unwrap().code,
            GovernedProcessJailErrorCode::InterpreterUnavailable
        );
        assert_eq!(
            python3_from_candidates(platform, &[candidate.as_path()]).err().unwrap().code,
            GovernedProcessJailErrorCode::InterpreterUnavailable
        );
    }
    // The layout itself is well formed; only ownership refuses it.
    assert!(macos_python3_layout(&candidate, GovernedJailInterpreterVersion { major: 3, minor: 9 }).is_some());

    // A symlink in a user-owned directory to a genuinely trusted interpreter.
    if let Ok(trusted) = GovernedJailInterpreter::python3_for_host() {
        let link = root_path.join("python3");
        std::os::unix::fs::symlink(&trusted.executable, &link).unwrap();
        assert!(python3_candidate(trusted.platform, &link).is_err());
    }
}

/// The library-tree walk applies its predicate to every entry at any depth,
/// checks but does not descend into denied subtrees, and is bounded. The
/// real predicate refuses user-owned entries and accepts root-owned ones.
#[test]
fn library_tree_walk_checks_every_entry_prunes_denied_subtrees_and_is_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(directory.path()).unwrap();
    fs::create_dir_all(root.join("a/b")).unwrap();
    fs::write(root.join("a/b/file"), b"").unwrap();
    fs::create_dir_all(root.join("denied/inner")).unwrap();
    fs::write(root.join("denied/inner/bad"), b"").unwrap();
    let named = |name: &'static str| {
        move |path: &Path, _: &fs::Metadata| path.file_name() != Some(std::ffi::OsStr::new(name))
    };
    let code = |result: Result<(), GovernedProcessJailError>| result.unwrap_err().code;
    // A refused entry three levels deep is found.
    assert_eq!(
        code(walk_tree(&root, &[], 100, named("file"))),
        GovernedProcessJailErrorCode::InterpreterUnavailable
    );
    assert_eq!(
        code(walk_tree(&root, &[], 100, named("bad"))),
        GovernedProcessJailErrorCode::InterpreterUnavailable
    );
    // Under a denied subtree it is never visited, yet the denied entry
    // itself is still checked.
    let denied = [root.join("denied")];
    assert!(walk_tree(&root, &denied, 100, named("bad")).is_ok());
    assert!(walk_tree(&root, &denied, 100, named("inner")).is_ok());
    assert!(walk_tree(&root, &denied, 100, named("denied")).is_err());
    // Six entries: a, a/b, a/b/file, denied, denied/inner, denied/inner/bad.
    assert!(walk_tree(&root, &[], 6, |_, _| true).is_ok());
    assert_eq!(
        code(walk_tree(&root, &[], 5, |_, _| true)),
        GovernedProcessJailErrorCode::InterpreterUnavailable
    );
    // The real predicate.
    assert!(!trusted_tree_entry(&fs::symlink_metadata(root.join("a/b/file")).unwrap()));
    assert!(trusted_tree_entry(&fs::symlink_metadata("/usr/lib").unwrap()));
    assert_eq!(
        code(validate_trusted_tree(&root, &[])),
        GovernedProcessJailErrorCode::InterpreterUnavailable
    );
}

/// Linux (pure; runs on every host): a synthetic little-endian ELF64 with a
/// dynamic section, as a shared-libpython launcher would have.
fn elf_with_needed(machine: u16, needed: &[&str]) -> Vec<u8> {
    const BASE: u64 = 0x40_0000;
    let dynamic_offset = 64 + 2 * 56;
    let dynamic_size = (needed.len() + 2) * 16;
    let strings_offset = dynamic_offset + dynamic_size;
    let mut strings = vec![0_u8];
    let mut name_offsets = Vec::new();
    for name in needed {
        name_offsets.push(strings.len() as u64);
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
    }
    let total = strings_offset + strings.len();
    let mut bytes = vec![0_u8; 64];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[0x12..0x14].copy_from_slice(&machine.to_le_bytes());
    bytes[0x20..0x28].copy_from_slice(&64_u64.to_le_bytes());
    bytes[0x36..0x38].copy_from_slice(&56_u16.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&2_u16.to_le_bytes());
    for (kind, offset, size) in [(1_u32, 0_u64, total as u64), (2, dynamic_offset as u64, dynamic_size as u64)] {
        let mut header = vec![0_u8; 56];
        header[..4].copy_from_slice(&kind.to_le_bytes());
        header[8..16].copy_from_slice(&offset.to_le_bytes());
        header[16..24].copy_from_slice(&(BASE + offset).to_le_bytes());
        header[32..40].copy_from_slice(&size.to_le_bytes());
        bytes.extend(header);
    }
    for (tag, value) in name_offsets
        .iter()
        .map(|offset| (1_u64, *offset))
        .chain([(5, BASE + strings_offset as u64), (0, 0)])
    {
        bytes.extend(tag.to_le_bytes());
        bytes.extend(value.to_le_bytes());
    }
    bytes.extend(strings);
    bytes
}

#[test]
fn elf_dynamic_section_yields_needed_libraries() {
    let bytes = elf_with_needed(62, &["libc.so.6", "libpython3.12.so.1.0"]);
    assert_eq!(
        elf64_needed(&bytes).unwrap(),
        ["libc.so.6".to_owned(), "libpython3.12.so.1.0".to_owned()]
    );
    assert_eq!(elf64_multiarch(&bytes), Some("x86_64-linux-gnu"));
    assert_eq!(elf64_multiarch(&elf_with_needed(183, &[])), Some("aarch64-linux-gnu"));
    assert_eq!(elf64_needed(&elf_with_needed(62, &[])).unwrap(), Vec::<String>::new());
    // Not ELF64 little-endian, or truncated: refused.
    assert_eq!(elf64_needed(b"#!/bin/sh\n"), None);
    let mut big_endian = bytes.clone();
    big_endian[5] = 2;
    assert_eq!(elf64_needed(&big_endian), None);
    assert_eq!(elf64_needed(&bytes[..bytes.len() - 8]), None);
    assert_eq!(elf64_needed(&bytes[..100]), None);
}

/// Arch links `/usr/lib64` to `lib`: the layout keeps one canonical stdlib
/// root and finds a shared libpython there; other libpython names, or one
/// that is missing, refuse.
#[test]
fn linux_layout_dedupes_a_symlinked_lib64_and_pins_a_shared_libpython() {
    let directory = tempfile::tempdir().unwrap();
    let prefix = fs::canonicalize(directory.path()).unwrap();
    fs::create_dir_all(prefix.join("bin")).unwrap();
    fs::create_dir_all(prefix.join("lib/python3.12")).unwrap();
    fs::write(prefix.join("lib/python3.12/os.py"), b"").unwrap();
    std::os::unix::fs::symlink("lib", prefix.join("lib64")).unwrap();
    let version = GovernedJailInterpreterVersion { major: 3, minor: 12 };
    let python = prefix.join("bin/python3.12");

    fs::write(&python, elf_with_needed(62, &["libc.so.6"])).unwrap();
    let layout = linux_python3_layout(&python, version).unwrap();
    assert_eq!(layout.library_roots, [prefix.join("lib/python3.12")]);
    assert!(layout.images.is_empty());
    assert_eq!(
        canonical_unique_directories([
            prefix.join("lib64/python3.12"),
            prefix.join("lib/python3.12"),
            prefix.join("absent"),
        ]),
        [prefix.join("lib/python3.12")]
    );

    fs::write(&python, elf_with_needed(62, &["libpython3.12.so.1.0", "libc.so.6"])).unwrap();
    assert!(linux_python3_layout(&python, version).is_none(), "missing libpython refuses");
    fs::write(prefix.join("lib/libpython3.12.so.1.0"), b"image").unwrap();
    let layout = linux_python3_layout(&python, version).unwrap();
    assert_eq!(layout.images, [prefix.join("lib/libpython3.12.so.1.0")]);

    fs::write(&python, elf_with_needed(62, &["libpython3.11.so.1.0"])).unwrap();
    assert!(linux_python3_layout(&python, version).is_none(), "another version refuses");
    fs::write(&python, b"not an elf").unwrap();
    assert!(linux_python3_layout(&python, version).is_none(), "unparseable refuses");

    // A needed libpython that is only a symlink is not a trusted image.
    let directories = [prefix.join("lib")];
    fs::remove_file(prefix.join("lib/libpython3.12.so.1.0")).unwrap();
    fs::write(prefix.join("lib/real.so"), b"image").unwrap();
    std::os::unix::fs::symlink("real.so", prefix.join("lib/libpython3.12.so.1.0")).unwrap();
    assert!(linux_libpython_images(&["libpython3.12.so.1.0".to_owned()], version, &directories).is_none());
}

/// A python.org framework left admin-group-writable is not trusted: any
/// admin user could replace its bytes.
#[cfg(target_os = "macos")]
#[test]
fn group_writable_python_org_framework_is_refused() {
    use std::os::unix::fs::MetadataExt;

    let candidate = Path::new(GOVERNED_JAIL_MACOS_PYTHON3_CANDIDATES[0]);
    let Ok(real) = fs::canonicalize(candidate) else {
        return;
    };
    let group_writable = real
        .ancestors()
        .any(|ancestor| fs::symlink_metadata(ancestor).is_ok_and(|metadata| metadata.mode() & 0o022 != 0));
    if group_writable {
        assert_eq!(
            python3_candidate(GovernedProcessJailPlatform::MacosSandboxExec, candidate)
                .err()
                .unwrap()
                .code,
            GovernedProcessJailErrorCode::InterpreterUnavailable
        );
    }
}

/// A jail refuses an interpreter discovered for another platform.
#[test]
fn an_interpreter_for_another_platform_is_refused() {
    let Ok(interpreter) = GovernedJailInterpreter::python3_for_host() else {
        return;
    };
    let Ok(mut jail) = GovernedProcessJail::strict_app(GovernedProcessJailLimits::default()) else {
        return;
    };
    jail.platform = match jail.platform {
        GovernedProcessJailPlatform::MacosSandboxExec => GovernedProcessJailPlatform::LinuxBubblewrap,
        GovernedProcessJailPlatform::LinuxBubblewrap => GovernedProcessJailPlatform::MacosSandboxExec,
    };
    assert_eq!(
        jail.with_interpreter(interpreter).err().unwrap().code,
        GovernedProcessJailErrorCode::InterpreterUnavailable
    );
}

/// A reviewed script, installed in its own PATH directory.
struct Script {
    directory: tempfile::TempDir,
    digest: [u8; 32],
}

const SCRIPT_NAME: &str = "skill-script";

impl Script {
    fn new(source: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(SCRIPT_NAME);
        let bytes = format!("#!/usr/bin/env python3\n{source}");
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            directory,
            digest: *blake3::hash(bytes.as_bytes()).as_bytes(),
        }
    }

    fn search_path(&self) -> String {
        fs::canonicalize(self.directory.path())
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }

    fn run(&self, jail: GovernedProcessJail, arguments: &[&str]) -> JailedRun {
        try_run_in_jail(jail, &self.search_path(), SCRIPT_NAME, arguments, &[], Some(self.digest))
            .unwrap()
    }
}

/// The trusted host interpreter. On macOS it skips only when no candidate is
/// installed at all; installed but untrusted candidates fail the test run.
fn host_interpreter() -> Option<GovernedJailInterpreter> {
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &GOVERNED_JAIL_MACOS_PYTHON3_CANDIDATES
    } else {
        &GOVERNED_JAIL_LINUX_PYTHON3_CANDIDATES
    };
    match GovernedJailInterpreter::python3_for_host() {
        Ok(interpreter) => Some(interpreter),
        Err(error) if candidates.iter().all(|candidate| !Path::new(candidate).exists()) => {
            skip(&format!("no python3 candidate installed: {error}"));
            None
        },
        Err(error) => {
            skip(&format!("no trusted python3 on this host: {error}"));
            None
        },
    }
}

fn strict_jail(interpreter: GovernedJailInterpreter) -> Option<GovernedProcessJail> {
    match GovernedProcessJail::strict_app(GovernedProcessJailLimits::default()) {
        Ok(jail) => Some(jail.with_interpreter(interpreter).unwrap()),
        Err(error)
            if matches!(
                error.code,
                GovernedProcessJailErrorCode::LauncherUnavailable
                    | GovernedProcessJailErrorCode::JailHelperUnavailable
            ) =>
        {
            skip(&format!("no jail launcher or helper on this host: {error}"));
            None
        },
        Err(error) => panic!("unexpected strict jail setup failure: {error}"),
    }
}

fn json(run: &JailedRun) -> serde_json::Value {
    assert_eq!(
        run.terminal,
        GovernedExecutionTerminal::Success,
        "exit={:?} stdout={} stderr={}",
        run.exit_code,
        run.stdout,
        run.stderr
    );
    serde_json::from_str(run.stdout.trim())
        .unwrap_or_else(|error| panic!("{error}: stdout={} stderr={}", run.stdout, run.stderr))
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{sync::atomic::Ordering, thread, time::Duration};

    use super::super::egress_tests::{JailRunError, TestBroker, Tripwire, TUNNEL_BODY};
    use super::*;
    use crate::{
        governed_batch_process::GovernedBatchProcessErrorCode,
        governed_execution_authority::GovernedExecutionAuthorityErrorCode,
    };

    #[test]
    fn host_discovery_pins_a_trusted_framework_python() {
        let Some(interpreter) = host_interpreter() else {
            return;
        };
        assert_eq!(interpreter.kind(), GovernedJailInterpreterKind::Python3);
        assert_eq!(interpreter.version().major, 3);
        assert_ne!(interpreter.executable, Path::new("/usr/bin/python3"));
        assert!(interpreter
            .executable
            .ends_with("Resources/Python.app/Contents/MacOS/Python"));
        assert_eq!(interpreter.images.len(), 1);
        assert!(interpreter.denied_roots[0].ends_with("site-packages"));
        let again = GovernedJailInterpreter::python3_for_host().unwrap();
        assert_eq!(again.digest(), interpreter.digest());
        assert_eq!(again.version(), interpreter.version());
    }

    /// A reviewed Python script prints JSON in the strict jail. The expected
    /// executable digest binds the script bytes; the audit names the
    /// interpreter; the strict schema is unchanged.
    #[test]
    fn script_prints_json_in_the_strict_jail() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(interpreter) = host_interpreter() else {
            return;
        };
        let version = interpreter.version();
        let digest = interpreter.digest();
        let Some(jail) = strict_jail(interpreter) else {
            return;
        };
        assert_eq!(jail.schema_version(), GOVERNED_PROCESS_JAIL_V1);
        assert_ne!(
            jail.profile_identity(),
            governed_process_jail_profile_identity(jail.platform(), GovernedProcessJailNetwork::Denied)
        );
        let audit = jail.audit();
        let evidence = audit.interpreter.unwrap();
        assert_eq!(evidence.schema_version, GOVERNED_JAIL_INTERPRETER_V1);
        assert_eq!((evidence.version, evidence.digest), (version, digest));
        assert!(evidence.script_exec_denied && evidence.launch_user_site_disabled);
        assert!(evidence.site_packages_read_denied);
        assert_eq!(
            evidence.profile_identity,
            governed_process_jail_interpreter_profile_identity(
                GovernedProcessJailPlatform::MacosSandboxExec,
                GovernedProcessJailNetwork::Denied,
                GovernedJailInterpreterKind::Python3,
                version,
            )
        );
        assert_eq!(evidence.profile_identity, jail.profile_identity());
        let audit_json = serde_json::to_value(audit).unwrap();
        assert_eq!(audit_json["interpreter"]["kind"], "python3");
        assert_eq!(audit_json["interpreter"]["version"], version.to_string());
        assert_eq!(audit_json["interpreter"]["launch_flags"], serde_json::json!(["-I", "-S", "-B"]));
        assert!(audit_json.get("egress").is_none());
        let rendered = audit_json.to_string();
        assert!(!rendered.contains("/Library") && !rendered.contains("/usr/"), "{rendered}");

        let script = Script::new(
            "import json, sys, urllib.request, ssl, xml.etree.ElementTree\n\
             ssl.create_default_context()\n\
             print(json.dumps({'ok': True, 'argv': sys.argv[1:],\n\
             \x20   'version': '%d.%d' % sys.version_info[:2],\n\
             \x20   'flags': [sys.flags.isolated, sys.flags.no_site, sys.flags.no_user_site,\n\
             \x20             sys.flags.dont_write_bytecode, sys.flags.ignore_environment]}))\n",
        );
        let run = script.run(jail, &["--query", "ti:jail"]);
        let output = json(&run);
        assert_eq!(output["ok"], true);
        assert_eq!(output["argv"], serde_json::json!(["--query", "ti:jail"]));
        assert_eq!(output["version"], version.to_string());
        assert_eq!(output["flags"], serde_json::json!([1, 1, 1, 1, 1]));

        // The install-review digest binds the SCRIPT bytes: another digest
        // is refused before dispatch.
        let Some(jail) = strict_jail(GovernedJailInterpreter::python3_for_host().unwrap()) else {
            return;
        };
        let refused = try_run_in_jail(jail, &script.search_path(), SCRIPT_NAME, &[], &[], Some([7; 32]));
        assert_eq!(
            refused.err(),
            Some(JailRunError::Authority(GovernedExecutionAuthorityErrorCode::ExecutableChanged))
        );
    }

    /// Nothing written to the workdir can be mapped executable: a native
    /// extension copied there cannot be loaded with `ctypes`, while the same
    /// module loads from the read-only stdlib.
    #[test]
    fn native_code_written_to_the_workdir_cannot_be_loaded() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(jail) = host_interpreter().and_then(strict_jail) else {
            return;
        };
        let script = Script::new(
            "import ctypes, glob, json, os, shutil\n\
             dynload = os.path.join(os.path.dirname(os.__file__), 'lib-dynload')\n\
             source = sorted(glob.glob(os.path.join(dynload, '_json*.so')) or glob.glob(os.path.join(dynload, '*.so')))[0]\n\
             copy = os.path.join(os.getcwd(), 'planted.so')\n\
             shutil.copyfile(source, copy)\n\
             out = {'copied': os.path.getsize(copy) == os.path.getsize(source)}\n\
             def load(name, path):\n\
             \x20   try:\n\
             \x20       ctypes.CDLL(path)\n\
             \x20       out[name] = 'loaded'\n\
             \x20   except OSError as error:\n\
             \x20       out[name] = str(error)\n\
             load('stdlib', source)\n\
             load('workdir', copy)\n\
             print(json.dumps(out))\n",
        );
        let output = json(&script.run(jail, &[]));
        assert_eq!(output["copied"], true, "{output}");
        assert_eq!(output["stdlib"], "loaded", "{output}");
        let workdir = output["workdir"].as_str().unwrap();
        assert!(workdir != "loaded" && workdir.contains("sandbox"), "{output}");
    }

    /// The launch flags are hygiene: a script can re-exec the interpreter
    /// without `-I -S -B`, but the re-exec'd interpreter is still inside the
    /// same profile and cannot read the host home or `~/.ssh`.
    #[test]
    fn a_reexec_without_the_launch_flags_stays_inside_the_profile() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(jail) = host_interpreter().and_then(strict_jail) else {
            return;
        };
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        let script = Script::new(
            "import json, os, sys\n\
             if sys.argv[2:] == ['child']:\n\
             \x20   out = {'isolated': sys.flags.isolated, 'no_site': sys.flags.no_site}\n\
             \x20   for name, path in [('ssh', os.path.join(sys.argv[1], '.ssh')), ('home', sys.argv[1])]:\n\
             \x20       try:\n\
             \x20           os.listdir(path)\n\
             \x20           out[name] = 'ok'\n\
             \x20       except BaseException as error:\n\
             \x20           out[name] = type(error).__name__\n\
             \x20   print(json.dumps(out))\n\
             \x20   sys.exit(0)\n\
             sys.stdout.flush()\n\
             os.execv(sys.executable, [sys.executable, sys.argv[0], sys.argv[1], 'child'])\n",
        );
        let output = json(&script.run(jail, &[home.to_str().unwrap()]));
        assert_eq!(output["isolated"], 0, "the re-exec dropped -I: {output}");
        assert_eq!(output["no_site"], 0, "the re-exec dropped -S: {output}");
        assert_eq!(output["home"], "PermissionError", "{output}");
        assert_ne!(output["ssh"], "ok", "{output}");
    }

    /// The jail strips loader injection and the framework launcher override
    /// from the child environment, whatever put them there.
    #[test]
    fn the_child_environment_drops_loader_injection() {
        // Only `harden_environment` is under test; no interpreter is needed.
        let Ok(jail) = GovernedProcessJail::strict_app(GovernedProcessJailLimits::default()) else {
            return;
        };
        let mut command = Command::new("/usr/bin/true");
        command
            .env("DYLD_INSERT_LIBRARIES", "/private/tmp/x.dylib")
            .env("dyld_library_path", "/private/tmp")
            .env("LD_PRELOAD", "/tmp/x.so")
            .env("LD_AUDIT", "/tmp/x.so")
            .env("GLIBC_TUNABLES", "glibc.malloc.check=3")
            .env("__PYVENV_LAUNCHER__", "/private/tmp/python")
            .env("KEPT", "1")
            .env("OLD_LD_FLAGS", "1");
        jail.harden_environment(&mut command);
        let environment = command
            .get_envs()
            .map(|(name, value)| (name.to_str().unwrap().to_owned(), value.is_some()))
            .collect::<std::collections::BTreeMap<_, _>>();
        for removed in [
            "DYLD_INSERT_LIBRARIES",
            "dyld_library_path",
            "LD_PRELOAD",
            "LD_AUDIT",
            "GLIBC_TUNABLES",
            "__PYVENV_LAUNCHER__",
        ] {
            assert_eq!(environment.get(removed), Some(&false), "{removed}");
        }
        assert_eq!(environment.get("KEPT"), Some(&true));
        assert_eq!(environment.get("OLD_LD_FLAGS"), Some(&true));
    }

    #[test]
    fn script_cannot_fork_or_exec_anything() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(jail) = host_interpreter().and_then(strict_jail) else {
            return;
        };
        let script = Script::new(
            "import json, os, subprocess, sys\n\
             out = {}\n\
             def attempt(name, action):\n\
             \x20   try:\n\
             \x20       out[name] = action()\n\
             \x20   except BaseException as error:\n\
             \x20       out[name] = type(error).__name__\n\
             def fork():\n\
             \x20   pid = os.fork()\n\
             \x20   if pid == 0:\n\
             \x20       os._exit(0)\n\
             \x20   return 'forked'\n\
             attempt('system', lambda: os.system('/usr/bin/true'))\n\
             attempt('subprocess', lambda: subprocess.run(['/usr/bin/true']).returncode)\n\
             attempt('fork', fork)\n\
             attempt('execv_sh', lambda: os.execv('/bin/sh', ['sh', '-c', 'echo escaped']))\n\
             attempt('execv_script', lambda: os.execv(sys.argv[0], [sys.argv[0]]))\n\
             print(json.dumps(out))\n",
        );
        let run = script.run(jail, &[]);
        let output = json(&run);
        assert!(!run.stdout.contains("escaped"));
        assert_ne!(output["system"], 0, "{output}");
        assert_eq!(output["subprocess"], "PermissionError", "{output}");
        assert_eq!(output["fork"], "PermissionError", "{output}");
        assert_eq!(output["execv_sh"], "PermissionError", "{output}");
        assert_eq!(output["execv_script"], "PermissionError", "{output}");
    }

    #[test]
    fn script_cannot_read_or_write_outside_its_roots() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(jail) = host_interpreter().and_then(strict_jail) else {
            return;
        };
        let outside = tempfile::tempdir().unwrap();
        let outside_path = fs::canonicalize(outside.path()).unwrap();
        let secret = outside_path.join("secret.txt");
        fs::write(&secret, b"host-secret").unwrap();
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        let script = Script::new(
            "import json, os, sys\n\
             secret, outside, home = sys.argv[1:4]\n\
             out = {}\n\
             def attempt(name, action):\n\
             \x20   try:\n\
             \x20       action()\n\
             \x20       out[name] = 'ok'\n\
             \x20   except BaseException as error:\n\
             \x20       out[name] = type(error).__name__\n\
             attempt('secret', lambda: open(secret).read())\n\
             attempt('outside_write', lambda: open(os.path.join(outside, 'planted'), 'w').write('x'))\n\
             attempt('ssh', lambda: os.listdir(os.path.join(home, '.ssh')))\n\
             attempt('ssh_key', lambda: open(os.path.join(home, '.ssh', 'id_ed25519')).read())\n\
             attempt('home', lambda: os.listdir(home))\n\
             attempt('passwd', lambda: open('/private/etc/passwd').read())\n\
             attempt('own_script', lambda: open(sys.argv[0]).read())\n\
             attempt('workdir', lambda: open('scratch', 'w').write('x'))\n\
             print(json.dumps(out))\n",
        );
        let run = script.run(
            jail,
            &[
                secret.to_str().unwrap(),
                outside_path.to_str().unwrap(),
                home.to_str().unwrap(),
            ],
        );
        let output = json(&run);
        for denied in ["secret", "outside_write", "ssh", "ssh_key", "home", "passwd"] {
            assert_ne!(output[denied], "ok", "{denied}: {output}");
        }
        assert_eq!(output["secret"], "PermissionError", "{output}");
        assert_eq!(output["home"], "PermissionError", "{output}");
        assert_eq!(output["own_script"], "ok", "{output}");
        assert_eq!(output["workdir"], "ok", "{output}");
        assert!(!outside_path.join("planted").exists());
        assert!(!run.stdout.contains("host-secret"));
    }

    /// A user site planted in the jail's own (writable) HOME is never
    /// imported, even after an explicit `site.main()`; the host user site and
    /// the stdlib `site-packages` are unreadable.
    #[test]
    fn script_cannot_import_from_user_site_packages() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(jail) = host_interpreter().and_then(strict_jail) else {
            return;
        };
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        let host_user_site = home.join("Library/Python");
        let script = Script::new(
            "import importlib, json, os, sys\n\
             home = os.environ['HOME']\n\
             version = '%d.%d' % sys.version_info[:2]\n\
             for directory in [os.path.join(home, 'Library', 'Python', version, 'lib', 'python', 'site-packages'),\n\
             \x20                 os.path.join(home, '.local', 'lib', 'python' + version, 'site-packages')]:\n\
             \x20   os.makedirs(directory, exist_ok=True)\n\
             \x20   open(os.path.join(directory, 'planted_user_site.py'), 'w').write('VALUE = 1\\n')\n\
             def attempt():\n\
             \x20   try:\n\
             \x20       importlib.import_module('planted_user_site')\n\
             \x20       return 'imported'\n\
             \x20   except BaseException as error:\n\
             \x20       return type(error).__name__\n\
             def listing(path):\n\
             \x20   try:\n\
             \x20       os.listdir(path)\n\
             \x20       return 'ok'\n\
             \x20   except BaseException as error:\n\
             \x20       return type(error).__name__\n\
             out = {'site_loaded': 'site' in sys.modules, 'before': attempt()}\n\
             import site\n\
             try:\n\
             \x20   site.main()\n\
             except BaseException as error:\n\
             \x20   out['site_main'] = type(error).__name__\n\
             out['after'] = attempt()\n\
             out['user_site_enabled'] = bool(site.ENABLE_USER_SITE)\n\
             out['host_user_site'] = listing(sys.argv[1])\n\
             out['stdlib_site_packages'] = listing(os.path.join(os.path.dirname(os.__file__), 'site-packages'))\n\
             print(json.dumps(out))\n",
        );
        let run = script.run(jail, &[host_user_site.to_str().unwrap()]);
        let output = json(&run);
        assert_eq!(output["site_loaded"], false, "{output}");
        assert_eq!(output["before"], "ModuleNotFoundError", "{output}");
        assert_eq!(output["after"], "ModuleNotFoundError", "{output}");
        assert_eq!(output["user_site_enabled"], false, "{output}");
        assert_ne!(output["host_user_site"], "ok", "{output}");
        assert_eq!(output["stdlib_site_packages"], "PermissionError", "{output}");
    }

    /// Interpreter mode composes with brokered egress: `urllib.request`
    /// takes the proxy from the jail's `HTTPS_PROXY` and sends CONNECT to
    /// the broker; a tunnel through the same proxy relays bytes end to end;
    /// a direct connection and DNS are refused.
    #[test]
    fn brokered_egress_reaches_only_the_broker_from_python() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(interpreter) = host_interpreter() else {
            return;
        };
        let broker = TestBroker::start();
        let tripwire = Tripwire::start();
        let jail = match GovernedProcessJail::strict_app_with_brokered_egress(
            GovernedProcessJailLimits::default(),
            GovernedEgressBrokerEndpoint::LoopbackTcp {
                port: NonZeroU16::new(broker.port).unwrap(),
            },
        ) {
            Ok(jail) => jail.with_interpreter(interpreter).unwrap(),
            Err(error) if error.code == GovernedProcessJailErrorCode::LauncherUnavailable => return,
            Err(error) => panic!("unexpected brokered jail setup failure: {error}"),
        };
        assert_eq!(jail.schema_version(), GOVERNED_PROCESS_JAIL_BROKERED_EGRESS_V1);
        let audit = jail.audit();
        assert_eq!(audit.egress.unwrap().profile_identity, jail.profile_identity());
        assert_eq!(audit.interpreter.unwrap().profile_identity, jail.profile_identity());
        let script = Script::new(
            "import json, socket, sys, urllib.parse, urllib.request\n\
             out = {}\n\
             proxy = urllib.request.getproxies().get('https')\n\
             out['proxy'] = proxy\n\
             try:\n\
             \x20   urllib.request.urlopen('https://refused.example/', timeout=10)\n\
             \x20   out['urllib'] = 'ok'\n\
             except BaseException as error:\n\
             \x20   out['urllib'] = str(error)\n\
             parts = urllib.parse.urlsplit(proxy)\n\
             tunnel = socket.create_connection((parts.hostname, parts.port), timeout=10)\n\
             tunnel.sendall(b'CONNECT allowed.example:80 HTTP/1.1\\r\\nHost: allowed.example:80\\r\\n\\r\\n')\n\
             head = b''\n\
             while not head.endswith(b'\\r\\n\\r\\n'):\n\
             \x20   head += tunnel.recv(1)\n\
             out['connect'] = head.split(b'\\r\\n')[0].decode()\n\
             tunnel.sendall(b'GET / HTTP/1.1\\r\\nHost: allowed.example\\r\\n\\r\\n')\n\
             body = b''\n\
             while True:\n\
             \x20   chunk = tunnel.recv(4096)\n\
             \x20   if not chunk:\n\
             \x20       break\n\
             \x20   body += chunk\n\
             out['body'] = body.split(b'\\r\\n\\r\\n', 1)[1].decode()\n\
             try:\n\
             \x20   socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=3)\n\
             \x20   out['direct'] = 'connected'\n\
             except BaseException as error:\n\
             \x20   out['direct'] = type(error).__name__\n\
             try:\n\
             \x20   socket.getaddrinfo('example.com', 80)\n\
             \x20   out['dns'] = 'resolved'\n\
             except BaseException as error:\n\
             \x20   out['dns'] = type(error).__name__\n\
             print(json.dumps(out))\n",
        );
        let run = script.run(jail, &[&tripwire.port.to_string()]);
        let output = json(&run);
        assert_eq!(output["proxy"], format!("http://127.0.0.1:{}", broker.port), "{output}");
        assert!(output["urllib"].as_str().unwrap().contains("403"), "{output}");
        assert_eq!(output["connect"], "HTTP/1.1 200 Connection established", "{output}");
        assert_eq!(output["body"], TUNNEL_BODY, "{output}");
        assert_eq!(output["direct"], "PermissionError", "{output}");
        assert_eq!(output["dns"], "gaierror", "{output}");
        thread::sleep(Duration::from_millis(100));
        assert_eq!(tripwire.hits.load(Ordering::SeqCst), 0);
        let requests = broker.requests();
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert!(requests[0].starts_with("CONNECT refused.example:443 HTTP/1."), "{requests:?}");
        assert_eq!(requests[1], "CONNECT allowed.example:80 HTTP/1.1");
    }

    /// A pinned interpreter whose bytes no longer match its digest is refused
    /// when a jail takes it, and a bound interpreter that changes before
    /// launch is refused before dispatch.
    #[test]
    fn a_modified_interpreter_is_refused() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(mut interpreter) = host_interpreter() else {
            return;
        };
        interpreter.digest = GovernedProcessJailDigest([0; 32]);
        let Ok(jail) = GovernedProcessJail::strict_app(GovernedProcessJailLimits::default()) else {
            return;
        };
        assert_eq!(
            jail.with_interpreter(interpreter).err().unwrap().code,
            GovernedProcessJailErrorCode::InterpreterUnavailable
        );

        let Some(mut jail) = host_interpreter().and_then(strict_jail) else {
            return;
        };
        jail.interpreter.as_mut().unwrap().digest = GovernedProcessJailDigest([0; 32]);
        let script = Script::new("print('must not run')\n");
        let refused = try_run_in_jail(jail, &script.search_path(), SCRIPT_NAME, &[], &[], None);
        assert_eq!(
            refused.err(),
            Some(JailRunError::Batch(GovernedBatchProcessErrorCode::InterpreterUnavailable))
        );

        // A swapped, user-owned executable is refused too.
        let Some(mut interpreter) = host_interpreter() else {
            return;
        };
        let impostor = tempfile::NamedTempFile::new().unwrap();
        interpreter.executable = fs::canonicalize(impostor.path()).unwrap();
        let Ok(jail) = GovernedProcessJail::strict_app(GovernedProcessJailLimits::default()) else {
            return;
        };
        assert_eq!(
            jail.with_interpreter(interpreter).err().unwrap().code,
            GovernedProcessJailErrorCode::InterpreterUnavailable
        );
    }

    /// Regression: the macOS process watchdog sized its group query with a
    /// null buffer, which XNU answers with a system-wide estimate, so any
    /// jailed child that lived long enough to be sampled ended as
    /// `ProcessLimitExceeded`. A child running past several samples, in
    /// strict and interpreter mode, now completes.
    #[test]
    fn a_long_running_jailed_child_is_not_mistaken_for_a_process_breach() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Ok(jail) = GovernedProcessJail::strict_app(GovernedProcessJailLimits::default()) else {
            return;
        };
        let run = try_run_in_jail(jail, "/usr/bin:/bin", "sleep", &["1.5"], &[], None).unwrap();
        assert_eq!(run.terminal, GovernedExecutionTerminal::Success, "stderr={}", run.stderr);
        let Some(jail) = host_interpreter().and_then(strict_jail) else {
            return;
        };
        let script = Script::new("import json, time\ntime.sleep(1.5)\nprint(json.dumps({'ok': True}))\n");
        assert_eq!(json(&script.run(jail, &[]))["ok"], true);
    }

    #[test]
    fn a_jail_takes_one_interpreter() {
        let Some(first) = host_interpreter() else {
            return;
        };
        let Some(jail) = strict_jail(first) else {
            return;
        };
        let second = GovernedJailInterpreter::python3_for_host().unwrap();
        assert_eq!(
            jail.with_interpreter(second).err().unwrap().code,
            GovernedProcessJailErrorCode::InterpreterUnavailable
        );
    }
}

/// NOT EXECUTED on macOS development hosts: needs `bwrap` and a trusted
/// `/usr/bin/python3`; it skips otherwise.
#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    fn strict_jail_with(limits: GovernedProcessJailLimits) -> Option<GovernedProcessJail> {
        let interpreter = host_interpreter()?;
        match GovernedProcessJail::strict_app(limits) {
            Ok(jail) => Some(jail.with_interpreter(interpreter).unwrap()),
            Err(error) => {
                skip(&format!("no Linux strict jail on this host: {error}"));
                None
            },
        }
    }

    /// CI states per leg whether the jail gets a user namespace of its own
    /// (`MAGICRUN_EXPECT_PROCESS_CEILING`); the guarantee must agree.
    #[test]
    fn the_process_ceiling_guarantee_matches_the_host() {
        let Some(jail) = strict_jail_with(GovernedProcessJailLimits::default()) else {
            return;
        };
        match std::env::var("MAGICRUN_EXPECT_PROCESS_CEILING").as_deref() {
            Ok("true") => assert!(jail.guarantees().process_ceiling),
            Ok("false") => assert!(!jail.guarantees().process_ceiling),
            _ => eprintln!("process_ceiling = {}", jail.guarantees().process_ceiling),
        }
    }

    /// Threads count against the task ceiling. With a user namespace of the
    /// jail's own, the kernel stops thread creation at the ceiling (`EAGAIN`,
    /// told apart from memory exhaustion by a `fork` probe at the limit);
    /// without one, the watchdog ends the run while the threads are held.
    /// Small stacks and one malloc arena keep the address-space ceiling out
    /// of the picture: with glibc's defaults, memory ran out after 11-14
    /// threads, well before the ceiling.
    #[test]
    fn a_thread_bomb_is_bounded() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let limits = GovernedProcessJailLimits {
            max_tasks: 32,
            ..GovernedProcessJailLimits::default()
        };
        let Some(jail) = strict_jail_with(limits) else {
            return;
        };
        let exact = jail.guarantees().process_ceiling;
        let script = Script::new(
            "import errno, json, os, sys, threading, time\n\
             threading.stack_size(64 * 1024)\n\
             hold = threading.Event()\n\
             threads = 0\n\
             out = {}\n\
             try:\n\
             \x20   while threads < 200:\n\
             \x20       threading.Thread(target=hold.wait, daemon=True).start()\n\
             \x20       threads += 1\n\
             except RuntimeError as error:\n\
             \x20   out['error'] = str(error)\n\
             out['threads'] = threads\n\
             try:\n\
             \x20   pid = os.fork()\n\
             \x20   if pid == 0:\n\
             \x20       os._exit(0)\n\
             \x20   os.waitpid(pid, 0)\n\
             \x20   out['fork'] = 'ok'\n\
             except OSError as error:\n\
             \x20   out['fork'] = errno.errorcode.get(error.errno, str(error.errno))\n\
             time.sleep(3)\n\
             print(json.dumps(out))\n\
             sys.stdout.flush()\n\
             os._exit(0)\n",
        );
        // One malloc arena: glibc otherwise reserves 64 MiB of address space
        // per thread's arena, which exhausted the address-space ceiling
        // after 11-14 threads, before the task ceiling was reached.
        let run = try_run_in_jail(
            jail,
            &script.search_path(),
            SCRIPT_NAME,
            &[],
            &[("MALLOC_ARENA_MAX", "1")],
            Some(script.digest),
        )
        .unwrap();
        if exact {
            let output = json(&run);
            // Strict mode: the ceiling is max_tasks + 1 (bubblewrap's init),
            // and the interpreter's main thread is one of them.
            let threads = output["threads"].as_u64().unwrap();
            assert!((26..=31).contains(&threads), "{output}");
            assert!(output["error"].as_str().is_some(), "{output}");
            assert_eq!(output["fork"], "EAGAIN", "the task ceiling, not memory: {output}");
        } else {
            assert_eq!(run.terminal, GovernedExecutionTerminal::ProcessLimitExceeded, "stdout={}", run.stdout);
        }
    }

    /// Processes too: forks stop at the ceiling (exact) or the watchdog ends
    /// the run.
    #[test]
    fn a_fork_bomb_is_bounded() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let limits = GovernedProcessJailLimits {
            max_tasks: 16,
            ..GovernedProcessJailLimits::default()
        };
        let Some(jail) = strict_jail_with(limits) else {
            return;
        };
        let exact = jail.guarantees().process_ceiling;
        let script = Script::new(
            "import json, os, signal, time\n\
             children = []\n\
             out = {}\n\
             try:\n\
             \x20   while len(children) < 60:\n\
             \x20       pid = os.fork()\n\
             \x20       if pid == 0:\n\
             \x20           time.sleep(10)\n\
             \x20           os._exit(0)\n\
             \x20       children.append(pid)\n\
             except OSError as error:\n\
             \x20   out['error'] = type(error).__name__\n\
             out['forks'] = len(children)\n\
             time.sleep(2)\n\
             for pid in children:\n\
             \x20   os.kill(pid, signal.SIGKILL)\n\
             \x20   os.waitpid(pid, 0)\n\
             print(json.dumps(out))\n",
        );
        let run = script.run(jail, &[]);
        if exact {
            let output = json(&run);
            let forks = output["forks"].as_u64().unwrap();
            assert!(forks <= 16 && forks >= 8, "{output}");
            assert_eq!(output["error"], "BlockingIOError", "{output}");
        } else {
            assert_eq!(run.terminal, GovernedExecutionTerminal::ProcessLimitExceeded, "stdout={}", run.stdout);
        }
    }

    /// With a ceiling requested, exit 126 with exactly the helper's refusal
    /// line is reported as the jail's failure, not as the command's exit.
    #[test]
    fn a_helper_refusal_is_a_jail_error() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(jail) = strict_jail_with(GovernedProcessJailLimits::default()) else {
            return;
        };
        let exact = jail.guarantees().process_ceiling;
        let script = Script::new(&format!(
            "import sys\nsys.stderr.write({:?})\nsys.stderr.flush()\nsys.exit(126)\n",
            egress_forwarder::JAIL_EXEC_REFUSAL_MARKER
        ));
        let result = try_run_in_jail(jail, &script.search_path(), SCRIPT_NAME, &[], &[], Some(script.digest));
        if exact {
            assert_eq!(
                result.err(),
                Some(super::super::egress_tests::JailRunError::Batch(
                    crate::governed_batch_process::GovernedBatchProcessErrorCode::JailHelperRefused
                ))
            );
        } else {
            // No ceiling requested: the helper cannot refuse, so this is the
            // command's own exit.
            assert_eq!(result.unwrap().exit_code, Some(126));
        }
    }

    /// A process that leaves the jail's process group and session is still
    /// counted: the watchdog follows descendants, not the group.
    #[test]
    fn the_watchdog_counts_a_setsid_escapee() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(jail) = strict_jail_with(GovernedProcessJailLimits::default()) else {
            return;
        };
        let script = Script::new(
            "import json, os, time\n\
             if os.fork() == 0:\n\
             \x20   os.setsid()\n\
             \x20   for _ in range(24):\n\
             \x20       if os.fork() == 0:\n\
             \x20           time.sleep(20)\n\
             \x20           os._exit(0)\n\
             \x20   time.sleep(20)\n\
             \x20   os._exit(0)\n\
             time.sleep(8)\n\
             print(json.dumps({'escaped': True}))\n",
        );
        let run = script.run(jail, &[]);
        assert_eq!(
            run.terminal,
            GovernedExecutionTerminal::ProcessLimitExceeded,
            "stdout={} stderr={}",
            run.stdout,
            run.stderr
        );
    }

    #[test]
    fn linux_script_prints_json_in_the_strict_jail() {
        let _budget = JAIL_PROCESS_BUDGET
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(jail) = host_interpreter().and_then(strict_jail) else {
            return;
        };
        let script = Script::new(
            "import json, subprocess, sys, urllib.request, ssl, xml.etree.ElementTree\n\
             out = {'flags': [sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode]}\n\
             try:\n\
             \x20   subprocess.run(['/bin/sh', '-c', 'true'])\n\
             \x20   out['subprocess'] = 'ran'\n\
             except BaseException as error:\n\
             \x20   out['subprocess'] = type(error).__name__\n\
             print(json.dumps(out))\n",
        );
        let output = json(&script.run(jail, &[]));
        assert_eq!(output["flags"], serde_json::json!([1, 1, 1]));
        assert_ne!(output["subprocess"], "ran");
    }
}
