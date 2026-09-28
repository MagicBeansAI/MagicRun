//! Declared exec roots. The declaration, profile, argv and identity tests run
//! on every host; the live tests launch the real `sandbox-exec` (macOS) or
//! `bwrap` (Linux).

use std::{collections::BTreeSet, os::unix::fs::PermissionsExt};

use super::egress_tests::{skip, try_run_in_jail, JailRunError, JailedRun, JAIL_PROCESS_BUDGET};
use super::*;
use crate::governed_execution::GovernedExecutionTerminal;

fn strings(args: &[OsString]) -> Vec<&str> {
    args.iter().map(|argument| argument.to_str().unwrap()).collect()
}

/// A fixed declaration of plain placeholder paths; no host checks.
fn declared_roots() -> GovernedJailExecRoots {
    GovernedJailExecRoots::declared(
        vec![
            GovernedJailExecRoot::new("/opt/skills/yt-dlp").excluding("config"),
            GovernedJailExecRoot::new("/opt/homebrew"),
        ],
        vec![
            PathBuf::from("/opt/skills/yt-dlp/bin"),
            PathBuf::from("/opt/homebrew/bin"),
        ],
    )
    .unwrap()
}

/// Golden: the exec-roots identities of the fixed declaration above, for
/// both platforms and networks, with and without a pinned interpreter.
#[test]
fn exec_roots_profile_identities_match_the_reviewed_goldens() {
    use GovernedProcessJailNetwork::{BrokeredEgress, Denied};
    use GovernedProcessJailPlatform::{LinuxBubblewrap, MacosSandboxExec};
    let python = |minor| Some((GovernedJailInterpreterKind::Python3, GovernedJailInterpreterVersion { major: 3, minor }));
    let roots = declared_roots();
    for (platform, network, interpreter, expected) in [
        (MacosSandboxExec, Denied, None, "blake3:882dea3f9ad68d30a34b252ecac88df8f3d520d38d4025a41c70837ac6f17758"),
        (MacosSandboxExec, BrokeredEgress, None, "blake3:d24d5fbd8ce3da3bdfabb9f14c34157468e9c42d8141ddcbd8e1c4bd87e33ab3"),
        (MacosSandboxExec, Denied, python(9), "blake3:f9adb289b487c90c1e24641f64d710a49b861fc20e62b66a614e1fcac0b8525a"),
        (MacosSandboxExec, BrokeredEgress, python(9), "blake3:5cad5cae7dddcd3758fee9501fe327bc0f3db18fd00cbd37cf5968d9461263e4"),
        (LinuxBubblewrap, Denied, None, "blake3:d2a6631a44b50757bafa7c8cb2560f0ea76ca695b5175719f24972b236ab9368"),
        (LinuxBubblewrap, BrokeredEgress, None, "blake3:a49b01f659919ac44d421a8b18d46a41ac6c9c2482f97bb96df3d62f96ba1f96"),
        (LinuxBubblewrap, Denied, python(12), "blake3:92c3ee150ccf806b75bc8b4b4ca648293182a5cfc4b47bd4f8fe82520b679465"),
        (LinuxBubblewrap, BrokeredEgress, python(12), "blake3:9ad41a994a396fcb307f94bc27be95c9f2d4425d0facde7c810e382a70fc3cce"),
    ] {
        let identity = governed_process_jail_exec_roots_profile_identity(platform, network, interpreter, &roots);
        assert_eq!(identity.to_string(), expected, "{platform:?} {network:?} {interpreter:?}");
    }
    assert_eq!(
        roots.declaration_digest().to_string(),
        "blake3:eb962b95498e8da018bc6ff9816dc19bdc3829f199d171e88a3627277f6a72bb"
    );
}

/// Exec-roots identities never equal an identity without them, and change
/// with every part of the declaration.
#[test]
fn exec_roots_identity_is_distinct_and_binds_the_declaration() {
    use GovernedProcessJailNetwork::{BrokeredEgress, Denied};
    use GovernedProcessJailPlatform::{LinuxBubblewrap, MacosSandboxExec};
    let (kind, version) = (GovernedJailInterpreterKind::Python3, GovernedJailInterpreterVersion { major: 3, minor: 9 });
    let python = Some((kind, version));
    let roots = declared_roots();
    let mut seen = BTreeSet::new();
    for platform in [MacosSandboxExec, LinuxBubblewrap] {
        for network in [Denied, BrokeredEgress] {
            assert!(seen.insert(governed_process_jail_profile_identity(platform, network).to_string()));
            assert!(seen.insert(
                governed_process_jail_interpreter_profile_identity(platform, network, kind, version).to_string()
            ));
            for interpreter in [None, python] {
                let identity = governed_process_jail_exec_roots_profile_identity(platform, network, interpreter, &roots);
                assert_eq!(
                    identity,
                    governed_process_jail_exec_roots_profile_identity(platform, network, interpreter, &roots)
                );
                assert!(seen.insert(identity.to_string()), "{platform:?} {network:?} {interpreter:?}");
            }
        }
    }
    let variants = [
        GovernedJailExecRoots::declared(
            vec![GovernedJailExecRoot::new("/opt/skills/yt-dlp"), GovernedJailExecRoot::new("/opt/homebrew")],
            vec![PathBuf::from("/opt/skills/yt-dlp/bin"), PathBuf::from("/opt/homebrew/bin")],
        ),
        GovernedJailExecRoots::declared(
            vec![
                GovernedJailExecRoot::new("/opt/skills/yt-dlp").excluding("config"),
                GovernedJailExecRoot::new("/opt/homebrew"),
            ],
            vec![PathBuf::from("/opt/homebrew/bin"), PathBuf::from("/opt/skills/yt-dlp/bin")],
        ),
        GovernedJailExecRoots::declared(
            vec![
                GovernedJailExecRoot::new("/opt/skills/yt-dlp").excluding("config"),
                GovernedJailExecRoot::new("/opt/homebrew"),
            ],
            vec![PathBuf::from("/opt/skills/yt-dlp/bin")],
        ),
        GovernedJailExecRoots::declared(
            vec![
                GovernedJailExecRoot::new("/opt/skills/yt-dlp").excluding("config/.env"),
                GovernedJailExecRoot::new("/opt/homebrew"),
            ],
            vec![PathBuf::from("/opt/skills/yt-dlp/bin"), PathBuf::from("/opt/homebrew/bin")],
        ),
    ];
    for platform in [MacosSandboxExec, LinuxBubblewrap] {
        let base = governed_process_jail_exec_roots_profile_identity(platform, Denied, None, &roots);
        for variant in &variants {
            let variant = variant.as_ref().unwrap();
            assert_ne!(variant.declaration_digest(), roots.declaration_digest());
            assert_ne!(
                governed_process_jail_exec_roots_profile_identity(platform, Denied, None, variant),
                base
            );
        }
    }
}

/// Golden: the macOS exec-roots profile. The strict base is unchanged; the
/// exec-roots allowances follow it, the exclusion denials come last.
#[test]
fn macos_exec_roots_profile_is_byte_identical_to_the_reviewed_golden() {
    let profile = macos_exec_roots_profile(
        Path::new("/opt/skills/yt-dlp/bin/yt"),
        None,
        &declared_roots(),
        Path::new("/private/tmp/private-work"),
        None,
    )
    .unwrap();
    let strict = macos_profile(
        Path::new("/opt/skills/yt-dlp/bin/yt"),
        None,
        Path::new("/private/tmp/private-work"),
    )
    .unwrap();
    assert!(profile.starts_with(&strict));
    assert_eq!(
        &profile[strict.len()..],
        "(allow process-fork)\n\
         (allow signal (target same-sandbox))\n\
         (allow file-write-data (literal \"/dev/null\"))\n\
         (allow file-read* process-exec (subpath \"/bin\"))\n\
         (allow file-read* process-exec (subpath \"/usr/bin\"))\n\
         (allow file-read* process-exec file-map-executable (subpath \"/opt/skills/yt-dlp\"))\n\
         (allow file-read* process-exec file-map-executable (subpath \"/opt/homebrew\"))\n\
         (allow file-read-metadata (literal \"/\"))\n\
         (allow file-read-metadata (literal \"/opt\"))\n\
         (allow file-read-metadata (literal \"/opt/skills\"))\n\
         (allow file-read-metadata (literal \"/private\"))\n\
         (allow file-read-metadata (literal \"/private/tmp\"))\n\
         (deny file-read* process-exec file-map-executable (subpath \"/opt/skills/yt-dlp/config\"))\n"
    );
    // The strict profile's own golden is untouched by this mode.
    assert!(strict.contains("(deny process-fork)\n"));
}

/// Interpreter plus exec roots on macOS: the interpreter is the exec
/// literal, its images and library are readable, its `site-packages` denial
/// and the egress rules come after the exclusions.
#[test]
fn macos_exec_roots_profile_with_interpreter_and_egress() {
    let grants = InterpreterGrants {
        executable: Path::new("/Library/Py.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python"),
        images: vec![Path::new("/Library/Py.framework/Versions/3.9/Py")],
        library_roots: vec![Path::new("/Library/Py.framework/Versions/3.9/lib")],
        denied_roots: vec![Path::new("/Library/Py.framework/Versions/3.9/lib/python3.9/site-packages")],
    };
    let profile = macos_exec_roots_profile(
        grants.executable,
        Some(&grants),
        &declared_roots(),
        Path::new("/private/tmp/private-work"),
        Some(("43127", true)),
    )
    .unwrap();
    let position = |needle: &str| profile.find(needle).unwrap_or_else(|| panic!("{needle}\n{profile}"));
    assert!(profile.contains(
        "(allow process-exec (literal \"/Library/Py.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python\"))"
    ));
    assert!(position("(allow file-read* (literal \"/Library/Py.framework/Versions/3.9/Py\"))")
        < position("(allow process-fork)"));
    assert!(position("(deny file-read* process-exec file-map-executable (subpath \"/opt/skills/yt-dlp/config\"))")
        < position("(deny file-read* (subpath \"/Library/Py.framework/Versions/3.9/lib/python3.9/site-packages\"))"));
    assert!(profile.ends_with("(allow network-outbound (remote tcp4 \"localhost:43127\"))\n"));
    assert!(!profile.contains("mach-lookup"));
}

/// Hostile characters in a root are escaped with the strict profile's own
/// SBPL escaping; control characters are refused.
#[test]
fn exec_roots_are_escaped_or_refused() {
    let roots = GovernedJailExecRoots::declared(
        vec![GovernedJailExecRoot::new("/opt/a\"b) (allow default)/ünï").excluding("c\\d")],
        vec![],
    )
    .unwrap();
    let rules = roots.macos_allow_rules(Path::new("/private/tmp/w")).unwrap()
        + &roots.macos_deny_rules().unwrap();
    assert!(rules.contains("(subpath \"/opt/a\\\"b) (allow default)/ünï\")"), "{rules}");
    assert!(rules.contains("(subpath \"/opt/a\\\"b) (allow default)/ünï/c\\\\d\")"), "{rules}");
    for bad in ["/opt/a\nb", "/opt/a\rb", "/opt/a\0b"] {
        assert!(GovernedJailExecRoots::declared(vec![GovernedJailExecRoot::new(bad)], vec![]).is_err(), "{bad:?}");
    }
}

/// Golden: the Linux exec-roots argv. No `/app`; the system exec
/// directories, the roots and the masks are bound before `/work`; the
/// declared `PATH` and the overlay are set; the installed program runs
/// through the same helper.
#[test]
fn linux_exec_roots_argv_is_identical_to_the_reviewed_golden() {
    let roots = declared_roots();
    let masks = vec![
        (PathBuf::from("/opt/skills/yt-dlp/config"), LinuxMask::Directory),
        (PathBuf::from("/opt/skills/yt-dlp/.env"), LinuxMask::File),
    ];
    let mounts = LinuxExecRootMounts {
        system: vec![Path::new("/bin"), Path::new("/usr/bin"), Path::new("/usr/lib")],
        roots: &roots,
        masks: &masks,
        path: roots.child_path(),
    };
    let exec = LinuxJailExec {
        helper: Path::new("/usr/libexec/magicrun/magicrun-jail-egress-forwarder"),
        status_fd: OsString::from("5"),
        task_ceiling: Some((OsString::from("257"), OsString::from("4026531837"))),
    };
    let args = linux_bwrap_args_for(
        &[Path::new("/lib"), Path::new("/lib64")],
        LinuxJailProgram::ExecRoots {
            mounts: &mounts,
            program: Path::new("/opt/skills/yt-dlp/bin/yt"),
        },
        Path::new("/tmp/private-work"),
        &exec,
        None,
        None,
    );
    assert_eq!(
        strings(&args),
        [
            "--die-with-parent", "--unshare-all", "--tmpfs", "/", "--dir", "/work", "--proc",
            "/proc", "--dev", "/dev", "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/bin", "/bin", "--ro-bind", "/usr/bin", "/usr/bin", "--ro-bind",
            "/usr/lib", "/usr/lib", "--ro-bind", "/opt/skills/yt-dlp", "/opt/skills/yt-dlp",
            "--ro-bind", "/opt/homebrew", "/opt/homebrew", "--tmpfs", "/opt/skills/yt-dlp/config",
            "--remount-ro", "/opt/skills/yt-dlp/config", "--ro-bind", "/dev/null",
            "/opt/skills/yt-dlp/.env", "--bind", "/tmp/private-work", "/work", "--ro-bind",
            "/usr/libexec/magicrun/magicrun-jail-egress-forwarder", "/run/magicrun/jail-helper",
            "--remount-ro", "/", "--remount-ro", "/proc", "--remount-ro", "/dev", "--chdir",
            "/work", "--setenv", "HOME", "/work", "--setenv", "TMPDIR", "/work", "--setenv", "TMP",
            "/work", "--setenv", "TEMP", "/work", "--setenv", "PATH",
            "/opt/skills/yt-dlp/bin:/opt/homebrew/bin:/usr/bin:/bin", "--setenv",
            "PYTHONNOUSERSITE", "1", "--setenv", "PYTHONDONTWRITEBYTECODE", "1", "--",
            "/run/magicrun/jail-helper", "--magicrun-jail-exec-v1", "257", "4026531837", "5", "--",
            "/opt/skills/yt-dlp/bin/yt",
        ]
    );

    // Interpreter and brokered egress compose: the interpreter binds and
    // the forwarder role are added, the flags are `-s -B`.
    let grants = InterpreterGrants {
        executable: Path::new("/usr/bin/python3.12"),
        images: Vec::new(),
        library_roots: vec![Path::new("/usr/lib/python3.12")],
        denied_roots: Vec::new(),
    };
    let egress = LinuxEgressMounts {
        socket: Path::new("/run/user/1000/broker.sock"),
        trust_bundle: None,
        environment: egress_environment_template("http://127.0.0.1:3128", None),
    };
    let args = linux_bwrap_args_for(
        &[Path::new("/lib")],
        LinuxJailProgram::ExecRoots {
            mounts: &mounts,
            program: Path::new("/opt/skills/yt-dlp/main.py"),
        },
        Path::new("/tmp/private-work"),
        &exec,
        Some(&egress),
        Some(&grants),
    );
    let args = strings(&args);
    assert!(args.ends_with(&[
        "/run/magicrun/jail-helper",
        "--magicrun-jail-egress-forwarder-v1",
        "3128",
        "/run/magicrun/egress.sock",
        "--",
        "/usr/bin/python3.12",
        "-s",
        "-B",
        "/opt/skills/yt-dlp/main.py",
    ]));
    assert!(args.windows(3).any(|window| window == ["--ro-bind", "/usr/lib/python3.12", "/usr/lib/python3.12"]));
    assert!(!args.contains(&"/app") && !args.contains(&"--share-net"));
}

/// Host-independent declaration rules.
#[test]
fn declarations_refuse_unsafe_shapes() {
    let root = |path: &str| GovernedJailExecRoot::new(path);
    let refused = |roots: Vec<GovernedJailExecRoot>, search: Vec<&str>| {
        GovernedJailExecRoots::declared(roots, search.into_iter().map(PathBuf::from).collect())
            .err()
            .map(|error| error.code)
    };
    let invalid = Some(GovernedProcessJailErrorCode::InvalidExecRoots);
    assert_eq!(refused(vec![], vec![]), invalid, "no root");
    assert_eq!(refused(vec![root("/")], vec![]), invalid, "the filesystem root");
    assert_eq!(refused(vec![root("opt/x")], vec![]), invalid, "relative");
    assert_eq!(refused(vec![root("/opt/x/../y")], vec![]), invalid, "not canonical");
    for reserved in ["/proc", "/dev/shm", "/work", "/app/x", "/run", "/run/magicrun/x"] {
        assert_eq!(refused(vec![root(reserved)], vec![]), invalid, "{reserved}");
    }
    assert_eq!(refused(vec![root("/opt/a"), root("/opt/a/b")], vec![]), invalid, "nested roots");
    assert_eq!(refused(vec![root("/opt/a"), root("/opt/a")], vec![]), invalid, "duplicate roots");
    assert_eq!(refused(vec![root("/opt/a").excluding("../b")], vec![]), invalid);
    assert_eq!(refused(vec![root("/opt/a").excluding("/opt/a/config")], vec![]), invalid);
    assert_eq!(refused(vec![root("/opt/a").excluding("")], vec![]), invalid);
    assert_eq!(refused(vec![root("/opt/a").excluding("x").excluding("x")], vec![]), invalid);
    assert_eq!(refused(vec![root("/opt/a")], vec!["/opt/b/bin"]), invalid, "PATH outside the roots");
    assert_eq!(refused(vec![root("/opt/a").excluding("cfg")], vec!["/opt/a/cfg/bin"]), invalid, "PATH excluded");
    assert_eq!(refused(vec![root("/opt/a")], vec!["/opt/a/b:c"]), invalid, "PATH separator");
    assert_eq!(refused(vec![root("/opt/a")], vec!["/opt/a/bin", "/opt/a/bin"]), invalid);
    let many = (0..=MAX_GOVERNED_JAIL_EXEC_ROOTS).map(|index| root(&format!("/opt/r{index}"))).collect();
    assert_eq!(refused(many, vec![]), invalid, "too many roots");
    let excluded = (0..=MAX_GOVERNED_JAIL_EXEC_ROOT_EXCLUSIONS)
        .fold(root("/opt/a"), |root, index| root.excluding(format!("x{index}")));
    assert_eq!(refused(vec![excluded], vec![]), invalid, "too many exclusions");
    let long = format!("/opt/{}", "a".repeat(MAX_GOVERNED_JAIL_EXEC_ROOT_PATH_BYTES));
    assert_eq!(refused(vec![root(&long)], vec![]), invalid, "too long");
    let roots = GovernedJailExecRoots::declared(vec![root("/opt/a").excluding("config")], vec![]).unwrap();
    assert_eq!(roots.child_path(), OsString::from("/usr/bin:/bin"));
    assert!(roots.admits(Path::new("/opt/a/bin/tool")));
    assert!(!roots.admits(Path::new("/opt/a")));
    assert!(!roots.admits(Path::new("/opt/a/config/tool")));
    assert!(!roots.admits(Path::new("/opt/ab/tool")));
    assert!(roots.overlaps(Path::new("/opt/a/work")) && roots.overlaps(Path::new("/opt")));
    assert!(!roots.overlaps(Path::new("/opt/b")));
}

/// A private directory usable as a root (owned by this user, 0755).
fn root_directory() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let path = fs::canonicalize(directory.path()).unwrap();
    (directory, path)
}

/// Host rules: `/`, the home directory and its ancestors, a writable root, a
/// symlinked exclusion and a root overlapping the jail's workdir are refused;
/// a symlinked root is canonicalized.
#[test]
fn host_declarations_refuse_unsafe_roots() {
    let invalid = |result: Result<GovernedJailExecRoots, GovernedProcessJailError>| {
        assert_eq!(result.err().map(|error| error.code), Some(GovernedProcessJailErrorCode::InvalidExecRoots));
    };
    invalid(GovernedJailExecRoots::new([GovernedJailExecRoot::new("/")], []));
    if let Some(home) = std::env::var_os("HOME").and_then(|home| fs::canonicalize(home).ok()) {
        invalid(GovernedJailExecRoots::new([GovernedJailExecRoot::new(&home)], []));
        invalid(GovernedJailExecRoots::new([GovernedJailExecRoot::new(home.parent().unwrap())], []));
    }
    let (_directory, path) = root_directory();
    let accepted = GovernedJailExecRoots::new([GovernedJailExecRoot::new(&path)], []).unwrap();
    assert_eq!(accepted.roots()[0].path(), path);
    for mode in [0o777, 0o775, 0o757] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        invalid(GovernedJailExecRoots::new([GovernedJailExecRoot::new(&path)], []));
        // A declaration validated earlier is refused at its recheck.
        assert!(accepted.revalidate().is_err(), "{mode:o}");
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    // A writable ancestor that is not a root-owned sticky directory.
    let child = path.join("nested");
    fs::create_dir(&child).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o775)).unwrap();
    invalid(GovernedJailExecRoots::new([GovernedJailExecRoot::new(&child)], []));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    // A symlinked root resolves to its canonical target.
    let (_links, links) = root_directory();
    std::os::unix::fs::symlink(&child, links.join("link")).unwrap();
    let linked = GovernedJailExecRoots::new([GovernedJailExecRoot::new(links.join("link"))], []).unwrap();
    assert_eq!(linked.roots()[0].path(), child);
    // An exclusion that is, or sits below, a symlink is refused.
    let (_outside, outside) = root_directory();
    std::os::unix::fs::symlink(&outside, child.join("config")).unwrap();
    invalid(GovernedJailExecRoots::new([GovernedJailExecRoot::new(&child).excluding("config")], []));
    invalid(GovernedJailExecRoots::new([GovernedJailExecRoot::new(&child).excluding("config/.env")], []));
    // A missing root or PATH entry.
    invalid(GovernedJailExecRoots::new([GovernedJailExecRoot::new(path.join("absent"))], []));
    invalid(GovernedJailExecRoots::new([GovernedJailExecRoot::new(&path)], [path.join("absent")]));

    // Overlap with the jail's own workdir.
    let jail = unlaunched_jail();
    let workdir = jail.canonical_workdir.clone();
    let parent = workdir.parent().unwrap().to_path_buf();
    let inside = GovernedJailExecRoots::declared(vec![GovernedJailExecRoot::new(workdir.join("x"))], vec![]).unwrap();
    let same = GovernedJailExecRoots::declared(vec![GovernedJailExecRoot::new(&workdir)], vec![]).unwrap();
    let around = GovernedJailExecRoots::declared(vec![GovernedJailExecRoot::new(&parent)], vec![]).unwrap();
    for roots in [inside, same, around] {
        assert_eq!(
            unlaunched_jail_at(&workdir).with_exec_roots(roots).err().map(|error| error.code),
            Some(GovernedProcessJailErrorCode::InvalidExecRoots)
        );
    }
    drop(jail);
    // A jail takes one declaration.
    let roots = GovernedJailExecRoots::new([GovernedJailExecRoot::new(&path)], []).unwrap();
    let jail = unlaunched_jail().with_exec_roots(roots.clone()).unwrap();
    invalid(jail.with_exec_roots(roots).map(|_| unreachable!()));
}

/// A jail around a private tempdir that is never launched.
fn unlaunched_jail() -> GovernedProcessJail {
    let directory = tempfile::tempdir().unwrap();
    let canonical_workdir = fs::canonicalize(directory.path()).unwrap();
    GovernedProcessJail {
        platform: GovernedProcessJailPlatform::MacosSandboxExec,
        launcher: PathBuf::from("/usr/bin/sandbox-exec"),
        canonical_workdir,
        _workdir: directory,
        limits: GovernedProcessJailLimits::default(),
        egress: None,
        interpreter: None,
        exec_roots: None,
        linux_helper: None,
        staging: std::sync::Mutex::new(()),
        missing_program_for_test: false,
    }
}

/// As [`unlaunched_jail`], reporting `workdir` as its workdir.
fn unlaunched_jail_at(workdir: &Path) -> GovernedProcessJail {
    let mut jail = unlaunched_jail();
    jail.canonical_workdir = workdir.to_path_buf();
    jail
}

/// Exec roots do not change the other audits and report themselves without
/// host paths; the in-place program is not a private snapshot.
#[test]
fn exec_roots_audit_is_value_free() {
    let (_directory, path) = root_directory();
    fs::create_dir(path.join("bin")).unwrap();
    let roots = GovernedJailExecRoots::new(
        [GovernedJailExecRoot::new(&path).excluding("config")],
        [path.join("bin")],
    )
    .unwrap();
    let plain = unlaunched_jail();
    assert!(plain.audit().exec_roots.is_none());
    assert!(serde_json::to_value(plain.audit()).unwrap().get("exec_roots").is_none());
    let jail = unlaunched_jail().with_exec_roots(roots.clone()).unwrap();
    let audit = jail.audit();
    assert!(!audit.guarantees.exact_executable_snapshot);
    assert!(audit.guarantees.host_writes_denied && audit.guarantees.direct_network_denied);
    let evidence = audit.exec_roots.unwrap();
    assert_eq!(evidence.schema_version, GOVERNED_JAIL_EXEC_ROOTS_V1);
    assert_eq!((evidence.roots, evidence.excluded_subpaths, evidence.search_path_entries), (1, 1, 1));
    assert_eq!(evidence.declaration_digest, roots.declaration_digest());
    assert_eq!(
        evidence.profile_identity,
        governed_process_jail_exec_roots_profile_identity(
            GovernedProcessJailPlatform::MacosSandboxExec,
            GovernedProcessJailNetwork::Denied,
            None,
            &roots,
        )
    );
    assert_eq!(evidence.profile_identity, jail.profile_identity());
    let rendered = serde_json::to_value(audit).unwrap().to_string();
    assert!(!rendered.contains(path.to_str().unwrap()), "{rendered}");
    assert_eq!(jail.schema_version(), GOVERNED_PROCESS_JAIL_V1);
    // The fixed environment overlay replaces PATH and adds the Python knobs.
    let mut command = Command::new("/usr/bin/true");
    command.env("PATH", "/usr/local/bin").env("PYTHONNOUSERSITE", "0");
    jail.harden_environment(&mut command);
    let environment = command
        .get_envs()
        .map(|(name, value)| (name.to_str().unwrap().to_owned(), value.map(|value| value.to_owned())))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        environment["PATH"],
        Some(OsString::from(format!("{}:/usr/bin:/bin", path.join("bin").display())))
    );
    assert_eq!(environment["PYTHONNOUSERSITE"], Some(OsString::from("1")));
    assert_eq!(environment["PYTHONDONTWRITEBYTECODE"], Some(OsString::from("1")));
}

// ---------------------------------------------------------------------------
// Live jails.

const SECRET: &str = "EXEC-ROOT-SECRET-7f3a";
const HOST_SECRET: &str = "HOST-SECRET-91c2";

/// An installed skill (root A) and a toolbox (root B) in private temp
/// directories, plus an outside directory holding a secret and a program.
struct Skill {
    _directories: Vec<tempfile::TempDir>,
    skill: PathBuf,
    tools: PathBuf,
    outside: PathBuf,
}

const SKILL_MAIN: &str = "skill-main";

impl Skill {
    fn new(main: &str) -> Self {
        let (skill_directory, skill) = root_directory();
        let (tools_directory, tools) = root_directory();
        let (outside_directory, outside) = root_directory();
        write_executable(&skill.join(SKILL_MAIN), main);
        fs::create_dir(skill.join("pkg")).unwrap();
        fs::write(skill.join("pkg/__init__.py"), "VALUE = 'pkg-ok'\n").unwrap();
        fs::create_dir(skill.join("config")).unwrap();
        fs::write(skill.join("config/.env"), format!("API_KEY={SECRET}\n")).unwrap();
        fs::create_dir(tools.join("bin")).unwrap();
        write_executable(&tools.join("bin/helper"), "#!/bin/sh\necho helper-ok \"$@\"\n");
        fs::write(outside.join("secret.txt"), HOST_SECRET).unwrap();
        write_executable(&outside.join("evil"), "#!/bin/sh\necho escaped\n");
        Self {
            _directories: vec![skill_directory, tools_directory, outside_directory],
            skill,
            tools,
            outside,
        }
    }

    fn roots(&self) -> GovernedJailExecRoots {
        GovernedJailExecRoots::new(
            [
                GovernedJailExecRoot::new(&self.skill).excluding("config"),
                GovernedJailExecRoot::new(&self.tools),
            ],
            [self.tools.join("bin")],
        )
        .unwrap()
    }

    fn run(&self, jail: GovernedProcessJail, arguments: &[&str]) -> Result<JailedRun, JailRunError> {
        try_run_in_jail(jail, self.skill.to_str().unwrap(), SKILL_MAIN, arguments, &[], None)
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// The trusted host interpreter, or a skip.
fn host_interpreter() -> Option<GovernedJailInterpreter> {
    match GovernedJailInterpreter::python3_for_host() {
        Ok(interpreter) => Some(interpreter),
        Err(error) => {
            skip(&format!("no trusted python3 on this host: {error}"));
            None
        },
    }
}

fn base_jail(limits: GovernedProcessJailLimits) -> Option<GovernedProcessJail> {
    match GovernedProcessJail::strict_app(limits) {
        Ok(jail) => Some(jail),
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

const PYTHON_PROBE: &str = "import json, os, subprocess, sys\n\
import pkg\n\
out = {'pkg': pkg.VALUE, 'flags': [sys.flags.isolated, sys.flags.no_site, sys.flags.no_user_site, sys.flags.dont_write_bytecode]}\n\
here = os.path.dirname(os.path.abspath(sys.argv[0]))\n\
secret, evil, home = sys.argv[1:4]\n\
def attempt(name, action):\n\
\x20   try:\n\
\x20       out[name] = action()\n\
\x20   except BaseException as error:\n\
\x20       out[name] = type(error).__name__\n\
attempt('helper', lambda: subprocess.run(['helper', 'x'], capture_output=True, text=True, timeout=10).stdout.strip())\n\
attempt('env', lambda: open(os.path.join(here, 'config', '.env')).read())\n\
attempt('config', lambda: os.listdir(os.path.join(here, 'config')))\n\
attempt('root_write', lambda: open(os.path.join(here, 'planted'), 'w').write('x'))\n\
attempt('secret', lambda: open(secret).read())\n\
attempt('evil', lambda: subprocess.run([evil], capture_output=True, text=True, timeout=10).stdout)\n\
attempt('home', lambda: os.listdir(home))\n\
attempt('work', lambda: open('result.txt', 'w').write('done'))\n\
out['path'] = os.environ.get('PATH')\n\
out['usersite'] = os.environ.get('PYTHONNOUSERSITE')\n\
print(json.dumps(out))\n";

/// The acceptance run: the pinned interpreter runs a script in place from
/// its root; it imports a package beside it, runs a helper from another
/// root through `PATH`, and writes only the workdir. It cannot read the
/// excluded `config/`, a file outside the roots or the home directory,
/// cannot write into a root, and cannot exec a program outside the roots.
#[test]
fn a_script_in_a_root_imports_runs_a_helper_and_writes_only_the_workdir() {
    let _budget = JAIL_PROCESS_BUDGET
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let Some(interpreter) = host_interpreter() else {
        return;
    };
    let Some(jail) = base_jail(GovernedProcessJailLimits::default()) else {
        return;
    };
    let skill = Skill::new(&format!("#!/usr/bin/env python3\n{PYTHON_PROBE}"));
    let roots = skill.roots();
    let jail = jail.with_interpreter(interpreter).unwrap().with_exec_roots(roots.clone()).unwrap();
    let identity = jail.profile_identity();
    let interpreter_audit = jail.audit().interpreter.unwrap();
    assert_eq!(interpreter_audit.launch_flags, GOVERNED_JAIL_PYTHON3_EXEC_ROOTS_FLAGS);
    assert!(!interpreter_audit.script_exec_denied);
    assert_eq!(
        identity,
        governed_process_jail_exec_roots_profile_identity(
            jail.platform(),
            GovernedProcessJailNetwork::Denied,
            Some((interpreter_audit.kind, interpreter_audit.version)),
            &roots,
        )
    );
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_owned());
    let secret = skill.outside.join("secret.txt");
    let evil = skill.outside.join("evil");
    let run = skill
        .run(jail, &[secret.to_str().unwrap(), evil.to_str().unwrap(), &home])
        .unwrap();
    let output = json(&run);
    assert_eq!(output["pkg"], "pkg-ok", "{output}");
    assert_eq!(output["flags"], serde_json::json!([0, 0, 1, 1]), "{output}");
    assert_eq!(output["helper"], "helper-ok x", "{output}");
    assert_eq!(output["work"], 4, "{output}");
    assert_eq!(
        output["path"],
        format!("{}:/usr/bin:/bin", skill.tools.join("bin").display()),
        "{output}"
    );
    assert_eq!(output["usersite"], "1", "{output}");
    for denied in ["env", "root_write", "secret", "evil", "home"] {
        assert!(output[denied].is_string(), "{denied}: {output}");
    }
    assert!(!run.stdout.contains(SECRET) && !run.stdout.contains(HOST_SECRET), "{output}");
    assert!(!run.stdout.contains("escaped"), "{output}");
    assert!(!skill.skill.join("planted").exists());
    if cfg!(target_os = "macos") {
        for denied in ["env", "config", "root_write", "secret", "evil", "home"] {
            assert_eq!(output[denied], "PermissionError", "{denied}: {output}");
        }
    } else {
        // Linux: the excluded directory is an empty read-only tmpfs; outside
        // paths are simply not mounted; the roots are read-only binds.
        assert_eq!(output["config"], serde_json::json!([]), "{output}");
        assert_eq!(output["env"], "FileNotFoundError", "{output}");
        assert_eq!(output["root_write"], "OSError", "{output}");
        for absent in ["secret", "evil"] {
            assert_eq!(output[absent], "FileNotFoundError", "{absent}: {output}");
        }
    }
}

/// A program outside the roots, or inside an excluded subpath, is refused
/// before dispatch even though the contract resolved it.
#[test]
fn a_program_outside_the_roots_is_refused_before_dispatch() {
    let _budget = JAIL_PROCESS_BUDGET
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let skill = Skill::new("#!/bin/sh\necho ran\n");
    write_executable(&skill.skill.join("config/tool"), "#!/bin/sh\necho ran\n");
    for (search, program) in [
        (skill.outside.clone(), "evil"),
        (skill.skill.join("config"), "tool"),
    ] {
        let Some(jail) = base_jail(GovernedProcessJailLimits::default()) else {
            return;
        };
        let jail = jail.with_exec_roots(skill.roots()).unwrap();
        let refused = try_run_in_jail(jail, search.to_str().unwrap(), program, &[], &[], None);
        assert_eq!(
            refused.err(),
            Some(JailRunError::Batch(crate::governed_batch_process::GovernedBatchProcessErrorCode::JailUnavailable)),
            "{program}"
        );
    }
    // The same skill's own program runs, without an interpreter, in place.
    let Some(jail) = base_jail(GovernedProcessJailLimits::default()) else {
        return;
    };
    let run = skill.run(jail.with_exec_roots(skill.roots()).unwrap(), &[]).unwrap();
    assert_eq!(run.terminal, GovernedExecutionTerminal::Success, "{} {}", run.stdout, run.stderr);
    assert_eq!(run.stdout.trim(), "ran");
}

/// `node`, from its own install root, runs an installed JS CLI in place from
/// another root through `#!/usr/bin/env node`, like an npm `.bin` shim. The
/// CLI loads a sibling module, cannot read its excluded `config/`, cannot
/// write into its root, and writes the workdir. Skips when no `node` is on
/// `PATH`, unless `MAGICRUN_REQUIRE_EXEC_ROOTS_NODE=1`.
#[test]
fn an_installed_node_cli_runs_in_place_from_its_root() {
    let _budget = JAIL_PROCESS_BUDGET
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let required = std::env::var_os("MAGICRUN_REQUIRE_EXEC_ROOTS_NODE").is_some_and(|value| value == "1");
    let limits = GovernedProcessJailLimits {
        max_memory_bytes: MAX_GOVERNED_JAIL_MEMORY_BYTES,
        ..GovernedProcessJailLimits::default()
    };
    let Some(jail) = base_jail(limits) else {
        return;
    };
    let Some((node_root, node_bin)) = node_install() else {
        assert!(!required, "MAGICRUN_REQUIRE_EXEC_ROOTS_NODE=1 but no usable node on PATH");
        eprintln!("SKIP: no node install usable as an exec root");
        return;
    };
    eprintln!("node root {} bin {}", node_root.display(), node_bin.display());
    let (_cli_directory, cli) = root_directory();
    fs::create_dir(cli.join("bin")).unwrap();
    fs::create_dir(cli.join("lib")).unwrap();
    fs::create_dir(cli.join("config")).unwrap();
    fs::write(cli.join("config/.env"), format!("API_KEY={SECRET}\n")).unwrap();
    fs::write(cli.join("lib/util.js"), "module.exports = { value: 'util-ok' };\n").unwrap();
    write_executable(
        &cli.join("bin/mmx"),
        "#!/usr/bin/env node\n\
         const fs = require('fs');\n\
         const path = require('path');\n\
         const out = { util: require('../lib/util.js').value, argv: process.argv.slice(2) };\n\
         function attempt(name, action) {\n\
           try { out[name] = action(); } catch (error) { out[name] = error.code || String(error); }\n\
         }\n\
         attempt('env', () => fs.readFileSync(path.join(__dirname, '..', 'config', '.env'), 'utf8'));\n\
         attempt('root_write', () => { fs.writeFileSync(path.join(__dirname, 'planted'), 'x'); return 'ok'; });\n\
         attempt('work', () => { fs.writeFileSync('node-result.txt', 'x'); return 'ok'; });\n\
         console.log(JSON.stringify(out));\n",
    );
    let roots = match GovernedJailExecRoots::new(
        [
            GovernedJailExecRoot::new(&node_root),
            GovernedJailExecRoot::new(&cli).excluding("config"),
        ],
        [node_bin.clone(), cli.join("bin")],
    ) {
        Ok(roots) => roots,
        Err(error) => {
            assert!(!required, "node root {} refused: {error}", node_root.display());
            eprintln!("SKIP: node root {} refused: {error}", node_root.display());
            return;
        },
    };
    let jail = jail.with_exec_roots(roots).unwrap();
    let run = try_run_in_jail(jail, cli.join("bin").to_str().unwrap(), "mmx", &["--flag", "value"], &[], None)
        .unwrap();
    let output = json(&run);
    assert_eq!(output["util"], "util-ok", "{output}");
    assert_eq!(output["argv"], serde_json::json!(["--flag", "value"]), "{output}");
    assert_eq!(output["work"], "ok", "{output}");
    assert_ne!(output["root_write"], "ok", "{output}");
    assert!(output["env"].is_string() && !run.stdout.contains(SECRET), "{output}");
    let expected_env = if cfg!(target_os = "macos") { "EPERM" } else { "ENOENT" };
    assert_eq!(output["env"], expected_env, "{output}");
    assert!(!cli.join("bin/planted").exists());
}

/// The install root of the first `node` on `PATH` and its canonical `bin`
/// directory. A Homebrew keg resolves to the Homebrew prefix (its libraries
/// live in other kegs); otherwise the parent of the binary's directory.
fn node_install() -> Option<(PathBuf, PathBuf)> {
    let node = std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join("node"))
        .find(|candidate| candidate.is_file())?;
    let node = fs::canonicalize(node).ok()?;
    let bin = node.parent()?.to_path_buf();
    let text = node.to_str()?;
    let root = match text.find("/Cellar/") {
        Some(index) => PathBuf::from(&text[..index]),
        None => bin.parent()?.to_path_buf(),
    };
    Some((root, bin))
}

/// Brokered egress composes with exec roots: the script in its root reaches
/// the broker through the proxy environment and nothing else, and still runs
/// a helper from another root.
#[test]
fn brokered_egress_composes_with_exec_roots() {
    let _budget = JAIL_PROCESS_BUDGET
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let Some(interpreter) = host_interpreter() else {
        return;
    };
    let skill = Skill::new(
        "#!/usr/bin/env python3\n\
         import json, socket, subprocess, urllib.parse, urllib.request\n\
         out = {}\n\
         proxy = urllib.request.getproxies().get('https')\n\
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
         \x20   socket.getaddrinfo('example.com', 80)\n\
         \x20   out['dns'] = 'resolved'\n\
         except BaseException as error:\n\
         \x20   out['dns'] = type(error).__name__\n\
         out['helper'] = subprocess.run(['helper'], capture_output=True, text=True, timeout=10).stdout.strip()\n\
         print(json.dumps(out))\n",
    );
    #[cfg(target_os = "macos")]
    let (broker, endpoint) = {
        let broker = super::egress_tests::TestBroker::start();
        let endpoint = GovernedEgressBrokerEndpoint::LoopbackTcp {
            port: NonZeroU16::new(broker.port).unwrap(),
        };
        (broker, endpoint)
    };
    #[cfg(target_os = "linux")]
    let (broker, endpoint) = {
        let broker = super::egress_tests::linux::UnixBroker::start();
        let endpoint = GovernedEgressBrokerEndpoint::UnixSocket {
            path: broker.path.clone(),
        };
        (broker, endpoint)
    };
    let jail = match GovernedProcessJail::strict_app_with_brokered_egress(GovernedProcessJailLimits::default(), endpoint) {
        Ok(jail) => jail,
        Err(error)
            if matches!(
                error.code,
                GovernedProcessJailErrorCode::LauncherUnavailable
                    | GovernedProcessJailErrorCode::EgressForwarderUnavailable
                    | GovernedProcessJailErrorCode::JailHelperUnavailable
            ) =>
        {
            skip(&format!("no brokered jail on this host: {error}"));
            return;
        },
        Err(error) => panic!("unexpected brokered jail setup failure: {error}"),
    };
    let roots = skill.roots();
    let jail = jail.with_interpreter(interpreter).unwrap().with_exec_roots(roots.clone()).unwrap();
    assert_eq!(jail.schema_version(), GOVERNED_PROCESS_JAIL_BROKERED_EGRESS_V1);
    let audit = jail.audit();
    assert_eq!(audit.egress.unwrap().profile_identity, jail.profile_identity());
    assert_eq!(audit.exec_roots.unwrap().profile_identity, jail.profile_identity());
    let output = json(&skill.run(jail, &[]).unwrap());
    assert_eq!(output["connect"], "HTTP/1.1 200 Connection established", "{output}");
    assert_eq!(output["body"], super::egress_tests::TUNNEL_BODY, "{output}");
    assert_eq!(output["dns"], "gaierror", "{output}");
    assert_eq!(output["helper"], "helper-ok", "{output}");
    let requests = broker.requests();
    assert_eq!(requests, ["CONNECT allowed.example:80 HTTP/1.1"], "{requests:?}");
}

/// macOS has no pid namespace and exec roots allow fork: a process that
/// leaves the launcher's group with `setsid` is still counted by the
/// watchdog and killed at teardown, because membership is decided by the
/// jail's sandbox, not the process group.
#[cfg(target_os = "macos")]
#[test]
fn a_setsid_escapee_is_counted_and_killed_on_macos() {
    let _budget = JAIL_PROCESS_BUDGET
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let Some(interpreter) = host_interpreter() else {
        return;
    };
    // The leader reports the escapee's pid and exits at once; the escapee
    // detaches from stdio and would sleep for a minute. With `bomb`, more
    // escapees than the process ceiling allows, and the leader waits.
    let skill = Skill::new(
        "#!/usr/bin/env python3\n\
         import os, sys, time\n\
         read, write = os.pipe()\n\
         if os.fork() == 0:\n\
         \x20   os.setsid()\n\
         \x20   null = os.open('/dev/null', os.O_RDWR)\n\
         \x20   for fd in (0, 1, 2):\n\
         \x20       os.dup2(null, fd)\n\
         \x20   os.write(write, str(os.getpid()).encode() + b'\\n')\n\
         \x20   time.sleep(60)\n\
         \x20   os._exit(0)\n\
         print(os.read(read, 32).decode().strip(), flush=True)\n\
         if sys.argv[1:] == ['bomb']:\n\
         \x20   for _ in range(24):\n\
         \x20       if os.fork() == 0:\n\
         \x20           os.setsid()\n\
         \x20           null = os.open('/dev/null', os.O_RDWR)\n\
         \x20           for fd in (0, 1, 2):\n\
         \x20               os.dup2(null, fd)\n\
         \x20           time.sleep(60)\n\
         \x20           os._exit(0)\n\
         \x20   time.sleep(10)\n",
    );
    let alive = |pid: libc::pid_t| {
        // SAFETY: signal 0 only probes whether `pid` exists.
        unsafe { libc::kill(pid, 0) == 0 }
    };
    let Some(jail) = base_jail(GovernedProcessJailLimits::default()) else {
        return;
    };
    let jail = jail.with_interpreter(interpreter).unwrap().with_exec_roots(skill.roots()).unwrap();
    assert!(jail.watch().macos_members().is_some(), "exec-roots jails track members");
    let run = skill.run(jail, &[]).unwrap();
    assert_eq!(run.terminal, GovernedExecutionTerminal::Success, "{} {}", run.stdout, run.stderr);
    let escapee = run.stdout.trim().parse::<libc::pid_t>().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!alive(escapee), "the setsid escapee {escapee} outlived the run");

    let Some(jail) = base_jail(GovernedProcessJailLimits::default()) else {
        return;
    };
    let jail = jail
        .with_interpreter(GovernedJailInterpreter::python3_for_host().unwrap())
        .unwrap()
        .with_exec_roots(skill.roots())
        .unwrap();
    let run = skill.run(jail, &["bomb"]).unwrap();
    assert_eq!(
        run.terminal,
        GovernedExecutionTerminal::ProcessLimitExceeded,
        "stdout={} stderr={}",
        run.stdout,
        run.stderr
    );
    let escapee = run.stdout.trim().parse::<libc::pid_t>().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!alive(escapee), "the setsid escapee {escapee} outlived the run");
}
