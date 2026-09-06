use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{anyhow, Context, Result};
use tool_runtime_core::inventory::SourceInventoryScanner;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Generate,
    Check,
}

#[derive(Debug, PartialEq, Eq)]
struct Args {
    mode: Mode,
    skill_root: PathBuf,
    source_label: String,
    json_path: PathBuf,
    report_path: PathBuf,
}

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tool-runtime-inventory: {error:#}");
            ExitCode::FAILURE
        },
    }
}

fn run(arguments: impl IntoIterator<Item = String>) -> Result<()> {
    let args = parse_args(arguments)?;
    let inventory = SourceInventoryScanner::new(&args.skill_root, &args.source_label)?.scan()?;
    let json = inventory.to_pretty_json()?;
    let report = inventory.to_markdown();

    if inventory.has_errors() {
        for finding in inventory.findings.iter().filter(|finding| {
            finding.severity == tool_runtime_core::inventory::FindingSeverity::Error
        }) {
            eprintln!("{} {}: {}", finding.code, finding.source, finding.detail);
        }
        return Err(anyhow!(
            "inventory contains {} error finding(s); existing artifacts were not changed",
            inventory.summary.errors
        ));
    }

    match args.mode {
        Mode::Generate => {
            write_artifact(&args.json_path, &json)?;
            write_artifact(&args.report_path, &report)?;
        },
        Mode::Check => {
            check_artifact(&args.json_path, &json)?;
            check_artifact(&args.report_path, &report)?;
        },
    }

    println!(
        "{} tool skills, {} actions, {} error(s), {} warning(s)",
        inventory.summary.active_tool_skills,
        inventory.summary.schema_actions,
        inventory.summary.errors,
        inventory.summary.warnings
    );
    Ok(())
}

fn parse_args(arguments: impl IntoIterator<Item = String>) -> Result<Args> {
    let mut arguments = arguments.into_iter();
    let mode = match arguments.next().as_deref() {
        Some("generate") => Mode::Generate,
        Some("check") => Mode::Check,
        Some("--help" | "-h") => return Err(anyhow!(usage())),
        _ => return Err(anyhow!(usage())),
    };

    let mut skill_root = None;
    let mut source_label = None;
    let mut json_path = None;
    let mut report_path = None;
    while let Some(flag) = arguments.next() {
        let destination = match flag.as_str() {
            "--skill-root" => &mut skill_root,
            "--source-label" => &mut source_label,
            "--json" => &mut json_path,
            "--report" => &mut report_path,
            "--help" | "-h" => return Err(anyhow!(usage())),
            _ => return Err(anyhow!("unknown argument '{flag}'\n{}", usage())),
        };
        if destination.is_some() {
            return Err(anyhow!("argument '{flag}' was supplied more than once"));
        }
        *destination = Some(
            arguments
                .next()
                .ok_or_else(|| anyhow!("argument '{flag}' requires a value"))?,
        );
    }

    Ok(Args {
        mode,
        skill_root: PathBuf::from(required(skill_root, "--skill-root")?),
        source_label: required(source_label, "--source-label")?,
        json_path: PathBuf::from(required(json_path, "--json")?),
        report_path: PathBuf::from(required(report_path, "--report")?),
    })
}

fn required(value: Option<String>, name: &str) -> Result<String> {
    value.ok_or_else(|| anyhow!("missing required argument '{name}'\n{}", usage()))
}

fn usage() -> &'static str {
    "usage: tool-runtime-inventory <generate|check> \\
     --skill-root <directory> --source-label <relative-label> \\
     --json <snapshot.json> --report <report.md>"
}

fn write_artifact(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating artifact directory '{}'", parent.display()))?;
    }
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("artifact path must end in a UTF-8 file name"))?;
    let temporary = path.with_file_name(format!(".{file_name}.tmp.{}", std::process::id()));
    let result = publish_temporary_artifact(&temporary, path, contents);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn publish_temporary_artifact(temporary: &Path, path: &Path, contents: &str) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temporary)
        .with_context(|| format!("creating temporary artifact '{}'", temporary.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("writing temporary artifact '{}'", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing temporary artifact '{}'", temporary.display()))?;
    fs::rename(temporary, path).with_context(|| {
        format!(
            "publishing temporary artifact '{}' as '{}'",
            temporary.display(),
            path.display()
        )
    })
}

fn check_artifact(path: &Path, expected: &str) -> Result<()> {
    let actual = fs::read_to_string(path)
        .with_context(|| format!("reading checked artifact '{}'", path.display()))?;
    if actual != expected {
        return Err(anyhow!(
            "artifact '{}' is stale; regenerate the Phase 0A inventory",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEST_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "tool-runtime-inventory-cli-{label}-{}-{nonce}-{}",
                std::process::id(),
                TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("create CLI fixture root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn args(values: &[&str]) -> Result<Args> {
        parse_args(values.iter().map(|value| (*value).to_string()))
    }

    #[test]
    fn parses_complete_generate_contract() {
        let parsed = args(&[
            "generate",
            "--skill-root",
            "skillshub",
            "--source-label",
            "skillshub",
            "--json",
            "inventory.json",
            "--report",
            "inventory.md",
        ])
        .expect("valid arguments");
        assert_eq!(parsed.mode, Mode::Generate);
        assert_eq!(parsed.skill_root, PathBuf::from("skillshub"));
        assert_eq!(parsed.source_label, "skillshub");
    }

    #[test]
    fn rejects_missing_duplicate_and_unknown_arguments() {
        assert!(args(&["check"]).is_err());
        assert!(args(&["check", "--skill-root", "a", "--skill-root", "b"]).is_err());
        assert!(args(&["generate", "--unexpected", "value"]).is_err());
    }

    #[test]
    fn invalid_inventory_does_not_overwrite_existing_artifacts() -> Result<()> {
        let root = TestRoot::new("fail-closed");
        let skill_root = root.path().join("skills/broken");
        fs::create_dir_all(&skill_root).expect("create broken skill");
        fs::write(
            skill_root.join("tool_schema.yaml"),
            "name: broken\nversion: 1.0.0\n",
        )
        .expect("write broken schema");
        let json = root.path().join("inventory.json");
        let report = root.path().join("inventory.md");
        let skills = root.path().join("skills");
        fs::write(&json, "known-good-json").expect("write existing JSON");
        fs::write(&report, "known-good-report").expect("write existing report");

        let error = run([
            "generate",
            "--skill-root",
            skills.to_str().expect("UTF-8 fixture path"),
            "--source-label",
            "skillshub",
            "--json",
            json.to_str().expect("UTF-8 fixture path"),
            "--report",
            report.to_str().expect("UTF-8 fixture path"),
        ]
        .into_iter()
        .map(str::to_string))
        .expect_err("invalid inventory must fail");
        assert!(error
            .to_string()
            .contains("existing artifacts were not changed"));
        assert_eq!(fs::read_to_string(json)?, "known-good-json");
        assert_eq!(fs::read_to_string(report)?, "known-good-report");
        Ok(())
    }

    #[test]
    fn artifact_write_is_atomic_and_check_detects_staleness() -> Result<()> {
        let root = TestRoot::new("atomic");
        let artifact = root.path().join("artifact.json");
        write_artifact(&artifact, "first")?;
        write_artifact(&artifact, "second")?;
        check_artifact(&artifact, "second")?;
        assert!(check_artifact(&artifact, "stale").is_err());
        assert_eq!(fs::read_to_string(&artifact)?, "second");
        Ok(())
    }
}
