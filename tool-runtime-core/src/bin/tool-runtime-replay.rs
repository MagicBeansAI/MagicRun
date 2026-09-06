use std::{
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{anyhow, Context, Result};
use tool_runtime_core::{
    classification::{ClassificationManifest, SourceClassification},
    inventory::SourceInventory,
    replay::ReplayCompiler,
};

const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Generate,
    Check,
}

#[derive(Debug, PartialEq, Eq)]
struct Args {
    mode: Mode,
    skill_root: PathBuf,
    inventory_path: PathBuf,
    classification_manifest_path: PathBuf,
    classification_path: PathBuf,
    json_path: PathBuf,
    report_path: PathBuf,
}

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tool-runtime-replay: {error:#}");
            ExitCode::FAILURE
        },
    }
}

fn run(arguments: impl IntoIterator<Item = String>) -> Result<()> {
    let args = parse_args(arguments)?;
    let inventory: SourceInventory = read_json(&args.inventory_path, "source inventory")?;
    let classification_manifest = read_classification_manifest(&args.classification_manifest_path)?;
    let classification: SourceClassification =
        read_json(&args.classification_path, "source classification")?;
    let catalog = ReplayCompiler::compile(
        &args.skill_root,
        &inventory,
        classification_manifest,
        &classification,
    )?;
    let json = catalog.to_pretty_json()?;
    let report = catalog.to_markdown();

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
        "{} fixtures, {} Google Workspace actions, {} primitive process, {} command process, {} compiled provider",
        catalog.summary.fixtures,
        catalog.summary.google_workspace_fixtures,
        catalog.summary.primitive_process_fixtures,
        catalog.summary.command_process_fixtures,
        catalog.summary.compiled_provider_fixtures,
    );
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, label: &str) -> Result<T> {
    let bytes = read_bounded(path, label)?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {label} '{}'", path.display()))
}

fn read_classification_manifest(path: &Path) -> Result<ClassificationManifest> {
    let bytes = read_bounded(path, "classification manifest")?;
    let contents = std::str::from_utf8(&bytes).with_context(|| {
        format!(
            "classification manifest '{}' is not valid UTF-8",
            path.display()
        )
    })?;
    ClassificationManifest::from_yaml(contents)
        .with_context(|| format!("parsing classification manifest '{}'", path.display()))
}

fn read_bounded(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading {label} metadata '{}'", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!("{label} path is not a regular file"));
    }
    let file =
        fs::File::open(path).with_context(|| format!("opening {label} '{}'", path.display()))?;
    let mut bytes = Vec::with_capacity(MAX_INPUT_BYTES.min(64 * 1024));
    file.take(MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label} '{}'", path.display()))?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(anyhow!("{label} exceeds {MAX_INPUT_BYTES}-byte limit"));
    }
    Ok(bytes)
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
    let mut inventory_path = None;
    let mut classification_manifest_path = None;
    let mut classification_path = None;
    let mut json_path = None;
    let mut report_path = None;
    while let Some(flag) = arguments.next() {
        let destination = match flag.as_str() {
            "--skill-root" => &mut skill_root,
            "--inventory" => &mut inventory_path,
            "--classification-manifest" => &mut classification_manifest_path,
            "--classification" => &mut classification_path,
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
        inventory_path: PathBuf::from(required(inventory_path, "--inventory")?),
        classification_manifest_path: PathBuf::from(required(
            classification_manifest_path,
            "--classification-manifest",
        )?),
        classification_path: PathBuf::from(required(classification_path, "--classification")?),
        json_path: PathBuf::from(required(json_path, "--json")?),
        report_path: PathBuf::from(required(report_path, "--report")?),
    })
}

fn required(value: Option<String>, name: &str) -> Result<String> {
    value.ok_or_else(|| anyhow!("missing required argument '{name}'\n{}", usage()))
}

fn usage() -> &'static str {
    "usage: tool-runtime-replay <generate|check> \\
     --skill-root <directory> --inventory <source-inventory.json> \\
     --classification-manifest <source-classification.yaml> \\
     --classification <source-classification.json> \\
     --json <replay-fixtures.json> --report <report.md>"
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
            "artifact '{}' is stale; regenerate the Phase 0C replay fixtures",
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
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "tool-runtime-replay-cli-{}-{nonce}-{}",
                std::process::id(),
                TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("create root");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parses_complete_contract() {
        let parsed = parse_args(
            [
                "generate",
                "--skill-root",
                "skillshub",
                "--inventory",
                "inventory.json",
                "--classification-manifest",
                "classification.yaml",
                "--classification",
                "classification.json",
                "--json",
                "replay.json",
                "--report",
                "replay.md",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .expect("arguments");
        assert_eq!(parsed.mode, Mode::Generate);
        assert_eq!(parsed.skill_root, PathBuf::from("skillshub"));
        assert_eq!(
            parsed.classification_manifest_path,
            PathBuf::from("classification.yaml")
        );
        assert_eq!(
            parsed.classification_path,
            PathBuf::from("classification.json")
        );
    }

    #[test]
    fn rejects_missing_duplicate_and_unknown_arguments() {
        assert!(parse_args(["check"].into_iter().map(str::to_string)).is_err());
        assert!(parse_args(
            ["check", "--skill-root", "a", "--skill-root", "b"]
                .into_iter()
                .map(str::to_string)
        )
        .is_err());
        assert!(parse_args(
            ["generate", "--unexpected", "value"]
                .into_iter()
                .map(str::to_string)
        )
        .is_err());
    }

    #[test]
    fn bounded_reader_rejects_oversized_and_symlinked_input() {
        let root = TestRoot::new();
        let large = root.0.join("large.json");
        fs::write(&large, vec![b'x'; MAX_INPUT_BYTES + 1]).expect("write large");
        assert!(read_json::<serde_json::Value>(&large, "test").is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let source = root.0.join("source.json");
            let link = root.0.join("link.json");
            fs::write(&source, "{}").expect("write source");
            symlink(&source, &link).expect("link");
            assert!(read_json::<serde_json::Value>(&link, "test").is_err());
        }
    }

    #[test]
    fn check_mode_detects_stale_artifact() {
        let root = TestRoot::new();
        let path = root.0.join("artifact.json");
        fs::write(&path, "old").expect("write artifact");
        assert!(check_artifact(&path, "new").is_err());
    }
}
