use std::{
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{anyhow, Context, Result};
use tool_runtime_core::{
    classification::{ClassificationCompiler, ClassificationManifest},
    inventory::SourceInventory,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Generate,
    Check,
}

#[derive(Debug, PartialEq, Eq)]
struct Args {
    mode: Mode,
    inventory_path: PathBuf,
    manifest_path: PathBuf,
    json_path: PathBuf,
    report_path: PathBuf,
}

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tool-runtime-classification: {error:#}");
            ExitCode::FAILURE
        },
    }
}

fn run(arguments: impl IntoIterator<Item = String>) -> Result<()> {
    let args = parse_args(arguments)?;
    let inventory = read_inventory(&args.inventory_path)?;
    let manifest = read_manifest(&args.manifest_path)?;
    let classification = ClassificationCompiler::compile(&inventory, manifest)?;
    let json = classification.to_pretty_json()?;
    let report = classification.to_markdown();

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
        "{} skills, {} adapters, {} exception(s), {} retained unknown(s)",
        classification.summary.classified_skills,
        classification.summary.classified_adapters,
        classification.summary.exceptions,
        classification.summary.unknowns,
    );
    Ok(())
}

fn read_inventory(path: &Path) -> Result<SourceInventory> {
    let bytes = read_bounded(path, 4 * 1024 * 1024, "source inventory")?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing source inventory '{}'", path.display()))
}

fn read_manifest(path: &Path) -> Result<ClassificationManifest> {
    let bytes = read_bounded(path, 1024 * 1024, "classification manifest")?;
    let yaml = String::from_utf8(bytes).context("classification manifest is not UTF-8")?;
    ClassificationManifest::from_yaml(&yaml)
}

fn read_bounded(path: &Path, max_bytes: usize, label: &str) -> Result<Vec<u8>> {
    let file =
        fs::File::open(path).with_context(|| format!("opening {label} '{}'", path.display()))?;
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label} '{}'", path.display()))?;
    if bytes.len() > max_bytes {
        return Err(anyhow!("{label} exceeds {max_bytes}-byte limit"));
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

    let mut inventory_path = None;
    let mut manifest_path = None;
    let mut json_path = None;
    let mut report_path = None;
    while let Some(flag) = arguments.next() {
        let destination = match flag.as_str() {
            "--inventory" => &mut inventory_path,
            "--classification" => &mut manifest_path,
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
        inventory_path: PathBuf::from(required(inventory_path, "--inventory")?),
        manifest_path: PathBuf::from(required(manifest_path, "--classification")?),
        json_path: PathBuf::from(required(json_path, "--json")?),
        report_path: PathBuf::from(required(report_path, "--report")?),
    })
}

fn required(value: Option<String>, name: &str) -> Result<String> {
    value.ok_or_else(|| anyhow!("missing required argument '{name}'\n{}", usage()))
}

fn usage() -> &'static str {
    "usage: tool-runtime-classification <generate|check> \\
     --inventory <source-inventory.json> --classification <classification.yaml> \\
     --json <normalized.json> --report <report.md>"
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
            "artifact '{}' is stale; regenerate the Phase 0B classification",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_complete_contract() {
        let parsed = parse_args(
            [
                "generate",
                "--inventory",
                "source.json",
                "--classification",
                "classification.yaml",
                "--json",
                "normalized.json",
                "--report",
                "report.md",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap();
        assert_eq!(parsed.mode, Mode::Generate);
        assert_eq!(parsed.inventory_path, PathBuf::from("source.json"));
    }

    #[test]
    fn rejects_missing_duplicate_and_unknown_arguments() {
        assert!(parse_args(["check"].into_iter().map(str::to_string)).is_err());
        assert!(parse_args(
            ["check", "--inventory", "a", "--inventory", "b"]
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
    fn bounded_reader_rejects_oversized_input() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "tool-runtime-classification-{nonce}-{}",
            std::process::id()
        ));
        fs::write(&path, [0_u8; 9]).unwrap();
        let result = read_bounded(&path, 8, "fixture");
        fs::remove_file(path).unwrap();
        assert!(result.is_err());
    }
}
