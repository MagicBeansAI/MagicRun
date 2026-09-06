use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub registry: RegistryConfig,
    pub semantic_search: Option<SemanticSearchConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            registry: RegistryConfig::default(),
            semantic_search: Some(SemanticSearchConfig::default()),
        }
    }
}

impl Config {
    pub fn load(
        config_path: &Path,
        _environment: Option<&str>,
        _profile: Option<&str>,
    ) -> Result<Self> {
        let config_str = std::fs::read_to_string(config_path).with_context(|| {
            format!(
                "failed to read runtime config file '{}'",
                config_path.display()
            )
        })?;

        let config: Config = serde_yaml::from_str(&config_str).with_context(|| {
            format!(
                "failed to parse runtime config file '{}'",
                config_path.display()
            )
        })?;

        Ok(config)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RegistryConfig {
    #[serde(rename = "type")]
    pub r#type: String,
    /// Extra "system-root" directories scanned at startup for additional
    /// skills and agent personality templates. Each entry is expected
    /// to (optionally) contain `skills/<skill>/tool_schema.yaml` and/or
    /// `agent_templates/agents/<id>/definition.agent.yaml` — mirroring
    /// the layout of the built-in `<storage_root>/system/` directory.
    ///
    /// The system-shared **skills** tier has been retired (v0.6.572):
    /// for skills, the layering is `scope → extras → embedded`. For
    /// agent personality templates the legacy
    /// `<storage_root>/system/agent_templates/` primary still loads;
    /// extras overlay on top of it (system-template migration is a
    /// separate workstream — see CHANGELOG v0.6.572).
    ///
    /// **Collision precedence within extras: first-listed wins** —
    /// matches `SkillLoader::discover`'s `or_insert` plus the
    /// PATH / XDG_DATA_DIRS convention. Put your highest-priority
    /// extras first.
    ///
    /// Supports `~` and environment-variable expansion (resolved by
    /// the caller via [`RegistryConfig::resolved_paths`]). Relative
    /// paths are resolved against the config file's directory.
    pub paths: Vec<String>,
    pub validation: ValidationConfig,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            r#type: "file".to_string(),
            paths: vec![],
            validation: ValidationConfig::default(),
        }
    }
}

impl RegistryConfig {
    /// Resolve each entry in `paths` to an absolute [`PathBuf`]:
    ///   - `~` and `~user` expand via `shellexpand::tilde`-equivalent
    ///     (we only handle leading `~/` here to avoid adding a
    ///     dependency)
    ///   - `$VAR` and `${VAR}` expand from the process environment
    ///   - Relative paths resolve against `config_dir` when provided,
    ///     else the current working directory
    ///
    /// **Existence is NOT checked here.** Callers must filter to
    /// existing directories themselves (so they can log a clear
    /// warning for the missing-path case). Empty entries are dropped.
    pub fn resolved_paths(&self, config_dir: Option<&Path>) -> Vec<PathBuf> {
        self.paths
            .iter()
            .filter_map(|raw| {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return None;
                }
                Some(resolve_path_entry(trimmed, config_dir))
            })
            .collect()
    }
}

fn resolve_path_entry(raw: &str, config_dir: Option<&Path>) -> PathBuf {
    let expanded = expand_env_vars(raw);
    let expanded = expand_tilde(&expanded);
    let path = PathBuf::from(expanded);
    if path.is_absolute() {
        return path;
    }
    match config_dir {
        Some(dir) => dir.join(path),
        None => path,
    }
}

fn expand_tilde(input: &str) -> String {
    if let Some(rest) = input.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            let mut joined = PathBuf::from(home);
            joined.push(rest);
            return joined.to_string_lossy().into_owned();
        }
    }
    input.to_string()
}

fn expand_env_vars(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('{') => {
                chars.next();
                let mut name = String::new();
                while let Some(&inner) = chars.peek() {
                    if inner == '}' {
                        chars.next();
                        break;
                    }
                    name.push(inner);
                    chars.next();
                }
                if let Ok(value) = std::env::var(&name) {
                    out.push_str(&value);
                }
            },
            Some(c) if c.is_ascii_alphabetic() || *c == '_' => {
                let mut name = String::new();
                while let Some(&inner) = chars.peek() {
                    if inner.is_ascii_alphanumeric() || inner == '_' {
                        name.push(inner);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if let Ok(value) = std::env::var(&name) {
                    out.push_str(&value);
                }
            },
            _ => out.push('$'),
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ValidationConfig {
    pub strict: bool,
    pub allow_unknown_fields: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            strict: true,
            allow_unknown_fields: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SemanticSearchConfig {
    pub enabled: bool,
    pub similarity_threshold: f64,
    pub max_results: usize,
}

impl Default for SemanticSearchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            similarity_threshold: 0.0,
            max_results: 25,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_paths_expands_tilde_and_env_vars() {
        std::env::set_var("EXTRA_SKILLS_DIR", "/opt/extra");
        let cfg = RegistryConfig {
            r#type: "file".into(),
            paths: vec![
                "~/my-skills".into(),
                "$EXTRA_SKILLS_DIR".into(),
                "${EXTRA_SKILLS_DIR}/inner".into(),
                "  ".into(),
                "./relative".into(),
            ],
            validation: ValidationConfig::default(),
        };
        let home = std::env::var("HOME").unwrap_or_default();
        let resolved = cfg.resolved_paths(Some(Path::new("/etc/magician")));
        assert_eq!(resolved.len(), 4, "empty entries dropped");
        assert_eq!(resolved[0], PathBuf::from(format!("{}/my-skills", home)));
        assert_eq!(resolved[1], PathBuf::from("/opt/extra"));
        assert_eq!(resolved[2], PathBuf::from("/opt/extra/inner"));
        assert_eq!(resolved[3], PathBuf::from("/etc/magician/./relative"));
    }
}
