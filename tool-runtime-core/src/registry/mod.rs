pub mod types;

use std::{
    collections::HashMap,
    fs,
    path::{Component, Path, PathBuf},
    sync::RwLock,
};

use anyhow::{anyhow, Context, Result};
use tracing::{debug, warn};
use walkdir::WalkDir;

use crate::config::{RegistryConfig, ValidationConfig};
use types::{CapabilityFile, ToolDefinition};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SourcePriority {
    Versioned = 0,
    Canonical = 1,
}

pub struct RegistryService {
    _config: RegistryConfig,
    tools: RwLock<HashMap<String, ToolDefinition>>,
}

impl RegistryService {
    pub async fn new(config: RegistryConfig) -> Result<Self> {
        let tools = load_tools_from_paths(&config.paths, &config.validation)?;
        Ok(Self {
            _config: config,
            tools: RwLock::new(tools),
        })
    }

    /// Register a single tool definition programmatically.
    /// Overwrites any existing definition with the same name.
    /// Uses interior mutability so callers only need `&self`.
    pub fn register_tool(&self, name: String, definition: ToolDefinition) {
        self.tools
            .write()
            .expect("RegistryService lock poisoned")
            .insert(name, definition);
    }

    /// Remove a tool definition by name, returning the old definition if present.
    pub fn unregister_tool(&self, name: &str) -> Option<ToolDefinition> {
        self.tools
            .write()
            .expect("RegistryService lock poisoned")
            .remove(name)
    }

    pub fn get_all_tools(&self) -> HashMap<String, ToolDefinition> {
        self.tools
            .read()
            .expect("RegistryService lock poisoned")
            .clone()
    }

    pub fn get_tool(&self, tool_name: &str) -> Option<ToolDefinition> {
        self.tools
            .read()
            .expect("RegistryService lock poisoned")
            .get(tool_name)
            .cloned()
    }

    pub fn is_tool_hidden_hierarchical(&self, _tool_name: &str, tool: &ToolDefinition) -> bool {
        tool.hidden
    }

    pub fn is_tool_enabled_hierarchical(&self, _tool_name: &str, tool: &ToolDefinition) -> bool {
        tool.enabled
    }
}

fn load_tools_from_paths(
    paths: &[String],
    validation: &ValidationConfig,
) -> Result<HashMap<String, ToolDefinition>> {
    let mut tools = HashMap::new();
    let mut sources: HashMap<String, (SourcePriority, PathBuf)> = HashMap::new();

    for configured_path in paths {
        let path = PathBuf::from(configured_path);
        if !path.exists() {
            debug!("Skipping non-existent capability path '{}'", path.display());
            continue;
        }

        if path.is_file() {
            load_tools_from_file(&path, &mut tools, &mut sources, validation)?;
            continue;
        }

        for entry in WalkDir::new(&path)
            .sort_by_file_name()
            .into_iter()
            // Skip directories that hold a different schema and are loaded by
            // a higher layer:
            //   - `packs/` — legacy CapabilityPackDefinition YAMLs
            //   - `skills/` — AgentSkills `tool_schema.yaml` (loaded by
            //     `magician::execution::load_pack_defs_from_skills_dir`)
            //   - `agent_templates/` — agent personality YAMLs (loaded by
            //     `AgentDefinitionStore`)
            .filter_entry(|e| {
                !(e.file_type().is_dir()
                    && matches!(
                        e.file_name().to_string_lossy().as_ref(),
                        "packs" | "skills" | "agent_templates"
                    ))
            })
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
        {
            let entry_path = entry.path();
            if is_yaml(entry_path) {
                load_tools_from_file(entry_path, &mut tools, &mut sources, validation)?;
            }
        }
    }

    Ok(tools)
}

fn load_tools_from_file(
    path: &Path,
    tools: &mut HashMap<String, ToolDefinition>,
    sources: &mut HashMap<String, (SourcePriority, PathBuf)>,
    validation: &ValidationConfig,
) -> Result<()> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read capability file '{}'", path.display()))?;

    let parsed = match parse_capability_file(&content, path, validation)? {
        Some(parsed) => parsed,
        None => return Ok(()),
    };

    let incoming_priority = source_priority(path);

    for mut tool in parsed.tools {
        if tool.name.trim().is_empty() {
            continue;
        }

        normalize_tool(&mut tool);
        let tool_name = tool.name.clone();
        match sources.get(&tool_name).cloned() {
            None => {
                tools.insert(tool_name.clone(), tool);
                sources.insert(tool_name, (incoming_priority, path.to_path_buf()));
            },
            Some((current_priority, current_path)) => {
                if incoming_priority > current_priority {
                    debug!(
                        "Tool '{}' from '{}' overrides lower-priority definition from '{}'",
                        tool_name,
                        path.display(),
                        current_path.display()
                    );
                    tools.insert(tool_name.clone(), tool);
                    sources.insert(tool_name, (incoming_priority, path.to_path_buf()));
                } else if incoming_priority < current_priority {
                    debug!(
                        "Ignoring lower-priority tool '{}' from '{}' because canonical definition \
                         already loaded from '{}'",
                        tool_name,
                        path.display(),
                        current_path.display()
                    );
                } else {
                    if validation.strict {
                        return Err(anyhow!(
                            "Equal-priority duplicate tool '{}' found in '{}' and '{}'",
                            tool_name,
                            current_path.display(),
                            path.display()
                        ));
                    }
                    warn!(
                        "Ignoring equal-priority duplicate tool '{}' from '{}' (keeping definition from '{}')",
                        tool_name,
                        path.display(),
                        current_path.display()
                    );
                }
            },
        }
    }

    Ok(())
}

fn parse_capability_file(
    content: &str,
    path: &Path,
    validation: &ValidationConfig,
) -> Result<Option<CapabilityFile>> {
    let parsed = if validation.allow_unknown_fields {
        serde_yaml::from_str::<CapabilityFile>(content)
    } else {
        serde_yaml::from_str::<types::StrictCapabilityFile>(content).map(CapabilityFile::from)
    };

    match parsed {
        Ok(parsed) => Ok(Some(parsed)),
        Err(err) => {
            if validation.strict {
                Err(err).with_context(|| {
                    format!(
                        "failed to parse capability file '{}' (strict=true, allow_unknown_fields={})",
                        path.display(),
                        validation.allow_unknown_fields
                    )
                })
            } else {
                warn!(
                    "Skipping malformed capability file '{}': {}",
                    path.display(),
                    err
                );
                Ok(None)
            }
        },
    }
}

fn source_priority(path: &Path) -> SourcePriority {
    if path.components().any(|component| {
        matches!(
            component,
            Component::Normal(segment) if segment.to_string_lossy().eq_ignore_ascii_case("versions")
        )
    }) {
        SourcePriority::Versioned
    } else {
        SourcePriority::Canonical
    }
}

fn normalize_tool(tool: &mut ToolDefinition) {
    if tool.description.trim().is_empty() {
        tool.description = tool.name.clone();
    }

    if tool.categories.is_empty() {
        tool.categories.push("uncategorized".to_string());
    }

    if tool.input_schema.is_null() {
        tool.input_schema = types::default_input_schema();
    }
}

fn is_yaml(path: &Path) -> bool {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => matches!(ext, "yaml" | "yml"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::config::ValidationConfig;

    static TEST_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "tool-runtime-core-{label}-{}-{nonce}-{}",
            std::process::id(),
            TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn write_tool_file(path: &Path, tool_name: &str, description: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("failed to create capability directory");
        }

        let yaml = format!(
            r#"tools:
  - name: {tool_name}
    description: {description}
    inputSchema:
      type: object
      properties: {{}}
      required: []
    categories:
      - test
    metadata: {{}}
    hidden: false
    enabled: true
"#
        );
        fs::write(path, yaml).expect("failed to write capability file");
    }

    fn write_raw_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("failed to create capability directory");
        }
        fs::write(path, content).expect("failed to write capability file");
    }

    fn validation(strict: bool, allow_unknown_fields: bool) -> ValidationConfig {
        ValidationConfig {
            strict,
            allow_unknown_fields,
        }
    }

    #[test]
    fn canonical_definition_beats_versions_duplicate() {
        let root = unique_temp_dir("canonical-wins");
        let result = (|| {
            let capabilities_root = root.join("capabilities");
            write_tool_file(
                &capabilities_root.join("versions/filesystem/versioned.yaml"),
                "duplicate_tool",
                "versioned",
            );
            write_tool_file(
                &capabilities_root.join("core/canonical.yaml"),
                "duplicate_tool",
                "canonical",
            );

            let loaded = load_tools_from_paths(
                &[capabilities_root.to_string_lossy().to_string()],
                &validation(true, false),
            )?;
            let selected = loaded
                .get("duplicate_tool")
                .expect("tool should be present after loading");
            assert_eq!(selected.description, "canonical");
            Ok::<(), anyhow::Error>(())
        })();

        let _ = fs::remove_dir_all(&root);
        result.expect("test should complete without loader errors");
    }

    #[test]
    fn versions_definition_is_used_when_no_canonical_exists() {
        let root = unique_temp_dir("versioned-only");
        let result = (|| {
            let capabilities_root = root.join("capabilities");
            write_tool_file(
                &capabilities_root.join("versions/filesystem/versioned.yaml"),
                "version_only_tool",
                "versioned",
            );

            let loaded = load_tools_from_paths(
                &[capabilities_root.to_string_lossy().to_string()],
                &validation(true, false),
            )?;
            let selected = loaded
                .get("version_only_tool")
                .expect("versioned tool should be loaded when no canonical definition exists");
            assert_eq!(selected.description, "versioned");
            Ok::<(), anyhow::Error>(())
        })();

        let _ = fs::remove_dir_all(&root);
        result.expect("test should complete without loader errors");
    }

    #[test]
    fn strict_mode_errors_on_equal_priority_duplicates() {
        let root = unique_temp_dir("strict-equal-priority");
        let result = {
            let capabilities_root = root.join("capabilities");
            write_tool_file(
                &capabilities_root.join("core/a.yaml"),
                "duplicate_tool",
                "first",
            );
            write_tool_file(
                &capabilities_root.join("core/b.yaml"),
                "duplicate_tool",
                "second",
            );

            let loaded = load_tools_from_paths(
                &[capabilities_root.to_string_lossy().to_string()],
                &validation(true, false),
            );
            assert!(
                loaded.is_err(),
                "strict mode should fail when two equal-priority files define the same tool name"
            );
            let err = loaded
                .err()
                .map(|e| format!("{e:#}"))
                .unwrap_or_else(|| "<missing error>".to_string());
            assert!(
                err.contains("Equal-priority duplicate tool"),
                "error should mention equal-priority duplicate: {err}"
            );
            Ok::<(), anyhow::Error>(())
        };

        let _ = fs::remove_dir_all(&root);
        result.expect("test should complete without loader errors");
    }

    #[test]
    fn non_strict_mode_keeps_first_equal_priority_duplicate() {
        let root = unique_temp_dir("non-strict-equal-priority");
        let result = (|| {
            let capabilities_root = root.join("capabilities");
            write_tool_file(
                &capabilities_root.join("core/a.yaml"),
                "duplicate_tool",
                "first",
            );
            write_tool_file(
                &capabilities_root.join("core/b.yaml"),
                "duplicate_tool",
                "second",
            );

            let loaded = load_tools_from_paths(
                &[capabilities_root.to_string_lossy().to_string()],
                &validation(false, false),
            )?;
            let selected = loaded
                .get("duplicate_tool")
                .expect("tool should still be present");
            assert_eq!(
                selected.description, "first",
                "non-strict mode should keep the first equal-priority definition"
            );
            Ok::<(), anyhow::Error>(())
        })();

        let _ = fs::remove_dir_all(&root);
        result.expect("test should complete without loader errors");
    }

    #[test]
    fn strict_mode_errors_on_malformed_yaml() {
        let root = unique_temp_dir("strict-malformed");
        let result = {
            let capabilities_root = root.join("capabilities");
            write_raw_file(
                &capabilities_root.join("broken.yaml"),
                "tools:\n  - name: malformed\n    description: [\n",
            );

            let loaded = load_tools_from_paths(
                &[capabilities_root.to_string_lossy().to_string()],
                &validation(true, false),
            );
            assert!(
                loaded.is_err(),
                "strict mode should fail on malformed capability files"
            );
            Ok::<(), anyhow::Error>(())
        };

        let _ = fs::remove_dir_all(&root);
        result.expect("test should complete without loader errors");
    }

    #[test]
    fn non_strict_mode_skips_malformed_yaml_and_loads_valid_tools() {
        let root = unique_temp_dir("non-strict-malformed");
        let result = (|| {
            let capabilities_root = root.join("capabilities");
            write_raw_file(
                &capabilities_root.join("broken.yaml"),
                "tools:\n  - name: malformed\n    description: [\n",
            );
            write_tool_file(&capabilities_root.join("valid.yaml"), "valid_tool", "valid");

            let loaded = load_tools_from_paths(
                &[capabilities_root.to_string_lossy().to_string()],
                &validation(false, false),
            )?;
            assert!(
                loaded.contains_key("valid_tool"),
                "non-strict mode should keep loading valid capability files"
            );
            Ok::<(), anyhow::Error>(())
        })();

        let _ = fs::remove_dir_all(&root);
        result.expect("test should complete without loader errors");
    }

    #[test]
    fn strict_mode_errors_on_unknown_fields_when_disallowed() {
        let root = unique_temp_dir("strict-unknown");
        let result = {
            let capabilities_root = root.join("capabilities");
            write_raw_file(
                &capabilities_root.join("unknown_field.yaml"),
                r#"tools:
  - name: strict_unknown
    description: unknown field test
    inputSchema:
      type: object
      properties: {}
      required: []
    categories:
      - test
    metadata: {}
    hidden: false
    enabled: true
    unexpected_field: true
"#,
            );

            let loaded = load_tools_from_paths(
                &[capabilities_root.to_string_lossy().to_string()],
                &validation(true, false),
            );
            assert!(
                loaded.is_err(),
                "strict unknown-field validation should reject unexpected keys"
            );
            Ok::<(), anyhow::Error>(())
        };

        let _ = fs::remove_dir_all(&root);
        result.expect("test should complete without loader errors");
    }

    #[test]
    fn packs_directory_is_skipped_during_walk() {
        let root = unique_temp_dir("packs-skipped");
        let result = (|| {
            let capabilities_root = root.join("capabilities");

            // A valid tool at the root level
            write_tool_file(
                &capabilities_root.join("valid.yaml"),
                "root_tool",
                "root tool",
            );

            // A file inside packs/ that would fail strict parsing if read
            write_raw_file(
                &capabilities_root.join("packs/browser.yaml"),
                r#"name: browser
description: "test pack"
parameters: []
implementation:
  type: compiled
  provider_name: browser
"#,
            );

            let loaded = load_tools_from_paths(
                &[capabilities_root.to_string_lossy().to_string()],
                &validation(true, false),
            )?;

            assert!(
                loaded.contains_key("root_tool"),
                "root-level tool should be loaded"
            );
            // packs/ directory should be entirely skipped
            assert!(
                !loaded.contains_key("browser"),
                "packs/ directory contents should not be parsed by RegistryService"
            );
            Ok::<(), anyhow::Error>(())
        })();

        let _ = fs::remove_dir_all(&root);
        result.expect("test should complete without loader errors");
    }

    #[test]
    fn allow_unknown_fields_true_accepts_unknown_fields() {
        let root = unique_temp_dir("allow-unknown");
        let result = (|| {
            let capabilities_root = root.join("capabilities");
            write_raw_file(
                &capabilities_root.join("unknown_field.yaml"),
                r#"tools:
  - name: permissive_unknown
    description: unknown field test
    inputSchema:
      type: object
      properties: {}
      required: []
    categories:
      - test
    metadata: {}
    hidden: false
    enabled: true
    unexpected_field: true
"#,
            );

            let loaded = load_tools_from_paths(
                &[capabilities_root.to_string_lossy().to_string()],
                &validation(true, true),
            )?;
            assert!(
                loaded.contains_key("permissive_unknown"),
                "unknown fields should be tolerated when allow_unknown_fields=true"
            );
            Ok::<(), anyhow::Error>(())
        })();

        let _ = fs::remove_dir_all(&root);
        result.expect("test should complete without loader errors");
    }
}
