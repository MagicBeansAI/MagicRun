use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CapabilityFile {
    pub metadata: Option<HashMap<String, Value>>,
    pub tools: Vec<ToolDefinition>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct StrictCapabilityFile {
    pub metadata: Option<HashMap<String, Value>>,
    pub tools: Vec<StrictToolDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    #[serde(alias = "inputSchema", alias = "input_schema")]
    pub input_schema: Value,
    pub categories: Vec<String>,
    pub metadata: HashMap<String, Value>,
    pub hidden: bool,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct StrictToolDefinition {
    pub name: String,
    pub description: String,
    #[serde(alias = "inputSchema", alias = "input_schema")]
    pub input_schema: Value,
    pub categories: Vec<String>,
    pub metadata: HashMap<String, Value>,
    pub hidden: bool,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

impl Default for ToolDefinition {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            input_schema: default_input_schema(),
            categories: vec![],
            metadata: HashMap::new(),
            hidden: false,
            enabled: true,
        }
    }
}

impl Default for StrictToolDefinition {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            input_schema: default_input_schema(),
            categories: vec![],
            metadata: HashMap::new(),
            hidden: false,
            enabled: true,
        }
    }
}

impl From<StrictCapabilityFile> for CapabilityFile {
    fn from(value: StrictCapabilityFile) -> Self {
        Self {
            metadata: value.metadata,
            tools: value.tools.into_iter().map(ToolDefinition::from).collect(),
        }
    }
}

impl From<StrictToolDefinition> for ToolDefinition {
    fn from(value: StrictToolDefinition) -> Self {
        Self {
            name: value.name,
            description: value.description,
            input_schema: value.input_schema,
            categories: value.categories,
            metadata: value.metadata,
            hidden: value.hidden,
            enabled: value.enabled,
        }
    }
}

pub fn default_enabled() -> bool {
    true
}

pub fn default_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {},
        "required": []
    })
}
