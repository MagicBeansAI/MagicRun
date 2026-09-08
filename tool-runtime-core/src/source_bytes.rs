//! Source bytes used by host-owned implementation attestations.
//!
//! These are the actual sources compiled into this crate revision, not cached
//! digests or a compatibility snapshot. Moving the crate must not require a
//! consumer to reach into a sibling checkout. Consumers own labels, hashing,
//! review policy, and the handling of identity changes on an upgrade.

pub const GOVERNED_PROCESS_JAIL: &[u8] = include_bytes!("governed_process_jail.rs");
pub const GOVERNED_BATCH_PROCESS: &[u8] = include_bytes!("governed_batch_process.rs");
#[cfg(magicrun_test_diagnostics)]
pub const PROCESS_TEST_DIAGNOSTICS: &[u8] = include_bytes!("process_test_diagnostics.rs");
pub const GOVERNED_EXECUTION_AUTHORITY: &[u8] = include_bytes!("governed_execution_authority.rs");
pub const GOVERNED_EXECUTION_COORDINATOR: &[u8] = include_bytes!("governed_execution_coordinator.rs");
pub const GOVERNED_EXECUTION: &[u8] = include_bytes!("governed_execution.rs");
pub const GOVERNED_EXECUTION_RESULT: &[u8] = include_bytes!("governed_execution_result.rs");
pub const ACTION_OVERRIDES: &[u8] = include_bytes!("action_overrides.rs");
pub const CREDENTIAL_PREPARATION: &[u8] = include_bytes!("credential_preparation.rs");
pub const CREDENTIAL_INJECTION: &[u8] = include_bytes!("credential_injection.rs");
pub const CREDENTIAL_MATERIALIZATION: &[u8] = include_bytes!("credential_materialization.rs");
pub const MANIFEST_PARSER: &[u8] = include_bytes!("manifest_parser.rs");
pub const MANIFEST_VALIDATION: &[u8] = include_bytes!("manifest_validation.rs");
pub const MCP_CATALOG_PROJECTION: &[u8] = include_bytes!("mcp_catalog_projection.rs");
