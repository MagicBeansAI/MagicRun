//! Source bytes used by host-owned implementation attestations.
//!
//! These are the actual sources compiled into this crate revision, not cached
//! digests or a compatibility snapshot. Moving the crate must not require a
//! consumer to reach into a sibling checkout. Consumers own labels, hashing,
//! review policy, and the handling of identity changes on an upgrade.

pub const GOVERNED_PROCESS_JAIL: &[u8] = include_bytes!("governed_process_jail.rs");
#[cfg(not(target_os = "macos"))]
pub const GOVERNED_BATCH_PROCESS: &[u8] = include_bytes!("governed_batch_process.rs");
// Existing host attestations of batch execution must cover its new delegated
// backend too; do not require consumers to discover a missing security input.
#[cfg(target_os = "macos")]
pub const GOVERNED_BATCH_PROCESS: &[u8] = concat!(
    include_str!("governed_batch_process.rs"),
    "\n// macOS batch launch backend\n",
    include_str!("governed_batch_process/macos_spawn.rs"),
).as_bytes();
#[cfg(target_os = "macos")]
pub const GOVERNED_MACOS_SPAWN: &[u8] = include_bytes!("governed_batch_process/macos_spawn.rs");
#[cfg(magicrun_test_diagnostics)]
pub const PROCESS_TEST_DIAGNOSTICS: &[u8] = include_bytes!("process_test_diagnostics.rs");
#[cfg(all(target_os = "macos", magicrun_test_diagnostics))]
pub const PROCESS_TEST_LAUNCH_DIAGNOSTICS: &[u8] =
    include_bytes!("process_test_diagnostics/launch.rs");
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

#[cfg(all(test, target_os = "macos"))]
mod tests {
    #[test]
    fn batch_attestation_includes_the_actual_native_backend() {
        assert!(super::GOVERNED_BATCH_PROCESS.ends_with(super::GOVERNED_MACOS_SPAWN));
        assert!(super::GOVERNED_BATCH_PROCESS.starts_with(include_bytes!("governed_batch_process.rs")));
    }
}
