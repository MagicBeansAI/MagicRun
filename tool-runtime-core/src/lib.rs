#[cfg(all(magicrun_test_diagnostics, not(debug_assertions)))]
compile_error!("magicrun_test_diagnostics is forbidden in release builds");
#[cfg(magicrun_test_diagnostics)]
#[doc(hidden)]
pub mod process_test_diagnostics;

pub mod action_overrides;
pub mod browser_profile_adapter;
pub mod canary;
pub mod classification;
pub mod config;
pub mod credential_filesystem;
pub mod credential_injection;
pub mod credential_lifecycle;
pub mod credential_lifecycle_coordinator;
pub mod credential_lifecycle_execution;
pub mod credential_lifecycle_observation;
pub mod credential_materialization;
pub mod credential_persistence;
pub mod credential_preparation;
pub mod credential_profile_store;
pub mod credential_profiles;
pub mod credential_status_cache;
pub mod governed_batch_process;
pub mod governed_execution;
pub mod governed_execution_authority;
pub mod governed_execution_coordinator;
pub mod governed_execution_result;
pub mod governed_process_jail;
pub mod governed_pty_process;
pub mod inventory;
pub mod manifest;
pub mod manifest_parser;
pub mod manifest_synthesis;
pub mod manifest_validation;
pub mod mcp_catalog_policy;
pub mod mcp_catalog_projection;
pub mod native_permission_adapter;
pub mod profile_selection;
pub mod registry;
pub mod replay;
pub mod scoped_paths;
pub mod source_bytes;
pub mod strategy_adapter;
pub mod tool_discovery;

#[cfg(test)]
mod phase3_qualification;
