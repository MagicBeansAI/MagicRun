//! In-jail egress forwarder of the Linux brokered-egress process jail. Install
//! it root-owned at one of
//! `tool_runtime_core::governed_process_jail::GOVERNED_JAIL_EGRESS_FORWARDER_PATHS`.
//! See `governed_process_jail::egress_forwarder` for the protocol.

#[cfg(unix)]
fn main() {
    tool_runtime_core::governed_process_jail::egress_forwarder::forwarder_main(
        std::env::args_os().skip(1),
    )
}

#[cfg(not(unix))]
fn main() {
    std::process::exit(
        tool_runtime_core::governed_process_jail::egress_forwarder::FORWARDER_EXIT_USAGE,
    );
}
