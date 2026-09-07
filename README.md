<div align="center">
  <h1>MagicRun</h1>
  <p><strong>Give agents tools. Keep execution under your control.</strong></p>
  <p>
    <a href="tool-runtime-core/CHANGELOG.md"><img src="https://img.shields.io/badge/source-v0.1.73-7C3AED.svg" alt="Source version 0.1.73" /></a>
    <a href="#build-on-magicrun"><img src="https://img.shields.io/badge/interface-Rust%20library-lightgrey.svg" alt="Interface: Rust library" /></a>
    <a href="#rust-toolchain"><img src="https://img.shields.io/badge/Rust-2021%20edition-orange.svg" alt="Rust language edition 2021" /></a>
    <a href="#license"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="MIT or Apache-2.0 license" /></a>
  </p>
  <p>
    <a href="#quick-start">Quick start</a> ·
    <a href="#what-it-covers">Coverage</a> ·
    <a href="#build-on-magicrun">For builders</a> ·
    <a href="docs/architecture.md">Architecture</a> ·
    <a href="#security-and-host-responsibilities">Security</a>
  </p>
</div>

Turn a tool request into an explicitly authorized, bounded local execution.
MagicRun gives application builders a shared path for validating tool contracts,
preparing credentials, running batch commands or interactive terminals, and
recording the outcome. Your application supplies the permissions, approvals
and credential backend.

- **Authorize before credentials.** Bind authorization to the exact invocation
  before asking the host to resolve credential material.
- **Keep execution bounded.** Govern working directories, environment, output,
  deadlines and cancellation; opt into an OS process jail where supported.
- **Keep your application in charge.** Embed the runtime behind your own agent,
  UI or tool service without adopting another daemon or process supervisor.

MagicRun is the Rust package **`tool-runtime-core`** (`tool_runtime_core` in code).
It powers Magician's local tool runtime. It is a library for trusted hosts—not
a ready-to-run agent application or a credential vault.

> [!WARNING]
> **Pre-1.0 library.** Review API and contract changes when upgrading. Runtime
> guarantees depend on your host integration and operating system; a successful
> build or tooling check is not security certification. The recipient process
> necessarily receives any credentials authorized for it.

## What it covers

| Capability / surface | Available today? | Integration and limits |
| :--- | :--- | :--- |
| **Rust application integration** | **Yes** | Embed `tool-runtime-core`; the host owns authorization, credential resolution, audit durability and model-facing output. |
| **New processes / command-line programs** | **Yes — library primitives** | `GovernedExecutionInvocation::execute_batch` runs an admitted contract with scoped environment/stdin and authorized credential placement. This is not an unrestricted shell tool. |
| **Interactive terminal sessions** | **Yes — governed PTY execution** | `execute_pty` requires a trusted host bridge and explicit policy. It does not attach to an arbitrary existing PID or terminal. |
| **Process isolation** | **Optional, platform-dependent** | `execute_batch_in_jail` uses an explicitly prepared jail. macOS/Linux implementations have platform prerequisites; unsupported jail requests fail closed. Ordinary batch execution is not automatically jailed. |
| **Credential environment, stdin and files** | **Conditional** | Only placements supported by the admitted contract are prepared. Filesystem delivery requires explicit authority and has platform/provider restrictions. No generic adoption of existing credential files. |
| **Tool discovery and catalog generation** | **Yes** | Manifest/schema validation, source inventory, classification, replay analysis and MCP catalog projection. Catalog membership does not grant execution permission. |
| **Standalone CLI** | **Development utilities only** | Inventory, classification and replay binaries inspect tool definitions. There is no general-purpose `magicrun exec` secret-injection command. |
| **MCP server / execution daemon** | **Not provided** | A builder can wrap the library in a trusted service; catalog helpers are not an MCP transport or authorization service. |
| **Browser credential fills** | **Not provided here** | MagicVault owns its standalone CDP and extension delivery adapters. Browser-profile helpers in this crate are not a browser-fill surface. |
| **New HTTP requests / running stateful services** | **No dedicated delivery surface** | A host may govern a CLI that makes requests, but that is process execution—not a secure HTTP broker or generic live credential-refresh adapter. |

MagicVault's standalone `0.4.0` integration uses this crate's existing public
coordinator for `secure_new_process`; its HTTP adapter is separate. MagicRun
itself still supplies no standalone secret-injection service. See the
[architecture and integration limits](docs/architecture.md).

## Quick start

Use a Rust toolchain with Cargo, a native linker and `make`. Repository checks
also need Python 3. OS-specific execution requires the relevant host support;
there is no universal platform-support claim.

### Build from source

```bash
git clone https://github.com/MagicBeansAI/MagicRun.git
cd MagicRun

make print-target-dir
make build

# Build the local library API documentation using the same artifact directory:
export CARGO_TARGET_DIR="$(make -s print-target-dir)"
cargo doc -p tool-runtime-core --no-deps
```

Open `$CARGO_TARGET_DIR/doc/tool_runtime_core/index.html` to browse the API.
`make build` compiles the library and development binaries; it does not start
an agent, open a terminal session, or enroll credentials.

Builds prefer `/Volumes/SSD1/magicrun/builds` when available and writable, otherwise
the checkout's ignored `target/`. [Build locations and overrides](#build-and-test-location).

### Add it to your Rust application

From an existing Cargo project:

```bash
cargo add tool-runtime-core --git https://github.com/MagicBeansAI/MagicRun.git
cargo add anyhow
```

This uses the source repository, not an assumed crates.io publication. Retain
your application's lockfile for reproducible builds and review dependency updates.

A small read-only starting point is inspecting your own tool-package directory:

```rust
use anyhow::{ensure, Context, Result};
use tool_runtime_core::inventory::SourceInventoryScanner;

fn main() -> Result<()> {
    let root = std::env::args_os()
        .nth(1)
        .context("pass a directory containing your tool packages")?;
    let inventory = SourceInventoryScanner::new(root, "tools")?.scan()?;

    ensure!(!inventory.has_errors(), "tool inventory contains validation errors");
    println!(
        "{} tools, {} actions, {} warnings",
        inventory.summary.active_tool_skills,
        inventory.summary.schema_actions,
        inventory.summary.warnings,
    );
    Ok(())
}
```

Put the example in your application's `src/main.rs`, then pass the parent
directory of your supported tool packages:

```bash
cargo run -- /absolute/path/to/your/tool-packages
```

The scanner recognizes supported tool schemas and runtime-contract packages; an
empty directory can produce an empty inventory. This example reads definitions:
it does not execute tools, resolve credentials or authorize anything. Use a
trusted local directory; inventory diagnostics are not a model-output filter.

## Build on MagicRun

For actual execution, start with
[`GovernedExecutionInvocation`](tool-runtime-core/src/governed_execution_coordinator.rs).
Construct a validated runtime contract, exact execution intent, credential
preparation/injection plans and call context before selecting batch, jailed
batch or PTY execution.

| Host integration point | Your application supplies |
| :--- | :--- |
| `GovernedExecutionAuthorizer` | Policy, human approval where needed, grants and resource evidence bound to the exact invocation |
| `CredentialMaterialResolver` | Only the authorized material from your chosen vault or credential provider |
| `GovernedExecutionAuditSink` | Durable, metadata-only audit handling and failure policy |
| `GovernedPtyBridge` | For PTY execution: trusted input/output handling that preserves the application's observation policy |
| Executable and filesystem authority | Reviewed executable provenance, allowed working roots and explicit file-placement permissions |

Callbacks must enforce their own I/O deadlines. The coordinator can reject a late
return; it cannot forcibly preempt arbitrary blocking host code. Preserve the
typed settlement and dispatch evidence when handling cancellation or uncertain
outcomes—do not turn uncertainty into an automatic retry.

The [architecture document](docs/architecture.md) contains the authority-flow
diagram, execution lifecycle, module map and version-bound drift baseline.
The [qualification fixtures](tool-runtime-core/tests/) show contract-level
integration cases; their synthetic providers are not production authorization
or credential backends.

### MagicRun, MagicVault and Magician

- **MagicRun** owns reusable tool-execution primitives.
- **MagicVault** owns credential custody and standalone browser/process/HTTP
  delivery surfaces, including human approval, fixed profiles and receipt-only
  model output. Its process adapter uses MagicRun's public coordinator.
- **Magician** supplies the integrated application, policy and execution ownership.

A builder may connect a vault to MagicRun through the resolver boundary.
Neither importing MagicRun nor combining libraries automatically supplies a safe
model-facing service. Existing consumers keep their own roots, credentials,
approvals and supervisor; library adoption does not replace those owners.

## Security and host responsibilities

MagicRun helps a trusted application govern execution; it does not make an
untrusted host safe. The host and authorized recipient can see credential
material. Arbitrary same-user software is outside this library's isolation
boundary, and a bounded output buffer is not by itself a secret filter.

Review authorization, executable provenance, credential placement, output/PTY
mediation, cleanup and audit durability together. Keep raw credentials out of
model requests, diagnostic logs and issue reports. Use synthetic data when
reporting problems, and report suspected vulnerabilities privately through the
repository's security reporting channel when available.

The `source_bytes` module exposes the actual compiled source for consumer-owned
attestation. Architecture fingerprints prompt review; they do not replace that
trust decision or freeze an internally “trusted” digest.

## Development

### Rust toolchain

The crate declares **Rust edition 2021**. An edition selects language rules;
a compiler version such as `1.88` identifies a Rust toolchain release. These
are separate Cargo settings: [`edition`](https://doc.rust-lang.org/cargo/reference/manifest.html#the-edition-field)
and [`rust-version`](https://doc.rust-lang.org/cargo/reference/rust-version.html).

MagicRun does not currently declare a minimum supported compiler version in its
manifest, nor does it publish a separately verified minimum-toolchain guarantee.
Use a current stable toolchain and qualify your resolved dependencies.
MagicVault's standalone MCP dependency has its own compiler requirement; that
does not set this crate's language edition or automatically impose the same
minimum on embedded consumers.

### Build and test location

All Makefile Cargo lanes share the selected `CARGO_TARGET_DIR`.
An explicit environment or command-line value wins over automatic SSD1 routing:

```bash
make print-target-dir
make BUILD_VOLUME=/mnt/fast-disk print-target-dir
make CARGO_TARGET_DIR=/absolute/path/to/build-cache test-lifecycle

# Raw Cargo commands need the same export:
export CARGO_TARGET_DIR="$(make -s print-target-dir)"
cargo test -p tool-runtime-core credential_lifecycle
```

Selection is read-only: it never creates a missing mount, follows an existing
cache-directory symlink, moves caches or changes runtime data. Dependency downloads
and OS-managed test temporary directories retain their existing locations.
Use distinct targets for concurrent worktrees and keep the drive connected while
builds run. MagicVault uses its own artifact directory.

### Verification

Choose a lane appropriate to the change:

```bash
# Lightweight documentation/build-tooling verification; no Rust execution:
make check-architecture test-architecture test-build-paths

# Focused credential-lifecycle tests:
make test-lifecycle

# Full workspace compile checks and tests:
make check
make test
```

`make check-architecture` compares source and documentation with the reviewed
baseline; `make check` includes it. Refresh the baseline only after reviewing
the affected boundaries. See [architecture drift review](docs/architecture.md#detecting-architectural-drift).

Library tests live here; Magician's built-in skill inventory and package-contract
suites stay in Magician because they require product source/data. The repository
qualification workflow is manual-only. Tooling tests do not qualify runtime
performance, platform isolation or consumer integrations.

## Documentation and contributing

- [Architecture, authority flow and versioned baseline](docs/architecture.md)
- [Public modules](tool-runtime-core/src/lib.rs) and [execution coordinator](tool-runtime-core/src/governed_execution_coordinator.rs)
- [Library qualification fixtures](tool-runtime-core/tests/)
- [Changelog and historical evidence boundaries](tool-runtime-core/CHANGELOG.md)

Describe the affected contract, expected outcome, source revision and OS when
opening an issue. Keep runtime data, credential files, built binaries, private
tool definitions and operator configuration out of commits. Public documentation
covers technical contracts, architecture, usage and verification.

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).
