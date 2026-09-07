# MagicRun

Governed local execution primitives for trusted application builders. The Rust
package remains `tool-runtime-core` (`tool_runtime_core` in source) so existing
integrations can adopt the repository without an API or schema rename.

The runtime owns manifest admission, typed invocation lowering, credential
preparation/delivery, governed batch and PTY execution, optional process jails,
bounded output, cancellation, and metadata-only settlement. The host implements
the authorization, credential-resolution, audit, and interactive bridge traits.
There is no model-facing credential-read API or standalone vault service here.

Start with `governed_execution_coordinator::GovernedExecutionInvocation` and its
`execute_batch`, `execute_batch_in_jail`, and `execute_pty` methods. Consumers
retain their existing execution owner; extraction does not introduce retries or
an additional process supervisor.

See the [versioned architecture and trust boundaries](docs/architecture.md),
including the component diagram for `tool-runtime-core 0.1.73`.

## Development and evidence

### Build and test location

Makefile check/build/test/run commands put Cargo artifacts in
`/Volumes/SSD1/magicrun/builds` when SSD1 and the existing path components are
writable directories. Without that volume, they fall back to this checkout's
ignored `target/`. MagicVault uses a separate `magicvault/builds` directory;
neither project shares an embedded consumer's build tree.

```bash
make print-target-dir
make check
make build
make test

# Other hosts can choose a different mount or an exact artifact directory:
make BUILD_VOLUME=/mnt/fast-disk print-target-dir
make CARGO_TARGET_DIR=/absolute/path/to/build-cache test-lifecycle

# Raw Cargo commands do not read the Makefile; export the selected path first:
export CARGO_TARGET_DIR="$(make -s print-target-dir)"
cargo test --workspace
```

An explicit environment or command-line `CARGO_TARGET_DIR` always wins.
Selection is read-only: it never creates a missing mount, follows an existing
cache-directory symlink, moves caches, or changes credential/runtime data.
Dependency downloads and OS-managed test temporary directories keep their
existing locations. Use distinct explicit targets for concurrent worktrees of
the same project, and keep the drive connected while builds run.

`make test-build-paths` checks selection, fallback, overrides and recipe environment
propagation using disposable fixture directories and a fake Cargo recorder. It
does not compile or run the Rust application/library suites.

### Architecture and runtime verification

`make check-architecture` compares the source and architecture document against
the reviewed versioned baseline; `make check` includes that gate. Run
`make test-architecture` for synthetic drift-checker tests. Baseline renewal is a
deliberate review action; it does not certify runtime behavior or approve a
consumer's source attestation.

Use `make check` and `make test` in this repository when verification is permitted.
The portable unit and qualification tests live with the crate. Magician's built-in
skill inventory and skill-package contract suites remain in Magician's own
`magician/tests/`; they require product source/data and are not portable library tests.

The `source_bytes` module exposes actual compiled source for consumer-owned
attestations. The host retains its source-review policy; no trusted digest is
frozen inside the library. Runtime, performance and platform qualification must
be established for the actual consumer and environment. Passing tooling checks
is not a substitute for those tests. The qualification workflow is manual-only.

Public documentation covers technical contracts, architecture, usage and
verification; planning/progress journals belong in Git history. Do not commit
runtime data, credential files, built binaries or operator configuration.

Licensed under MIT OR Apache-2.0; see the included license files.
