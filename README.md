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

## Development and evidence

Use `make check` and `make test` in this repository when verification is permitted.
The portable unit and qualification tests live with the crate. Magician's built-in
skill inventory and skill-package contract suites remain in Magician's own
`magician/tests/`; they require product source/data and are not portable library tests.

This first extraction is based on Magician revision
`aef928c000138fea035eea034118f8c23db582ed`, runtime package `0.1.73`.
Production Rust source and portable fixtures were moved without execution changes.
No checks or tests were run during extraction, by explicit owner instruction;
compilation, runtime behavior, performance, and platform qualification remain
unverified. The workflow is manual-only and has not been dispatched.

The repository's source snapshot is independent of Magician's private history.
No runtime data, credential files, built binaries, or operator configuration are
part of the export. Repository visibility is unchanged by this extraction.

Licensed under MIT OR Apache-2.0; see the included license files.
