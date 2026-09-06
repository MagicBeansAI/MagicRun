# Changelog

All notable changes to the tool-runtime-core project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---
## [Unreleased]

_Current development version: `0.1.73`._

### Fixed - the adapter inventory test asserted on gitignored artifacts (0.1.73)

- `active_adapter_inventory_names_only_existing_or_materializable_owned_sources`
  required every classified source to be a file on disk, but `.gitignore`
  ignores `skillshub/*/bin/` wholesale and re-admits each adapter source
  through a per-skill allowlist. Two of the forty declared files were not
  covered by that allowlist, so the test asserted whether the machine that ran
  it happened to have the files, not whether the inventory was sound. It failed
  on a second machine and passed on the first.
- `skillshub/work-modules/bin/work-modules` was the real defect: a hand-written
  Python adapter, added to the classification manifest on 2026-09-02, that git
  had never carried. It is now allowlisted and committed.
- `browser/bin/agent-browser` is the opposite case — a genuine build artifact
  from `make setup-agent-browser`, correctly ignored, which the test passed
  over only because `make test-rust` depends on that setup target. It joins
  `metabase-pp-cli` in `generated_sources`, so the test no longer doubles as a
  check that setup has run. `verify-agent-browser` already does that, and more
  strictly. Verified by deleting both binaries: 8/8 still pass.

### Fixed - fast jailed exits win the first resource sample race (0.1.72)

- The parent-side jail sampler now waits one bounded observation interval and
  reaps the owned child at the top of every collection tick before enforcing a
  sampled limit. A genuine fast exit therefore returns its real status instead
  of being killed and misclassified because its launcher tree raced the first
  sampler tick; hard kernel limits still apply from exec.
- The macOS deny-default profile now permits only the literal root-directory
  data read required by Darwin libc while resolving the inherited working
  directory. This prevents a pre-`main` SIGABRT without granting any root
  subtree, Mach service, network, or additional executable authority.

### Removed - `skill_type: facade`

- Schema-backed inventory accepts only `skill_type: tool` as
  executable. `facade` is a `schema_skill_type_conflict`.

### Added - Skill audience expose flags

- `metadata.magician.expose` is parsed as `SkillExposeAudience`.
  `agents` defaults to `true`. `apps` defaults to `false`. A present
  but unknown expose field fails closed. The flags are catalog
  audience only and grant no execution authority.

### Added

- Tier 1 assertion `no_declared_parameter_accepts_an_explicit_null` in
  `tests/tool_skill_contract.rs`. For every skill using
  `input_delivery: canonical_json_stdin` it compiles the typed action catalog,
  proves a null-free baseline invocation lowers cleanly, then asserts that
  setting each declared parameter to `null` is rejected as `InvalidParameter`.

  This pins the property that keeps an explicit `null` out of adapter envelopes.
  Adapters fill absent parameters with `setdefault`, which fills only keys that
  are *absent*; a `null` is present, so it would survive and reach expressions
  like `results[: args.max_results]`, where `results[:None]` is the whole list —
  a declared result cap silently disabled, failing open with no error. Two
  shipped adapters slice a caller-facing cap that way. What stops it is that the
  typed parameter vocabulary has no nullable variant, so
  `validate_runtime_parameter` rejects `null` on every arm and canonical-JSON
  lowering validates each value on its way into the envelope. Adding a nullable
  type, or coercing `null` to a declared default during lowering, would reopen
  the hole in every canonical-JSON adapter at once; this now goes red first.
  Investigation and proof:
  `docs/plans/2026-08-15-explicit-null-defeats-adapter-bounds.md`.

### Changed

- Hardened `AuthContract` credential target validation for `ConfigDirectory`:
  generic `ConfigDirectory` targets now only accept `ProfileAuthRoot` as a source,
  while `Secret` is accepted only for `provider: minimax` + `name: MMX_CONFIG_DIR`.
  Non-Unix hosts now reject both `ScopedFile` and `ConfigDirectory` targets.

### Fixed

- Restored config-directory credential-injection coverage with the reviewed
  MiniMax provider identity, so the fixture exercises the admitted
  `MMX_CONFIG_DIR` contract instead of constructing an invalid generic secret
  target. Production provider gating remains unchanged.
- `CredentialInjection` for Minimax now materializes secrets only into
  `MMX_CONFIG_DIR/config.json` and zeroizes the serialized JSON payload bytes
  after write, preventing leaked payload bytes in long-lived memory.
- `manifest_validation` now rejects invalid `ConfigDirectory`+`Secret` combinations
  during contract admission before dispatch planning.

## [0.1.69] - 2026-08-15

### Added

- Added `MemoryLimitEnforcement` and `memory_limit_enforcement()`, replacing the
  boolean answer to "can this host hold a declared `runtime.limits.memory_bytes`"
  with the mechanism that holds it: `KernelAddressSpace` (`setrlimit(RLIMIT_AS)`),
  `ParentFootprintWatchdog`, or `None`.
  `process_memory_limits_are_enforceable()` is retained and is now true when
  either mechanism applies.

- Darwin now **holds** a declared memory ceiling instead of refusing it. The
  collection loop samples the owned process group's `ri_phys_footprint` every
  `POLL_INTERVAL` and terminates the group on breach. Previously Darwin could run
  no skill declaring a ceiling at all: `RLIMIT_AS` is aliased onto `RLIMIT_RSS`
  there and returns `EINVAL` for every finite value, so the contract was refused
  at construction and `document-to-markdown` — the only packaged skill declaring
  `memory_bytes` — was unrunnable on the platform.

  This is deliberately a **detection** bound and not an allocation bound. A child
  may exceed its ceiling for up to one sampling interval, and an allocation
  serviced and released between two samples is never observed. It is strictly
  weaker than the kernel bound, which is why the mechanism is reported rather
  than hidden behind a boolean. The group, not the leading pid, is the unit of
  measurement, so a skill that forks a helper cannot place its allocation outside
  the ceiling its manifest declared.

- Added `GovernedExecutionTerminal::MemoryLimitExceeded` and
  `CredentialExecutionFailure::ProcessMemoryExceeded`. Both are kept distinct
  from the timeout path so an operator reading the audit can tell a runaway
  allocation from a slow one; a breach reported as `TimedOut` would advise
  raising a timeout on a process killed for what it held.

- Added `canary::CanaryExpectation::max_cost_commodity`, and made it **required**
  whenever `max_cost_microunits` is declared (and refused when it is not). A spend
  ceiling that does not name what it counts cannot be compared to what a package
  reports. Packages price in different commodities deliberately —
  `semantic-websearch-via-exa` reports `usd`, `news-search-via-tavily` reports
  `tavily_credit`, because Tavily returns no money figure at all and the value of a
  credit belongs to the operator's plan — and the product's own retrieval budgets are
  keyed by commodity for exactly that reason. Reading the *encoding* from the package
  had already removed one factor-of-a-million error; the commodity is the other half.
  Without it, exa's ceiling of 20000 USD-microunits was copied onto tavily, where one
  basic search — a real cost near $0.008 — was judged as a dollar of spend. A zero
  ceiling is also refused, since it forbids the call the canary is declared to make.

- Added `canary`: the `tool-runtime.canary.v1` manifest vocabulary for the live
  tool-skill verification lane. A skill declares a cheap, read-only invocation
  and its expectations; skills that message real people, read private data,
  place orders, or drive the live desktop declare an explicit exemption with a
  recorded reason instead. The schema rejects a canary whose only assertion is
  exit-zero, since a broken adapter satisfies that too, and it bounds fixture
  names so a canary cannot reach outside its package.

- Added `ChildEnvironmentVariable::SslCertFile` and admitted `SSL_CERT_FILE` to the
  portable CLI baseline so governed adapters whose interpreter ships no trust store can
  verify TLS. The name is admitted here only; the value stays runtime-owned policy and
  is never cloned from the parent environment. `hermetic()` still admits nothing, so a
  hermetic contract that needs TLS must opt into the portable baseline.
- Added `process_memory_limits_are_enforceable()`, a per-target predicate for whether
  a spawned child can actually be held to a finite address-space ceiling, plus the
  `UnenforceableMemoryLimit` error code that reports its refusal.
- Added a lowering regression pin for an optional `split_positional` string whose
  value is empty. Several shipped skills declare `flags` that way with a default of
  `''`, and lowering it to a single empty token would malform the invocation rather
  than omit the flag — `awk "" '{print $2}' file` selects an empty program and prints
  nothing. Pinned because it is an easy thing to "fix" in the manifests when the
  cause is in the splitter.

### Changed

- A contract declaring `runtime.limits.memory_bytes` is now refused during
  construction on any host that cannot enforce it, before a permit, a reservation,
  or a process exists. Darwin aliases `RLIMIT_AS` onto `RLIMIT_RSS` and answers every
  finite value with `EINVAL`, so the ceiling previously died at spawn, after the work
  of admission had already been done. There is no substitute on that platform:
  `RLIMIT_DATA` bounds only the `brk` segment, which a modern allocator's `mmap`
  arenas never occupy. The alternative — applying the limit and swallowing the
  platform's rejection — is worse than refusing, because it leaves the child running
  while the manifest still advertises a bound nothing enforces. The declaration
  itself stays valid and portable; only this host declines to act on it.

### Fixed

- A governed CLI skill declaring fixed public configuration in
  `requires.environment` could not execute at all. Those names reach the child
  through `provide_fixed`, but the compiled injection plan never admitted them, so
  `governed_environment` rejected the whole environment as a baseline mismatch and
  the call failed with `CredentialMaterializationFailed` before dispatch — a
  credential error for a skill that declares no credential. This took every
  officecli-backed skill dark. The plan now seeds `child_environment_names` from
  `requires.environment` as well. Admitting them cannot shadow anything: validation
  already refuses process-sensitive names and any name colliding with an authored
  injection target, and `provide_fixed` already refuses a name colliding with a
  baseline variable.
- A binary resident on the macOS sealed system volume is now launched in place
  instead of from the private snapshot copy. Every `/usr/bin` and `/bin` tool ships
  as a universal image whose arm64e slice uses the pointer-authentication ABI, which
  is admissible only for platform binaries — and the kernel decides platform-binary
  status from where the file *lives*, not from what it carries. A copy keeps its
  Apple signature completely intact and is still SIGKILLed at exec, yielding no exit
  code and two empty streams. **Residence, not signature, is the test.** The
  practical effect was that no `/usr/bin` tool ran under this runtime at all; `awk`,
  `sed`, `tar`, `curl`, and `sqlite3` died identically. This narrows a security
  boundary for exactly one filesystem shape, and only because the alternative is
  stronger: the sealed volume is mounted read-only and verified against a sealed
  APFS snapshot, so the file cannot be swapped between binding and exec by anything
  a private temp directory would have stopped. The condition is re-evaluated per
  launch, immediately after revalidation, so a volume that stopped being sealed is
  caught.
- An executable that names its libraries through `@rpath` now has its sibling `lib/`
  directory materialized into the snapshot alongside it. Such a binary loses its
  libraries the moment it is copied away from them, because `@loader_path` follows
  the copy — which is why `pdftotext` could not run, needing
  `@rpath/libpoppler.159.dylib`. Only the near-universal `@loader_path/../lib` shape
  is reproduced and nothing else is inferred; only depth-one entries whose bytes are
  a Mach-O image are admitted, so static archives, `pkgconfig` text, and typelib
  subdirectories stay out. A versioned alias is materialized as a regular copy of
  its target's bytes under the link's own name, and only when that target resolves
  inside the same source directory, so no symlink is ever created inside the bundle
  and a link pointing out of the package tree copies nothing. Bounded at 256 entries
  and 64 MiB. This *extends* the snapshot rather than relaxing it: every byte the
  child loads is still a governed copy.

---
## [0.1.68] - 2026-08-09

### Added

- Added a generic typed `metadata.magician.<extension>` parser that reuses the
  governed `SKILL.md` source, frontmatter, YAML-shape, reference, tag, depth, and
  parsed-node limits. Product subsystems can own strict declarative extensions
  without adding secondary manifests or widening the runtime contract vocabulary.
- Added typed diagnostics and focused hostile-input coverage for absent, malformed,
  unknown-field, oversized, and invalidly named product extensions.
- Added finite `workspace_path` action parameters with exact read/create modes,
  schema projection, replay parity, an automatic workspace resource scope, and
  an automatic delegated-write approval floor for create paths.
- Added bounded batch-process address-space limits that participate in contract
  binding and a shared 8 GiB governed memory reservation budget.

### Changed

- Batch process launch now applies declared memory limits before exec; PTY and
  MCP contracts reject memory declarations they cannot enforce.

## [0.1.67] - 2026-08-09

### Added

- Added one shared provider-neutral projection for the five stable official-SDK MCP
  product controls, consumed by product registration, inventory, and replay without
  copying live remote tool schemas into checked artifacts.
- Added exact full-inventory coverage requiring 63 single-source governed packages,
  exactly one frozen former schema per package, explicit ownership for every retained
  adapter/support file, and no local adapter on an official-SDK MCP package.

### Changed

- Completed Phase 7 inventory/classification/replay support for QR/device, remote MCP,
  browser/native, unauthenticated, and remaining secret-backed tool families.
- Classification now diagnoses an inconsistent source join instead of relying on an
  internal panic invariant.
- Canonical-JSON action parameters may use their manifest-owned stdin ceiling while
  the final encoded object remains bounded by the aggregate stream cap; native runtime
  controls remain capped at 64 KiB and never enter child argv.
- Regenerated the final 63-skill/39-adapter/425-action inventory, classification, and
  replay evidence with no inventory warning or error.

### Verification

- `make check-all` passes with the Phase 5G, service-name, generated-artifact, workspace
  compile, frontend, and iOS gates enabled. The canonical Rust run passes all 10,158
  executed tests with 14 explicitly skipped, followed by a clean Rust doctest pass.

---

Older entries: [`docs/archive/changelogs/tool-runtime-core.md`](../docs/archive/changelogs/tool-runtime-core.md)
