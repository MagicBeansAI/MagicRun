# Changelog

All notable changes to the tool-runtime-core project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---
## [Unreleased]

_Current development version: `0.1.78`._

### Staged input files (`0.1.78`)

- Add `GovernedProcessJail::stage_input_file(name, bytes)`: one fresh,
  owner-read-only file in the private workdir before launch, addressed by a
  plain single-component name, bounded by the jail's file ceilings; the host
  path is never returned. New error code `InvalidInputFile`. Profiles,
  identities and goldens are unchanged.

### Linux fixes found by the first real Linux run (`0.1.78`)

- **Linux task ceiling moved into the jail.** `RLIMIT_NPROC` is no longer
  set on bubblewrap (first set to the ceiling, which failed for any busy
  user; then to the UID's task count plus the ceiling, which still failed
  with setuid bubblewrap and was a shared, host-wide budget). Linux charges
  it per (user namespace, UID) and checks ancestor namespace owners against
  a limit snapshotted at namespace creation. Every Linux jail now binds the
  trusted `magicrun-jail-egress-forwarder` at `/run/magicrun/jail-helper` and
  runs it first as an exec shim (`--magicrun-jail-exec-v1`), which sets
  `RLIMIT_NPROC = max_tasks + GOVERNED_JAIL_HELPER_TASKS` inside the jail's
  own user namespace and execs; in the brokered mode it then execs the
  forwarder role. It refuses (exit 126) to apply a ceiling outside a new user
  namespace. Setuid bubblewrap without user namespaces gets no ceiling and
  reports `guarantees().process_ceiling == false` (watchdog only).
  - **Install:** the helper is now required for every Linux jail mode, not
    only brokered egress. Without it a Linux jail fails to build with the new
    `JailHelperUnavailable`.
  - New `GovernedProcessJailLimits::max_tasks` (threads; default 256, max
    1024, at least `max_processes`), `DEFAULT_GOVERNED_JAIL_TASKS`,
    `MAX_GOVERNED_JAIL_TASKS`, `GOVERNED_JAIL_HELPER_TASKS`, and
    `GovernedProcessJailAudit::linux_helper_digest`. The audit JSON gains
    `max_tasks` (all platforms) and, on Linux, `linux_helper_digest`; the
    Linux strict argv golden and the Linux profile identities rotate: strict
    `blake3:1fc54240…cc61a0` → `blake3:ab90ccc5…d0fe3c`, brokered
    `blake3:3c4fcba8…e142cc` → `blake3:e2822def…4fbe8e`. macOS identities are
    unchanged.
- **Exact ceiling only where the kernel enforces it.** The in-jail ceiling
  also needs a kernel at least `MIN_GOVERNED_JAIL_TASK_CEILING_KERNEL` (5.17;
  older kernels count the UID's tasks host-wide inside a user namespace, and
  5.14-5.16 carry ucounts bugs) and a non-root real UID (never held to
  `RLIMIT_NPROC`); otherwise the shim only execs and `process_ceiling` is
  `false`. The shim also refuses a ceiling when it runs as UID 0.
  Its refusal (exit 126 with exactly `JAIL_EXEC_REFUSAL_MARKER` on stderr)
  is reported as the new `GovernedBatchProcessErrorCode::JailHelperRefused`,
  not dispatched. The ceiling's machinery allowance is per mode (bubblewrap's
  init, plus the forwarder when brokered); the watchdog allows the same plus
  the launcher on Linux, and nothing on macOS. A helper whose device, inode,
  size or times changed since the jail was built is refused at launch.
- **Compatibility.** `0.1.78` adds public fields
  (`GovernedProcessJailLimits::max_tasks`,
  `GovernedProcessJailAudit::linux_helper_digest`) and enum variants
  (`GovernedProcessJailErrorCode::JailHelperUnavailable`,
  `GovernedBatchProcessErrorCode::JailHelperRefused`). Struct literals and
  exhaustive matches in consumers need updating, which a `0.1.x` patch bump
  does not signal under strict semver; this crate is pre-1.0 and consumers
  pin exact revisions.
- **Watchdog escape (Linux).** The watchdog found jail members by process
  group, so a jailed command that called `setsid()` escaped process, CPU and
  memory sampling. It now follows the launcher's descendants by parent link
  (nothing leaves the pid namespace) and sums threads as well as processes;
  both counts allow the launcher, the in-jail init and the forwarder on top
  of `max_processes`/`max_tasks`. macOS also counts threads.
- **Egress forwarder: sends lost at child exit on Linux.** A connection the
  child completed just before exiting could still be in the listen queue, and
  the post-exit drain never accepted it, so a fire-and-forget upload
  delivered nothing. The drain accepts the queue once, at exit; never again,
  so a surviving descendant cannot open new brokered connections.
- **A recreated working directory could pass revalidation on Linux.** Linux
  filesystems reuse a freed inode number immediately, so a directory removed
  and recreated under the same name matched on device and inode alone.
  Directory identity now includes birth time on Linux (`statx`), except on
  overlayfs, where copy-up changes it. Not on macOS: APFS birth time moves
  with `touch -t <past>`, which gave false "changed" errors.
- **CI.** The manual workflow gains a `linux-jail` job (Ubuntu 24.04) with
  the helper installed and `MAGICRUN_REQUIRE_LINUX_JAIL=1`, over three legs:
  unprivileged user namespaces, setuid bubblewrap, and setuid bubblewrap with
  `user.max_user_namespaces=0`. Checkouts do not persist credentials.

### Interpreter mode for the governed process jail (`0.1.77`)

- Add `GovernedJailInterpreter`, a validated, pinned interpreter produced
  only by fixed host discovery: `GovernedJailInterpreter::python3_for_host()`.
  There is no constructor taking a caller path. It carries the canonical real
  executable, a BLAKE3 digest of the executable and its pinned images, the
  `major.minor` version and read-only library roots. The executable, every
  image and every library root pass the trusted-launcher checks (root-owned,
  not group/other-writable, canonical, no symlink components); library trees
  are walked entry by entry (root-owned; non-symlinks not group/other-writable).
  No interpreter is run during discovery.
  - macOS tries `GOVERNED_JAIL_MACOS_PYTHON3_CANDIDATES` in order: python.org
    `/Library/Frameworks/Python.framework`, then the CommandLineTools
    `Python3.framework` (`Versions/Current/bin/python3`). The
    candidate spelling must be root-owned end to end. It resolves to
    `Versions/X.Y/bin/pythonX.Y`; the jail execs
    `Versions/X.Y/Resources/Python.app/Contents/MacOS/Python` directly (the
    `bin` binary is a stub that would re-exec it), pins the framework library
    `Versions/X.Y/<Name>`, reads `Versions/X.Y/lib` and denies
    `lib/pythonX.Y/site-packages`. `/usr/bin/python3` (an `xcrun` shim needing
    fork/exec) is never used. A python.org framework left `root:admin` 0775
    (as on the development host) is refused as admin-writable unless
    tightened; CommandLineTools (`root:wheel` 0755) passes.
  - Linux takes canonical `/usr/bin/python3` (`python3.N`) with library roots
    `/usr/lib/python3.N` and, where present, `/usr/lib64/python3.N`.
  - Windows and other hosts refuse (`UnsupportedPlatform`).
- Add `GovernedProcessJail::with_interpreter(self, interpreter)`, composing
  with `strict_app` and `strict_app_with_brokered_egress`. The governed
  executable snapshot becomes the script; argv is
  `<interpreter> -I -S -B <script-snapshot> <args...>`
  (`GOVERNED_JAIL_PYTHON3_FLAGS`). The script is still resolved, hashed and
  privately snapshotted by the governed executor, so
  `with_expected_executable_digest` binds the script bytes. The interpreter
  digest and trust checks are rerun when the jail takes it and again
  immediately before every launch. A jail takes one interpreter, for its own
  platform.
  - macOS profile: the strict profile rendered with the interpreter as the
    only `process-exec` literal, plus a read-only literal of the script
    snapshot, read-only literals of the pinned images, read-only library
    subpaths and a trailing `(deny file-read* (subpath ".../site-packages"))`.
    `process-fork` stays denied; the script is never exec-allowed. The
    brokered rules are appended unchanged.
  - Linux argv: the interpreter and its library roots are `--ro-bind`ed at
    their own paths before the read-only remount, and the command becomes
    `<interpreter> -I -S -B /app/<script>` (under the forwarder when brokered).
    Compile-checked only; not run on a Linux host.
- Identity and audit: `profile_identity()` differs in interpreter mode and
  equals the new `governed_process_jail_interpreter_profile_identity(platform,
  network, kind, version)`, which binds interpreter kind, `major.minor` and
  flags but no host path. `GovernedProcessJailAudit::interpreter`
  (`GovernedJailInterpreterAudit`: kind, version, digest, flags, profile
  identity) records which interpreter ran and is omitted otherwise. The jail
  schema stays that of its network mode. New error code
  `InterpreterUnavailable`.
- The bubblewrap argv and the audit JSON of existing jails are unchanged; the
  Linux profile identities are unchanged and now pinned by golden tests.

#### Review fixes (`0.1.77`)

- **Strict profile change (macOS), identities rotate.** The strict SBPL
  profile ends with `(deny file-map-executable (subpath "<workdir>"))`, so
  files written to the workdir cannot be `dlopen`ed (`ctypes.CDLL` included),
  mapped `PROT_EXEC`, or injected via `DYLD_INSERT_LIBRARIES` on a re-exec.
  It is defense in depth, not a code-execution barrier: in-memory code via
  `mprotect`/`ctypes` still runs, inside the same profile. Tools that unpack
  a library into `TMPDIR` and load it (some JNA, sqlite-jdbc, .NET
  single-file, packaged Node addons) stop working in the jail. The jail's
  environment backstop now also strips `LD_*` and `GLIBC_TUNABLES`. This
  applies to every mode. The
  macOS profile identities rotate: strict
  `blake3:e783cb6b…020d31` → `blake3:8a06b6cf…32dcd2`, brokered
  `blake3:89b6c07b…2f09f6` → `blake3:97a0d14f…60aacb`. Linux identities are
  unchanged. `harden_environment` strips `DYLD_*` and `__PYVENV_LAUNCHER__`.
- **Audit wording.** `GovernedJailInterpreterAudit::flags` is now
  `launch_flags` and `user_site_denied` is `launch_user_site_disabled`; both
  are launch hygiene, since a script can re-exec the interpreter without them
  (still inside the same profile). `script_exec_denied` is `false` on Linux,
  where bubblewrap has no exec control and `/work` is not `noexec`.
- **Linux discovery.** Shared-libpython builds pin `libpython3.N.so.*` from
  the executable's ELF `DT_NEEDED` as an image (found as a regular file in the
  canonical `/usr/lib64`, `/usr/lib/<multiarch>` or `/usr/lib`; otherwise
  refused), and stdlib roots are canonicalized and deduplicated (`lib64 ->
  lib`). Compile-checked only.
- **macOS discovery.** The Xcode.app candidate is dropped (`/Applications`
  is `root:admin` 0775 on stock macOS). The interpreter digest is streamed.
- **macOS process watchdog.** The process-group sample no longer uses a
  null-buffer sizing call that XNU answers with a system-wide estimate; any
  jailed child sampled at least once was ending as `ProcessLimitExceeded`.
- **Egress forwarder (Linux).** No poll spin after a peer hang-up, a paused
  listener after `EMFILE`/`ENFILE`, non-blocking broker connects (a full
  backlog closes the client; 2 s bound), up to 1 s of outbound delivery after
  the child exits, relays clamped to what `RLIMIT_NOFILE` leaves after the
  descriptors open at start, and a brokered Linux
  jail refuses `max_open_files` below `MIN_GOVERNED_JAIL_BROKERED_OPEN_FILES`
  (8). An unreadable forwarder candidate falls through to the next one.
- **Errors.** `GovernedBatchProcessErrorCode::InterpreterUnavailable` reports
  a pinned interpreter that changed before launch.

### Brokered-egress process jail (`0.1.76`)

- Add `GovernedProcessJail::strict_app_with_brokered_egress(limits, broker)`,
  an explicitly opted-in jail whose only reachable network is one host-owned
  HTTP CONNECT broker (`GovernedEgressBrokerEndpoint`). The broker, not the
  jail, enforces the destination allowlist, resolves names, refuses private
  addresses and meters bytes; the jail guarantees it is the sole endpoint.
  - macOS takes `LoopbackTcp { port }`: the strict SBPL profile plus exactly
    `(allow network-outbound (remote tcp4 "localhost:<port>"))` (IPv4 TCP only) and read-only
    access to `/private/etc/ssl` (and `/etc` symlink metadata). No
    `mach-lookup` is granted, so DNS (mDNSResponder) and trustd remain
    unreachable; no bind/inbound rule is granted.
  - Linux takes `UnixSocket { path }` (an existing socket owned by the caller
    in a directory nobody else can write). Bubblewrap keeps `--unshare-all`
    (isolated netns, only `lo`, no resolver files); the socket, a host trust
    bundle and the trusted forwarder are bind-mounted read-only, and the new
    `magicrun-jail-egress-forwarder` binary (installed root-owned at one of
    `GOVERNED_JAIL_EGRESS_FORWARDER_PATHS`) listens on `127.0.0.1:3128` (at most 16 concurrent relays) in the
    jail's netns, runs the exact executable as its only child, relays each
    connection to the socket, and exits with the child's exact status.
  - The child environment gets `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` (and
    lowercase) set to `http://127.0.0.1:<port>`, empty `NO_PROXY`/`no_proxy`,
    and `SSL_CERT_FILE` when a host trust bundle is exposed. The overlay is
    applied after every contract value, so a package cannot re-point it. A
    child that ignores the proxy variables cannot connect anywhere.
- Add identity: `GovernedProcessJail::{network, platform, profile_identity}`,
  `governed_process_jail_profile_identity(platform, network)` (an
  endpoint-independent BLAKE3 over the rendered profile/argv template and
  environment overlay, computable without a jail), and
  `GovernedProcessJailAudit::egress` (`GovernedProcessJailEgressAudit`: broker
  kind/port, proxy port, forwarder digest, profile and binding identities).
  A brokered jail reports schema `tool-runtime.governed-process-jail.brokered-egress.v1`.
- `source_bytes::GOVERNED_PROCESS_JAIL` now also carries the forwarder source
  (`source_bytes::GOVERNED_JAIL_EGRESS_FORWARDER` alone).
- The strict profile is unchanged: golden tests pin its macOS SBPL bytes, its
  bubblewrap argv (now built by a pure builder) and its audit JSON (`egress` is
  omitted when absent). New error codes: `UnsupportedEgressBroker`,
  `EgressBrokerUnavailable`, `EgressForwarderUnavailable`.
- No new API for secrets: caller-authorized environment already reaches a
  jailed child through the existing `auth.injections` secret → environment
  path (`CredentialPreparationPlan::new` + `CredentialMaterialResolver`).

### Declared login prompts (`0.1.75`)

- Add `auth.lifecycle.login_prompts`: the prompts a login hook may print on
  the PTY, each a `kind` (`username`, `password`, `otp`, `device_code`,
  `operator`) and the literal `marker` the prompt line ends with (1–128
  bytes, no control characters). `manifest::declared_login_prompt` matches
  only the current line, ANSI escapes dropped, ending exactly with a declared
  marker — never arbitrary terminal text. Written for Magician's secure-HITL
  authenticated dispatch (P4): the host answers a matched prompt through its
  own secure channel or reports a typed `authentication_required` challenge.
- Add `CredentialLifecyclePendingKind::Password` beside `Otp`.
- Contracts without `login_prompts` are unchanged; no process, credential or
  wire contract moves.

### Windows compilation

- Keep declared-artifact collection fail-closed on non-Unix targets without
  compiling the Unix-only file-identity path. This restores Windows builds;
  artifact authority remains unavailable there until an equivalent safe handle
  walk is implemented.

### macOS non-jailed batch launch

- Use `posix_spawn` with an open-directory file action, explicit argv/env and
  stdio, close-by-default descriptors, and a new process group. No userspace
  fork, shell fallback or retry is introduced. macOS 10.15+ is required for this
  backend; unavailable support fails the operation closed. Existing jailed
  launches, PTY behavior and non-macOS backends are unchanged.
- Preserve executable/cwd authority, parent footprint limits, output bounds,
  cancellation and wait-before-cleanup settlement. New C-string copies zeroize
  on drop; original authorized inputs are validated directly, not read back
  from Command's potentially substituted malformed strings.
- Add real no-fork positive-control, cwd replacement, closed-stdio, inheritable
  descriptor, malformed-input, spawn-error and native-child ownership tests.
  Diagnostic snapshots distinguish native spawn from the historical callback
  probe; native launch does not fabricate callback completion.
- Include the new production backend in the existing macOS batch source
  fingerprint. Consumer upgrades still require a fresh source-attestation
  review; no Magician checkout or dependency is updated automatically.

### Earlier test-only process investigation (`0.1.73`)

- Add a macOS-only shared atomic pre-exec stage probe for active synthetic
  captures. Child writes require no allocation, locks, logging or descriptors;
  parent observations distinguish callback entry/completion without claiming
  exec or recipient entry. Allocation failure remains diagnostic-only. Add
  real child-death, callback-error and exec-failure boundary coverage. Normal
  builds omit the probe; process behavior and consumer dependencies are unchanged.
- Name every namespace in the reviewed Apple header, including its invalid
  category, with complete mapping coverage and unknown-value refusal. The first
  consumer CI recurrence reached the prior decoder's catch-all; that failure is
  retained and this classifier correction is not a process runtime fix.
- Add a macOS owned-child exit-reason observation before cleanup/reap: one
  parent-only fixed-size query per captured signal exit, closed OS reason
  categories and explicit unavailable/malformed outcomes. No payload, raw code
  or process identity is retained; normal builds do not query or include it.
  Add scope, bounds, decoder and real self-signal regression coverage. This is
  additional evidence collection, not a fix or a signal-sender attribution.
- Add bounded, thread-scoped child wait/signal/cleanup observations under an
  explicit debug compiler cfg. Normal builds omit them; standard release builds
  reject the cfg. No output bytes, credentials, paths, PIDs or raw exit codes
  are retained. Add real normal/nonzero/SIGTERM/SIGKILL classification tests.
- Default execution and production API are unchanged; this is not a claimed
  fix for the intermittent MagicVault process failure. Literal batch source
  fingerprints do change, so consumer attestations require their normal review
  when upgrading. Existing Magician dependencies are not updated.

### Development tooling and documentation

- Rework the public README around the product, with capability and host-integration
  tables, source/build quick starts, a read-only Rust example, security boundaries
  and an explicit distinction between language edition and compiler version.
- Add the versioned runtime architecture diagram and a reviewed source/document
  fingerprint baseline, with a drift gate in `make check` and synthetic tests.
- Route Makefile Cargo artifacts to SSD1 when available, preserving explicit
  overrides and a checkout-local fallback. Add isolated build-routing tests.
- Runtime source, API and consumer-owned attestations are unchanged by these
  tooling/documentation updates; the crate version remains `0.1.73`.

The inherited entries below include consumer-owned inventory and integration
tests. Those paths and historical results belong to Magician's workspace, not
to the portable library's current qualification.

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

- Added inventory/classification/replay support for QR/device, remote MCP,
  browser/native, unauthenticated, and remaining secret-backed tool families.
- Classification now diagnoses an inconsistent source join instead of relying on an
  internal panic invariant.
- Canonical-JSON action parameters may use their manifest-owned stdin ceiling while
  the final encoded object remains bounded by the aggregate stream cap; native runtime
  controls remain capped at 64 KiB and never enter child argv.
- Regenerated the final 63-skill/39-adapter/425-action inventory, classification, and
  replay evidence with no inventory warning or error.

### Verification

- Historical consumer-workspace verification recorded service-name,
  generated-artifact, workspace compile, frontend and iOS gates passing, plus
  10,158 executed Rust tests, 14 explicitly skipped and a clean Rust doctest pass.
  These are not standalone MagicRun test counts or results for the current source.

---

Earlier consumer-specific release history is not included in this repository.
