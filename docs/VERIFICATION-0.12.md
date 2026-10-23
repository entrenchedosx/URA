# v0.12 advanced debugger engineering verification

Date: 2026-10-23. Version `0.12.0-dev`, branch `v0.12-advanced-debugging`.
Baseline: `0df07ccfd1f1d2f517d3743e7f12557e5e0091e0` on
`v0.11-windows-debugger`, 303 passing tests and55 MCP tools. That checkpoint and
older branches/tags/releases remain preserved. This report describes a scoped
source checkpoint, **not completion of the full v0.12 prompt or an accepted public
release**. Current native input/cancellation/DPI acceptance remains outstanding;
WOW64 is unimplemented. No public v0.12 tag/release has been created.

The owner prohibited desktop control. No native desktop application, display
settings or UI automation was used. Process tests launch only freshly compiled
repository-owned windowless Rust fixtures; attach tests select only those
fixtures' exact PIDs. Static inspection of existing file fixtures never executes
them. There is no unknown-sample, elevation, kernel or unrelated-process testing.

## Implemented and verified subset

- Native x64 DR0-3 execution/write/readWrite points, aligned widths, occupied-slot
  rejection, per-thread/global allocation, new-thread bindings and ownership-aware
  event/TF classification. Disable/remove is logical before physical retirement.
- Unsigned bounded register conditions, low32 aliases, short circuit, hit policies,
  true/false-hit continuation and known RCX1/2/3 original-call behavior.
- Run-to and actual-unwind caller PC/SP step-out with conservative rejection;
  stronger stack traversal/cycle bounds and matched local symbol names/lines.
- Observed event and TF instruction/register-change tracing, count/serialized-byte/
  duration/step bounds, ordered pages, drop reporting, stop/clear and new-file JSON
  export. Target exit stops the recorder. A blocked final instruction can retain
  explicitly reported cleanup ownership after recording stops.
- Actual memory-region queries, bounded paused captures with explicit missing
  ranges, known-byte comparison, captured shared-decoder disassembly and atomic
  no-clobber JSON export. No inferred memory writes or reconstructed executable.
- Explicit local main-image MSF7 PDB, PE RSDS GUID+age/index/load checks, held-file
  identity, serialized DbgHelp access and disabled network search. Mismatches reject.
- Shared native/CLI/MCP service operations:64 total MCP tools,25 debugger tools,
  preserving all55 prior tools. Bulk capture and file export require separate
  grants in addition to authorized launch/attach/session control.
- Project schema8 point definitions preserve hash/RVA/kind/length/condition/hit
  policy, migrate legacy defaults only on explicit write, reject corrupt metadata
  and roll back partial restore. Thread IDs, counters, traces and dumps do not
  silently become persistent project state.

Native changes extend existing panels and add Execution Trace (28 panels total).
Actual worker capture and the same trace panel are tested headlessly. That does
not verify mouse/keyboard interaction, dialogs, OS scale, graphics drivers or GPU
presentation. Full contracts and interface examples are in
[ADVANCED-DEBUGGER.md](ADVANCED-DEBUGGER.md).

## Quality gates and regression evidence

Windows x64/MSVC host. Final application build checks:

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| `cargo test --workspace --locked` | **323 passed,0 failed,0 ignored** |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo build --workspace --release --locked` | Passed, all three applications |

All303 baseline tests remain;20 additional tests exercise the new behavior.
Existing tests gain assertions without deleting prior coverage. Logs are local
under `target/v12-tests.log`, `target/v12-clippy.log` and
`target/v12-release-build.log`. The final incremental Release build took29.95s;
this is not a clean-build benchmark.

Actual Windows regressions cover slot exhaustion, actual execution/write/readWrite
exceptions, alignment, new threads, false conditions/counts, TF+data-watch store
completion, bounded traces/eviction/order, retained event lifecycle, captures/
missing ranges/limits/decode/compare, actual caller return, matched/mismatched PDBs,
permissions, schema compatibility, project restore, real CLI/MCP and native worker
operations. Tests observe normal target exit42 after detach, including eight
hardware detach cycles and eight trace/pause/detach races;40 additional focused
hardware detach iterations passed after final repair. Cleanup diagnostics remain
bounded and available in the actual event log.

Failure tests retain uncertain software-byte/protection ownership until verified
restoration, preserve application exception disposition when deferred hardware
cleanup fails before classification, and fail closed if another thread's software
breakpoint interrupts an ordinary pending TF step. That combined handoff requires
detach/explicit termination. The real two-thread regression then detaches and
verifies normal exit42. Ordinary TF stepping no longer suspends unrelated threads;
only displaced software-byte execution requires that suspension.

An actual two-second Sleep syscall regression verifies that trace user-stop and
duration expiry interrupt recording and pause within one second on this host.
It permits owned TF to remain only with `pendingInstructionCleanup:true`; clean
handoff/detach can wait for the blocked instruction. Detach attempts are bounded
and retain ownership on failure. No guarantee of instant safe detach from an
arbitrarily blocked instruction is claimed.

## Independent adversarial review

A separate read-only agent reviewed hardware slots, event ownership, conditions,
trace/capture bounds, symbols, permission/restore boundaries and cleanup races.
It did not author edits or execute targets/UI. Findings repaired include snapshot
arithmetic overflow, low32 condition aliases, current DR slot identity checks,
blocked trace interruption, normalized data-watch/TF causes, retained byte and
protection rollback ownership, partial restore ownership, queued cross-thread
hardware/TF cleanup, DLL-unload retirement, conservative exception disposition
before fallible cleanup and the foreign-step/software-displacement continuation
shortcut. Actual regressions exercise repaired boundaries. Final orchestration,
measurements and packaging were reviewed locally; no separate review of every
final line is claimed. Broad architecture/stepping coverage remains incomplete.

## Release application audits and performance

The fresh sequential Release [basic debugger audit](benchmarks/0.12-debugger-release.json)
passes CLI and MCP launch, known repeated calls, original-byte restoration,
step, registers/memory/stack/modules, persistence, stale denial, exit42, exact-PID
attach, pause, clean target-preserving detach and permission denials. The
[advanced audit](benchmarks/0.12-advanced-release.json) passes real HW conditions,
readWrite watches with an actual observed BEEF store, run-to, validated step-out, regions,32-byte equality and64KiB
capture/export/reimport, no overwrite, PDB lookup, observed event export,
100 instruction steps with changed registers, clear/stop and capture/output denials.
The [patching audit](benchmarks/0.12-headless-release.json) preserves old exact-byte
CLI/MCP exports, undo/redo, stale checks, manifests, raw and ELF32 behavior.
Each report records the three actual Release executable SHA256 values.

Sequential local transport-inclusive measurements (CLI / MCP):

| Operation/sample | CLI | MCP |
|---|---:|---:|
| Registers median |0.126ms|0.225ms|
|4096-byte read median, basic session|0.518ms|0.681ms|
|Call-stack median, basic session|3.389ms|2.884ms|
|100 observed instruction steps|22.092ms|22.529ms|
|Observed steps per second in that sample|4526|4439|
|Retained trace entries / serialized payload|301 / 96285bytes|301 / 96587bytes|
|Mixed advanced snapshot RPC median|21.607ms|21.241ms|
|Mixed PDB load/lookup RPC median|24.089ms|22.835ms|
|Paused advanced server peak working set|18071552bytes|21385216bytes|

The snapshot/symbol medians mix their action kinds and include local protocol,
JSON work and event-owner polling; they are not isolated64KiB capture or PDB-load
throughput. Active event recording polls for expiry while paused (20ms owner wait),
which explains slower inspection than the basic inactive recorder. Trace steps
include status observation latency. No general target slowdown, hardware-breakpoint
runtime overhead ratio or isolated allocator usage is established. Expensive
single stepping is not described as low-overhead.

Paused basic/advanced servers each measured0.0% of one core during their respective
one-second samples at Windows timer resolution. This is not mathematically zero
CPU or an OS wakeup/GPU measurement. Trace maxBytes bounds serialized entry payload,
not total JSON/allocator heap. Four captures/4MiB requested bytes and trace count/
payload/time/step limits bound retained work; total heap profiling remains open.

The [predicate benchmark](benchmarks/0.12-condition-release.json) runs five batches
of100000 evaluations over captured registers:189.8–271.5ns/evaluation. It measures
an already parsed predicate, excluding production parsing, Windows events and
transport; it is not a breakpoint hit-overhead measurement.

The [Release headless trace-panel benchmark](benchmarks/0.12-trace-view-release.json)
renders385 events from an actual128-step owned trace using the real native panel,
Classic/Dark and simulated1.0/1.5 scales. First frames took5.904–8.472ms; subsequent
frame build+tessellation samples took0.481–1.184ms (three frames/configuration).
This excludes OS windows, real DPI, interaction, GPU and presentation;385 retained
events do not qualify a maximally populated trace or general large-view latency.

## Local package and public release status

A local `URA-0.12.0-dev-windows-x64.zip` is assembled with the three tested Release
applications, locked dependency inventory/license texts, icon and documentation.
The ZIP CRC, sidecar/per-file SHA256 manifest, complete file inventory, image
identity and extracted static CLI/MCP64-tool queries are checked by
`verify-audit-package.py`. Basic debugger, advanced debugger and patching audits
are then rerun against its extracted applications with fresh owned fixtures.
The resulting archive hash and extracted workflow results are in
[the package report](benchmarks/0.12-package.json). That report is external to the
archive to avoid a circular archive checksum. This is a local audit artifact,
not a public download, signed installer or accepted release.

The source branch can be pushed as a reviewed development checkpoint. No public
v0.12 prerelease/tag/download is accepted; older public releases remain unchanged.
A later public candidate must satisfy outstanding correctness/architecture scope,
real native interaction, cancellation and current OS DPI acceptance, then verify
the actually downloaded artifact. Headless checks never substitute for those gates.

## Explicit remaining work

- WOW64 adapter, real owned x86 contexts/stepping/disassembly/stacks and fixture
  qualification. Architecture detection rejects it; an available compiler does
  not constitute implementation or verification.
- Broader optimized/recursive/missing-unwind/exception stepping corpus, safe
  foreign-thread software-displacement handoff, and bounded blocked-instruction
  cleanup beyond cooperative retry.
- Arbitrary DLL symbols, symbol servers, full C++ debug types, source stepping,
  DWARF and richer pseudocode integration.
- Real native trace/snapshot interaction, current OS scale and graphics acceptance;
  GPU/presentation/OS wakeup and total heap/general target-overhead profiling.
- Complete trace replay, observed CFG overlays, indirect-edge integration, automatic
  unpacking/executable reconstruction, remote/emulation/kernel/multi-architecture
  backends. Remote identity/authentication/reconnect architecture is design only.

Ledger:165 tracked capabilities —17 Supported,97 Partial,45 Missing,6 Unverified.
These counts are not an overall IDA/Ghidra parity percentage. Unfinished v0.12
items carry into the next milestone alongside emulation; none are relabelled done.
