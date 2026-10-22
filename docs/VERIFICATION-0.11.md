# v0.11 Windows debugger development verification

Date: 2026-10-22. Version `0.11.0-dev`, branch `v0.11-windows-debugger`.
The preserved v0.10 source checkpoint is
`5dc489cd88427a46cfef9b15eb55fd3fe7bf7b03` on `v0.10-binary-patching`.
That milestone remains unaccepted for public release because its native input,
cancellation and current OS DPI gates remain incomplete. No existing release,
tag, main branch or user changes were overwritten.

This is a verified development source checkpoint with a real, scoped Windows
debugger. It is **not an accepted public v0.11 release**. The owner's desktop
control restriction remains in effect. Automated tests execute only freshly
compiled, repository-owned windowless fixtures, including explicit attachment
to those fixtures' exact PIDs. No native desktop application was started.

## Implemented scope and boundaries

The new `ura-debugger` crate provides an actual Windows user-mode backend on a
Windows x64 host for x64 PE targets, without elevation. WOW64, ARM64, non-Windows,
remote and kernel targets return unsupported rather than using a fake backend.
One event-owner thread performs launch/attach, Windows event reception,
continuation, context access and cleanup. Bounded commands/snapshots carry unique
session identities and reject stale operations. Launch/attach initialization stays
distinct from Running until an actual stop. Process, thread, module and exception
events come from Windows; event handles and owned duplicates have separate
lifetimes.

Launch accepts an executable, arguments, working directory, controlled environment
overrides and an entry stop. Attach validates an exact PID and executable image.
Service permissions pin image hashes; the backend checks a held image handle and
the actual process-creation event's image identity. An asynchronous identity
failure forbids resume, stepping, breakpoint mutation and runtime inspection,
then cleans up. Static analysis and ordinary file writes confer no execution
permission.

Software breakpoints save/verify original bytes, change page protection only as
needed, restore it and flush instruction cache. Hits validate/rewind RIP, restore
the displaced instruction, use TF for one execution and rearm before releasing
owned thread-suspension increments. Failed repairs fail closed. Removing and
restoring a point at the displaced IP does not immediately retrigger the same
call. Direct-call step-over filters both thread and stack position; indirect
calls, an already-owned return address and step-out are explicitly deferred.
Application first/second-chance exceptions pause with details and default to
`DBG_EXCEPTION_NOT_HANDLED` on continuation.

Paused registers, bounded runtime memory, thread/module inspection and live
disassembly are real target observations. DbgHelp StackWalk64 uses local unwind
metadata without network/PDB searching; incomplete stacks remain incomplete.
Main-module SHA-256 plus runtime base/RVA maps to a matching static image. Dirty
file overlays disable mapping. Runtime banners/IP navigation do not assert that
live memory equals file bytes or manufacture dynamic pseudocode.

Clean detach restores owned bytes, trap flags and suspension increments, drains
an in-flight debugger break-in and preserves the target. Attached targets are
never implicitly killed. Failed attached cleanup retains the owner for retry and
reports `cleanupPending`; it may delay headless shutdown. Native close is blocked
while a session/control operation is active. Forced OS termination of URA is
outside the orderly detach/EOF guarantee. Pause identification relies on the
observed ntdll break-in helper export and is verified on this Windows build;
unavailable helper identity rejects pause before issuance.

## Interfaces and persistence

Native docking adds nine real debugger panels/controls, bringing the total to 27:
Debugger, Registers, Threads, Call Stack, Runtime Memory, Modules, Debug Events,
Breakpoints and Runtime Disassembly. Register changes, memory navigation, copying,
breakpoint edits, selected threads and static navigation use shared service data.
OS calls run off paint; stale captures are cleared on session/stop/thread changes.
The real worker is tested headlessly. Actual input, dialogs, presentation and
current OS DPI behavior are **Unverified**.

CLI `debug` is a bounded JSON-line session process. MCP adds 16 functional
`ura_debug_*` tools for **55 total tools**, retaining all 39 earlier tools.
Both use the same service, session checks and schema-versioned result envelopes.
Debugging is disabled by default; launch, attach, exact target, exact PID and
attached termination have separate explicit permissions. `--enable-writes` does
not grant debugging. General live memory/register editing is absent.

SQLite schema7 stores bounded main-module hash/RVA/enabled breakpoint definitions,
separate from file patches and static caches. Legacy read-only projects do not
migrate; explicit writes migrate and preserve prior data. Wrong-project save,
stale absolute addresses and invalid/duplicate definitions reject. Restore
preflights and rolls back newly added points on failure. No memory dump or
environment secret is persisted. Native grants the exact user-selected project
path even when it is in a different directory from the image.

## Quality gates and real-process evidence

Host: Windows 11 Home x64, build 26200; Rust 1.99.1 MSVC toolchain. Final checks:

- `cargo fmt --check`: passed.
- `cargo test --workspace --locked`: **303 passed, 0 failed, 0 ignored**.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo build --workspace --release --locked`: passed for all three applications.

All 287 baseline tests remain. Sixteen additional tests cover debugger backend
failure paths, actual process workflows, service policy, schema migration,
CLI/MCP and native worker integration. Tests compile the owned fixture themselves,
without a hidden manual binary-build prerequisite. Local logs are under
`target/v11-final-tests.log`, `target/v11-clippy.log` and
`target/v11-release-build.log`.

The Windows tests observe entry, repeated known-function hits, original byte
restoration, TF instruction stepping, direct-call step-over to the exact return
address, concurrent worker threads, DLL events, registers, readable/invalid memory,
unwind frames, normal exit42 and abnormal application breakpoint termination.
Attach/detach tests prove the owned child survives detach and exits42. Drop cleanup,
stale sessions, canceled launch, bounded events, failed context/continuation
rollback and in-flight pause cleanup have regression coverage. Known source
arguments RCX=1,2,3 independently establish that breakpoint restore did not repeat
or skip a call. No comparison with WinDbg is claimed.

Fresh Release CLI/MCP [debugger audit](benchmarks/0.11-debugger-release.json)
passed real launch, entry/RIP agreement, repeated stops, TF step, breakpoint
enable/disable, register/memory/stack/module reads, schema7 save/restore, stale
denial, exit42, exact-PID attach, pause and target-preserving detach. Writes-only
launch and ungranted attached termination reject. The actual MCP process discovers
55 tools and preserves protocol-only stdout. Existing Release
[patching audit](benchmarks/0.11-headless-release.json) passed exact-byte exports,
undo/redo, stale-preview rejection, original preservation, manifests, raw/ELF32
and CLI/MCP byte equality. Neither audit starts the desktop or an unknown sample.

## Independent adversarial review

A separate read-only reviewing agent inspected ownership, event continuation,
breakpoint/context repair, step races, shutdown, permissions, stale UI state and
persistence. It did not author the implementation or run UI/process tests.
Substantial findings were fixed: service/backend identity races, continuation and
interrupted-step rollback, fail-open IP repair, retained cleanup ownership,
canceled launch, suspension rollback, wrong-project empty save, partial restore,
native external-project grants, paused repaint polling, cleanup-pending command
availability and asynchronous image-authorization bypass. Regressions exercise
the repaired boundaries. The last in-flight pause, displaced breakpoint restore
and event-wait throughput adjustments were reviewed locally and tested after the
independent passes; a separate review of every final adjustment is not claimed.
No known critical finding is intentionally left unresolved.

## Performance observations and limits

The fresh sequential Release audit ran without concurrent Cargo work or UI
polling. Local transport-inclusive samples (CLI / MCP):

| Operation | CLI | MCP |
|---|---:|---:|
| Register retrieval, median | 0.129 ms | 0.190 ms |
| 4096-byte memory request, median | 0.543 ms | 0.746 ms |
| Call stack request, median | 2.767 ms | 3.028 ms |
| Cached modules request, median | 0.129 ms | 0.176 ms |
| Step command through observed paused snapshot | 0.646 ms | 0.954 ms |

The paused servers used 0.0% of one core over each one-second sample at Windows
timer resolution, not a claim of mathematically zero CPU. Peak working sets were
12,947,456 / 15,187,968 bytes, including the transport/server. Retained snapshots
contained 29 / 28 events, serialized to 3528 / 3418 bytes; that is serialization
size, not isolated queue allocation. Retention is capped at 256 events with a
dropped count. Cached status avoids OS reads. Running event waits are bounded at
20 ms; paused owners block on commands. These are small local samples, not p95,
cross-machine guarantees or target-only memory throughput.

OS event occurrence-to-handler latency, real breakpoint-to-UI presentation,
GPU timing, and general target slowdown have not been measured. Native running
presentation polls at 150 ms, which is a design interval rather than measured
hit-to-UI latency. Broader optimized workloads and Windows revisions need testing.

## Local package audit

The local `URA-0.11.0-dev-windows-x64.zip` is an unpublished engineering artifact.
It contains the three optimized executables with URA/`0.11.0-dev` version
resources, the authorized official icon, Cargo.lock, documentation, project
license and third-party notices. Size: **17,976,037 bytes**. SHA-256:

```text
24f81500bc21bd8830c966c62646e70cd3d3561ab3d59f7cdcfe25ae468d2319
```

Fresh extraction passed ZIP CRC, sidecar checksum and **593** manifest file hashes,
with every packaged file listed. All three images match the tested Release
binaries, and the icon matches the repository artwork. License collection covered
278 workspace/dependency packages, 271 third-party notice directories and zero
missing texts. Extracted CLI/MCP version, signature/type/C-decompiler/export
checks and all 55-tool discovery passed. The real controlled debugger and patching
audits were repeated against the **extracted executables**: launch, stepping,
memory/stack/modules, repeated breakpoint restore, exact-PID attach/pause/detach,
permission denials, exit42, byte-exact patch export, raw/ELF32 and history all
passed. The native EXE was not started.

See [sanitized archive and extracted workflow evidence](benchmarks/0.11-package.json).
The ZIP's documentation snapshot precedes this external audit; this source report
records the subsequent results without changing the verified archive. No accepted
public download, public tag or re-download verification is claimed.

## Parity, release blockers and next milestone

The ledger tracks **147 capabilities: 17 Supported, 76 Partial, 49 Missing,
5 Unverified**. These are ledger statuses, not an overall competitor parity
percentage. Thirty debugger capabilities have individual evidence/limits rather
than a broad fully-supported debugger claim. See [ledger](FEATURE-PARITY.md),
[debugger contract](DEBUGGER.md) and [roadmap](ROADMAP.md).

Before an accepted public prerelease:

1. Verify real native launch/attach/pause/continue, breakpoint edits, step controls,
   thread/register/memory/stack/module navigation and project save/restore through
   actual input; observe orderly close/detach and concurrent activity.
2. Complete native in-flight cancellation/stale-result checks and the current
   required real OS DPI/workflow checklist. Headless rendering at simulated scales
   and previous partial DPI observations do not satisfy these gates.
3. Requalify the inherited v0.10 patch/edit/export/dialog workflows. They remain
   unaccepted, not silently promoted by debugger automation.
4. After acceptance, rebuild/package the final source, repeat extraction audits,
   create a unique tag/prerelease, upload ZIP/checksum, re-download and verify the
   archive hash and tag target. Existing releases must remain intact.

v0.12 priorities include qualified live native workflows, WOW64 with its proper
context APIs, broader concurrency/exception/unwind cases, symbol integration,
hardware/conditional breakpoints and richer performance evidence. Step-out,
arbitrary runtime editing, tracing, remote/kernel debugging and emulation remain
explicit future obligations. Existing decompiler and patching limitations remain.
