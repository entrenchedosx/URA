# Independent engineering review — v0.16

Three separate review agents examined the actual working source, independently of
the implementation agent. This is a code/adversarial engineering review, not an
external security certification or a claim of OS sandboxing. No desktop was used.

| Reviewer | Scope | Concrete findings repaired |
|---|---|---|
| v16_worker_review | Worker/protocol/runtime/SDK/grants/cancellation | Flattened instruction response mismatch; debugger operation mapping; service-lock cancellation; Bridge destructor blocking; stale completion; file __main__/__file__; core source truncation; blocked stdin response writes; completion hashing/deadline overrun; plugin dataclass import/sys.modules; leaked interpreter after rejected plugin queue admission |
| v16_plugin_review | ZIP/Windows paths, registry, transactions, events, address spaces | Reserved enabled.json ID; grant document write/read cap mismatch; null-schema configuration bound; traversal/junction/tree bounds; code-tree snapshot between validation/import; atomic revision coverage; mapping-crossing byte reads; missing ordinary rename/comment events; detached close metadata; event cross-kind suppression; bounded event payload/page cursor; disable/admission race |
| v16_native_batch_review | Native state, batch, CLI/MCP, subsequent debugger investigation | Console retained-job exhaustion; stale navigation/results after project reset; failed/cancelled batch attempt resume; missing batch capabilities; segment-size overflow; malformed CLI JSON panic; ignored CLI emulation grant; plugin host needing unrelated binary; short-image navigation; double-close of system-managed debug handles after detach |

The worker reviewer reproduced real CPython failures in separate ignored harnesses:
100 ms mutex-contention cancellation at103 ms after the fix, rejection of findings
after project closure, a blocked raw-protocol response that defeated old deadlines,
and a64 MiB completion identity hash that turned a10 ms limit into a1,453 ms successful
job. Main-source regressions now supervise writer/API/final-validation tasks; immutable
binary digests are cached and overlays receive fresh digest caches. The dataclass
case is exercised by the shipped analyzer example.

Registry fixes validate a bounded archive snapshot, Windows-safe names, reparse
points, all installed bytes and a private execution snapshot. Enable/disable/callback
admission use a lifecycle lock within a host. Atomic project edits use immediate
transactions and compare persisted metadata revision before committing. Tests cover
rollback, names/comments/signatures/stack types/type libraries, external metadata,
deleted-project closure, payload bounds/gaps and fast ordered callbacks.

The native/batch review exposed failure evidence that must remain visible: a later
full regression run failed the existing debugger detach test with WAIT_FAILED on a
still-owned duplicated handle. The correction clears only bookkeeping for Windows
debug-event handles after detach; independent owned duplicates retain RAII cleanup.
The prior extra CloseHandle could race process-wide numeric handle reuse. The narrow
test and whole debugger unit suite pass after correction; subsequent final regression
results are recorded in VERIFICATION-0.16.md. Microsoft documents system-managed
debug event handle cleanup in [WaitForDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent).
The detach-specific ownership diagnosis also used compatibility implementation
evidence; it was treated as an inference until exercised against real owned fixtures.

Review agents re-read fixes as they landed. Some final changes, including broader
typed metadata transactions and package qualification, were validated by the main
agent and automated checks rather than an additional independent final-source audit.
No blanket “all code independently verified” claim is made.

Residual boundaries: trusted Python retains OS access; user-controlled DLLs and native
extensions are not made safe. Multiple writable managers of one registry are not a
cross-process transactional service. Already admitted bounded Rust calls may finish
after Python cancellation. Events have finite rings and explicit gap reporting.
Custom decoder semantic claims cannot be proved by length/CFG validation. External
IR/ABI/stack semantic providers, native visual acceptance and broader third-party
dependency compatibility remain incomplete. Public download audits are release
evidence, not a substitute for those limitations.

Publishing integration follow-up: the separate publish runner now explicitly installs the same pinned verification-only dependencies as qualification; it does not rely on the builder job or a preinstalled global psutil. The unique dev.1 tag preserves the earlier unaccepted tag.
