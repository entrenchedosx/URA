# Advanced debugger contracts (v0.12)

Version `0.12.0-dev`, branch `v0.12-advanced-debugging`. This is an incomplete
engineering milestone and source checkpoint, not an accepted public release.
The [v0.11 foundation](DEBUGGER.md) remains applicable except where extended here.
All implemented runtime features require a Windows x64 host and x64 PE target.
Static x86 analysis does not establish WOW64 debugger support.

## Breakpoints and conditions

`configureBreakpoint` takes a runtime address string, `kind` (`software`,
`hardwareExecute`, `write`, `readWrite`), length, optional live thread ID,
condition, `hitAfter` and `hitEvery`. Hardware execution uses length1; data uses
naturally aligned lengths1/2/4/8. There is no read-only data-watch encoding.
Four DR slots per thread are shared with any existing target-owned state.
The manager preserves unowned addresses/control bits, rejects occupied slots
and general-detect state, and validates slot identity before claiming a hit.
An all-thread point binds observed current and newly created threads; resource
failure stops execution rather than silently omitting coverage. One thread's
slot number need not equal another's. Thread-specific points expire with their
thread and are not persisted as global definitions.

Conditions accept unsigned integer constants (decimal/hex), captured GP/flag
registers, 32-bit aliases, comparisons, bitwise `& | ^`, logical `! && ||`, and
parentheses. Logical evaluation short circuits. Limits: 512 ASCII characters,
128 tokens, nesting24. No script evaluation, memory dereference, assignment,
network access or arbitrary calls. Parse errors reject configuration; evaluation
errors stop conservatively with an event. `hits` counts observed hardware/software
hits before the condition. A stop is eligible when hits >= hitAfter and
(hits-hitAfter) modulo hitEvery is zero, then its predicate is evaluated. Both
counts must be positive; counts reset each session. `setCondition` changes the
predicate/policy without resetting an existing session's hit count.

False software hits still execute the original displaced instruction exactly
once before rearming. Hardware execution faults resume with RF; data watchpoints
trap after the instruction. Owned TF and hardware causes are classified together;
external debug causes remain application exceptions with NOT_HANDLED disposition
by default. First/second chance application exceptions are never unconditionally
swallowed, including errors before normal event classification.

### Retirement, interruption and detach

Global disable/remove is logical immediately. Physical slots on another thread
remain owned until that thread's actual next debug event; Windows context DR6
alone cannot prove whether a hit is already queued. Status reports pending cleanup
and a removed row can remain `owner: retiring`. Another point at that address can
conflict until retirement completes. DLL unload uses the same retirement path.

A pause on a helper thread can overtake an in-flight TF instruction on another
thread, including an instruction blocked in a syscall. Recording stops promptly,
but `trace.pendingInstructionCleanup` explicitly reports retained TF ownership.
Continue completes that owner thread's pending step before another step can start.
If a different thread also owns a displaced software breakpoint, continuation
fails closed and requires detach/termination; that combined handoff is not yet
implemented. Repair/poison checks run before any interrupted-step shortcut.
Detach removes software bytes, releases owned suspension increments and performs
per-thread debug-event handoffs to clear TF/DR state. It can temporarily resume
the target and observe its natural exit. A blocked instruction can delay cleanup.
The detach attempt is bounded to three seconds; after a timeout, pause and wait
for an event before retrying detach. Failure retains the event owner
and resources for retry or explicit termination, rather than abandoning a queued
owned exception in the target. An attached process is never implicitly killed.
EOF cleanup may wait for safe attached-target cleanup; forced OS termination is
outside that orderly guarantee. Normal resume is rejected while detach cleanup
ownership remains. Byte/protection rollback uncertainty similarly requires cleanup.

## Advanced control and stacks

`runTo` takes a readable executable runtime VA and uses a temporary software
point filtered to the stopped event thread. An enabled existing user software
point at the destination can be borrowed; it is preserved. Disabled/unarmed
conflicts reject. There is no inferred instruction-boundary proof for an arbitrary
user-supplied VA; select a decoded instruction address.

`stepOut` uses the actual caller PC/SP from bounded DbgHelp StackWalk64. It requires
an advancing stack within8MiB and a readable executable caller address, then
filters the stop to that thread and caller SP. It does not guess an arbitrary
stack word. Cycles, missing/incomplete unwind metadata or ambiguous caller state
reject. Cancellation/intervening stops remove owned temporary points. Existing
direct-call step-over remains supported; indirect-call/existing-return-point
cases remain explicitly unsupported. Complete optimized/recursive/exception-unwind
stepping coverage has not been qualified.

## Observed traces

Start explicitly while paused. Event mode records actual subsequent debugger
lifecycle/exception/breakpoint/state observations while normal execution remains
under the user's control. Instruction mode uses real CPU TF steps for the stopped
event thread, recording paused IP transitions and optional changed registers.
It can suspend other threads during a displaced software instruction. This is
expensive debugger-driven tracing; no Intel PT, system-wide instruction coverage,
precise wall-clock timing or inferred memory-write evidence is claimed.

TraceConfig bounds: maxEvents1..10000, maxBytes1024..4194304 serialized entry
payload bytes, maxDurationMs1..60000, maxSteps1..100000. Defaults:2048 events,
1MiB payload,10seconds,1000 steps, changed registers enabled. A ring evicts old
entries and reports dropped/truncated counts; an entry too large stops recording.
Counts, path/context strings and payload are bounded, but maxBytes is not a
measurement or exact cap of total allocator/JSON overhead. Expiry is checked by
the event owner, including while paused. Stop requests a verified Windows break-in
if an instruction is in flight. Final TF cleanup can remain pending as above.
Process exit/detach stops recording; captured evidence remains readable.

Read pages use sequence `after` (exclusive) and limit1..512. Sequence values
increase within a recording; clear/start creates a new recording. Export format
`ura-observed-trace`, schemaVersion1, includes session/PID, summary, ordered events,
sequence/elapsedMicros, thread, kind, address string, module base/size/path/SHA/RVA
when known and captured detail/register changes. Always `lateStart:true` and
`completeExecution:false`; finite observations never prove complete coverage.
Export/reimport JSON equality is audited; there is no trace replay engine.

The native Execution Trace panel provides start/stop/clear, bounded pages,
virtualized rows, thread/module/address filters, register-change details,
page-local observed address frequencies, matching static navigation and export.
Its captured module identity permits navigation after target exit. Unknown module
identity does not produce a static mapping. Observations do not change CFG/IR/HIR,
prove unobserved paths impossible or recover universal types. Automatic observed
CFG overlays and indirect-edge integration remain future work.

## Regions and memory captures

`memoryRegions` pages actual VirtualQueryEx mappings (limit1..256), including
base/size, state, protection, type and readability. Capture is explicit and paused:
1..1048576 requested bytes, at most four retained captures and4MiB aggregate
requested ranges per session. Traversal is bounded to256 pieces and two seconds.
No-access/guard/reserved memory is not forced readable. Missing/partial chunks
remain explicit; address addition and retention-budget arithmetic are checked.
Select a bounded range obtained from a region/module query; there is no implicit
whole-process dump or automatic large-module reconstruction.

Each capture preserves session/PID, sequence/time, requested runtime range,
region/module identity, known bytes/missing ranges and SHA256 of concatenated
captured bytes with that exact hash scope stated. `list`, `info`, `remove`,
`compare`, `disassembly`, `export` operate on retained IDs. Compare against another
capture or an explicitly authorized live read reports known compared/changed bytes
and unknown ranges; at most256 individual changes are returned. Captured decode
uses the shared x64 decoder over a contiguous known chunk, never fills gaps with
invented bytes. The native Memory panel exposes retained evidence after target
exit, compact Hex/ASCII, comparison, region and decode controls. This is foundation
for runtime-code inspection, not automatic unpacking, PE reconstruction, relocation
repair or import recovery.

Capture/live comparison needs `--enable-debug-capture`. Trace/snapshot file export
also needs `--enable-writes`, path-policy approval and a new filename. Export is
bounded to32MiB serialized JSON and uses a synced temporary file plus atomic
no-clobber persistence. Existing destinations are preserved. No trace/dump is
silently stored in the ordinary SQLite project or uploaded.

## Local symbols and persistence

`symbols load` requires an explicit allowed local MSF7 PDB (<=128MiB), a known
main-image runtime base and matching PE RSDS GUID+age. The file is held read-only
without write/delete sharing; DbgHelp index and loaded-module identities are
rechecked. A shared lock serializes StackWalk64 and symbols. Network symbol search
is disabled, UNC paths reject, and mismatched/missing data returns an error.
`lookup` returns bounded symbol/displacement and line metadata when present;
source contents are not downloaded. Call stacks use those verified names/lines.
This is main-image local PDB support, not arbitrary DLL/symbol-server loading,
source stepping, inlining, full C++ types, DWARF or pseudocode type import.

Project schema8 adds kind/length/condition/hit policy to main-image hash/RVA point
definitions. Schema7 defaults remain software/length1/unconditional/count1. Read-only
legacy opens do not migrate; explicit writes migrate. Invalid/corrupt/oversized
metadata rejects; restore preflights and rolls back newly added ownership even
when a failed configuration retained cleanup state. Runtime thread IDs and hit
counts are not persisted; saving thread-filtered points rejects rather than
widening coverage. Restoring over a retiring point conflicts until safe cleanup.

## CLI and MCP examples

Run one interactive process; use the returned session in subsequent JSON lines:

```powershell
ura-cli --allow C:\work --enable-debug-launch --debug-target C:\work\owned.exe --enable-debug-capture --enable-writes debug
```

```json
{"operation":"capabilities"}
{"operation":"launch","executable":"C:\\work\\owned.exe"}
{"operation":"configureBreakpoint","session":"RETURNED_SESSION","address":"0x140001020","kind":"hardwareExecute","condition":"ecx == 2","hitAfter":1,"hitEvery":1}
{"operation":"configureBreakpoint","session":"RETURNED_SESSION","address":"0x140010000","kind":"write","length":8}
{"operation":"runTo","session":"RETURNED_SESSION","address":"0x140001040"}
{"operation":"stepOut","session":"RETURNED_SESSION"}
{"operation":"trace","session":"RETURNED_SESSION","action":"start","config":{"mode":"instructions","maxSteps":100,"maxEvents":512,"maxDurationMs":5000}}
{"operation":"trace","session":"RETURNED_SESSION","action":"read","after":0,"limit":128}
{"operation":"trace","session":"RETURNED_SESSION","action":"stop"}
{"operation":"snapshot","session":"RETURNED_SESSION","action":"capture","address":"0x140001020","length":32}
{"operation":"snapshot","session":"RETURNED_SESSION","action":"export","id":1,"destination":"C:\\work\\capture.json"}
{"operation":"symbols","session":"RETURNED_SESSION","action":"load","base":"0x140000000","pdb":"C:\\work\\owned.pdb"}
```

Addresses above illustrate syntax; derive actual VAs from that session's module
base/RVA. Poll status between control operations until the required paused state.
MCP has64 total tools,25 debugger tools, including nine new operations listed in
[MCP.md](MCP.md), using the same service and JSON precision. There is no shared
session across independent CLI/server processes. Static permission grants no
execution; launch/attach/target/PID/attached termination remain separate. Session
possession controls stepping, points and bounded reads only for its authorized
target. Capabilities are readable without executing one.

## WOW64 investigation and future transports

IsWow64Process2 architecture detection remains fail-closed. Genuine x86/WOW64
would require Wow64Get/SetThreadContext with WOW64_CONTEXT, EIP/ESP and x86 decoder
mode, separate pointer-sized module/stack handling and real x86 event fixtures.
An installed x86 compiler alone does not verify those semantics. The adapter is
not implemented; capabilities report `wow64:false`. No WOW64 test is claimed.
ARM64, non-Windows, kernel and remote debugging likewise remain unsupported.

The shared Backend/Command interface and explicit capability query form a local
boundary only. A future remote adapter must negotiate architecture/capabilities
under an authenticated encrypted transport, bind a unique server+session+process
identity to scoped target/read/capture/control grants, sequence and bound events,
reject stale reconnect commands and require explicit reauthorization on identity
change. Memory/context/symbol payloads remain untrusted. Loss of transport must
retain server-side cleanup ownership and report reconnect/error state, never
pretend that local IDs refer to a new remote process. GDB RSP would need a separate
verified architecture/address adapter plus authentication wrapper; it is not
implemented. No listener, remote tool, unauthenticated service or network grant
has been added. Remote parity remains Missing.

## Primary references

- [Windows x64 CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context).
- [Intel SDM, debug registers/exceptions](https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf), DR6/DR7 and RW/LEN encodings.
- [Wow64GetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64getthreadcontext), investigated future boundary.
- [SymSrvGetFileIndexInfoW](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symsrvgetfileindexinfow).
- [SymLoadModuleExW](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symloadmoduleexw).

Current tests, performance scope, independent review and acceptance gaps are in
[VERIFICATION-0.12.md](VERIFICATION-0.12.md).
