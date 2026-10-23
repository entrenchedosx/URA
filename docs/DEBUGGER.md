> This document records the v0.11 debugger foundation. Current advanced behavior,
> including deferred hardware/TF cleanup, schema8 and additional permissions, is
> specified in [ADVANCED-DEBUGGER.md](ADVANCED-DEBUGGER.md).

# v0.11 native Windows debugger

Development version `0.11.0-dev`, branch `v0.11-windows-debugger`. This is a real
local Windows user-mode backend, using documented debug APIs. It controls only
explicitly selected targets. Static inspection and file patches never launch or
attach to a process. Current native interaction acceptance remains unverified.

## Supported scope

- Native Windows x64 host and x64 PE target, without elevation. WOW64, ARM64,
  Linux/macOS, remote and kernel debugging are explicitly unsupported.
- Explicit executable, arguments, working directory, bounded environment overrides,
  entry breakpoint, launch and attach to an exact permitted PID/image.
- Windows process/thread/module events, ASLR module bases, pause, continue,
  software breakpoints, CPU instruction step and direct-call step-over.
- Actual paused registers, bounded memory reads, live disassembly with the shared
  iced-x86 decoder, and DbgHelp StackWalk64 using local unwind metadata.
- Registers, Threads, Call Stack, Runtime Memory/Modules/Disassembly, Breakpoints,
  Debug Events and Debugger controls in native docking. All OS operations run off
  paint; existing dock layouts remain readable. The current OS DPI and real input
  checklist has not been accepted.

Step-out, source-level stepping, conditional/hardware breakpoints, arbitrary
register/memory editing, PDB/DWARF lookup, trace databases and remote adapters are
not implemented. Step-over rejects indirect calls and an already-owned return
address. Temporary breakpoints filter thread and stack position. Interruptions
cancel temporary stepping conservatively; unsafe resumption is rejected.

## Ownership and state

`ura-debugger::Backend` defines the backend boundary. Only the Windows x64
implementation exists. A bounded controller channel (32 commands) feeds one owner
thread. That thread launches/attaches, receives events, reads/sets context,
continues each outstanding event once and performs detach/cleanup. Other threads
read bounded snapshots. Handles from debug events are tracked separately from
owned duplicates; Windows closes event handles on exit continuation, while owned
duplicates use RAII. No privilege escalation or driver is involved.

| State | Permitted operations / transitions |
|---|---|
| Idle, Exited, Detached, Failed without a target | Explicit launch or attach |
| Launching, Attaching | Consume actual Windows initialization events |
| Running, Stepping | Inspect cached event/module/thread state; request pause or termination |
| Paused with an outstanding event | Context, memory, stack, breakpoint edits, step, continue, detach, terminate |
| Detaching, Terminating | Complete OS lifecycle and invalidate runtime handles |

Opaque session handles are unique across controllers in the process. Every
post-start control/query validates its session. A new session cannot inherit an
old session's commands. Selecting a non-event thread changes inspection; stepping
requires the actual stopped event thread. Registers/memory are cleared or marked
unavailable while running or after exit. Paused means an outstanding Windows debug
event, not a guessed collection of individually suspended threads.

Paused/inactive owners block awaiting commands. Running owners use bounded
WaitForDebugEventEx waits. Native presentation polls running sessions at 150 ms;
paused sessions rely on replies/actions and do not force that repaint loop.
Commands wait at most five seconds. A timed-out queued request is canceled, with
another check immediately before OS launch/attach; the owner reconciles any
operation already in progress. This is cooperative cancellation, not a claim that
CreateProcess/DbgHelp can be forcibly interrupted inside a Windows call.

## Breakpoint and exception semantics

Each software breakpoint records session, ID, runtime address, module/RVA where
known, original byte, owner, enabled/armed state and hits. Existing application
INT3 bytes are rejected as owned breakpoints. Writes are restricted to the single
checked breakpoint byte; page protection is restored and instruction cache flushed.
No general runtime write API is exposed.

On a managed hit, the event owner validates/repairs RIP, restores the original byte
and retains displaced-instruction ownership. Continuation sets the CPU trap flag,
temporarily suspends other threads with exactly tracked increments, executes the
displaced instruction and rearms the breakpoint before releasing those increments.
Failed continuation rolls back context, new temporary breakpoints and owned
suspensions. Unsuccessful repairs remain fail-closed and retain cleanup ownership.
Newly created threads are accounted for; an identified debugger break-in thread
can deliver a requested pause during stepping.

The initial Windows loader breakpoint is restricted to the initialization phase
and observed ntdll mapping. Requested pauses require the identified break-in
thread. Identification uses the observed ntdll `DbgUiRemoteBreakin` export without
calling that internal function; pause is rejected before issuance if helper
identity is unavailable. This path is verified on the tested Windows build, not
every Windows revision. Application breakpoint and other first/second-chance exceptions remain
paused with details; **continue defaults to DBG_EXCEPTION_NOT_HANDLED** for them.
The caller may explicitly choose to handle an application exception with
`passException:false`. No blanket handled-exception policy is used.

Clean detach requires pause, restores debugger-owned bytes/TF/suspensions and
leaves the target running. A requested break-in already in flight is drained before
detach, so it cannot deliver a delayed unhandled INT3 after the debugger leaves.
Closing native URA is blocked while launch/control or
an active debug session remains. CLI/MCP shutdown attempts clean detach; a launched
target may be terminated only if cleanup cannot complete safely. Attached targets
are never implicitly terminated. If attached cleanup fails, the event owner is
retained for retry and status reports `cleanupPending`; control commands are
unavailable during that cleanup. Shutdown may therefore wait rather than abandon
a running process with owned breakpoint bytes. Forced OS termination of URA is
outside the clean-shutdown guarantee.

## Memory, stacks and static analysis

Runtime memory is explicitly a separate address space. Reads require a paused
event and permit 1..65536 bytes within a readable memory region, with partial
results, Windows errors and region/protection metadata. Runtime disassembly reads
these bytes, including armed INT3, rather than the file/patch overlay. It is bounded
to 128 instructions. No sample is uploaded.

Stacks are bounded to 64 frames and use Windows unwind metadata through DbgHelp.
Calls are serialized, with local metadata and symbol-server/PDB searching disabled.
Unknown frames/symbols remain unknown; no plausible-address stack scan is used.
Completeness is never inferred from a successful partial walk.

Main-module identity plus observed runtime base/RVA permits navigation to the
matching static image. The native disassembly highlights a mapped paused IP and
Pseudocode shows a separate runtime-evidence banner. Selecting a runtime row/frame
can navigate static views. Dirty file overlays disable that mapping. This does not
prove live memory matches file bytes, rebuild runtime pseudocode or promote an
observed execution path to a universal static fact.

## Permissions and interfaces

CLI and MCP debugging are disabled by default. `--enable-writes` grants neither
execution nor attach. Configure exact reviewed target files, not just directories:

```text
ura-cli --allow C:\work --enable-debug-launch --debug-target C:\work\owned.exe debug
ura-mcp --allow C:\work --enable-debug-launch --debug-target C:\work\owned.exe
ura-mcp --allow C:\work --enable-debug-attach --debug-target C:\work\owned.exe --debug-pid 1234
```

Attach also checks the PID's actual executable and architecture. Allowed file
hashes are pinned at policy configuration and rechecked under the backend's held
file handle before launch/attach. Terminating an attached target needs the separate
`--enable-debug-terminate-attached` flag. No general live memory-write permission
exists. Native launch/attach is an explicit user action on the displayed image/PID.
Environment values and runtime dumps are not saved into projects.

CLI `debug` is one interactive JSON-line process. Sessions do not survive its exit
or connect to another invocation. Each command is at most 64 KiB; replies are
`{"schemaVersion":1,"result":...}` or the existing structured error. Example input:

```json
{"operation":"launch","executable":"C:\\work\\owned.exe","arguments":[],"breakAtEntry":true}
{"operation":"status"}
```

Use the returned session in subsequent commands. Operations are `status`,
`continue`, `pause`, `step` (`over:true` for step-over), `detach`, `terminate`,
`threads`, `registers`, `readMemory`, `callStack`, `modules`, `disassembly`,
`events` and `breakpoints`. Addresses are hexadecimal strings. Poll `status`
for asynchronous stops; command acceptance does not imply execution has stopped.

MCP adds 16 functional `ura_debug_*` tools, bringing the total to **55**. They
route to the same service and return the same schema/result envelope. Read-only
annotations describe individual tools; execution permission is independently
enforced even when ordinary project writes are enabled. Server stdout remains
protocol-only. Binary names, symbols, metadata and debug output remain data.

## Project persistence

Schema7 adds separate bounded debugger breakpoint definitions. Legacy projects
remain readable without migration; explicit writes/open migrate them. Only main
module SHA-256, hexadecimal RVA and enabled state are persisted: no obsolete
absolute runtime addresses, environment secrets or memory dumps. Saved definitions
are installed only by an explicit restore into a paused identity-matched image.
`breakpoints` actions `save`/`restore` require `project`; save additionally requires
ordinary project-write permission. Native UI grants the exact user-selected
project path separately, so binary and project folders may differ. Wrong-project
save is rejected even with an empty list. Restore validates all definitions and
rolls back newly created points on failure; any unresolved rollback IDs are reported.

Limits include 1024 breakpoints/threads, 512 modules, 256 retained ordered events
(with dropped count), 64 KiB reads/command lines and bounded arguments/environment.
There is no persistent trace or runtime-memory database.

## Verification and references

Tests compile repository-owned `tests/fixtures/debuggee.rs` into per-test-process
windowless fixtures before execution. Arithmetic, recursion, threads, DLL load/
unload, repeated hits, direct calls, application exceptions and normal exit are
controlled source behavior. Unknown downloaded executables are never run. See
[verification](VERIFICATION-0.11.md) for actual counts, reviews and pending gates.

Primary references: [Windows debug events](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugeventex),
[exception handling](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling),
[detach](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocessstop),
[StackWalk64](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-stackwalk64).
