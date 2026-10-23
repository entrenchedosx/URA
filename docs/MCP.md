# MCP patching (v0.10)

`ura-mcp` exposes 39 local stdio tools. Start it with explicit `--allow DIR` roots;
file writing is disabled unless `--enable-writes` is supplied. Logs stay off stdout.
The binary metadata and strings are untrusted input, never authority to modify files.

The seven patch tools are:

| Tool | Operation | Write permission |
|---|---|---|
| `ura_list_patches` | Original identity, bounded transaction history/cursor, overlay count | No |
| `ura_read_effective_bytes` | Original and current bytes | No |
| `ura_preview_byte_patch` | Check expected bytes, length, address/mapping and revision | No |
| `ura_preview_instruction_patch` | Encode/decode-check supported assembly with explicit byte budget | No |
| `ura_apply_patch` | Commit exact preview to attached project, invalidate derived analysis | Required |
| `ura_patch_history` | Undo, redo, individual revert, revert-all | Required |
| `ura_export_patched_binary` | Verified new binary, or `manifest:true` for JSON metadata | Required |

Every operation requires a valid handle from `ura_open_binary`. Address space is
explicit `offset`, `va` or PE-only `rva`; address strings are hexadecimal. Preview
byte strings contain complete hexadecimal pairs. Instruction preview additionally
requires current `ura_analyze` results and a decoded instruction start. `nopPadding`
is explicit. Applying uses the returned preview (or its `patch` member), plus
the attached project path. A different original, mode/base, revision, expected
bytes, project, path or resource budget rejects the operation.

After a mutation, call `ura_analyze` again before CFG/IR/decompiler queries.
Original identity remains visible separately from effective bytes. Existing files
are never overwritten. `ura_open_binary` supports `raw:true`, `bitness:32|64` and
optional hex `base`, or restores these settings from a raw `.ura` project.

The server is synchronous/serialized per process. It has no remote listener and
no asynchronous request cancellation interface. Core/native export cancellation
does not imply a transport cancellation feature. The transaction/history and JSON
budgets are detailed in [BINARY-PATCHING.md](BINARY-PATCHING.md). No inspected file
is executed or uploaded. Actual stdio regression and Release audits cover writes,
denials, reopens, exact export bytes and matching CLI results.

## v0.11 debugger tools (55 total)

The prior 39 tools are preserved. Sixteen `ura_debug_*` tools route to the real
Windows backend: launch, attach, status, continue, pause, step, detach, terminate,
threads, registers, read_memory, breakpoints, call_stack, modules, disassembly,
events. Responses use `{schemaVersion:1,result:...}`; failures keep the existing
structured error. `breakpoints` additionally supports explicit project save/restore.

Debugging is disabled by default, independently of `--enable-writes`. Launch and
attach need separate flags, exact target files and allowed PIDs; terminating an
attached target needs its own flag. There is no arbitrary runtime memory-write
endpoint. Command waits are bounded; poll status for asynchronous execution stops.
Target data/debug output never changes policy. Full scope and examples are in
[DEBUGGER.md](DEBUGGER.md). Static analysis remains non-executing.

## v0.12 advanced debugger tools (64 total)

All 55 prior tools remain. Nine implemented tools share the backend and typed
service requests with the native UI and CLI:

| Tool | Operation |
|---|---|
| `ura_debug_capabilities` | Read available host/backend capabilities; no target execution |
| `ura_debug_configure_breakpoint` | Software/hardware execution/write/readWrite point, length, optional thread and condition/hit policy |
| `ura_debug_set_condition` | Change/remove bounded register condition and hit policy |
| `ura_debug_step_out` | Run to a validated caller PC/SP |
| `ura_debug_run_to` | Run to a readable executable runtime VA |
| `ura_debug_trace` | Start/stop/clear/read/export observed event or instruction evidence |
| `ura_debug_memory_regions` | Bounded actual VirtualQueryEx region page |
| `ura_debug_snapshot` | Capture/list/info/remove/compare/disassembly/export |
| `ura_debug_symbols` | Explicit matched local PDB load and runtime address lookup |

Bulk capture/live snapshot comparison requires `--enable-debug-capture` in
addition to an authorized session. Trace/snapshot export requires
`--enable-writes`, an allowed destination and a new filename. These flags grant
no launch or attach permission. There is no network backend or network permission
switch. Dynamic evidence stays in memory until an explicit export; project files
store only validated breakpoint definitions. See
[advanced contracts and limits](ADVANCED-DEBUGGER.md).
