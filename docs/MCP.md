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
