# v0.10 binary patching

Development version `0.10.0-dev`, branch `v0.10-binary-patching`. This implements
fixed-size file overlays and explicit modified-file export. It does not implement
live-process memory modification, arbitrary executable rewriting or full parity.

## Original identity and transaction model

`crates/ura-core/src/patch/` is the shared engine. A `PatchDocument` shares immutable
original bytes through `Arc`; its sparse ordered overlay contains only differences.
Editing a byte does not clone the original image. A preview binds original SHA-256,
effective revision, exact expected bytes and equal-length replacements. Every edit
is checked before any transaction commits; overlapping ranges within a transaction
are rejected. An intentional later overlap must present the current effective bytes.

Transactions retain monotonic IDs, creation order, original file offsets, before/
after bytes, kind and comments. Original bytes remain available separately. The
cursor defines applied versus undone history. Undo/redo is deterministic; a new
commit truncates the redo tail without reusing IDs. Individual revert creates an
inverse transaction and refuses later overlapping edits. Revert-all is itself
undoable and supports sparse overlays. History-operation edit limits account for
sparse resets separately from ordinary proposals, while retaining byte/history caps.

Limits: 512 MiB original images, 1 MiB replacement/read/overlay bytes, 256 edits in
an ordinary transaction, 4096 transactions, 16 MiB combined before/after history,
4096 comment bytes, 256-byte instruction regions and 64 assembly instructions in
16 KiB text. History operations may contain up to 1 MiB individual changed runs.
This bounds the worst case; heavily fragmented histories still have allocation and
replay overhead. The engine currently exposes synchronous control-based export
cancellation; MCP requests are serialized and do not expose asynchronous cancellation.

## Address spaces and supported formats

Address interpretation is always explicit: `offset`, `va` or PE-only `rva`.
Address text is hexadecimal; assembly integer operands additionally accept explicit
`0d` decimal. Kernel-sized virtual addresses are rendered losslessly as hex strings.

- PE32/PE32+: header/image-base and section file-backed mapping. The declared
  header extent must cover the checked NT/optional/section tables. Layout headers
  are protected against modification. Zero-filled virtual bytes, ambiguous maps,
  mapping-crossing ranges and truncated backing are rejected.
- ELF32/ELF64: loadable segments provide virtual-to-file mapping, independently
  of section addresses. ELF header/program/section tables are protected. Memory
  tails without file backing are rejected. Extended header numbering is currently
  rejected for patching. Both endian encodings are read by the mapping layer;
  instruction editing supports only x86/x64, with little-endian fixtures verified.
- Raw images: explicit x86/x64 mode, with an optional explicit virtual base.
  Without a base, only file-offset operations are available. The configuration is
  persisted in the project; no guessed base or automatic format fallback is used.
  Native Desktop can open these `.ura` projects prepared by CLI/MCP. A native
  direct raw-file configuration dialog is not implemented.
- Mach-O, firmware-specific loaders, section insertion, relocation rebuilding,
  code caves, trampolines and signature repair are not implemented.

File-offset byte edits may target file data outside mapped virtual sections, but
cannot change protected PE/ELF layout tables. Fixed length preserves file layout.
Changing data/import contents can still alter program behavior. Export parsing
does not establish that a modified program executes correctly.

## Instruction editing

The text frontend delegates all machine encoding to the existing MIT-licensed
[iced-x86 encoder](https://github.com/icedland/iced/blob/master/src/rust/iced-x86/README.md).
It is intentionally a supported subset, not a full textual x86 assembler:

- `nop`, `ret`, `int3`;
- register/register `mov`, `add`, `sub`, `xor`, `and`, `or`, `cmp`, `test`;
- register/immediate `mov`, `add`, `sub`, `cmp`, with checked encoded widths;
- direct numeric `call`, `jmp` and all 16 conditional branch families/aliases.

Memory operands, labels, directives and other forms are rejected. Semicolons or
newlines separate instructions. The actual virtual origin is used for every
encoding; short/near branch selection must decode to the requested absolute target.
The result is decoded with iced-x86 and compared against requested typed operands.
Controlled LLVM-generated PE/ELF fixtures and fixed expected opcode vectors provide
independent encoding checks. No new assembler runtime or external process is needed.

The selected overwrite span must start at a currently decoded instruction and end
on a complete instruction boundary. A larger span is an explicit user budget.
Overlong replacements are rejected. Shorter replacements require explicit NOP
padding. Neither subsequent instructions nor addresses move.

## Project persistence and invalidation

SQLite schema6 adds a separate bounded patch-state record. Legacy projects remain
readable without migration; write/open workflows migrate them. Original SHA-256
and raw configuration are verified before replaying both applied and redo history.
Corrupt expected bytes, IDs, counters or metadata reject restoration. Project
writes use optimistic revision checks under an immediate SQLite transaction, so
another handle cannot silently replace a newer patch history. Save/attach workflows
transfer or rehydrate the corresponding state explicitly. Annotations, types and
decompiler overrides remain in their existing tables.

Every accepted byte change creates a fresh effective analysis snapshot. Disassembly,
functions, CFGs, xrefs, jump tables, IR/SSA, type inference, HIR, call graphs and
pseudocode caches are invalidated together. This deliberately uses whole-image
invalidation; precise affected-function recomputation is future work. A contiguous
effective image is materialized once for parsing/reanalysis, so this operation can
copy the whole file despite the sparse editor representation. It is not performed
per paint or for each individual byte within a transaction.

Native workers tag replies with a new generation; reads cannot capture an old
binary while a patch is pending. Failed/cancelled transactions reload the persisted
project. Conflict summaries are computed once in the worker using interval union,
then read by virtualized Patch Manager rows. Busy state is tied to the relevant job.
Annotations retain original address anchors and are visibly labelled for review;
their semantic association with rewritten instructions is not automatically proved.

## Interfaces

Native Desktop adds an Edit-menu Patch Manager, selected-byte range editor, an
instruction editor on Disassembly, preview/apply/cancel, original/current bytes,
changed-byte colour in Hex, address navigation, overlap state, history actions and
binary/manifest export. Mutation, file dialogs, parsing and export run through the
existing worker. Automated native integration and panel rendering are distinct
from real interaction acceptance; no live v0.10 GUI check has been performed.

CLI examples (all paths must be inside `--allow` roots):

```text
ura-cli --allow C:\work --enable-writes patch C:\work\sample.exe init --destination C:\work\sample.ura
ura-cli --allow C:\work patch C:\work\sample.exe --project C:\work\sample.ura instruction --space va --address 140001020 --budget 1 --assembly ret
ura-cli --allow C:\work --enable-writes patch C:\work\sample.exe --project C:\work\sample.ura instruction --space va --address 140001020 --budget 1 --assembly ret --apply
ura-cli --allow C:\work --enable-writes patch C:\work\sample.exe --project C:\work\sample.ura export --destination C:\work\modified.exe
```

`patch read`, `preview`, `apply --preview FILE`, `list`, `history --action
undo|redo|revert|revertAll` and `manifest` expose the other workflows. Preview/apply
JSON carries expected bytes and revision. `--raw --bitness 32 --base 1000` explicitly
configures a raw image; omit the base for file offsets only. Patch commands emit JSON.

MCP has **39 tools**, including `ura_list_patches`, `ura_read_effective_bytes`,
`ura_preview_byte_patch`, `ura_preview_instruction_patch`, `ura_apply_patch`,
`ura_patch_history` and `ura_export_patched_binary` (`manifest:true` exports metadata).
`ura_open_binary` accepts explicit `raw`, `bitness` and optional hex `base`, or reads
the persisted raw configuration from a supplied project. Preview/list/read work in
read-only mode. Applying history or writing exports requires `--enable-writes`,
allowed paths and the attached project. No inspected binary is executed or uploaded.

## Export and release boundary

Export refuses every existing destination, including the original. It streams a
new temporary file in the destination directory, syncs it, compares every byte
against the effective overlay, reparses supported executable formats and computes
SHA-256 before atomic no-clobber publication. The on-disk original identity check
is size-bounded and streamed. Cancelled/failed operations do not publish partial
executables. Patch manifests use the same new-file policy. Signatures/checksums
may become invalid; there is no automatic execution or signature-preservation claim.

The v0.9 source checkpoint is preserved; its incomplete live acceptance has not
been relabelled as passed. v0.10 native interaction/export dialogs and final release
qualification require authorisation to use the desktop. Until those checks pass,
only a verified development source checkpoint is eligible for publication.

Reference workflows: Ghidra's official [Original File exporter help](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/help/help/topics/ExporterPlugin/exporter.htm)
and [IDA 9.0 patching documentation](https://docs.hex-rays.com/9.0/user-guide/user-interface/menu-bar/edit/patch-core).
These describe reference capability families, not URA parity claims.
