# Isolated CPU execution, trace replay and captured-memory analysis

Version 0.13.0-dev is an incomplete engineering checkpoint. It adds actual scalar
instruction execution, indexed evidence browsing and sparse memory analysis.
Live debugging, emulation and replay are separate modes with separate grants.
See [verification](VERIFICATION-0.13.md) and [release policy](RELEASING.md).

## CPU model and shared semantics

`ura-core/src/dynamic/cpu.rs` fetches executable bytes from its own virtual memory,
uses the existing iced-x86 decoder and `ir/lift.rs` single-instruction builder,
evaluates the shared typed operations, and commits registers, writes and the next
IP. It does not walk the static CFG as a substitute for executing instructions.
The static IR and emulator share arithmetic, addressing, aliases and flag rules.
CALL has a distinct concrete transfer path because abstract ABI clobbers are not
CPU execution semantics. RET reads the virtual stack. Internal calls push the
actual return address and update a bounded call-depth counter.

Initial coverage is a **scalar subset**, in both 32-bit and 64-bit decoder modes:

| Family | Implemented scope |
|---|---|
| MOV/MOVZX/MOVSX/MOVSXD | Existing supported scalar GPR/memory/immediate forms |
| LEA | Existing decoded address forms, RIP-relative and address-size overrides |
| ADD/SUB/AND/OR/XOR/CMP/TEST | Existing 8/16/32/64-bit forms, wrapping and defined arithmetic flags |
| INC/DEC | Shared semantics added in v0.13; CF preserved |
| SHL/SHR/SAR | Shared scalar shift semantics, masked counts, zero-count flag preservation, sign fill and explicitly undefined flags |
| ROL/ROR | Existing shared scalar rotate subset; no RCL/RCR |
| MUL/IMUL/DIV/IDIV | Existing supported scalar forms, full products and explicit divide faults |
| CBW/CWDE/CDQE/CWD/CDQ/CQO | Existing supported sign-extension forms |
| CMOVcc/SETcc/Jcc | Existing supported arithmetic-flag conditions |
| PUSH/POP/CALL/RET/JMP | Supported near scalar forms; POP-to-memory/far/16-bit x86 call forms rejected |
| NOP | Decoded supported NOP forms only |

This table describes instruction families, **not every encoding/prefix/form**.
Unsupported operations stop with a structured fault before machine state commits.
LOCK/REP, vector/FPU state, system calls, privileged instructions, string
instructions, a general OS environment, peripheral emulation and arbitrary
Windows-program execution are absent. Unsupported instructions never become NOPs.

GPR aliases use the shared root-register/slice model. Initial values specify root
registers and the six arithmetic flags, not arbitrary alias spellings. An x64
32-bit write zero-extends; smaller writes preserve unaffected bits. The state
returns `instructionPointer`, `flagsValue`, `flagsKnownMask` and individual
register/flag values. Unknown flag values serialize as null. Only CF/PF/AF/ZF/SF/OF
and reserved bit1 are represented by the flags mask; this is not complete RFLAGS.
Flat CS/DS/ES/SS is required for x86; nonzero bases are rejected. Explicit FS/GS
bases are analyst assumptions and do not establish a Windows TEB/environment.

Default GP and arithmetic-flag initial values are zero. The stack is an explicit
64KiB RW mapping at 0x70000000 with a pointer-sized zero return sentinel. A RET
at root depth to this sentinel stops with `rootReturn`. Initial SP overrides are
validated as width-correct values; subsequent accesses still require mapped
permissions. There is no host-address dereference or host API invocation.

## Memory, images and external calls

Mappings carry a virtual base, size, permissions, source and owned bytes. They are
sorted, nonoverlapping regions; large gaps consume no backing allocation. Region
count and aggregate size are checked before allocation. Explicit mapping tails,
BSS and the stack are zero-initialized; missing captured bytes are never filled.
Reads and writes enforce R/W permissions; fetch enforces X even on execute-only
regions. Stores validate the entire destination before committing. Instructions
are decoded afresh after every step, so executable writes cannot leave a stale
instruction cache. COW snapshots clone backing storage only on later writes.

Loaders accept little-endian x86 PE32, x64 PE32+, x86/x64 ELF PT_LOAD segments,
explicit raw buffers and known captured ranges. PE sections and ELF segments
use their declared preferred virtual addresses, file offsets, sizes and rights.
Non-x86 native binaries are rejected, even when their bitness is32 or64. ELF BSS
is explicit segment zero-fill. A rebase request for a native executable is
rejected. No loader relocations, import binding, TLS startup or dynamic linking
are performed; this is partial image mapping, not a Windows/ELF process loader.
Import slots contain only mapped file data. An external/nonexecutable call target
faults unless the analyst explicitly supplies an exact target-to-return-value
model. Such a model changes only the scalar return register, records an
`AssumedExternalReturn` event and has no memory/OS side effects. It is not an ABI
or Windows API implementation.

## Execution controls and budgets

Core `Emulator::run` supports single stepping, bounded batches, run-until,
breakpoints, stop cancellation, initial-state reset and checkpoint restore.
Each instruction evaluates into scratch state and stages writes before commit.
An invalid access, undefined branch condition, bad divide or unsupported opcode
leaves the failing instruction's architectural changes unapplied.

| Resource | Default | Maximum |
|---|---:|---:|
| Lifetime instructions since reset/restore | 100,000 | 1,000,000 |
| Wall time per run | 1,000ms | 10,000ms |
| Mapped memory | 8MiB | 16MiB |
| Call depth | 64 | 256 |
| Retained events | 2,048 | 10,000 |
| Serialized event payload | 1MiB | 4MiB |
| Saved checkpoints | 2 | 4 |

The service admits at most four emulators, four replays and four images. Trace
pages are1..512 events, memory reads/writes at most64KiB, imports16MiB and replies
8MiB. COW history can retain additional bounded region copies; the mapped-byte
counter and serialized trace limit do **not** claim to measure total heap use.
CLI command lines are at most64KiB. CPU cancellation is checked between
instructions. Service execution uses a separate worker; run returns promptly,
status uses a cached snapshot, stop sets an atomic flag, and mutation/inspection
of a running machine fails with a busy error. Close/shutdown cancels and joins
owned emulation workers. Heavy image analysis runs off the native paint thread;
CLI/MCP image analysis is synchronous and bounded, so it can temporarily delay
another request sharing that service. No hard real-time responsiveness is claimed.

Checkpoint restore resets retained history and records a sequence gap; it is not
reverse execution. The event stream includes committed instruction/next IP,
bytes, flow, register deltas and writes, with retained/dropped counts. No initial
full-register/memory snapshot is embedded in its replay format.

## Recorded trace replay and CFG evidence

`dynamic/replay.rs` imports schema1 `ura-observed-trace` and
`ura-emulation-trace`. It validates format/version, event sizes, positive ordered
sequences, observed process/session identities, address strings, optional bitness,
module base/RVA/hash consistency and register-name/count limits. It never runs
the source executable. JSON is parsed once; event paging is bounded. Thread
observation positions and register checkpoints every128 captures make each seek
apply at most127 changes after its checkpoint. Gaps clear continuity; thread
selection keeps that thread's last captured IP and registers together.

Observed samples describe paused instruction boundaries. Emulated register deltas
are **after** the instruction and use `nextAddress` as their sampled IP. States
include `capturedAtSequence`, sample timing, continuity and completeness. Missing
registers and historical memory stay unavailable. Back/forward browsing is
record navigation, not reverse debugging. Neither dropped events nor unobserved
paths establish complete program execution.

Overlay mapping requires exact captured module SHA256 and valid RVA translation
to the loaded original image. Active patch overlays are rejected for native/MCP
original-image correlation. The result counts **instruction observations per
block** and observations at block entries, not complete block execution or
coverage. Consecutive same-thread captures following a decoded control transfer
produce provenance-bearing transition candidates, including static disagreement.
The first512 candidates are retained with total/retained/truncated metadata.
Static edges/blocks are never rewritten. Matching hashes describe the original
module file; source runtime bytes may still have changed, so this uncertainty
is explicit. Emulated exports currently lack module identities and consequently
do not automatically produce matching static overlays. Symbol identity is not
reconstructed beyond captured module metadata.

## Sparse captured-memory analysis

`ura-memory-image` schema1 stores bitness, provenance, known virtual ranges and
permissions, explicit missing ranges and optional original identity. Import also
accepts bounded v0.12 `ura-memory-snapshot` exports and verifies their known-byte
hash and sizes. Legacy snapshots lack CPU mode: x64 is an explicitly labelled
assumption unless `image/open` supplies bitness32/64. A contradictory architecture
on an image bundle is rejected. Analysts must choose the appropriate mode.

Known executable ranges feed the existing function discovery, CFG, IR and SSA
machinery at their captured VAs. Pseudocode reconstruction currently uses the
selected contiguous executable range; sparse cross-range source recovery is
partial. Discovery is bounded to5,000 instructions,256 functions and2,048 blocks.
Hex/disassembly show known bytes; holes remain unmapped. Image analysis/export
is a sparse bundle, **not reconstruction of a portable executable** with rebuilt
imports/relocations/headers. There is no automated unpacker or original-entry
recovery.

Images can be made from original files, effective patched static sessions,
observed snapshots or explicit emulated memory. Current comparison requires the
same requested virtual range in both images, reports known/unknown/changed bytes
and returns at most256 individual differences. Byte changes alone are labelled
cause unknown; loader relocation, patching and runtime-write causes are never
guessed. Differing load bases require an analyst-supplied aligned image; there
is no automatic relocation-aware diff.

## Interfaces and permissions

Native Emulation has real create/run/step/stop/reset, initial-state/mapping inputs,
register highlighting, history instruction selection, virtual decode, checkpoints,
memory reads, explicit trace export and image analysis. Execution Trace selects
live recording or imported replay, with thread selection, indexed browsing and
matching original-image CFG evidence/navigation. Expensive service work executes
on workers. Results are bounded previews; live native input/DPI/GPU acceptance
remains unverified under the owner's desktop restriction.

CLI: `ura-cli --allow <root> --enable-emulation [--enable-writes] dynamic`.
This is an interactive JSON-line service; handles live until EOF/close. Example:

```json
{"operation":"emulation","action":"create","config":{"entry":"0x1000","mappings":[{"base":"0x1000","size":6,"bytes":[184,42,0,0,0,195],"permissions":{"read":true,"write":false,"execute":true}}]}}
{"operation":"emulation","action":"run","session":"emu-1","steps":20}
{"operation":"emulation","action":"status","session":"emu-1"}
```

Use the returned session handle; poll status until `busy:false` before inspection.
Success is `{schemaVersion:1,result:...}`. Errors use the established error view.
A native/raw path may replace config mappings; native files use preferred entry
addresses, raw paths require explicit mode/base. `image` may select an existing
captured-image handle. Complete action names are in `ura-service/src/dynamic.rs`.

MCP adds three functional action-based tools: `ura_emulation`, `ura_trace_replay`
and `ura_memory_image` (67 total). They use the same core/service operations.
MCP wraps dynamic success as `{schemaVersion:1,result:...}` inside structured
content. `ura_trace_replay` also supports `overlay` with an analyzed static
`binary` handle; `ura_memory_image/fromBinaryHandle` copies effective static
bytes. CLI dynamic handles are a separate service and do not expose these
static-handle bridge operations. Native uses its current static workspace.

Emulation is denied by default and requires **--enable-emulation**, independently
of debugger grants. Read-only replay/image inspection needs path permission but
no execution grant. File export additionally requires **--enable-writes**, an
allowed destination and a new filename; exports are atomic/no-clobber. This
never enables native launch, attach, live memory capture, termination or network
access. Those existing debugger grants remain separate. Session/image/replay
state is transient, not persisted into project schema8. Existing project
migration and patch/decompiler tests remain in the full suite.

Instruction references: [Intel architecture manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).
The implementation reuses iced-x861.21 and URA IR; no third-party emulator or OS
model was added. This documentation does not assert full architectural coverage.
