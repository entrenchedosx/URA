# v0.14 processor scope

URA now uses a shared analysis/IR/SSA/decompiler pipeline for verified scalar
subsets of AArch64, ARM32, Thumb, RV64I and RV32I. This is a Windows x64 product
analysing those targets, not a Windows ARM64 host build or full ISA/OS emulator.
Existing x86/x64 paths remain available. The source and package version is
`0.14.0-dev`; public acceptance additionally requires the release verification
receipts described in [RELEASING.md](RELEASING.md).

## Capability matrix

“Partial” means a genuine implemented subset. Missing/unverified features are
not made available by selecting a processor name.

| Capability | AArch64 | ARM32 / Thumb | RV64I / RV32I |
|---|---|---|---|
| Binary processor metadata | Partial: width, little endian, mode, alignment, ABI/register roles | Partial: uniform mode evidence; ambiguous/mixed mode rejected | Partial: XLEN, ABI names, length/alignment |
| Mature instruction decoding | Partial: Capstone 5.0.6, little endian | Partial: ARM 4-byte; Thumb 2/4-byte | Partial: base and compressed decoding |
| Scalar registers | Partial: x0–30, W aliases, SP, XZR/WZR | Partial: r0–14, PC read rules, SP/LR/fp/ip/sb/sl aliases | Partial: 31 mutable roots, immutable zero, ABI aliases |
| SIMD / floating / crypto state | Missing; names/widths are metadata only | Missing | Missing |
| Arithmetic flags | Partial: NZCV for implemented operations; no x86 flags | Partial: NZCV; unimplemented shifter-carry forms rejected | Supported: no fabricated arithmetic flags; CSRs unsupported |
| Direct control flow | Partial: B/B.cond, CBZ/NZ, TBZ/NZ, BL | Partial: direct branch/BL; supported BX/POP returns | Partial: conditional branches, JAL/JALR, supported standard-link returns |
| Indirect flow / switches | Partial: explicit unresolved edges | Partial: unknown destinations retained | Partial: unknown destinations retained |
| Function discovery | Partial: executable mappings, entry/symbol/call seeds | Partial: uniform modes only | Partial: scalar linked ELF/raw |
| Typed IR | Partial: real scalar effects, addresses, memory, guards, unknown barriers | Partial: implemented scalar instructions | Partial: integer ALU/shift/compare, load/store, branch/call |
| SSA / dominators / dataflow | Supported on verified typed scalar IR | Supported on verified typed scalar IR | Supported on verified typed scalar IR |
| Calling conventions | Partial: AAPCS64 scalar registers, stack arguments, returns | Partial: AAPCS32 scalar subset | Partial: ILP32/LP64 integer convention |
| Stack-slot recovery | Partial: exact SSA offsets from incoming SP; saved incoming link/register candidates | Partial: same bounded proofs | Partial: same bounded proofs |
| Type recovery | Partial: scalar widths, pointer/load/store evidence, declared overrides | Partial: scalar evidence; 32-bit cross-function propagation remains limited | Partial: scalar evidence; RV32 cross-function propagation limited |
| C-like pseudocode | Partial: deterministic shared source pipeline and assembly provenance | Partial: supported uniform scalar functions | Partial: supported scalar functions |
| Isolated execution | Partial: real scalar effects, bounded virtual memory/calls/traces/cancellation | Partial: supported subset, interworking/IT rejected | Partial: base integer subset; compressed execution rejected |
| Live debugging | Missing | Missing | Missing |
| Instruction assembly | Missing; x86 encoding explicitly refused | Missing; x86 encoding explicitly refused | Missing; x86 encoding explicitly refused |
| Fixed byte patch overlays | Partial: original identity, preview/history/export retained | Partial: explicit raw mode persists | Partial: explicit raw mode persists |
| Verified native mapping | Partial: ARM64 PE and ELF preferred addresses | Partial: ELF; ARM32 PE mode qualification absent and rejected | Partial: linked ELF |
| Explicit raw selection | Supported within implemented modes | Supported; aligned bases, uniform mode | Supported; correct XLEN |
| Mach-O | Static metadata retained; target-specific runtime model missing/unverified | Mode qualification incomplete | Runtime model missing |

MIPS and PowerPC remain **Missing** semantic backends. Their existing metadata
recognition is not decoding, lifting, decompilation or execution support.
Big-endian semantics, mixed ARM/Thumb mappings, Thumb IT state, BLX interworking,
RISC-V compressed execution, alternate link conventions, vector/FP/atomic/system
operations, full relocation/linker/OS models and complete indirect dispatch are
future work. Unsupported instructions produce static barriers with unknown state
and diagnostics, or a concrete fault before instruction commit.

## Implementation and safety

`processor.rs` owns identity/metadata and normalizes Capstone's typed operand
details. Only the ARM64, ARM and RISC-V C decoder backends are enabled. Per-thread
decoder handles avoid repeatedly creating engines and do not require unsafe
Send/Sync declarations. Formatted disassembly text is not parsed for semantics.
Small encoding fields restore implicit RISC-V alias operands and distinguish ARM
NOP from unsupported hints that Capstone places under the same ID.

`ir/risc.rs` supplies scalar effects over the existing typed bitvector IR.
W writes zero-extend into X roots; zero registers discard writes. Address
calculations use the selected width. Calls expose target plus the complete
architectural state in the existing IR contract. Abstract results/caller-saved
state/memory remain unknown; concrete calls execute mapped virtual callees.
AArch64 x18, ARM r9 and RISC-V platform-dependent state are not used as proof of
portable preservation across an unknown callee.

AArch64 scalar coverage includes moves/wide constants, ADR/ADRP, integer
add/subtract/compare/logical operations, shifted/extended operands, scalar
conditional selects, multiply and widening/high-half forms, divide, rotates,
extensions, scalar literal/base/index loads/stores and supported pair/writeback
forms. Division has ARM zero-divisor and signed-overflow results, rather than
borrowing x86 divide faults. Constrained/unpredictable writeback aliases and
duplicate load-pair destinations are rejected.

ARM/Thumb has real scalar arithmetic, supported predicates, NZCV comparisons,
loads/stores, stack lists, calls and returns. Unsupported standalone shift carry
effects and modified-immediate carry forms are conservative barriers/faults.
An IT instruction ends static traversal rather than making its body
unconditionally executable. Native Thumb entry pointers are normalized at the
image boundary; concrete link values retain the Thumb bit. Mixed-mode and
authenticated/system transfers are not silently treated as ordinary branches.

RISC-V supports the verified base integer ALU, signed/unsigned comparisons,
masked shifts, loads/stores, LUI/AUIPC, standard scalar calls and returns. RV64 W
operations sign-extend the 32-bit result. Unaligned scalar memory access is
explicitly outside the current emulator policy. M/A/F/D/V/CSR operations and
compressed execution are not claimed.

`decomp/stack_risc.rs` follows SSA copies and constant address offsets from
incoming SP. Conflicting/cyclic phi paths, non-affine addresses and exhausted
budgets stay unknown. Recovered slots are physical memory evidence, not proven
source locals. Saved-register labels require a store of a native-width incoming
value below entry SP; restoration is not proved. Write-only accesses above entry
SP do not establish incoming arguments. The return-address register is separate
from x86's stack return-address offset.

Static IR budgets remain 1,024 blocks / 10,000 instructions / 80,000 operations.
Stack provenance additionally has a 100,000-node resolution budget, depth64,
20,000 accesses and 2,048 slots. Emulator/session/memory/time/trace/path/write
limits from [the dynamic analysis scope](EMULATION-DYNAMIC-ANALYSIS.md) remain.
No target syscall or external call invokes a host API.

## Interfaces and projects

Native binary analysis automatically uses verified loader metadata; its existing
disassembly, CFG, IR, SSA, types and pseudocode panels share the engine. The
Emulation panel adds a processor selector and automatic native-image mode.
No new live native input/DPI/presentation acceptance is asserted.

CLI raw analysis accepts, for example:

```text
ura-cli --allow C:/samples decompile C:/samples/code.raw --raw --processor aarch64 --base 1000 --function 1000 --json
```

Supported canonical names are x86, x86-64, aarch64, arm, thumb, riscv32, riscv64.
The old raw bitness-only API retains its x86/x64 interpretation. Native parse
failure never selects raw automatically. Explicit raw bases must respect the
selected instruction alignment. A saved raw project retains its processor;
resaving/reopening cannot enable x86 assembly over ARM/RISC-V.

The existing 67 MCP tools expose the same engine. `ura_open_binary` accepts a
raw `processor` string. `ura_emulation` accepts `config.processor` with the
matching `bitness`; image metadata must agree. Emulated disassembly, image
analysis and exported trace/replay identity retain the processor. Existing
separate execution, path and write grants remain required. No tool was added
merely to change architecture.

## Primary references and attribution

- [Capstone Rust 0.14.0 documentation](https://docs.rs/capstone/0.14.0/capstone/):
  decoder API; locked Capstone-sys0.18.0 bundles C Capstone5.0.6.
- [Arm AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
  and [AAPCS32](https://github.com/ARM-software/abi-aa/blob/main/aapcs32/aapcs32.rst):
  scalar register and stack conventions.
- [Arm architecture instruction documentation](https://developer.arm.com/documentation/ddi0596/2021-06/Base-Instructions/ADDS--shifted-register---Add--shifted-register---setting-flags-?lang=en):
  defined arithmetic effects; unsupported forms remain explicit.
- [Microsoft ARM64 ABI](https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions):
  W/X alias rules and Windows platform-register limitations.
- [RISC-V unprivileged ISA](https://docs.riscv.org/reference/isa/_attachments/riscv-unprivileged.pdf)
  and [integer psABI](https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-cc.adoc):
  integer operations, W sign extension and register/stack conventions.
- [Unicorn source](https://github.com/unicorn-engine/unicorn): version2.1.4 is
  an external test oracle, not a product runtime. See [THIRD_PARTY.md](../THIRD_PARTY.md).

Independent source-AST execution additionally checks 671 scalar cases against
the reference emulator. Unknown callees are not concretely executed by the
source AST verifier.

The processor tests and [v0.14 verification](VERIFICATION-0.14.md) establish URA's
implemented scope. Manual names or successful decoding alone do not.
