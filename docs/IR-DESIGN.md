# URA IR design — development schema 1

This describes working code on `v0.7-advanced-analysis`, based on v0.6 commit
`9d2b83e`. It is a decompiler foundation, not C-like output or a complete machine
model. The native application is versioned `0.7.0-dev` while release gates remain
open; see [verification](VERIFICATION-0.7.md).

## Pipeline and ownership

`ura-core::ir::inspect::analyze` constructs one verified bundle:

1. Decode the selected function's original file-backed instruction bytes.
2. Lift to typed raw operations, preserving CFG block ownership and instruction addresses.
3. Verify raw IR, compute dominators/frontiers, place phi nodes and rename values.
4. Independently verify SSA against recomputed CFG dominance.
5. Compute def-use counts, conservative constants, branch proofs and dead definitions.

The native worker, service, CLI and MCP use these same passes. Formatted assembly
operand strings are never semantic inputs. Analysis reports do not rewrite the
binary, source CFG, instructions or branches. The IR interpreter in `evaluate`
is a regression-test oracle that interprets IR; it never executes a sample.

## Types, values and operations

`Bits(n)` is an unsigned bit vector, 1–64 bits. Arithmetic wraps modulo 2^n.
`Address(n)` is a distinct type; integer/address conversion requires `ToAddress`
or `ToBits`. Addresses and constant payloads serialize as hexadecimal strings,
including 64-bit values above JavaScript's exact integer range. There is one
flat, byte-addressed, little-endian memory space. Separate physical, overlay,
I/O and non-byte-addressed spaces are future work.

Variables identify register roots, individual flags, an opaque memory token or
instruction-local temporaries. A constant has an explicit type and masked value.
Raw temporaries have one local definition. Every operation carries its machine
instruction address. Each block has its original half-open source range and a
separate terminator; address order and range overlap are verified.

| Operations | Semantics |
|---|---|
| Copy; Add/Sub; And/Or/Xor/Not | Typed copy, modular arithmetic, bitwise Boolean operations |
| Shl/Shr | Logical IR shifts; a count at least the width yields zero; these are not an assertion of x86 shift-instruction coverage |
| Equal/UnsignedLess | Same-width bit vectors producing one bit |
| ZeroExtend/SignExtend/Truncate | Explicit width changes; extension requires a larger result |
| Extract/Insert | Bounded bit-region read/replacement; other bits survive insertion |
| Select/Parity | Boolean choice; even parity of the low byte |
| ToAddress/ToBits | Same-width explicit representation conversion |
| Load/Store | Address, access width and memory dependency are explicit; loads/stores are observable |
| Call | Abstract call with target and all current state; no ABI preservation assumptions |
| Unknown/Barrier | Unknown definitions; an observable barrier consumes prior state and invalidates represented architectural state |

Terminator kinds are jump, conditional branch, indirect, return and unresolved.
Internal successors and missing/external exits are separate. Branches record
taken and fall-through destinations. Escaping paths preserve every represented
architectural variable exactly once. An indirect transfer remains open even when
heuristic jump-table edges have been recovered.

## Register and memory model

x64 has 16 GPR roots; x86 has eight 32-bit roots. AX/AL/AH and their counterparts
are explicit extracts/inserts into the root. In long mode an EAX write zeroes the
upper RAX half; a 16/8-bit write preserves unrelated bits. REX byte registers and
R8–R15 slices follow decoder identity, not spelling heuristics.

CF, PF, AF, ZF, SF and OF are separate one-bit variables. ADD/SUB/CMP compute carry,
signed overflow, auxiliary carry, zero, sign and low-byte parity. AND/OR/XOR/TEST
clear CF/OF and leave AF explicitly unknown. All 16 ordinary Jcc predicates are
combinations of these flags. Instruction-pointer-relative addresses use decoder
provenance and the decoded next IP; there is no speculative register value for IP.

Address calculation uses modular base/index/scale/displacement arithmetic, with
16/32-bit address-size overrides where decoded. LEA does not add a segment base.
Long-mode ordinary segment bases are ignored; FS/GS bases are explicit unknown
address inputs. The 32-bit model assumes flat code and a 32-bit stack descriptor;
data/stack segment bases remain explicit inputs. Descriptor validation, limits,
real mode, canonical-address faults and exception edges are not modeled.

Loads depend on the current memory token; stores define a new token. All memory
may alias. No load value is propagated from a previous store, including stack
stores. Calls conservatively invalidate memory and every represented register,
flag and segment base. This is scalar SSA plus an opaque, unpartitioned memory
dependency, not an alias-sensitive memory-SSA implementation. Faults and volatile
accesses are retained conservatively as observable loads/stores; branch proofs
describe normal completion, not exception behavior.

## Exact initial lifting coverage

| Instruction | Supported forms within the stated flat x86/x64 model |
|---|---|
| MOV | GPR/register, immediate and 8/16/32/64-bit scalar memory forms |
| MOVZX/MOVSX/MOVSXD | Decoder-valid scalar widening/truncation and root-register write behavior |
| LEA | GPR destination; decoded base/index/scale/displacement or IP-relative memory-form address |
| ADD/SUB/AND/OR/XOR/CMP/TEST | Scalar register, memory and immediate forms at 8/16/32/64 bits; decoded immediate sign extension |
| PUSH | GPR, scalar memory or immediate; native or 16-bit operand size; snapshot operand before changing SP |
| POP | GPR destinations, including SP; stack increment before destination write; memory destination unsupported |
| JMP | Near direct and GPR/scalar-memory indirect destinations; far forms remain unresolved barriers |
| Jcc | The 16 ordinary flag conditions; counter/loop-family branches have unknown conditions and barriers |
| CALL | Near target plus abstract conservative call effects; no concrete callee execution or ABI inference |
| RET | Native-width near return, optional unsigned imm16 stack adjustment; 16-bit operand override unsupported |
| NOP | No state change |

LOCK/repeat prefixes, SIMD/vector/FPU, unsupported arithmetic
outside the listed set, system/privileged operations, far transfers and other
register classes produce explicit unsupported diagnostics and state barriers.
A failed partial lift rolls back operations **and** temporary variables before
emitting that barrier. Invalid/truncated source instructions or inconsistent CFG
boundaries reject the function rather than presenting verified IR for them.

## CFG, jump tables and uncertainty

Entry/export/symbol/call/manual seeds and ownership remain the existing analysis
foundation. Function lookup requires an actual retained source block, not only a
bounding address range. A block-budget stop preserves retained function ownership
and prunes dangling edges. Partial analysis is identified in headless IR output.

Jump-table recovery recognizes two exact contiguous, unsigned-guarded patterns:

- `CMP index,N; JA default; JMP [index*pointer_width + absolute_table]`.
- x64 `CMP index,N; JA default; [MOV index32,source32]; LEA base,[RIP+table];
  MOVSXD target,[base+index*4]; ADD target,base; JMP target`.

For the second form, a 32-bit comparison requires the explicit zero-extending
copy; a 64-bit comparison can bound the 64-bit index directly. There must be
2–256 entries wholly within one read-only file-backed region. Entries are native
absolute pointers or signed 32-bit offsets relative to the table. Every target
must decode in executable bytes without conflicting instruction/function starts,
overlapping first instructions or pointing into the table. Failure adds a bounded
diagnostic and leaves the transfer unresolved. Writable tables, relocations at
runtime, alternate dispatch paths, stack-spilled dispatch, sparse/compressed
tables and other compiler patterns remain outside coverage.

Recovered edges have `guardedPatternHeuristic` confidence and `exhaustive:false`
in CFG JSON. A byte pattern is not a proof that all executions use only those
entries. Tail calls require a direct jump to a separately discovered function
entry and are reported as candidates. One-instruction direct/indirect jumps are
thunk candidates; no calling convention or shared-tail ownership is inferred.

Original fixtures include guarded absolute/relative byte sequences and a C
switch built with Clang 22.1.8 at `-O0`, `-O1`, `-O2` for PE and `-O2` for ELF.
Optimized fixtures recover six targets; the unoptimized spilled pattern is
deliberately unresolved. Rebuild with `scripts/build-switch-fixtures.ps1`.

## Dominance, SSA and dataflow

Dominators use reverse-postorder iteration and intersect immediate-dominator
chains. A tree interval numbering supports constant-time dominance queries;
frontiers guide iterated phi placement. Entry backedges include a virtual initial
predecessor. Renaming walks the dominator tree with explicit stacks, not recursion.
Phi arguments are indexed by predecessor block. Architectural version 0 denotes
unknown input; temporaries cannot have an undefined version 0. Unreachable source
blocks are listed and omitted from SSA. Verification recomputes dominance and
checks predecessors, unique definitions, edge-specific phi dominance, initial
inputs, types, source ranges and exit-state coverage.

Propagation uses a dependency worklist with bottom/constant/unknown states. Pure
operations use the same bit-vector evaluator as semantic tests; conflicting phi
values and unknown effects join to unknown. `x XOR x` and `x SUB x` can establish
zero without knowing x. Branch proofs are reports only. Dead definitions are
computed backwards from terminators, full exit state, loads, stores, calls and
unknown/barrier effects. All uses, including calls and exits, are counted.

## Limits, cancellation and caches

Per function: 10,000 source instructions, 1,024 blocks, 80,000 raw operations,
4,096 CFG edges, bounded phi definitions/inputs. Oversized functions return an
error; they are not truncated and labeled verified. CFG traversal, lifting, SSA
and propagation check cancellation. Verifiers have bounded input budgets.

The service retains at most two verified function bundles per binary handle;
the native view retains one. Session identity includes an immutable binary hash.
Reanalysis clears caches; native replies also carry binary generation and analysis
revision. Raw/SSA selection reuses the bundle. The project SQLite schema stays at
v3: no redundant IR is serialized. Existing annotations/manual seeds survive;
IR is rebuilt on reopen. `irVersion:1` and response `schemaVersion:1` are distinct.
The native project view adds an optional defaulted `ir_ssa` preference. IR is
hidden in the default dock layout and its rows are virtualized.

CLI/MCP pages bound rows and return the variable catalogue entries referenced by
that page, exact addresses, source operations and unsupported counts. MCP still
serializes synchronous service requests; transport-level cancellation/progress
is not implemented. Core/native cancellation is available.

## Source study and licensing

Official Ghidra source was inspected at
[`b8e9917e4c01959fe97ba94954731ed8cf2d201c`](https://github.com/NationalSecurityAgency/ghidra/tree/b8e9917e4c01959fe97ba94954731ed8cf2d201c):

- [sleigh.cc](https://github.com/NationalSecurityAgency/ghidra/blob/b8e9917e4c01959fe97ba94954731ed8cf2d201c/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh.cc)
  separates instruction translation, temporary storage and p-code emission. URA
  keeps decoder details inside its lifter; it does not embed SLEIGH definitions.
- [varnode.hh](https://github.com/NationalSecurityAgency/ghidra/blob/b8e9917e4c01959fe97ba94954731ed8cf2d201c/Ghidra/Features/Decompiler/src/decompile/cpp/varnode.hh)
  distinguishes storage location/size from SSA definitions. URA uses root-register
  slices and explicit typed SSA versions rather than independent aliases.
- [heritage.cc](https://github.com/NationalSecurityAgency/ghidra/blob/b8e9917e4c01959fe97ba94954731ed8cf2d201c/Ghidra/Features/Decompiler/src/decompile/cpp/heritage.cc)
  separates phi placement and renaming, with additional overlap/load/store work.
  URA's independent scalar implementation stops before alias refinement.
- [jumptable.cc](https://github.com/NationalSecurityAgency/ghidra/blob/b8e9917e4c01959fe97ba94954731ed8cf2d201c/Ghidra/Features/Decompiler/src/decompile/cpp/jumptable.cc)
  validates recovery models and preserves failure/partial state. URA uses a much
  smaller pattern recognizer and retains unresolved indirect flow.
- Earlier address-space and basic-block findings remain in
  [GHIDRA-RESEARCH.md](GHIDRA-RESEARCH.md). Instruction semantics were checked
  against the [Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
  and iced-x86 1.21's decoded operands, widths and immediate APIs.

The inspected Ghidra files have Apache-2.0 headers. No Ghidra code, tables,
processor definitions or assets were copied into URA. Rust implementation and C
fixtures are original; URA retains MIT licensing. No new runtime dependency was
added. `serde_json`, already in the workspace, is a core dev-dependency for the
benchmark harness. Python profiling scripts optionally require psutil.

Future decompilation needs broader differential semantics testing, explicit ABI
and exception models, alias analysis, structured control flow and type recovery.
The present IR deliberately provides none of those as fabricated pseudocode.

## Shared concrete instruction semantics (v0.13)

The single-instruction CPU entry uses the same decoder and Builder operations as
static lifting. INC/DEC now preserve CF, and SHL/SHR/SAR implement masked counts,
zero-count preservation, SAR sign fill, defined CF/OF rules and undefined flags.
Two locked HIR snapshots were deliberately updated because these instructions no
longer produce unsupported barriers. Raw IR logical shift operators retain their
own width semantics; the instruction builder supplies the architectural count
mask and flag behavior. Concrete CALL handles stack/control transfer without the
static lifter's abstract ABI clobbers. Prefix modes are determined from leading
prefixes only, never displacement bytes. See dynamic tests and verification.
