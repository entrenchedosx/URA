# v0.14 multi-architecture verification

Date: 2026-10-23. Version `0.14.0-dev.1`, branch
`v0.14-multi-architecture`. Baseline
`660e3a02866fce2445a04c80af813da2b7f1d7d4` was clean, equal to fetched
origin/v0.13-emulation-dynamic-analysis, and passed 352 tests. The containing
commit identifies this report's exact source. Historical tags/releases and main
are preserved. The v0.9–v0.13 versions remain source checkpoints, not
retroactively accepted releases.

**Scope: scalar multi-architecture development prerelease candidate.**
The code qualifies only for the implemented subsets described in
[MULTI-ARCHITECTURE.md](MULTI-ARCHITECTURE.md). Public acceptance additionally
requires the exact-source build receipt, complete package audit, unique tag,
fresh three-EXE assets and successful public re-download receipts. A source
push or this report alone does not establish publication.

## Implementation

A mature typed decoder now feeds processor-independent discovery, blocks,
xrefs, typed IR, generic SSA/dominators/dataflow and the existing semantic/C-like
source pipeline. ARM64 adds real X/W/SP/zero-register effects, NZCV arithmetic,
PC-relative addresses, scalar memory/writeback/pairs, arithmetic/select/multiply/
divide/rotate and direct/indirect control-transfer subsets. Static unknown effects
remain barriers; concrete unsupported effects stop before instruction commit.
No target syscall or unknown callee executes a host API.

AAPCS64/AAPCS32 and RV integer ABI metadata use their real argument/result
registers, rather than Win64/SysV x86 defaults. Scalar stack arguments and physical
slots are recovered by bounded exact SSA offsets from incoming SP. Saved incoming
link/register stores are candidates, not proof of restoration. Conflicting
joins/indices stay unknown. Return-address-register metadata avoids inventing an
x86 return slot. Unsupported aggregate/vector ABI and whole-program type claims
remain absent.

ARM32/Thumb and RV64I/RV32I have meaningful scalar decoding/CFG/IR/SSA/pseudocode
and isolated execution. Thumb IT/interworking/conditional-BX, compressed RV
execution, alternate link forms, vector/FP/system/atomic state, big endian and
mixed-mode transitions remain explicitly unsupported. Uniform Thumb metadata
normalizes the low entry bit; raw selection requires aligned bases and matching
bitness. ARM32 PE mode qualification is absent and rejected. ARM64 PE and linked
ELF mappings use preferred addresses, existing PT_LOAD/filesz/memsz/permission
checks and bounded backing memory. Mach-O runtime reconstruction, relocations,
dynamic linking and OS models are not implemented.

Native reuses its current analysis panels and adds an emulation processor
selector; CLI adds explicit raw processor selection. Existing 67 MCP tools expose
the shared engine. Raw processor metadata persists through project save/resave/
reopen and fixed byte patches; x86 assembly is refused for other processors.
Trace/image/replay identity retains the processor. Default-denied emulation,
separate writes, path grants, no-clobber exports, bounded replies and worker
cancellation remain in force.

## Debugger safety repair

The Windows debugger remains scoped to x64. WOW64 contexts and new-processor
debugging are **Missing**, explicitly rejected, and are not claimed as untestable
implemented features. The v0.14 owner's definition permits unsupported features
and unsafe cases to remain gated.

The reproduced ordinary-TF / foreign software displacement now serializes the
foreign instruction while parking the original thread's ordinary step. A queued
trap consumes only its owner's intent; byte rearm and suspension release remain
with the active displacement. Context-update rollback does not discard a restored
parked owner. Detach retains TF/hardware cleanup ownership until actual thread
handoff; timeout means explicit safe stop/retry/termination, not unsafe detachment.
True nested displacement, existing rearm ownership and uncertain rollback remain
blocked.

A full-suite intermittent failure exposed newly created foreign threads being
suspended during ordinary TF steps. This contradicted the blocking-instruction
policy. New-thread suspension is now limited to actual software-byte displacement,
deduplicated, and removed on thread exit. A real owned thread regression proves
zero owned suspends for ordinary TF and exactly one for displacement; the foreign
breakpoint race then passed eight fresh-process stress repetitions.

Only freshly compiled repository-owned windowless native fixtures were launched.
No unrelated user application, foreign native executable, desktop window or
computer-use automation was used.

## Tests and independent semantics

The preflight workspace run passed **369 tests** (352 baseline plus17), with no
ignored or filtered required tests. Strict all-target Clippy and formatting
checks passed. The committed-source package helper reruns those mandatory gates
and the complete locked Release build; its receipts are authoritative for the
final artifact's exact source.

Owned source `tests/samples/processors.c` was compiled with **LLVM Clang22.1.8**
at O0/O1/O2/O3 into ARM64 PE/ELF, uniform ARM/Thumb ELF and RV32I/RV64I ELF.
`aarch64-edges.s` adds exact arithmetic/condition/division/rotate/wide-constant
and deliberately unpredictable rejection encodings. The committed fixture
manifest checks all image and source hashes; no foreign image is host-executed.

The external **Unicorn2.1.4** reference run records:

- **767 successful execution comparisons** across the six processor/container
  combinations and edge corpus. All scalar roots/NZCV and final written memory
  bytes are compared; 6,928 written-byte positions across cases were checked.
- **671 independently executed C-like AST cases**, comparing return values and
  changed memory with Unicorn. The source executor has its own arithmetic/memory/
  control implementation. Unknown call effects prevent whole-callee AST execution,
  so nested-call cases are compared concretely and validated statically instead.
- **290 requested static analyses** with verified IR/SSA and real pseudocode.
- **36 explicit unsupported boundaries**, rather than successful emulation:
  ARM conditional-BX and Thumb IT cases at O1–O3. They fault at the uncommitted
  instruction and retain static diagnostics/barriers.
- **Zero unexpected failures**. This is a scalar corpus, not exhaustive ISA
  validation or a proof against all machine-state inputs.

See [machine-readable oracle report](benchmarks/0.14-processor-oracle.json).
Core processor tests additionally verify deterministic source, cancellation,
stack slots/arguments/saved links, W zero extension, carry/zero flags, zero/mode
register banks, original-byte preservation, raw metadata/conflicts/alignment,
ARM aliases/post-index, constrained A64 rejection, unsupported-vector/system/hint
effects and trap/PC-write CFG boundaries. Existing x86 semantic tests remain.

CLI/MCP Release preflight checks passed native/raw processor creation, virtual
disassembly, bounded execution, image IR/pseudocode, source-file SSA/pseudocode,
reset/restore, stale handles, no-clobber exports, default-denied execution and
write/path restrictions. The package helper repeats them on fresh executables.
MCP tool count remains **67**.

## Separate adversarial review

Two independent reviewing agents performed read-only reviews after implementation.
Findings repaired with regression coverage:

- ARM register post-index omitted writeback.
- A64 W/X writeback aliasing and duplicate load-pair unpredictable destinations.
- Abstract call operand layout, caller-saved r12 and unknown post-call link values.
- Thumb native entry normalization and external-stub link low bit.
- ARM sb/sl aliases, unsupported PC writes, compressed trap and extended control
  stopping boundaries.
- Existing raw-project resave processor preservation and explicit raw alignment.
- Parked-step rollback ownership and new-thread suspension of ordinary TF.
- Above-entry write-only/saved-register accesses overstating incoming stack bytes.

Reviewers confirmed the repaired ownership paths and conservative affine SSA
join/cycle/width logic on re-read. Review is not exhaustive formal verification.

## Performance and limits

Three sequential **Release** samples per report, with no desktop launch:

- [Per-processor pipeline and 10k-step measurements](benchmarks/0.14-processors-release.json):
  mature decode separately (10 iterations), CFG, lift, SSA, dataflow, decompile,
  isolated execution, backing memory and pre-requested cancellation.
- [Current x86 dynamic/replay measurements](benchmarks/0.14-dynamic-release.json)
  versus a [fresh same-host v0.13 baseline build](benchmarks/0.14-baseline-controlled.json).
  Baseline source was exported from the exact original commit under target/,
  built with the same installed toolchain, then current source was rebuilt.

The controlled median execution rates were approximately **121,587** versus
**119,528 instructions/s** (about1.7% lower here). The historical0.13 report had
different ambient load and is not used as a controlled baseline. Median indexed
replay seek increased from about0.00518ms to0.00963ms: an unresolved measured
regression, approximately4.4 microseconds/query, documented for profiling.
No blanket performance improvement is claimed.

Processor microbenchmark median 10k scalar-step times were approximately53ms
x64,118ms A64,64ms ARM,65ms Thumb,84ms RV32,87ms RV64. The 2,001-instruction A64
case produced1,007 pseudocode lines, about2.7ms CFG and35.4ms full decompile
median. These are synthetic single-function workloads and include uncached decode
for self-modifying correctness. They are not million-instruction throughput or
interactive scrolling claims.

Emulator backing in loop tests was about64KiB plus code; the processor benchmark's
whole-process sampled peak working set was about20MiB. This does not measure all
retained-object/private heaps, COW historical backing or a GUI workload.
Already-requested cancellation took roughly4–5 microseconds in these samples;
separate CLI/MCP async cancellation preflight completed below1ms locally.
GPU/presentation, idle native CPU, real OS DPI, scrolling and native input remain
unverified under the desktop restriction.

Budgets remain bounded; see processor scope for IR/stack limits and dynamic scope
for execution/memory/trace/session constraints. No decoder cache bypasses changed
virtual code bytes.

The initial tagged GitHub run [40022422403](https://github.com/entrenchedosx/URA/actions/runs/40022422403)
correctly withheld publication: a baseline symlink-escape test opened its input
fixture outside its sole allowed temporary root. This PC could not create the
symlink, while the hosted Windows runner could, exposing the test setup error.
The test now copies the input into the granted folder and separately verifies
that the original outside fixture is denied. No product path grant was broadened.
The original tag is preserved without a release; `v0.14.0-dev.1` receives fresh
qualification and assets. Saved performance reports retain their original
`0.14.0-dev` measurement identity; the engine code is unchanged in this revision.

## Distribution and remaining work

Windows x64 Desktop/CLI/MCP must be freshly compiled from the exact committed
source. The existing tag workflow is extended, not replaced: strict checks plus
the pinned external oracle, individual EXEs, full ZIP, complete license texts,
BUILD-INFO and checksum manifest, draft verification and public re-download.
Capstone wrapper/C backend and LLVM-derived license texts are audited explicitly.
Unicorn is a test-only external tool, never included in the product package.

Public release identity and hashes are recorded by the successful run's
`BUILD-INFO.json`, `package-verification.json` and
`download-public/github-verification.json`. Until those exist and pass, this
report claims verified source/candidate scope only. No older version is
backfilled using newer code.

The updated ledger has **205 capabilities:20 Supported,128 Partial,50 Missing,
7 Unverified**. Added rows expose processor-specific gaps; these are inventory
counts, not a percentage of IDA/Ghidra parity. MIPS/PPC, full ISA/ABI/vector/FP,
mixed modes/RVC, new debuggers/assemblers, advanced source/alias/type recovery,
debug metadata, remote/kernel/debugger backends, deobfuscation, plugins, diffing
and collaboration remain future obligations.
