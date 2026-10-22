# Feature parity ledger

Audited 2026-10-22 for the v0.9 source checkpoint. Full feature-set parity with IDA Pro, relevant Hex-Rays components and Ghidra is a permanent multi-release objective. This ledger must be reviewed on every milestone; v0.9 does not establish product parity.

Each row is one auditable capability. **Supported** means verified within the stated scope, **Partial** means meaningful but incomplete implementation, **Missing** means no product implementation, and **Unverified** means insufficient acceptance evidence. Counts describe this ledger, not a percentage of either competitor's entire feature set. Add rows as research reveals further capabilities; never hide a gap by merging categories.

Competitor cells link primary documentation showing the surrounding capability family. “Available” is family-level availability, subject to edition, architecture, backend and version; it does not claim identical semantics or coverage. Where the research does not establish a particular feature, the cell says “Not assessed.” No competitor binaries were installed, copied or reverse engineered. Source implementation/test claims below come from this repository, not competitor documentation.

Evidence: **C-AST** = `crates/ura-core/tests/c_decompiler.rs`; **SEM** = `crates/ura-core/tests/decomp_semantics.rs`; **CLI** = `crates/ura-cli/tests/cli.rs`; **MCP** = `crates/ura-mcp/tests/stdio.rs`. Other core/native/project/service tests are under the named crate's `tests/` or `#[cfg(test)]` modules. Source paths without a crate prefix are relative to `crates/ura-core/src/`; `ura-native`, `ura-project`, `ura-service`, `ura-cli`, `ura-mcp` denote those crates' `src/` modules. “—” means no implementation/evidence. Manual evidence is deliberately separate from automated evidence; historical checks never become current acceptance checks automatically.

Live v0.9 results, package checks, performance and remaining acceptance gates are recorded in [VERIFICATION-0.9.md](VERIFICATION-0.9.md). The current OS DPI blocker and exact owner checklist are in [RELEASE-QUALIFICATION-0.8.md](RELEASE-QUALIFICATION-0.8.md).

Ledger totals: **129 capabilities** — **17 Supported**, **52 Partial**, **56 Missing**, **4 Unverified**.

## Disassembly and processors

| ID | Capability | IDA / Hex-Rays | Ghidra | URA | Architecture/platform | Implementation | Automated evidence | Manual evidence | Limits | Target |
|---|---|---|---|---|---|---|---|---|---|---|
| D-01 | x86/x64 instruction decoding | Available [I-D][I-D] | Available [G-B][G-B] | **Supported** | x86/x64; Windows verified | `disasm.rs` | core disassembly tests | Not a manual gate | Decoder coverage exceeds executable semantics | v0.9 |
| D-02 | ARM/Thumb and AArch64 decoding | Available [I-D][I-D] | Available [G-B][G-B] | **Missing** | x86/x64; Windows verified | `—` | — | — | Metadata recognition only | Later processors |
| D-03 | RISC-V/MIPS/PowerPC decoding | Available [I-D][I-D] | Available [G-B][G-B] | **Missing** | x86/x64; Windows verified | `—` | — | — | Metadata recognition only | Later processors |
| D-04 | 16-bit/segmented instruction analysis | Available [I-D][I-D] | Available [G-B][G-B] | **Missing** | x86/x64; Windows verified | `—` | — | — | No segmented analysis model | Later processors |
| D-05 | Scalar instruction lifting | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | x86/x64; Windows verified | `ir/lift.rs` | core ir tests; SEM | Not a manual gate | MOV/LEA/ADD/SUB/bitwise/CMP/TEST/stack/branch subset | v0.10 |
| D-06 | Multiply/divide/rotate/CMOV/SETcc lifting | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | x86/x64 scalar; strongest full-width corpus x64 | `ir/lift.rs; ir/evaluate.rs; decomp/execute.rs` | SEM known-result conditions, products, division/faults, counts 0–255; C-AST integer promotion | See v0.9 finalisation | MUL/IMUL, DIV/IDIV with #DE guard, ROL/ROR, all CMOV/SETcc; RCL/RCR, general exception/memory-fault model absent | v0.9 |
| D-07 | Floating/vector instruction semantics | Available [I-D][I-D] | Available [G-B][G-B] | **Missing** | x86/x64; Windows verified | `ir/lift.rs explicit barriers` | SEM unsupported effects | — | x87/SSE/AVX effects remain unknown | Later semantics |
| D-08 | Recursive function discovery | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | x86/x64; Windows verified | `analysis.rs` | core analysis tests | Not a manual gate | Seeded bounded traversal; cannot prove all code | v0.10 |
| D-09 | Manual function starts | Available [I-D][I-D] | Available [G-B][G-B] | **Supported** | x86/x64; Windows verified | `analysis.rs; ura-project` | service/project tests | Not a manual gate | Executable mapped addresses only | v0.9 |
| D-10 | Direct code cross references | Available [I-D][I-D] | Available [G-B][G-B] | **Supported** | x86/x64; Windows verified | `analysis.rs` | core/service tests | Not a manual gate | Decoded direct edges only | v0.9 |
| D-11 | Data cross references | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | x86/x64; Windows verified | `analysis.rs` | core reference tests | Not a manual gate | Provable RIP-relative/absolute addresses only | v0.10 |
| D-12 | Control-flow graph extraction | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | x86/x64; Windows verified | `analysis.rs; jumptable.rs` | core switch tests | Not a manual gate | Indirect candidate edges are non-exhaustive | v0.10 |
| D-13 | Function graph visualization | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | x86/x64; Windows verified | `ura-native/graph_view.rs` | native render tests | Not a manual gate | No general editable graph layout persistence | v0.10 |
| D-14 | Call graph and recursion SCCs | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | x86/x64; Windows verified | `decomp/callgraph.rs` | core/service decomp tests | Not a manual gate | Bounded graph; indirect calls incomplete | v0.10 |
| D-15 | Calling-convention recovery | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | x86/x64; Windows verified | `decomp/abi.rs` | core ABI tests | Not a manual gate | Scalar Win64/SysV64 and narrow x86 evidence | v0.10 |

## Decompiler

| ID | Capability | IDA / Hex-Rays | Ghidra | URA | Architecture/platform | Implementation | Automated evidence | Manual evidence | Limits | Target |
|---|---|---|---|---|---|---|---|---|---|---|
| C-01 | Independent semantic C-like AST | Available [I-C][I-C] | Available [G-A][G-A] | **Supported** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source` | C-AST; SEM | See v0.9 verification; historical checks separate | Version 1; reconstructed pseudocode contract | v0.9 |
| C-02 | Deterministic C-like emitter/export | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/print.rs; ura-service/decomp.rs` | C-AST; CLI; MCP | See v0.9 verification; historical checks separate | Explicit helpers; no guaranteed recompilation | v0.10 |
| C-03 | Fixed-width integer expressions | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/print.rs` | C-AST; SEM | See v0.9 verification; historical checks separate | Only lifted scalar operations; helper intrinsics remain | v0.10 |
| C-04 | Signed and unsigned interpretation | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/print.rs` | C-AST signed-formal regression | See v0.9 verification; historical checks separate | Machine bit patterns explicit; signed idiom simplification incomplete | v0.10 |
| C-05 | SSA destruction and cycle copies | Decompiler internals; exact implementation not assessed | Decompiler internals; exact implementation not assessed | **Supported** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/build.rs` | C-AST 1024 simultaneous-copy cases; SEM | See v0.9 verification; historical checks separate | Edge-local copies; memory stays ordered | v0.9 |
| C-06 | Temporary elimination | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/build.rs` | C-AST constant/provenance and call snapshot regressions; SEM | See v0.9 verification; historical checks separate | Observable-slice use counts and SSA constants; single-use pure same-block only; no load/call motion or general lifetime coalescing | v0.10 |
| C-07 | Nested conditional reconstruction | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/build.rs` | SEM nested/diamond fixtures | See v0.9 verification; historical checks separate | Uniquely entered closed regions only | v0.10 |
| C-08 | Loop reconstruction | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/build.rs` | SEM loop/nested-loop paths | See v0.9 verification; historical checks separate | Proved reductions emit while(true) with explicit exits | v0.10 |
| C-09 | Canonical for/do-while syntax | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `—` | — | — | Equivalent explicit loops/gotos retained | v0.10 |
| C-10 | Switch source reconstruction | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `jumptable.rs candidates only` | core switch tests; SEM C++ corpus | — | Heuristic targets never promoted to complete source switch | v0.10 |
| C-11 | Short-circuit source operators | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `—` | — | — | Explicit conditions retained | v0.10 |
| C-12 | Labels/gotos for remaining CFG | Available [I-C][I-C] | Available [G-A][G-A] | **Supported** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/build.rs` | SEM irreducible/external cases | See v0.9 verification; historical checks separate | No invented structured region | v0.9 |
| C-13 | Register parameter reconstruction | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/build.rs` | C-AST narrow/formal regressions | See v0.9 verification; historical checks separate | Exact entry register/low-width proofs; stack/vector args incomplete | v0.10 |
| C-14 | Named source locals/lifetime coalescing | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/build.rs` | C-AST naming regression | See v0.9 verification; historical checks separate | Deterministic SSA-backed locals; no lifetime coalescing | v0.10 |
| C-15 | Stack-slot names and type evidence | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/stack.rs; ura-native/views.rs` | service decomp persistence tests | See v0.9 verification; historical checks separate | Physical slots; store annotations; not scalarized C locals | v0.10 |
| C-16 | Pointer analysis and memory syntax | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/types.rs; decomp/source` | SEM memory/order tests | See v0.9 verification; historical checks separate | Explicit loads/stores; no general alias proof | v0.10 |
| C-17 | Named structure-field expressions | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/types.rs layouts only` | — | — | No field syntax without exact layout proof | v0.10 |
| C-18 | Direct calls and known prototypes | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/build.rs` | C-AST call argument regressions | See v0.9 verification; historical checks separate | Call clobbers explicit; concrete call evaluation stops | v0.10 |
| C-19 | Imported API call identities | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/imports.rs; decomp/source` | core import tests; existing trusted-slot resolver | See v0.9 verification; historical checks separate | Narrow validated prototype catalog and slot paths | v0.10 |
| C-20 | ABI returns | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/build.rs` | C-AST narrow return; SEM | See v0.9 verification; historical checks separate | Scalar register candidates; floating/aggregate ABI unknown | v0.10 |
| C-21 | Bidirectional instruction/source maps | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/print.rs; ura-native/views.rs` | C-AST provenance; native render tests | See v0.9 verification; historical checks separate | Many addresses per line; synthetic lines have no invented address | v0.10 |
| C-22 | Cross-function type constraints | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/flow.rs; decomp/program.rs` | core program/flow tests | See v0.9 verification; historical checks separate | Bounded scalar facts; memory/stack propagation incomplete | v0.10 |
| C-23 | Unsupported-effect diagnostics | Available [I-C][I-C] | Available [G-A][G-A] | **Supported** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/build.rs` | C-AST UD2; SEM unknown paths | See v0.9 verification; historical checks separate | Unknown operations stay explicit, no fabricated source | v0.9 |
| C-24 | Cancellation and output budgets | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source; ura-native/worker.rs` | SEM cancellation; service limits | See v0.9 verification; historical checks separate | 20k lines/80k operations/1024 blocks; CLI/MCP synchronous | v0.10 |
| C-25 | Compiler idiom recovery | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `decomp/source/build.rs` | SEM Clang C/C++ O0–O3 PE/ELF | See v0.9 verification; historical checks separate | No MSVC/GCC compiler matrix or general optimized idiom model | v0.10 |
| C-26 | Exception/unwind-aware decompilation | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 core; strongest semantic corpus x64 PE/ELF | `—` | — | — | SEH/C++ exception control not modeled | Later semantics |

## Debugger

| ID | Capability | IDA / Hex-Rays | Ghidra | URA | Architecture/platform | Implementation | Automated evidence | Manual evidence | Limits | Target |
|---|---|---|---|---|---|---|---|---|---|---|
| DBG-01 | Launch/attach native process debugging | Available [I-DBG][I-DBG] | Available [G-DBG][G-DBG] | **Missing** | None implemented; Windows native target proposed | `—` | — | — | Static analysis only | v0.12 |
| DBG-02 | Remote target debugging | Available [I-DBG][I-DBG] | Available [G-DBG][G-DBG] | **Missing** | None implemented; Windows native target proposed | `—` | — | — | No remote debugger protocol | Later debugging |
| DBG-03 | Software breakpoints | Available [I-DBG][I-DBG] | Available [G-DBG][G-DBG] | **Missing** | None implemented; Windows native target proposed | `—` | — | — | No debug session | v0.12 |
| DBG-04 | Hardware breakpoints/watchpoints | Available [I-DBG][I-DBG] | Available [G-DBG][G-DBG] | **Missing** | None implemented; Windows native target proposed | `—` | — | — | No debug registers model | Later debugging |
| DBG-05 | Live register inspection/editing | Available [I-DBG][I-DBG] | Available [G-DBG][G-DBG] | **Missing** | None implemented; Windows native target proposed | `—` | — | — | Static entry-value helpers are not live registers | v0.12 |
| DBG-06 | Live memory inspection/editing | Available [I-DBG][I-DBG] | Available [G-DBG][G-DBG] | **Missing** | None implemented; Windows native target proposed | `—` | — | — | Hex view reads the file only | v0.12 |
| DBG-07 | Thread enumeration/control | Available [I-DBG][I-DBG] | Available [G-DBG][G-DBG] | **Missing** | None implemented; Windows native target proposed | `—` | — | — | No debug thread model | v0.12 |
| DBG-08 | Live stack/backtrace inspection | Available [I-DBG][I-DBG] | Available [G-DBG][G-DBG] | **Missing** | None implemented; Windows native target proposed | `—` | — | — | Static stack recovery is separate | v0.12 |
| DBG-09 | Step into/over/out | Available [I-DBG][I-DBG] | Available [G-DBG][G-DBG] | **Missing** | None implemented; Windows native target proposed | `—` | — | — | No execution control | v0.12 |
| DBG-10 | Instruction/function tracing | Available [I-DBG][I-DBG] | Available [G-DBG][G-DBG] | **Missing** | None implemented; Windows native target proposed | `—` | — | — | Interpreter test trace is not native tracing | v0.12 |
| DBG-11 | Trace persistence/replay | Family documented; exact scope not assessed | Family documented; exact scope not assessed | **Missing** | None implemented; Windows native target proposed | `—` | — | — | No trace database | Later debugging |
| DBG-12 | Debugger scripting | Available [I-DBG][I-DBG] | Available [G-DBG][G-DBG] | **Missing** | None implemented; Windows native target proposed | `—` | — | — | No debugger API | Later debugging |

## Binary patching

| ID | Capability | IDA / Hex-Rays | Ghidra | URA | Architecture/platform | Implementation | Automated evidence | Manual evidence | Limits | Target |
|---|---|---|---|---|---|---|---|---|---|---|
| P-01 | Hex byte editing | Available [I-P][I-P] | Available [G-B][G-B] | **Missing** | None implemented | `—` | — | — | Current hex view is read-only | v0.11 |
| P-02 | Instruction assembly | Available [I-P][I-P] | Available [G-B][G-B] | **Missing** | None implemented | `—` | — | — | No assembler integration | v0.11 |
| P-03 | Patch history | Family documented; exact scope not assessed | Family documented; exact scope not assessed | **Missing** | None implemented | `—` | — | — | No patch model | v0.11 |
| P-04 | Patch undo/redo | Family documented; exact scope not assessed | Family documented; exact scope not assessed | **Missing** | None implemented | `—` | — | — | No mutation transaction model | v0.11 |
| P-05 | Modified executable export | Available [I-P][I-P] | Available [G-B][G-B] | **Missing** | None implemented | `—` | — | — | No PE/ELF writer | v0.11 |
| P-06 | Post-patch analysis invalidation | Available [I-P][I-P] | Available [G-B][G-B] | **Missing** | None implemented | `—` | — | — | Project-edit cache invalidation exists; bytes cannot change | v0.11 |
| P-07 | Expected-byte verified application | Available [I-P][I-P] | Available [G-B][G-B] | **Missing** | None implemented | `—` | — | — | Needs original-byte/hash guards | v0.11 |
| P-08 | Relocation/signature-aware patching | Scope not assessed | Scope not assessed | **Missing** | None implemented | `—` | — | — | Loader/signing concerns not implemented | Later patching |

## Binary formats

| ID | Capability | IDA / Hex-Rays | Ghidra | URA | Architecture/platform | Implementation | Automated evidence | Manual evidence | Limits | Target |
|---|---|---|---|---|---|---|---|---|---|---|
| F-01 | PE executable metadata/imports/exports | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | Windows host verification; x86/x64 analysis unless stated | `binary/mod.rs; decomp/imports.rs` | core binary/import tests; PE fixtures | Not a manual gate | Not a full Windows loader/emulator | v0.10 |
| F-02 | ELF metadata/symbols/import slots | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | Windows host verification; x86/x64 analysis unless stated | `binary/mod.rs; decomp/imports.rs` | core ELF/import tests; ELF fixtures | Not a manual gate | Relocations/thunks only narrow supported subset | v0.10 |
| F-03 | Mach-O inspection | Available [I-D][I-D] | Available [G-B][G-B] | **Unverified** | Windows host verification; x86/x64 analysis unless stated | `binary/mod.rs object reader` | Limited automated validation | Not a manual gate | Broader Mach-O corpus/platform verification absent | Later formats |
| F-04 | Raw binary import/base selection | Available [I-D][I-D] | Available [G-B][G-B] | **Missing** | Windows host verification; x86/x64 analysis unless stated | `analysis.rs internal CodeImage API only` | — | — | No product raw-loader workflow | Later formats |
| F-05 | Firmware/Intel HEX/S-record loaders | Available [I-D][I-D] | Available [G-B][G-B] | **Missing** | Windows host verification; x86/x64 analysis unless stated | `—` | — | — | No firmware memory-map loader | Later formats |
| F-06 | COFF/ELF relocatable object workflow | Available [I-D][I-D] | Available [G-B][G-B] | **Unverified** | Windows host verification; x86/x64 analysis unless stated | `binary/mod.rs object reader` | No end-to-end object workflow gate | Not a manual gate | Recognition does not establish relocation-aware analysis | Later formats |
| F-07 | Static archive members | Available [I-D][I-D] | Available [G-B][G-B] | **Missing** | Windows host verification; x86/x64 analysis unless stated | `—` | — | — | No archive workspace | Later formats |
| F-08 | Memory dumps | Available [I-D][I-D] | Available [G-B][G-B] | **Missing** | Windows host verification; x86/x64 analysis unless stated | `—` | — | — | No dump import/address-space reconstruction | Later formats |
| F-09 | Dyld/shared caches | Available [I-D][I-D] | Available [G-B][G-B] | **Missing** | Windows host verification; x86/x64 analysis unless stated | `—` | — | — | No cache loader | Later formats |
| F-10 | Overlay/rebase/segment editor | Available [I-D][I-D] | Available [G-B][G-B] | **Missing** | Windows host verification; x86/x64 analysis unless stated | `—` | — | — | Read-only section mapping | Later formats |

## Symbols and types

| ID | Capability | IDA / Hex-Rays | Ghidra | URA | Architecture/platform | Implementation | Automated evidence | Manual evidence | Limits | Target |
|---|---|---|---|---|---|---|---|---|---|---|
| T-01 | Executable symbol/import/export names | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 type descriptions; Windows native editors | `binary/mod.rs; analysis.rs` | core/service symbol tests | See v0.9 verification; historical checks separate | No general symbol server/demangler pipeline | v0.10 |
| T-02 | PDB debug information | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 type descriptions; Windows native editors | `—` | — | — | No PDB loader | Later symbols |
| T-03 | DWARF debug information | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 type descriptions; Windows native editors | `—` | — | — | No DWARF loader | Later symbols |
| T-04 | Structures/unions with explicit layouts | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 type descriptions; Windows native editors | `decomp/types.rs; ura-native/editors.rs` | core type validation; service library persistence | See v0.9 verification; historical checks separate | Manual bounded layouts, no automatic full layout recovery | v0.10 |
| T-05 | Enum definitions/value substitution | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 type descriptions; Windows native editors | `decomp/types.rs` | core type tests | See v0.9 verification; historical checks separate | TypeRef only; no enum member database/editor | v0.10 |
| T-06 | Function prototypes and overrides | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 type descriptions; Windows native editors | `decomp/signature.rs; ura-project` | service decomp persistence; CLI/MCP writes | See v0.9 verification; historical checks separate | Validated subset, no full declarator parser | v0.10 |
| T-07 | C++ classes/object models | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 type descriptions; Windows native editors | `—` | — | — | C++ corpus does not imply class reconstruction | Later C++ |
| T-08 | Vtable discovery/dispatch resolution | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 type descriptions; Windows native editors | `—` | — | — | Indirect dispatch remains unknown | Later C++ |
| T-09 | RTTI-based recovery | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 type descriptions; Windows native editors | `—` | — | — | No RTTI analyzer | Later C++ |
| T-10 | Type libraries/typedef aliases | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 type descriptions; Windows native editors | `decomp/types.rs; ura-project` | service type-library round trip | See v0.9 verification; historical checks separate | Per-project bounded JSON; no mature shared archive format | v0.10 |
| T-11 | C header parsing | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 type descriptions; Windows native editors | `—` | — | — | Narrow type syntax only | Later types |
| T-12 | Source line/inline debug maps | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 type descriptions; Windows native editors | `—` | — | — | Only machine instruction provenance | Later symbols |

## Advanced analysis

| ID | Capability | IDA / Hex-Rays | Ghidra | URA | Architecture/platform | Implementation | Automated evidence | Manual evidence | Limits | Target |
|---|---|---|---|---|---|---|---|---|---|---|
| A-01 | Constant propagation | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 scalar IR; x64 semantic corpus | `ir/dataflow.rs` | core IR/dataflow tests | Not a manual gate | Conservative scalar constants only | v0.10 |
| A-02 | SSA and def-use analysis | Available [I-C][I-C] | Available [G-A][G-A] | **Supported** | x86/x64 scalar IR; x64 semantic corpus | `ir/ssa.rs; ir/dataflow.rs` | core SSA tests; SEM | Not a manual gate | Within bounded lifted functions | v0.9 |
| A-03 | Dominators/frontiers | Available [I-C][I-C] | Available [G-A][G-A] | **Supported** | x86/x64 scalar IR; x64 semantic corpus | `ir/ssa.rs` | core dominator tests; CLI/MCP | Not a manual gate | Entry-reachable graph only | v0.9 |
| A-04 | Value-set/range analysis | Scope not assessed | Scope not assessed | **Missing** | x86/x64 scalar IR; x64 semantic corpus | `—` | — | — | Constants are not general value sets | Later analysis |
| A-05 | Function similarity matching | Lumina/signature family; exact similarity scope not assessed | [BSim](https://ghidra.re/ghidra_docs/GhidraClass/BSim/BSimTutorial_Basic_Queries.html) | **Missing** | x86/x64 scalar IR; x64 semantic corpus | `—` | — | — | No similarity index | Later comparison |
| A-06 | Library signature recognition | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 scalar IR; x64 semantic corpus | `decomp/api.rs; decomp/imports.rs` | core import tests | Not a manual gate | Name/slot-validated catalog; no FLIRT-like byte signatures | Later recognition |
| A-07 | Byte/pattern search | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 scalar IR; x64 semantic corpus | `ura-native/navigation.rs` | native navigation tests | Not a manual gate | Address/name/string search; no full masked binary pattern workflow | v0.10 |
| A-08 | Binary comparison/diff transfer | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 scalar IR; x64 semantic corpus | `—` | — | — | No paired program analysis | Later comparison |
| A-09 | Deobfuscation/opaque predicates | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 scalar IR; x64 semantic corpus | `—` | — | — | No semantic rewrite proof framework | v0.13 |
| A-10 | General CPU emulation | Available [I-C][I-C] | Available [G-A][G-A] | **Missing** | x86/x64 scalar IR; x64 semantic corpus | `ir/evaluate.rs; decomp/execute.rs; decomp/source/evaluate.rs` | SEM bounded interpreter tests | — | No OS/environment/peripheral emulator | Later emulation |
| A-11 | Indirect-call target recovery | Available [I-C][I-C] | Available [G-A][G-A] | **Partial** | x86/x64 scalar IR; x64 semantic corpus | `decomp/callgraph.rs; decomp/imports.rs` | core callgraph/import tests | Not a manual gate | Bounded register/slot proofs only | v0.10 |
| A-12 | Memory alias analysis | Family documented; exact scope not assessed | Family documented; exact scope not assessed | **Partial** | x86/x64 scalar IR; x64 semantic corpus | `ir/dataflow.rs` | SEM stale-memory regressions | Not a manual gate | Opaque token prevents unsound reuse; no precise alias sets | v0.10 |
| A-13 | Taint/symbolic execution | Scope not assessed | Scope not assessed | **Missing** | x86/x64 scalar IR; x64 semantic corpus | `—` | — | — | No symbolic path solver | Later analysis |

## Automation

| ID | Capability | IDA / Hex-Rays | Ghidra | URA | Architecture/platform | Implementation | Automated evidence | Manual evidence | Limits | Target |
|---|---|---|---|---|---|---|---|---|---|---|
| AUT-01 | Headless CLI queries | Available [I-API][I-API] | Available [G-H][G-H] | **Supported** | Windows CLI/MCP verified; core Rust library | `ura-cli/main.rs` | CLI process tests | Not a manual gate | Bounded per-binary operations | v0.9 |
| AUT-02 | Structured CLI decompile/export | Available [I-API][I-API] | Available [G-H][G-H] | **Partial** | Windows CLI/MCP verified; core Rust library | `ura-cli/main.rs; ura-service/decomp.rs` | CLI; service export test | Not a manual gate | C-like subset, opt-in AST and writes | v0.10 |
| AUT-03 | MCP decompile/query/export | Not assessed | Not assessed | **Partial** | Windows CLI/MCP verified; core Rust library | `ura-mcp/server.rs` | MCP stdio process tests | Not a manual gate | 32 tools; local stdio; same core bounds | v0.10 |
| AUT-04 | Programmatic Rust API | Available [I-API][I-API] | Available [G-H][G-H] | **Partial** | Windows CLI/MCP verified; core Rust library | `ura-core/lib.rs; ura-service/lib.rs` | workspace integration tests | Not a manual gate | No stable extension compatibility contract | Later SDK |
| AUT-05 | Embedded scripting console | Available [I-API][I-API] | Available [G-H][G-H] | **Missing** | Windows CLI/MCP verified; core Rust library | `—` | — | — | No scripting runtime | Later SDK |
| AUT-06 | Public plugin/extension SDK | Available [I-API][I-API] | Available [G-H][G-H] | **Missing** | Windows CLI/MCP verified; core Rust library | `—` | — | — | No loadable extension ABI | Later SDK |
| AUT-07 | Analysis event hooks | Available [I-API][I-API] | Available [G-H][G-H] | **Missing** | Windows CLI/MCP verified; core Rust library | `—` | — | — | Internal worker events are not a public hook API | Later SDK |
| AUT-08 | Batch project/directory processing | Available [I-API][I-API] | Available [G-H][G-H] | **Partial** | Windows CLI/MCP verified; core Rust library | `ura-cli` | CLI per-file process tests | Not a manual gate | External shell can loop files; no managed batch job model | Later batch |
| AUT-09 | Path/write policy enforcement | Not assessed | Not assessed | **Supported** | Windows CLI/MCP verified; core Rust library | `ura-service/paths.rs` | service path tests; CLI/MCP denied-write tests | Not a manual gate | Allowed roots; writes opt-in; export create-new | v0.9 |

## Projects and collaboration

| ID | Capability | IDA / Hex-Rays | Ghidra | URA | Architecture/platform | Implementation | Automated evidence | Manual evidence | Limits | Target |
|---|---|---|---|---|---|---|---|---|---|---|
| PRJ-01 | Project database persistence | Available [I-TEAM][I-TEAM] | Available [G-I][G-I] | **Supported** | Windows SQLite projects schema 5 | `ura-project` | project migrations/round trips | See v0.9 verification; historical checks separate | One binary identity per project | v0.9 |
| PRJ-02 | Function name overrides | Available [I-TEAM][I-TEAM] | Available [G-I][G-I] | **Supported** | Windows SQLite projects schema 5 | `ura-project; ura-service/service.rs` | service project round trip | See v0.9 verification; historical checks separate | Separate from recovered symbols | v0.9 |
| PRJ-03 | Instruction comments/annotations | Available [I-TEAM][I-TEAM] | Available [G-I][G-I] | **Supported** | Windows SQLite projects schema 5 | `ura-project; ura-native/views.rs` | project/service annotation tests | See v0.9 verification; historical checks separate | Inspector annotations; not inline pseudocode comments | v0.9 |
| PRJ-04 | Signature/stack/type persistence | Available [I-TEAM][I-TEAM] | Available [G-I][G-I] | **Supported** | Windows SQLite projects schema 5 | `ura-project; ura-service/decomp.rs` | service decomp project reopen tests | See v0.9 verification; historical checks separate | Overrides separate from inferred facts | v0.9 |
| PRJ-05 | Multiple binaries in one project | Available [I-TEAM][I-TEAM] | Available [G-I][G-I] | **Missing** | Windows SQLite projects schema 5 | `—` | — | — | One binary identity per database | Later projects |
| PRJ-06 | Shared server projects | Available [I-TEAM][I-TEAM] | Available [G-I][G-I] | **Missing** | Windows SQLite projects schema 5 | `—` | — | — | No project server | Later collaboration |
| PRJ-07 | Concurrent collaborative edits | Family documented; exact scope not assessed | Family documented; exact scope not assessed | **Missing** | Windows SQLite projects schema 5 | `—` | — | — | No merge/ownership protocol | Later collaboration |
| PRJ-08 | Annotation JSON import/export | Available [I-TEAM][I-TEAM] | Available [G-I][G-I] | **Partial** | Windows SQLite projects schema 5 | `ura-project` | project/service export tests | See v0.9 verification; historical checks separate | Export supported; general merge/import incomplete | Later projects |
| PRJ-09 | Versioned schema migration | Available [I-TEAM][I-TEAM] | Available [G-I][G-I] | **Supported** | Windows SQLite projects schema 5 | `ura-project` | project migration tests | See v0.9 verification; historical checks separate | Migration is not collaborative version history | v0.9 |
| PRJ-10 | Project version history/merge | Available [I-TEAM][I-TEAM] | Available [G-I][G-I] | **Missing** | Windows SQLite projects schema 5 | `—` | — | — | No commit/merge model | Later collaboration |

## Professional GUI

| ID | Capability | IDA / Hex-Rays | Ghidra | URA | Architecture/platform | Implementation | Automated evidence | Manual evidence | Limits | Target |
|---|---|---|---|---|---|---|---|---|---|---|
| UI-01 | Docking and workspace restore | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | Windows native eframe/egui; OS 100% currently available | `ura-native/app.rs` | native dock/render tests; historical manual v0.8 | See v0.9 verification; historical checks separate | Current interaction and 150% checks tracked separately | v0.10 |
| UI-02 | Address/symbol/string search | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | Windows native eframe/egui; OS 100% currently available | `ura-native/navigation.rs` | native navigation tests | See v0.9 verification; historical checks separate | Not all operand/pattern search modes | v0.10 |
| UI-03 | Navigation history | Available [I-D][I-D] | Available [G-B][G-B] | **Supported** | Windows native eframe/egui; OS 100% currently available | `ura-native/navigation.rs` | native history tests | See v0.9 verification; historical checks separate | Mapped locations only | v0.9 |
| UI-04 | Cross-linked assembly/hex/graph views | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | Windows native eframe/egui; OS 100% currently available | `ura-native/views.rs` | native render/navigation tests | See v0.9 verification; historical checks separate | Current live verification recorded in verification doc | v0.10 |
| UI-05 | Pseudocode virtualized lines/highlighting | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | Windows native eframe/egui; OS 100% currently available | `ura-native/views.rs` | native all-panel rendering tests | See v0.9 verification; historical checks separate | Simple lexical colors; no editable source buffer | v0.10 |
| UI-06 | Pseudocode/assembly synchronization | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | Windows native eframe/egui; OS 100% currently available | `ura-native/views.rs` | C-AST maps; native render tests | See v0.9 verification; historical checks separate | Line-level many-to-many, not exact tokens | v0.10 |
| UI-07 | Pseudocode variable uses/navigation | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | Windows native eframe/egui; OS 100% currently available | `ura-native/views.rs` | C-AST variable IDs; native render tests | See v0.9 verification; historical checks separate | Context menu capped at 32 uses; machine-backed locals | v0.10 |
| UI-08 | Pseudocode variable/type editing | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | Windows native eframe/egui; OS 100% currently available | `ura-native/editors.rs` | service persistence; native render tests | See v0.9 verification; historical checks separate | Signature and physical stack editors; no arbitrary SSA-local rename | v0.10 |
| UI-09 | Type/structure editor | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | Windows native eframe/egui; OS 100% currently available | `ura-native/editors.rs` | native render; service type persistence | See v0.9 verification; historical checks separate | Bounded manual definitions | v0.10 |
| UI-10 | Debugger GUI panels | Available [I-D][I-D] | Available [G-B][G-B] | **Missing** | Windows native eframe/egui; OS 100% currently available | `—` | — | — | Menu states debugger unavailable | v0.12 |
| UI-11 | Keyboard shortcuts including F5 | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | Windows native eframe/egui; OS 100% currently available | `ura-native/app.rs` | native render/navigation tests | See v0.9 verification; historical checks separate | F5 opens pseudocode; no complete configurable keymap | v0.10 |
| UI-12 | Light/dark themes | Available [I-D][I-D] | Available [G-B][G-B] | **Partial** | Windows native eframe/egui; OS 100% currently available | `ura-native/design.rs` | native multiple-theme render tests | See v0.9 verification; historical checks separate | Current live interaction evidence separately tracked | v0.10 |
| UI-13 | Real OS 150% DPI verification | Not assessed | Not assessed | **Unverified** | Windows native eframe/egui; OS 100% currently available | `ura-native` | No current 150% gate | See v0.9 verification; historical checks separate | Host Settings not targetable; manual checklist required | Release gate |
| UI-14 | Large-function interaction latency | Not assessed | Not assessed | **Unverified** | Windows native eframe/egui; OS 100% currently available | `ura-native/worker.rs; ura-native/views.rs` | Bounded worker/virtualization tests | See v0.9 verification; historical checks separate | Headless performance does not prove live latency | Release gate |
## Research and maintenance

Primary documentation was checked on 2026-10-22. Competitor documentation changes independently; these links establish a comparison baseline, not a frozen specification. Processor breadth is documented by [IDA](https://docs.hex-rays.com/core/disassembler/specification/supported-processors) and [Ghidra SLEIGH](https://ghidra.re/ghidra_docs/languages/index.html). Revisit edition/platform details before promoting a row to a verified parity claim. Capability names above are a product inventory, not copied documentation prose.

Priorities: v0.10 decompiler/type/alias/idiom refinement; v0.11 transactional verified patching; v0.12 native debugging/tracing; v0.13 proof-backed deobfuscation. Later work includes processor/loaders, debug symbols, emulation, comparison, stable SDK/plugins and collaboration. See [ROADMAP.md](ROADMAP.md). These are dependency-led proposals, not promised release contents.

[I-D]: https://docs.hex-rays.com/core/disassembler "IDA disassembler"
[I-C]: https://docs.hex-rays.com/core/decompiler "Hex-Rays decompiler"
[I-DBG]: https://cpp.docs.hex-rays.com/group__dbg__funcs.html "IDA debugger SDK"
[I-P]: https://docs.hex-rays.com/9.0/release-notes/6_2 "IDA patch application"
[I-API]: https://docs.hex-rays.com/ "IDA developer resources"
[I-TEAM]: https://docs.hex-rays.com/add-ons/teams "IDA Teams"
[G-B]: https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html "Ghidra beginner guide"
[G-A]: https://ghidra.re/ghidra_docs/GhidraClass/Advanced/improvingDisassemblyAndDecompilation.pdf "Ghidra decompilation guide"
[G-DBG]: https://ghidra.re/ghidra_docs/GhidraClass/Debugger/README.html "Ghidra debugger"
[G-H]: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md "Ghidra headless"
[G-I]: https://ghidra.re/ghidra_docs/GhidraClass/Intermediate/Intermediate_Ghidra_Student_Guide.html "Ghidra intermediate guide"
