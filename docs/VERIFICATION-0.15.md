# v0.15 symbolic analysis and deobfuscation verification

Date: 2026-10-24. Version **0.15.0-dev**, branch `v0.15-symbolic-deobfuscation`.
The containing commit identifies this report's source. Baseline: accepted public
`v0.14.0-dev.2`, commit `18388805070c4d9f093dfcfec722cb8409e19f78`, initially
clean with 369 passing tests. Historical releases/tags and main are preserved.

This qualifies a **bounded scalar development prerelease** within
[the implemented scope](SYMBOLIC-DEOBFUSCATION.md). Public acceptance additionally
requires the exact clean tagged build receipt, fresh three-EXE assets, package
audit and successful public re-download receipts. A source push or this report
alone does not establish publication. No live native input/DPI/GPU acceptance
is claimed. The final engineering report and workflow receipts identify the
full source commit, binary/ZIP hashes and actual download results.

## Engine, proofs and limits

Decoder → typed raw IR → SSA/dataflow → symbolic DAG/paths → real Z3 → validated
branch overlay → rebuilt SSA/dataflow → existing HIR/C-like AST/pseudocode.
The original bytes, instructions, CFG and source remain available. No second
decompiler, inspected sample execution or automatic binary patching is introduced.

Typed expressions cover 1–64-bit arithmetic, high products, guarded wide
division, bitwise/shift/rotate operations, signed/unsigned comparisons, select,
concat, extract/insert, extensions, parity and little-endian scalar memory.
Poison represents undefined dependencies. Persistent byte arrays have 32/64-bit
addresses and preserve possibly aliasing stores; configured permissions/wrap
checks constrain paths. No complete OS/heap/concurrency model is claimed.

Locked `z3`0.21.1 / `z3-sys`0.13.1 / `z3-src`501.0.1 builds **Z3 5.1.0.0**
statically, including the Windows C/C++ runtime. No developer solver installation,
runtime download or arbitrary solver executable is used. Product queries use
the fixed early windowless worker in the current EXE, Windows Job memory/
kill-on-close limits and parent kill/reap deadlines. Native enters that worker
before GUI initialization. DirectZ3 is a library/test backend whose host must
provide isolation; dropping a future does not cancel native Z3.

SAT/UNSAT/UNKNOWN/TIMEOUT/UNSUPPORTED/ERROR/CANCELLED/LIMIT stay distinct.
Local predicate proofs ignore user concrete assumptions and overapproximate
SSA phis with independent arbitrary roots. Unknown external effects disqualify
local pruning. A feasible retained side, UNSAT opposite side and a separate
validation query are mandatory. All preceding effects/fault guards are retained.
Path-local facts never globally prune the CFG. This is local branch-selection
equivalence within encoded semantics, not whole-executable equivalence.

Dispatcher comparisons identify candidates; proved prefix transitions form a
partial logical overlay. Indirect branch/call sets need feasible candidates
and blocking UNSAT for prefix completeness. Only mapped executable instruction
boundaries enter the logical edge overlay. Calls stop execution; call depth is
explicitly zero. Arbitrary dispatcher deletion, complete switch recovery,
invariant synthesis, interprocedural execution and general taint remain absent.
CMOV/select is modeled but not rewritten by the branch-only refinement pass.

Defaults: 128 states, 64 paths, depth64, 20,000 operations, 128 queries, 15 s
pipeline deadline, 20,000 DAG nodes/depth128, solver500 ms/2M resource units/
256 MiB and retained-state accounting64 MiB. Hard caps: states512, paths/depth/
queries256, operations200,000, total120 s, nodes40,000/depth128, solver10 s/
50M units/1 GiB and state accounting256 MiB; functions512 blocks/4,096 variables/
128 architectural inputs. Requests64 KiB, pages64 records/1 MiB, results24 MiB,
four retained/two running sessions. State accounting is separate from total
application RSS, binary/decompiler storage and the isolated solver.

## Quality gates and preserved regressions

- Formatting: passed `cargo fmt --all -- --check`.
- Strict lint: passed `cargo clippy --workspace --all-targets --locked -- -D warnings`.
- Tests: **393 passed, zero failed/ignored** in final local qualification.
- Release: passed `cargo build --workspace --release --locked`, plus both adapters.

The 24 added tests comprise 20 symbolic tests, NOT/NEG width/flag truth tables,
native worker/core/stale-completion regression, atomic metadata merge and
oversized edited Unicode project rejection. Native tests include headless
painting of all 30 panels and project reopen. The numerical-model symbolic test
checks 40 input/width cases against independent Rust integer formulas. Other
tests cover real SAT/UNSAT, resource-limit UNKNOWN and actual 1 ms TIMEOUT,
poison, malformed DAG/arity/deserialization, four alias classes, stores/loads,
wraparound, joins, dispatcher state transitions, indirect branch/call sets,
faults, path/query truncation and cancellation. Failed queries never enable proof.
The operation cap is checked inside recursive predicate construction as well as
forward execution; a one-operation regression requires zero queries/rewrites.

The single changed legacy HIR snapshot contains `NOT rax`; its historical
unknown-effect barrier is deliberately replaced by verified complement semantics.
The test remains locked to the new structure. No test was removed. The Z3
dependency raises workspace MSRV to1.85; associated `is_none_or` lint updates in
existing code are mechanical. Native already uses a newer Rust/edition floor.

## Independent semantic corpus and decompiler quality

[Baseline report](benchmarks/0.15-symbolic-baseline-release.json) records hashes,
compiler, host and per-function outcomes. Owned Clang22.1.8 PE/ELF C/assembly
fixtures use O0–O3; source/eight image hashes are checked. Inspected images run
only in pinned Unicorn2.1.4. Original/derived IR states and C-like AST returns/
memory are compared with Unicorn and independent C formulas. Undefined flags
and unimplemented Unicorn x86-32 segment-base registers are excluded.

| Check | Result |
|---|---:|
| x64 compiler functions | 80 |
| Raw x86 function | 1 |
| Additional non-x86 symbolic functions | 18 |
| Total independent input execution cases | 873 |
| Original/derived C-like AST comparisons | 1,746 |
| Original/derived IR comparisons | 1,746 |
| Defined register/flag comparisons | 41,862 |
| Proved/pruned opaque edges across x64 fixtures | 4 |
| Recovered prefix dispatcher transitions across fixtures | 16 |
| False-positive pruning in designated adversarial families | 0 |

The additional 72 symbolic inputs cover arithmetic, signed selection and widths
in ARM64 PE/ELF, RV64/RV32 ELF and uniform ARM/Thumb ELF O0. This is shared
symbolic integration evidence, not full processor deobfuscation coverage. The
separate retained [processor oracle](benchmarks/0.15-processor-oracle.json)
still passes **767 machine comparisons, 671 C-like AST executions, 290 static
analyses**, 36 explicit unsupported ARM/Thumb boundaries and zero failures.

The genuine public v0.14 CLI, version0.14.0-dev.2, has SHA256
`da50db4d452008878f4ac6c9e86a41884995c0d6e68b6438e4c39676872b34d7`.
On the same 80 x64 functions it emits **2,108 lines / 96 unresolved operations**.
v0.15 original output has **1,986 / 0**, derived **1,958 / 0**. The first
122-line gain includes NOT/NEG semantics; the additional **28-line** gain is
proof-gated branch pruning. Compiler optimization already removes many opaque
identities. Designated nonopaque/wrap/signed adversarial cases retain live
branches. These are bounded tests, not universal accuracy/equivalence claims.

[Opaque original](examples/0.15/ura_opaque_even.original.c) versus
[derived](examples/0.15/ura_opaque_even.simplified.c) is **34→26 lines**.
[Flattened original](examples/0.15/ura_flattened.original.c) versus
[derived](examples/0.15/ura_flattened.simplified.c) remains **47→47**: prefix
transition evidence does not yet remove general dispatcher noise from C-like
text. Machine temporaries/casts, explicit memory helpers, incomplete loops/
switches, aggregate types and call effects remain major gaps. No new IDA/Ghidra
comparative benchmark was run; no proprietary code was copied.

## Release measurements and bounded failure

Host: Ryzen5 7500F, six cores/12 logical CPUs, 16,636,239,872 bytes RAM,
Windows build26200. Release adapter, direct Z3, psutil7.2.2 RSS sampling. Other
build activity was present: these are recorded engineering measurements, not
controlled comparative CPU benchmarks. Direct timing excludes product worker
startup/isolation, measured separately.

Baseline-corpus median/p95 solver latency: **19.293/47.088 ms**; sampled peak
adapter-plus-children RSS **72,609,792 bytes**. Across 80 x64 functions: 1,250
queries, 126 paths, 10,213 counted IR operations, 30,041 ms pipeline time and
29,745 ms symbolic time (about343 counted IR operations/s including solver
overhead). Per-function completeness, outcomes, counts and state accounting
are recorded. v0.14 whole-CLI wall time is a separate measurement, not directly
comparable to this expanded pipeline. Separate DAG throughput and CFG/source
stage profiles are not claimed.

A real independent-bit branch family stops at four states/two paths in1,575 ms,
reports incomplete coverage and peaks at16,184 accounted state bytes. An owned
over-capacity CFG is explicitly rejected in36 ms. Loops, flattened fixtures,
actual timeout/unknown queries and result caps test additional failure paths.
Arbitrary large CFG performance and complete application heap bounds remain open.

## Interfaces, persistence and review

Native background controls expose bounds, input registers, analysis categories,
cancel, proof/model/path/transition/target/value-set pages and virtualized
original/derived source. Unique request IDs reject same-function restart races;
project/analysis revisions and cancellation reject stale replies. CLI `symbolic`
and the new generic MCP `ura_symbolic` use the shared service: **68 tools total**.

[Headless Release evidence](benchmarks/0.15-symbolic-headless-release.json)
checks all three fixed workers, actual SAT/malformed/poison outcomes, empty-CWD
operation, PE imports, CLI/MCP pages/proofs/models, generation/context rejection,
cancel and close. Active-job cancellation/reaping measured10.673 ms; historical
save/load1,127.704/4.871 ms in that run, including filesystem/scanner/scheduler
effects. Static analysis grants no sample launch, debugger attach, live memory
or network access. Export/save require write/allowed paths; exports never clobber.

Effective byte/processor/IR/solver/options/context identities and generations
invalidate stale authority. Saved findings are bounded and non-authoritative.
Atomic SQLite merge preserves unrelated layout keys; oversized edited text is
rejected by SQL byte length before copying/parsing into Rust. Schema8 and older
schema regression compatibility remain intact. No live GUI was launched.

Three independent static review passes covered expressions/solver/value sets,
engine proof/refinement/resources, and interfaces/permissions/releases. All
eight concrete findings were repaired, reread within scope and regression-tested.
Reviewers ran no tests; implementing-agent checks are not independent review.
See [review details](REVIEW-0.15.md).

## Packaging, acceptance and parity

An uncommitted local audit is not a publishable receipt. Final qualification
is repeated by the guarded tag workflow on exact clean source, with unique
root compiler metadata rebuilding Desktop/CLI/MCP. Static solver/runtime,
assets, complete license texts, source lock, verification docs and internal
hashes enter the ZIP. PE imports reject external Z3/MSVCP/VCRUNTIME dependence;
extracted copies repeat actual worker and CLI/MCP tests and match individual EXEs.
The local precommit package audit passed all 642 listed members and collected
284 dependency packages with zero missing license texts. A subsequent strict
operation-budget guard is regression-tested separately; the tag workflow rebuilds
and audits the final source again. No precommit EXE is a final release input.

Required assets: `ura-native.exe`, `ura-cli.exe`, `ura-mcp.exe`,
`URA-0.15.0-dev-windows-x64.zip`, `SHA256SUMS.txt`. Publication verifies a new
draft, then actual public downloads. Failed candidates require a new unique
version/tag; historical assets are immutable. Final full commit/hash/download
results belong to the workflow receipts and final engineering report.

[Ledger](FEATURE-PARITY.md): **228 capabilities — 23 Supported, 148 Partial,
49 Missing, 8 Unverified**, within explicit scopes, not an overall parity
percentage. [Roadmap](ROADMAP.md) retains v0.16 scripting/plugins, v0.17 debug
symbols/C++, v0.18 diffing, v0.19 remote/kernel work and v0.20+ remaining gaps.
Full IDA/Hex-Rays/Ghidra feature parity remains unfinished.
