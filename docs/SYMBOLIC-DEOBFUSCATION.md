# Symbolic analysis and deobfuscation — v0.15 scope

URA evaluates verified scalar IR using fixed-width symbolic expressions and real
Z3 queries. Results are analysis overlays. Executable bytes, original instructions,
the original CFG and the unrefined C-like reconstruction remain available.

## Engine and solver

`ura-core/src/symbolic` contains the expression DAG, typed Z3 translation,
bounded SSA executor, proof evidence, finite value sets and alias queries.
Scalar widths are 1–64 bits; byte-array memory has 32- or 64-bit addresses.
Supported expressions include arithmetic, multiplication/high products, guarded
wide division, bitwise operations, logical/arithmetic shifts, rotates, signed and
unsigned comparisons, selection, concatenation, extraction/insertion, extensions,
parity, and little-endian scalar loads/stores. Undefined values carry poison;
unknown instructions and external effects remain conservative boundaries.

The locked backend is `z3` 0.21.1 / `z3-sys` 0.13.1 / `z3-src` 501.0.1. The
actual library identifies itself as **Z3 5.1.0.0**. Cargo builds it statically from
the checked source crate. Windows also uses the static C/C++ runtime. No solver
DLL, solver installation, runtime download or arbitrary solver executable is used.
The MIT notices are included in the normal dependency-license collection.

Product queries run in an owned instance of the current URA executable, using
the fixed early `--ura-smt-worker` entry point. It reads a bounded typed query
and exits; the Desktop executable enters this path before GUI initialization.
A Windows Job Object imposes a process-memory limit and kill-on-close cleanup.
The parent enforces wall deadlines, output bounds and cancellation, then kills
and reaps the worker. The public `DirectZ3` library/test backend requires its host
to provide process isolation; a native solver call is not made cancellable merely
by dropping a future. Native UI work runs on the existing background worker.

SAT, UNSAT, UNKNOWN, TIMEOUT, UNSUPPORTED and ERROR are distinct. Cancellation
and resource limits are also explicit statuses. Only the required UNSAT proof,
paired with a feasible retained outcome and a separate validation query, enables
a branch rewrite. A failure, killed worker or unknown result never becomes UNSAT.

## Proof scope and reconstruction

Universal local predicate queries resolve supported SSA definitions backwards.
Each join/loop phi becomes an independent arbitrary value. This overapproximates
the possible states and deliberately loses correlations. These proofs ignore
configured concrete inputs and memory assumptions. Functions containing unknown
external-effect boundaries are excluded from local branch rewriting.

Bounded execution instead follows predecessor-specific phis, maintains path
constraints and explores feasible successors. Configured concrete registers,
memory bytes and memory regions apply to this entry model. Paths terminate at
returns, modeled faults, external/indirect boundaries, unknown effects or limits.
Missing coverage is reported. Path-local impossibility is never promoted into
an unrestricted global CFG rewrite.

A validated rewrite redirects one IR branch to the retained destination. It
retains all preceding statements, memory effects and fault guards. SSA and
dataflow are rebuilt and the existing decompiler constructs the derived HIR,
C-like AST and pseudocode. The original reconstruction is preserved separately.
This is local branch-selection equivalence; URA does **not** claim a general
whole-program equivalence theorem.

Dispatcher analysis identifies loop-carried register state compared against
multiple constants. Structure alone is a candidate, not proof of obfuscation.
Repeated visits recover logical state transitions with solver evidence under
captured function-entry prefixes. These transitions remain explicitly partial;
the pass does not erase dispatcher side effects or rewrite arbitrary flattened
functions into a complete high-level switch.

Indirect branch and call targets use finite SSA value-set suggestions and actual
solver queries. Each suggested target must be feasible. A final blocking UNSAT
query is required before a set is exhaustive under that prefix. Discovered values
are not automatically executable edges. The decompiler orchestrator exposes a
separate CFG/call-graph overlay only for mapped executable instruction boundaries,
with the original indirect-transfer identity and proof scope preserved. Calls
remain analysis boundaries; their effects are not emulated by the symbolic engine.

Finite value sets are overapproximations with top/bottom, bounded joins, known
bits and unsigned bounds. Nonconvergence or cancellation widens facts to top.
Value-set suggestions are never silently asserted to be exact reachable sets.
Dependency names are expression dependencies, not a complete taint framework.

## Memory and limits

One persistent byte array retains store/load dependencies, including potentially
aliasing stores. Scalar accesses are little endian. Pointer-width wraparound and
configured region permissions are checked on executed paths. Unspecified bytes
are arbitrary. There is no operating-system memory, concurrent-thread, MMIO,
API, exception-delivery or allocator model. The optional alias service distinguishes
same ranges, disjoint ranges, potential alias and unknown with real queries;
possible wraparound cannot establish disjointness.

Defaults: 128 explored states, 64 paths, depth 64, 20,000 IR operations, 128
queries, 15 seconds for the pipeline, 20,000 expression nodes, expression depth
128, 500 ms / 2,000,000 Z3 resource units / 256 MiB per solver worker, and a
64 MiB retained-state accounting budget. Calls are not traversed: call depth is
zero. Hard caps include 512 states, 256 paths/depth/queries, 200,000 operations,
120 seconds, 40,000 nodes, expression depth 128, solver timeout 10 seconds,
solver memory 1 GiB, and retained-state accounting 256 MiB. Functions are limited
to 512 blocks, 4,096 variables and 128 architectural register/flag inputs.

Retained-state accounting conservatively budgets queued/current maps and path
vectors; it is not a promise that the entire application RSS equals that number.
Existing binary storage, decompiler data, bounded result storage and the isolated
solver are separate allocations. Product results are capped at 24 MiB, API pages
at 1 MiB, requests at 64 KiB, and sessions at four retained / two running.

## Interfaces and persistence

The native **Deobfuscation** tab exposes analysis/cancel controls, bounded options,
concrete register inputs, predicates, paths, proofs/models, dispatcher transitions,
targets, derived edges, value sets, and original/derived pseudocode. Source rows
are virtualized. Configuration and bounded historical findings can accompany the
existing SQLite workspace. Historical findings require reanalysis before use.

CLI: `ura-cli symbolic <binary> [normal analysis/raw options]` opens one static
handle and prints a JSON ready record. Subsequent newline-delimited requests use
the same shared service as MCP. Example:

```json
{"action":"start","function":"0x140001000","options":{"maxPaths":32,"solver":{"timeoutMs":500}}}
{"action":"status","session":"sym-1"}
{"action":"page","session":"sym-1","category":"predicates","limit":16}
{"action":"proof","session":"sym-1","index":0}
{"action":"page","session":"sym-1","category":"simplified","offset":0,"limit":32}
{"action":"cancel","session":"sym-1"}
{"action":"close","session":"sym-1"}
```

MCP adds one implemented generic tool, **`ura_symbolic`**, bringing the tool count
to **68**. Actions: `start`, `status`, `cancel`, `summary`, `page`, `proof`, `model`,
`export`, `save`, `load`, `close`. Page categories also include `queries`, `paths`,
`dispatchers`, `targets`, `indirectEdges`, `variables`, `edges`, `expressions`,
`valueSets`, `original`, `simplified`, `cfg`. Offset/limit pages return at most 64
records. Proof replay checks the exact query digest and expression prefix.

Static symbolic analysis grants no sample execution, debugger attachment, live
memory access, binary write or network capability. Exports/save require the
existing write grant and allowed paths; exports use create-new semantics.

Fresh report identities include effective bytes, processor, IR/analysis versions,
solver/options and decompiler context. Service jobs additionally check immutable
byte ownership, analysis generation, project identity and manual seeds. Changes
invalidate authority; cancelled or stale results cannot replace newer UI state.
Saved metadata is bounded, historical and never loaded as an enabled proof.
An atomic SQLite view-state merge preserves unrelated keys without a new schema.

## Coverage and remaining work

x86/x64 scalar IR is the primary qualification target. Generic verified ARM64,
RV32/RV64 and uniform ARM/Thumb IR can use the same expression semantics, subject
to the existing processor-lifting limits. The v0.15 symbolic oracle exercises
scalar arithmetic, signed selection and width behavior in 18 O0 PE/ELF functions
across these five non-x86 processor modes, with 72 input cases. The full retained
processor oracle separately checks O0–O3 and explicit unsupported boundaries.
This does not add floating/vector/system
semantics, mixed ARM modes, OS models, interprocedural execution, precise general
heap alias sets, comprehensive taint, invariant synthesis, arbitrary protector
recovery or general equivalence checking. Pure conditional selections/CMOV are
modeled but are not independently rewritten by the branch-only refinement pass.

No live native input, real display scaling, GPU or visual acceptance is claimed
when desktop control is prohibited. Headless painting and owned worker-process
tests are separate evidence. See [verification](VERIFICATION-0.15.md),
[review scope](REVIEW-0.15.md), and [the parity ledger](FEATURE-PARITY.md).

Primary solver/build references: [Rust Z3 API](https://docs.rs/z3/0.21.1/z3/),
[native binding](https://docs.rs/z3-sys/0.13.1/z3_sys/),
[Rust runtime linkage](https://doc.rust-lang.org/reference/linkage.html#static-and-dynamic-c-runtimes).
