# v0.8 finalisation checkpoint — 2026-10-21

This is a verified **source checkpoint**, not acceptance of the full v0.8
finalisation checklist. It continues the user's commits through `162fabb` and
their uncommitted import work on `v0.8-decompiler-foundations`, retaining that
history. The previous audit checkpoint is `d85b7cd`; the public `v0.8.0-dev`
release still points to `1194403`. Historical audit reports remain unchanged.

Version remains `0.8.0-dev`. No new tag, release, ZIP or download checksum is
claimed. The proposed `v0.8.0-dev.1` was absent when checked; it is reserved for
an accepted release rather than attached to an incomplete milestone.

## Recovered baseline and completed work

The user's new typed-tree/postdominator commits were preserved. The incoming
working tree failed three import tests. The PE32+ test placed its import
directory and directory count at incorrect optional-header offsets, and its
MessageBox import named the wrong DLL. After fixing the fixture, the renderer
also needed to accept a recovered signature for an indirect slot call.

| Work item | Checkpoint status |
|---|---|
| Preserve typed tree, snapshot tests and postdominator work | Done |
| Self-contained types, SSA values, original operations and machine provenance | Added as HIR source metadata |
| Deterministic rendering from serialized core HIR | Round-trip regression passes |
| Finite-exit postdominators and conservative join proof | Implemented; independent graph reference passes |
| Bounded cross-function type demands | Implemented for exact native-width register copies |
| PE/ELF import slot identities and PE curated prototype binding | Implemented for the subset below |
| Shared native/core, service, CLI and MCP results | Integrated; optional typed AST added to existing query |
| Project compatibility and editor regressions | Existing tests retained and passing |
| Release build, tests, strict lint, CLI/MCP processes | Passing; details below |
| Complete high-level semantic equivalence, return/forward propagation | Still open |
| New actual desktop interaction and DPI checks | Not performed under user's desktop-control restriction |
| Accepted and published corrected prerelease | Withheld |

## HIR and control flow

`HirStatement` and `HirExpr` retain the user's enum-based tree for arithmetic,
casts, selects, memory accesses, phis, calls, returns, branches, labels and
loops. Unsupported effects and unavailable operands remain explicit. The tree
is accompanied by `HirSource`: target address width, variable names/kinds/types,
original SSA blocks/operations/terminators, constant facts and the effective
structured function signature. SSA `(variable, version)` pairs remain distinct;
folded/dead display definitions do not delete their original machine semantics.
`hir::render_ast` can render the core tree without loading the binary again.

This is still a presentation tree backed by typed SSA. It is **not yet a fully
independent high-level semantic IR** with inferred types and provenance on every
expression/control region. Some presentation nodes still use signature text or
display-oriented return variants. Variable-level recovered type inference still
aggregates some SSA versions; the new SSA catalog does not fix that inference.

Postdominators describe finite paths to exits. External SSA exits now survive
graph conversion, and unresolved terminators also feed a synthetic exit.
Graphs above 1,024 blocks/4,096 edges and a block colliding with the synthetic
sink are rejected. Reachability, traversal and iteration poll cancellation.

The structurer no longer falls back to a shortest-common-reachable-block search.
A candidate join must additionally pass a least-fixed-point proof that **every
maximal path** from both arms reaches it. A cycle avoiding the candidate or an
unknown/external exit prevents that proof. The graph is reused for these checks.
Unproved joins retain conservative transfer handling. This improves join safety;
it does not establish equivalence for every legacy loop/region transformation.

An independent test enumerates all 4,096 three-node graphs with an optional
external successor. Recursive path/cycle exploration checks all-path reachability;
a separate exit-reachability reference checks finite-path postdominators. Cases
include multiple exits, self loops, irreducible cycles and unreachable code.
These are graph-semantic tests, not an interpreter-based proof of complete HIR.

## Interprocedural parameter demands

The core pipeline hydrates supplied import hints before ABI recovery and runs
`program::enrich`. Native workers already invoke this shared core pipeline;
service/CLI/MCP queries therefore receive the same effective results.

The solver builds a bounded outgoing direct-call scope from the selected
function. It follows actual call-state operands through at most 16 exact,
same-type `Copy` definitions to an incoming architectural register. Indirect
calls can connect to an exact recovered import slot. The caller parameter must
belong to its selected convention. PE x86-64 uses a Win64 container default,
ELF x86-64 a System V default; explicit conventions take precedence. These
defaults remain assumptions, not proof that arbitrary assembly follows an ABI.

Supplied, known, native-width register parameter types seed a deterministic
sorted worklist. Demands travel from callee parameters to the exact caller
entry values passed at those sites, including transitively through wrappers.
Facts accumulate monotonically; recursive SCCs converge without inventing facts
in an unseeded cycle. Differing types remain distinct claims and produce unknown
effective types/conflicts. An absorbing overdefined state bounds each parameter
to four retained distinct types. Existing assertions retain precedence and
conflicts remain visible in the program report. A supported demand cannot erase
unknown/conflicting local ABI evidence from an unsupported/narrower demand.

Limits: 16 retained functions, 80,000 retained SSA statements, 512 parameter
nodes, 1,024 site/register edges and 8,192 updates. Each lifted function also
obeys the existing IR limits. One prospective bundle can be built before the
aggregate limit is checked. Reaching a scope/edge bound marks the result partial;
convergence only describes the retained graph. No provisional derived signature
escapes an unconverged solve. Cancellation is polled throughout. With no supplied
signature hints, the empty demand set is already at a fixed point and callee
bodies are not lifted. That result is not recovered whole-program type coverage.

Supported tests include two ABI-shaped Win64 wrappers passing a supplied pointer,
exact site/SSA provenance, conflicting assertions, call clobbers, recursive
fixed points, order independence and the function-scope bound.

**Not implemented:** forward actual-to-formal inference, return-consumer demand,
return-value propagation, stack arguments, width-changing/phi transfers,
variadic/vector/aggregate classification or x86-32 cross-function solving.
Unknown calls still conservatively clobber all tracked registers and memory.
No selective ABI preservation or new XMM lifting is claimed.

## Import recovery

- PE32/PE32+: import descriptors, exact IAT virtual addresses, DLL/name identity,
  ordinal identities, and OriginalFirstThunk fallback. Bound IAT storage is
  checked separately from lookup entries; address arithmetic is checked.
- ELF x86/x86-64: supported GLOB_DAT/JUMP_SLOT dynamic relocations reference
  actual undefined dynamic-symbol indices. Defined symbols and relocation
  numbers belonging to other architectures are rejected/ignored appropriately.
- Identities carry resolution method and optional DLL/ordinal. Conflicting
  identities for one slot fail explicitly. Limits are 4,096 bindings, 256 PE
  descriptors, 1,024 thunks per descriptor, 8,192 ELF symbols/relocations and
  256 bytes per name. Undecodable UTF-8/empty names mark the report incomplete. Partial results expose truncation; controlled APIs cancel.
- Automatic prototypes require an exact curated symbol plus a small DLL
  allowlist: MessageBoxA/W from USER32, other supported Win32 APIs from
  KERNEL32/KERNELBASE, and C functions from MSVCRT/UCRTBASE. PE64 C imports use
  Win64, PE32 C imports cdecl and PE32 Win32 imports stdcall. User hints win.
- ELF lacks recovered library/version ownership here, so a familiar ELF name
  never automatically receives a libc prototype. Ordinals retain identity and
  never receive a fabricated function name/prototype.

API contracts are external knowledge, not proof of a loaded DLL's behavior.
PE delay imports, forwarded/API-set identity, complete PLT/thunk ownership and
external call-graph nodes/site integration remain unfinished. ELF without usable
section-backed dynamic tables is not covered. Curated binding is deliberately
narrower than arbitrary name normalization. Notes and failures are explicit.

Header/ABI rules were checked against Microsoft's
[PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) and
[x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention).
ELF traversal uses the installed object crate's actual symbol/relocation API;
independent constructed bytes test a nontrivial undefined symbol index.

## Service, CLI, MCP and persistence

`highlevel <binary> --function <address> --json --ast` and
`ura_get_high_level_ir` with `ast: true` expose the typed tree plus source
semantics. Without the flag, line pagination remains unchanged. Typed AST
payloads above 2 MiB return a clear limit error; callers can use paged lines/IR.
The protocol projects nested addresses to hexadecimal strings, including values
above JavaScript's integer precision. The core Rust serialization retains its
in-memory u64 convention. Program results include scope, exact edges/SSA operands,
claims/origins, updates, convergence and truncation. MCP still has 30 tools;
its existing synchronous request/cancellation model was not changed.

Project schema remains v5. HIR/program results are transient analysis, not new
persisted edits. Existing signatures, stack overrides, types, names, comments
and migration paths retain their tests. Actual CLI output is compared with the
shared service, including the AST option. A Release MCP process handshakes,
lists all tools, queries the typed AST and round-trips a project type library.

## Dedicated adversarial review

This checkpoint received a separate code-and-regression review pass by the
implementer; no independent human/agent review or new desktop session is claimed.

| Finding | Resolution/evidence |
|---|---|
| PE fixture silently had no imports | Corrected optional-header directory fields; 13 import regressions cover both widths, ELF, ordinals and malformed/ambiguous identities |
| A slot signature existed but indirect rendering ignored it | Slot resolution shared with ABI recovery; imported-call test checks actual rendering |
| Any DLL could receive a familiar symbol's prototype | Exact DLL/symbol checks; wrong-DLL negative cases |
| PE CRT imports defaulted to System V | Explicit target-dependent PE convention; CRT regression |
| ELF enumerator position was used as symbol index | Actual symbol index and undefined-symbol filtering; independent ELF byte fixture |
| Infinite/outside paths could disappear from join selection | External exits retained; heuristic fallback removed; exhaustive independent graph tests |
| A propagated supported demand erased a local conflict | Unknown local evidence preserved; original conflict regression retained |
| Empty evidence still lifted a callee scope | Empty fixed-point shortcut; measured again after repair |
| Protocol consumers could lose address bits | Nested hex projection; above-2^53 regression |

## Verification, measurements and release decision

Automated gates: **213 passing tests**, formatting check, strict Clippy across
workspace/all targets, workspace Windows Release build and Release examples.
No tests were removed, and the user's 16 rendered snapshots were retained.
The baseline's three import failures are repaired. The native worker/editor/
navigation/tessellation and project migration/reopen tests pass.

The sanitized measured results are in
[benchmarks/0.8-finalisation.json](benchmarks/0.8-finalisation.json). They include
separate HIR/import/program timings, full pipeline timings, AST sizes, observed
peak process working set, fresh CLI processes versus the retained `d85b7cd`
local audit executable, and a seeded two-wrapper demand benchmark. Input images
are read, never executed. Empty demand results are distinguished from seeded
propagation. Timing and memory samples are observations, not universal bounds.

The seeded demand benchmark (100 repetitions) traversed three functions/eight
register edges and converged after two fact updates: **0.178 ms** per solver
run and **0.378 ms** for the complete pipeline. Ordinary sample measurements
used three repetitions per function: 2 functions in the small PE, 7 each in
O0 PE/O2 PE/O2 ELF and the 16 largest liftable NTDLL functions, with no failures.

For the 1,768-instruction NTDLL function, HIR construction averaged **30.433 ms**,
the empty-demand solver shortcut **0.0019 ms**, and the full pipeline
**61.831 ms**. It rendered 12,567 lines/3,243 unresolved items; its core AST was
5,828,592 bytes, above the optional protocol payload limit. A real CLI query
returns paged lines successfully and explicitly rejects the oversized AST.
The old audit's HIR measurement was 10.761 ms/8,198 lines: the stricter join
proof and self-contained tree add work and retain more unresolved structure.
This is a known HIR cost increase, not a performance improvement claim.
Observed NTDLL peak working set was **118.238 MiB**. The older harness measured
different work without the full pipeline/AST serialization, so peak-memory
values are not a controlled before/after comparison.

| Fresh CLI process, small PE, five runs | d85b7cd local audit median | Current median |
|---|---:|---:|
| Analyze | 23.370 ms | 21.987 ms |
| Signature | 22.705 ms | 22.506 ms |
| High-level lines | 22.441 ms | 21.984 ms |

All samples/outliers and executable/input hashes are retained in the JSON.
The paired small-process results do not establish a significant speedup.
The Release MCP process reported 30 tools, typed-AST success, program convergence
and type-library round-trip success. Its first signature query was 0.607 ms;
cached line query was 0.155 ms (single observations, not percentiles).

No native app, window control, display setting, idle-CPU experiment or DPI
interaction was launched during this continuation, respecting the user's request
to avoid the PC skill. Therefore no new actual desktop interaction/save/reopen
or layout success is asserted. Automated project/worker tests and the Release
build do not substitute for that release gate.

The complete finalisation criteria are not met: fully semantic HIR/SSA-specific
recovered types, broad region equivalence tests, forward/return propagation and
external call-graph integration remain open. Those are **v0.8 completion work**,
not relabeled as v0.9. After those and permitted native/DPI checks pass, build and
clean-extract all three binaries under a new unique tag, publish, then verify
the downloaded ZIP's checksum. The old public artifact must remain unchanged.
