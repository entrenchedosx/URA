# v0.8 semantic engine continuation — 2026-10-21

This continues `b54e4cb4a49802831cbc0c59ad11c6eda2cbe9da` on
`v0.8-decompiler-foundations`. The incoming tree was clean. Its 213 tests,
formatting, strict workspace Clippy and Windows Release build passed before
implementation. Earlier audits and measurements are preserved unchanged.

This remains an **unaccepted source checkpoint**, version `0.8.0-dev`.
Desktop control was initially prohibited, then explicitly authorized by the user.
The final Release desktop was exercised live as described below. OS display
scaling could not be tested: Windows Settings did not expose a targetable window.
The public `v0.8.0-dev` release is unchanged, and `v0.8.0-dev.1` is not created.
A local packaging check does not constitute a published or accepted release.

## Semantic representation

`decomp::semantic` is independent of C-like formatting. It has stable indexed
SSA values, operation nodes, shared provenance records and explicit block
transfers. Each value carries its exact SSA `(variable, version)`, machine
storage type, inferred type, definition reference, type evidence and conflicts.
Operations refer to value IDs/typed constants; they do not duplicate entire
source blocks or embed C expressions. Source records retain original IR opcode,
block/ordinal and exact instruction address. Phi nodes are explicitly synthetic
with no invented instruction address.

Supported nodes include fixed-width arithmetic/bit operations, comparisons,
extensions/truncations, extraction/insertion, selection, phis, memory effects,
calls, unknown effects and branches/exits. Signed extension, unsigned comparison
and storage widths remain explicit. The effective signature records integer/
pointer ABI locations and uncertainty. A return retains both the machine RET
destination and, when available, the ABI result operand. These are distinct.

Control is deliberately kept as explicit transfers. Irreducible or unproved
regions do not become guessed executable loops/ifs. The older C-like
presentation AST remains for compatibility, with its original 16 snapshots;
it is a diagnostic view, not verified compilable source. The new executable
model is authoritative for the differential semantic checks. No equivalence
claim is made for arbitrary execution of the legacy formatted tree.

The type report now has a `values` collection keyed by exact SSA definitions.
An address use of one RAX version does not type an unrelated later definition.
Unknown machine definitions remain unknown unless justified symbolic call-type
evidence is attached; that never establishes their concrete values. Legacy
`variables` summaries remain for existing clients. The native Types panel adds
virtualized SSA definition rows and per-definition evidence/conflict tooltips.

## Independent execution checks

The original raw-IR interpreter and new `decomp::execute` use separate arithmetic,
memory, phi and control implementations. The semantic evaluator does not call
the original interpreter or constant folder. Tests compare return destinations,
architectural register state (including ABI return registers), memory and block
traces from equal initial states. Supported fixtures must execute concretely;
an unexpected unknown result cannot pass as a successful equivalence case.

Coverage includes bounded exhaustive arithmetic inputs, partial register writes,
byte sign extension, unsigned comparisons, diamonds, shared successors, multiple
returns, loop phis, nested loops, early exits, a two-entry irreducible cycle,
indirect/external exits, an explicitly unknown call and bounded infinite loops.
Opaque memory mutations stop execution rather than reusing stale concrete bytes.
Each interpreter has an overall 100,000-operation cap; the semantic evaluator
also rejects a block budget outside 1..100,000. Inspected binaries are never run.

Clang 22.1.8 builds four freestanding PE/ELF fixtures at O0 and O2 from
`tests/samples/semantic.c`. Across 96 compiled cases, both models are compared
with each other and with independent known C results for addition, memory updates
and a volatile loop. The build script and small fixtures are retained, and their
hashes/compiler version are recorded with the measurements.

These are bounded tests of the documented scalar subset. They are not a proof
for arbitrary binaries. Concrete call summaries, floating-point/vector execution,
exceptions and arbitrary operating-system memory are outside this evaluator.

## Combined argument and return constraints

The prior exact-copy backward demand pass is retained. A new combined SSA graph
links actual values, observed formal parameters and normal returns. Formal use
is established from local register-root evidence or supplied prototypes, then
closed transitively over exact forwarding relationships. Merely having a
register in call state does not establish a formal parameter.

The sorted worklist carries monotone type claims and explicit unknown/overdefined
states through copies, supported casts, integer extensions/truncations, forward
actual-to-formal relationships, phis and returns. Address demands can follow
constant-offset address calculations, but arbitrary arithmetic does not preserve
pointer identity. Storage-width observations are separated from supplied/use
claims, so a machine word alone does not defeat stronger pointer evidence.
Compatible unknown pointees are canonicalized; incompatible supplied types stay
conflicting. Unknown phi/return alternatives receive a conservative audit after
the evidence fixed point and propagate uncertainty in a second bounded solve.

Return propagation correlates the exact RAX definition emitted as a call effect
with that call's callee. It does not select an arbitrary later write to RAX.
Callee return evidence reaches callers; caller dereferences or typed call uses
constrain returned values. Untouched return locations, one unestablished path,
unknown calls and void-call results remain unknown. Ignoring a result does not
infer void. User overrides retain effective-signature precedence; contradictory
claims remain in the report. No provisional derived types escape an unconverged
solve. The actual IR still clobbers all tracked call state conservatively.

Scalar user overrides now receive the appropriate supported ABI return register;
constructing a signature from an override had previously left its return location
empty. Demands on a narrow formal parameter do not type the entire wider caller
register. Unused upper return bits are not assumed known. The relevant Windows
rules are documented in Microsoft's
[x64 ABI](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention).

Scope/budgets:

- 16 lifted functions and 80,000 retained source SSA statements, plus existing
  per-function IR bounds. One prospective bundle may be built before checking
  the aggregate scope budget.
- 24,000 combined fact nodes, 80,000 transfer links and 160,000 updates per solve.
  Four retained type claims widen to overdefined; unknown is monotone.
- Propagated type descriptions are limited to 16 nodes and bounded names/reasons.
  Unsupported rich types are left unpropagated and mark the scope partial.
- SSA type records are capped at 20,000 values with bounded evidence per value.
- Cancellation is polled during scope recovery, type inference, graph solving,
  semantic lowering and import recovery. Convergence applies only to the retained
  scope, not the whole binary.

The combined ABI subset is PE/ELF x86-64 integer/pointer registers with explicit
or container-default conventions. Container defaults remain assumptions. Stack
argument propagation, x86-32 cross-function solving, XMM/vector/aggregate ABI
classification, arbitrary alias inference and complete source-type recovery
remain unsupported. Existing x86-32 local ABI/stack recovery is preserved.

## External call graph

The shared graph now contains explicit external nodes for proved import calls,
with slot, DLL/name/ordinal identity, binding mechanism, optional curated prototype
and runtime uncertainty. It supports native-width flat-memory PE IAT/ELF GOT
calls and jumps, exact import thunks, and the existing in-block SSA proof for
register calls loaded from an import slot. Register-call proof recovery has an
additional 16-function/80,000-operation budget. Segment-relative or unproved
operands remain unresolved.

Every edge retains the actual calling/jumping instruction. A caller's direct
edge to a thunk is retained, followed by the thunk's distinct external edge;
the same call site is not flattened and counted again. Resolved sites are
removed from the unresolved count. Internal SCCs remain internal and external
leaves update caller/callee/root/leaf statistics. Native workers and service/
CLI/MCP queries use this same import-aware builder.

Curated prototypes still require the existing exact PE DLL/symbol/ABI checks.
Verified import thunks can forward those hints into argument/return constraints.
ELF symbol-slot identities do not acquire guessed libc ownership or prototypes.
Runtime interposition, delay imports, forwarded/API-set ownership, general
register-jump thunks and ELF dynamic tables without the supported sections remain
outside the documented subset.

## Protocols, persistence and bounds

The MCP server retains 30 tools and schema version 1. Existing line queries and
the legacy `ast` flag remain available. New optional queries are:

```text
ura-cli highlevel sample.exe --function 140001020 --json --semantic
ura-cli highlevel sample.exe --function 140001020 --json --semantic-block 140001020
ura_get_high_level_ir: {handle, function, semantic: true}
ura_get_high_level_ir: {handle, function, semanticBlock: "0x140001020"}
```

Semantic pages retain global IDs, total counts, type-coverage status, effective
signature and source provenance. A block selection has `complete: false` and
lists referenced definitions outside the selection. It is never presented as
a complete executable function. All new addresses use the existing hexadecimal
address serializer, preserving all 64 bits.

Optional HIR payloads remain limited to 2 MiB. A streaming byte counter rejects
an oversized legacy AST before allocating its entire JSON value. Program views
retain bounded fact/call subsets and explicitly report omitted details; a 1 MiB
transport budget can omit detailed facts while keeping scope and convergence
metadata. Exact selected-block SSA type evidence is separately retrievable.

Project schema remains v5. All semantic/program results are transient. Existing
signature/type/stack edits, annotations, manual starts and project migrations
retain their data. Tests cover semantic cache invalidation after an override and
project reopening with a fresh analysis request. MCP's existing synchronous
transport cancellation model is unchanged.

## Dedicated review

This was an implementation plus a separate adversarial self-review pass. No
independent human/agent review is claimed. Substantial
findings fixed and covered include:

- Missing return locations on override-only scalar signatures.
- Narrow-formal demands incorrectly flowing into an entire wider register.
- A void/unknown call result becoming apparently known from a later dereference.
- Compatible unknown pointees unnecessarily exhausting distinct-claim capacity.
- Opaque memory effects reusing stale bytes in the execution oracle.
- Register-indirect IAT calls resolving in HIR but missing from the external graph.
- Unbounded optional AST JSON allocation before the transport size check.
- Ambiguous type summaries being applied across SSA versions.
- Native editor grids shrinking input fields to approximately 24 pixels under
  egui 0.36. Explicit column counts and minimum input sizes restore readable
  stack, parameter and structure fields; rebuilt stack/structure editors were
  checked live.

## Verification and release decision

Final gate results and measured costs are recorded with the completed run in
`docs/benchmarks/0.8-completion.json`. The earlier finalisation measurements remain
in their original file. The controlled HIR comparison uses the retained
`b54e4cb` benchmark executable, the same NTDLL input and function, and the same
diagnostic-output workload. Full-pipeline timings include additional semantic
and interprocedural work and are not treated as an unchanged-workload comparison.

Formatting, strict all-target workspace Clippy, all **237 tests**, the workspace
Release build and Release benchmark examples pass. Actual Release CLI/MCP
queries pass, with 30 tools and schema v1. Full semantic pages, block pages,
legacy ASTs and type-library round trips were exercised through stdio.

For NTDLL `0x1800AA290` (1,768 instructions, 440 blocks), the controlled legacy
HIR build averages **10.899 ms**, versus **26.758 ms** from the retained `b54e4cb`
harness on the same binary/function (59.3% lower). It still emits 12,567 lines.
This optimization caches the existing strong join proof; all 4,096 small graph
combinations agree with its independently tested uncached implementation.

The expanded pipeline averages **170.831 ms**, versus 60.800 ms for the older,
smaller pipeline. The combined program solver accounts for 111.601 ms and
analyzes 16 functions/18,517 facts, versus the previous empty-seed shortcut's
one-function scope. Semantic lowering takes 9.062 ms, re-rendering 6.345 ms,
semantic JSON serialization 15.571 ms and SSA type inference 5.418 ms. These
added costs are real; the pipeline is not advertised as faster. Across the
16 largest NTDLL functions, observed process peak working set is **169.914 MiB**.
This peak includes the expanded benchmark workload and is not a controlled
memory comparison with the historical 118.238 MiB run.

The core semantic JSON is 8,525,674 bytes and legacy AST is 5,832,536 bytes.
Actual CLI full-AST and full-semantic requests fail clearly with `limit_exceeded`
at 2 MiB. The entry-block semantic response succeeds at 696,071 bytes, retains
global totals (15,322 nodes, 15,227 values, 440 blocks) and says `complete: false`.
Default paged line output remains usable (76,441 bytes in this query).

Live desktop checks used the owned `ura64.exe` fixture and a disposable project:

- Opened a binary, selected both functions, viewed assembly and the three-block
  loop CFG; compact docking and text were inspected at the current desktop scale.
- Opened the high-level analysis inspector; selecting the line at `0x140001029`
  selected the matching CMP instruction in disassembly.
- Changed the loop signature return to `u32`, renamed stack slot -8 to
  `gui_saved_frame`, changed its type to `u64`, and created `NewStruct` with
  `field0: u32` at offset 0.
- Saved the workspace, exited, rebuilt the editor-layout repair and reopened the
  project in a byte-identical verification copy. All three edits persisted,
  the selected instruction was restored, and the repaired editors were readable.
- A 15-second target-process sample with the fixture/structure editor visible
  measured **1.146% of one logical core**, with 191.645 MiB working set. No URA
  UI polling or compilation occurred during that interval. This single condition
  does not explain the historical intermittent idle-CPU issue.

Launching `SystemSettings.exe` through the authorized computer-use tool returned
`launched app did not expose a targetable window`. A subsequent window inventory
also contained no Settings window. No scale setting was changed, so no restoration
was necessary. **Current OS-level DPI acceptance remains unverified**; older DPI
records are historical evidence, not verification of these new editors.

A fresh local package/clean-extraction check passed for the three Release EXEs,
resource/version agreement, assets, dependency licences, CLI and MCP. All 567
listed files match their hashes, 277 dependency packages have licence notices,
and the extracted native EXE reached its Ready workspace in a separate live
startup check. The ZIP is 16,073,145 bytes with SHA-256
`30f21b7378bf79f5779ed8669e3d827861ac5717c8a4131eb92f3cea21de40c5`.
The sanitized extraction report is `docs/benchmarks/0.8-completion-package.json`.
Its packaged documentation describes verification in progress; this final source
report records the result without rebuilding a self-referential checksum. Logs,
SHA-256 sidecar and extraction report stay beside the local ZIP. This is a
packaging verification checkpoint, not an accepted public prerelease.

No force push, `main` update, moved tag, overwritten old release or fabricated
download verification is authorized by a passing compiler test. The corrected
public tag remains withheld while current OS-level DPI acceptance is unverified.
Continue v0.8 acceptance before starting v0.9. Future work includes verified
structured-source rendering, richer ABI/memory models and broader compiler inputs;
a universal C/C++ decompiler is not claimed here.
