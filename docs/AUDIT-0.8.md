# v0.8 checklist audit and repair

Audit date: 2026-10-21. Starting source: `11944034856dceb65bed0f485a7e8f889b7a2348`
on `v0.8-decompiler-foundations`. The working tree was clean. The v0.7 baseline
is `1d0f48460d777e133bceae7866f734903aa4470b` (97 tests). The starting v0.8 source
passed 122 tests and had already been published as `v0.8.0-dev`.

**The full supplied v0.8 checklist is not complete.** The starting documentation
described a useful foundations checkpoint, but several checked roadmap items were
broader than the implemented or tested behavior. This audit repairs concrete
defects and missing editing/persistence paths; it does not reclassify the entire
checklist as done. The existing public ZIP predates these repairs. No existing
tag or archive is overwritten, and no new accepted prerelease is claimed.

## Repairs

- Stack SP/FP facts now merge monotonically per CFG block. A loop with changing
  SP terminates with unknown facts; disagreeing predecessors no longer select
  the last path. x86 native register families, unsupported writes, indexed and
  segmented accesses, saved-register evidence and home-space classification
  have dedicated regressions.
- ABI recovery retains low-confidence container defaults. Shared x64 registers,
  self-canceling instructions, zero comparisons, unknown call results, conflicting
  cleanup amounts and conflicting callee hints do not become invented signatures.
- Stack and ABI passes poll cancellation. Desktop decompiler jobs use a real
  cancellation token and expose Cancel; mutually queued IR/decompiler jobs cannot
  replace each other's token. Type/HIR cancellation is checked at pass boundaries.
- Calls retain every observed call-site address. Indirect calls anywhere in a
  block are counted, as well as unresolved indirect jumps. Graph output is capped
  at 8,192 functions and 20,000 sites.
- Sign extension in the structural display states both source and destination
  widths. Missing call arguments and unavailable return locations are unresolved.
- Native signature editing supports convention, return type, parameter names,
  locations/types and unknown/no/yes variadic state. Stack names/types can be edited
  by double-click; their context menu lists actual instruction references. Reset
  removes only the user override. Inferred evidence remains separate.
- Native Types supports user structures, unions, fields and aliases. Existing
  structured types, widths and field storage/provenance survive unrelated edits.
  Unknown sizes and alignment remain optional; definitions are user assertions.
- Project schema v5 adds a bounded, validated type library. v1-v4 projects migrate
  forward; read-only attachment does not migrate or follow the stored binary path.
  Existing annotations, function names and manual functions are retained. Older
  URA versions cannot read schema v5 projects after migration.
- CLI adds `type-library`, `set-signature` and `set-variable-type`. Writes require
  `--enable-writes` and the attached matching project; writes cannot mix two
  projects for the same binary. Definition-file reads obey allowed roots
  and a 1 MiB limit.
- MCP now has 30 tools. `ura_get_structure(handle,name)` returns a real structure
  definition. This corrects the original tool's mistaken high-level-text alias;
  use `ura_get_high_level_ir` for control flow. `ura_get_types` without a function
  reads the type library; `ura_set_type_library` validates and atomically replaces
  it behind the existing write gate. Existing function type queries remain valid.
- Type validation bounds nesting, named-layout traversal and arithmetic; rejects
  cyclic by-value layouts, invalid alignments, conflicting known storage widths
  and size overflow. `size_t` uses the target width, including curated API helpers;
  ambiguous `long` is rejected and `time_t` stays incomplete without an ABI model.
- Packaging supports a separate output directory, keeps prior artifacts and
  license collections, and hashes nested documentation/license files too.

The independent review and its semantic cases are recorded in
[REVIEW-0.8.md](REVIEW-0.8.md). Final test/build/measurement results are recorded
in [VERIFICATION-0.8.md](VERIFICATION-0.8.md).

## Checklist status after repair

| Requested area | Status and remaining work |
|---|---|
| Existing project, native UI, icon, CLI/MCP, v0.7 behavior | Preserved; existing tests retained. Source continues on the existing branch. |
| Idle CPU investigation | Measured against the verified public v0.7 executable; root cause still unresolved. No accessibility removal or artificial sleep in the app. |
| Calling convention subsystem | Scalar register/stack evidence exists for Win64, SysV64 and x86 conventions. Complete XMM classes, aggregates, hidden return pointers, ABI-aware call clobbers, return consumers and complete argument counts remain unfinished. |
| Stack reconstruction | Bounded physical slots and SP/FP relations work on the tested subset. Dynamic realignment, indexed frames, general spill/liveness/array recovery and arbitrary custom callee cleanup remain unresolved. The implementation uses decoded instruction semantics and CFG dataflow, rather than full IR memory analysis. |
| Type representations and user editing | Descriptions, manual structures/unions/aliases and signature/physical-slot overrides persist. Full ABI layout computation, inferred fields/structures and general SSA-variable overrides remain unfinished. |
| Conservative type inference | Scalar width/address-use constraints and supplied callee hints exist. SSA-version-specific type solving, complete numeric/pointer conflict solving and inferred pointee layouts remain unfinished. |
| Interprocedural analysis | Real direct-call sites and SCCs exist. Imported graph nodes, trusted import binding, return-consumer analysis and a bounded fixed-point type/signature solver across recursive calls are missing. The curated API helper is not automatically connected to import analysis. |
| IR optimization | Existing constant/dataflow/dead-definition reports remain. These are not a verified rewriting optimizer: copy propagation, safe DCE, memory alias refinement and transformed-IR equivalence tests are still needed. |
| High-level representation | The current public view is a diagnostic structural rendering of SSA. It is not a typed expression/statement AST separated from formatting. Proper postdominators, validated region structuring, irreducible-CFG semantic tests and independent source/behavior equivalence remain unfinished. Do not treat its C-like text as accurate decompiled source. |
| Difficult binaries | Existing tail/thunk candidates and narrow guarded switches remain. No general obfuscation recovery, unpacking or devirtualization is claimed. |
| Native interface | Real editable signature, stack and user-type forms now exist, with source navigation and persistent overrides. Broader live DPI and complex-layout coverage remains necessary. |
| CLI/MCP/persistence | Shared engine and bounded/gated queries and writes are tested, including restart. MCP still serializes synchronous service calls and lacks transport cancellation/progress. |
| Testing and research | Independent semantic regressions and primary-source review added. Broad MSVC/GCC/Clang optimization/ABI corpora, debug-metadata comparisons and malformed/adversarial fuzzing are not complete. |
| Performance | Actual Release measurements are recorded. No whole-program propagation timing exists because that solver is absent. OS wakeups/context switches, GPU/presentation and input-to-paint timing remain unmeasured. |
| Publication | The previous prerelease exists. Corrected source is a development checkpoint; replacing/moving the published tag is explicitly avoided. Full acceptance and a new public artifact require the outstanding semantic scope and validation gates. |

## Primary-source research applied

[Ghidra's PrototypeModel](https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/PrototypeModel.html)
separates a calling-convention storage model from a concrete function prototype,
including argument locations, killed registers and stack offsets. URA's convention
tables are a beginning of that model; reading one shared register cannot establish
the full prototype. This is an implementation inference from that architecture.

[Microsoft's x64 ABI](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170)
describes positional GPR/XMM arguments, caller-reserved shadow space and aggregate
rules. The audit tests the scalar subset and explicitly leaves the unimplemented
vector/aggregate cases open rather than claiming complete Windows x64 recovery.

[LLVM's GEP documentation](https://llvm.org/docs/GetElementPtr.html) distinguishes
address calculations from dereferences and warns that IR element types alone
cannot establish type-based alias facts. URA therefore retains address-use evidence
and does not equate an integer index or zero comparison with a valid typed pointer.
No external implementation code was copied for these repairs.
