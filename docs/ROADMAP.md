# Roadmap

## v0.8 - foundations checkpoint, full checklist unfinished

- [x] Tested scalar ABI evidence and conservative return/argument uncertainty.
- [x] Monotone SP/FP dataflow and physical stack slots with instruction references.
- [x] Scalar type constraints; bounded, validated manual structures/unions/aliases.
- [x] Native signature/stack/type editors and project schema v5 persistence.
- [x] Direct-call sites, SCCs, indirect-transfer counts and bounded graph queries.
- [x] Shared CLI/MCP queries and explicit writes; 30 MCP tools.
- [x] Independent adversarial review and regressions for the repaired subset.
- [ ] Complete vector/aggregate ABI models and caller return-consumer evidence.
- [x] Bind a narrow DLL/symbol-checked PE prototype subset; recover bounded PE/ELF slot identities.
- [ ] Integrate imported call-graph nodes, sites and complete thunk/PLT identity.
- [x] Solve supplied native-width register parameter demands with a bounded monotone worklist.
- [ ] Add forward, stack and return-consumer propagation with SSA-specific type conflicts.
- [x] Retain a typed presentation AST with self-contained SSA types/operations and independently checked postdominator join proofs.
- [ ] Complete high-level semantic types/provenance and interpreter-based region equivalence tests.
- [ ] Implement verified IR rewriting/alias refinements and semantic comparisons.
- [ ] Broaden compiler/optimization/debug-metadata and malformed-input validation.
- [ ] Resolve idle CPU and collect OS wakeup/GPU/presentation/latency measurements.
- [ ] Accept and publish a new artifact after remaining semantic gates are met.

The earlier `v0.8.0-dev` public archive predates the audit repairs. See
[checklist audit](AUDIT-0.8.md), [independent review](REVIEW-0.8.md),
[decompiler design](DECOMPILER.md) and [verification](VERIFICATION-0.8.md).
The later [finalisation checkpoint](FINALISATION-0.8.md) records the partial
implementations, 213 tests and outstanding acceptance gates without rewriting
historical audit results.

## v0.7 — development checkpoint, release blocked

- [x] Typed bit-vector IR and scalar x86/x64 lifting with explicit unknown effects.
- [x] Register aliasing, arithmetic flags, stack/address and conservative memory/call semantics.
- [x] Verifiers, dominators/frontiers, scalar SSA, def-use, constants and dead definitions.
- [x] Guarded absolute/relative jump tables; optimized PE/ELF and adversarial fixtures.
- [x] Tail/thunk candidates, honest indirect-flow metadata and CFG budget consistency.
- [x] Optional native IR panel; matching CLI and four new MCP queries.
- [x] Bounded revision-aware memory caches; existing SQLite projects preserved.
- [x] Actual Windows OS 150% scale check and Release measurements.
- [ ] Explain/fix variable process CPU outside UI painting; stack profiling unavailable on this host.
- [ ] Capture OS/thread wakeup counts and GPU/presentation timing.
- [ ] Complete broader cross-compiler/relocation-aware jump-table and ABI coverage.
- [ ] Publish v0.7 prerelease only after blockers close.

See [verification](VERIFICATION-0.7.md) and [IR design](IR-DESIGN.md). Historical
milestones below describe earlier releases; unchecked legacy items can be
superseded by the development work above.

Proposed next stages are broader semantic/dataflow validation, then types and ABI
inference, structured control flow, and only afterward tested C-like output.
Decompiler milestones are conditional on correctness rather than fixed dates.

## v0.1 — shipped

The first release is a complete read-only inspection loop, verified end-to-end against the
deterministic fixtures.

- [x] Tauri 2 desktop shell with an Obsidian Dark interface
- [x] PE, ELF and Mach-O parsing through `object`, with bounded input and clear format errors
- [x] Metadata, sections, symbols, imports and exports
- [x] x86/x64 disassembly with `iced-x86`: bytes, flow classification, branch targets, warnings
- [x] Paged, virtualized disassembly with keyboard navigation and branch following
- [x] Chunked hex viewer with offset/ASCII gutter and address mapping
- [x] ASCII and UTF-16LE string scanning with filters and navigation
- [x] Command palette for addresses, symbols, sections and commands
- [x] Inspector with selection, binary and project facts
- [x] SQLite `.ura` projects: annotations, selected address, binary hash verification
- [x] Startup binary argument and end-to-end acceptance flow
- [x] Rust workspace tests and clean TypeScript/Vite build

## v0.2 — workspace overhaul (complete)

Priority: make simultaneous views usable and keep the interface coherent at any window size.
This work is UI-only; the analysis engine and IPC surface are unchanged.

- [x] Dockview workbench: Explorer, Disassembly, Overview, Strings, Hex, Inspector, Messages
- [x] Resizable panels, default geometry and reset-layout action
- [x] Layout persistence in `localStorage` with a versioned key
- [x] Context-based session, settings, messages and workspace state
- [x] Rebuilt command palette, toolbar, status bar, welcome screen and preferences dialog
- [x] Responsive disassembly, hex, strings, explorer and overview layouts
- [x] Hex row-width selection (8/16/32), byte selection and context actions
- [x] Automatic initial string scan plus manual re-scan

## v0.3 — function analysis (complete)

Priority: turn linear disassembly into navigable program structure, with honest limits.

- [x] Recursive-descent function discovery from entry points, exports, symbols and call targets
- [x] Basic-block partitioning with fall-through, jump and taken edges
- [x] Call/jump/conditional xrefs indexed per address
- [x] Functions explorer: search, sort, pagination, virtualized rows, origin badges and counts
- [x] Interactive CFG view: BFS layout, zoom/pan/fit, block selection, jump to disassembly
- [x] Xrefs in the inspector and a dedicated panel, with function/address scope
- [x] F2 rename with project persistence and display-name overlay across all views
- [x] Cancellable background analysis with progress events, diagnostics and partial-result state
- [x] Project schema v2 (`function_names`) with automatic v1 migration
- [x] Deterministic fixture acceptance: discover → CFG → xrefs → rename → save → reopen

## v0.4 — navigation and workflow (complete)

Priority: help analysts move through an image instead of reading linearly.

- [x] Symbol/annotation navigation history with back and forward
- [x] Go-to improvements: virtual addresses, explicit offsets, relative/section deltas, pasted
      dumps and searchable candidates
- [x] Annotation export as portable JSON alongside the SQLite project
- [x] Persist view state per project (address, CFG function, history, active panel)
- [x] Manual function creation and deletion; manual seeds survive re-analysis
- [x] Data cross-references for RIP-relative and absolute memory operands
- [ ] Jump-table recovery — deferred; see below

Jump tables were evaluated for v0.4 and deliberately deferred. MSVC and GCC emit jump tables
in data sections (`.rdata`/`.rodata`), while the analysis engine walks only executable
file-backed sections and has no safe data-section reader. Resolving entries without reading
those bytes would fabricate targets. Instead, indirect jumps and calls are explicitly labelled
as unresolved in the disassembly, and data references cover the memory operands that can be
proven from decoded instructions. A future pass should add a bounded data reader, validate
table extents and entry count against the preceding bounds check, and mark any recovered table
as heuristic.

## v0.5 — native Rust desktop migration

- [x] eframe/egui application using the existing Rust engine and SQLite crate.
- [x] Ten dockable views, native dialogs, command palette and keyboard navigation.
- [x] Virtualized disassembly/functions/strings, visible-range hex and cached CFGs.
- [x] Annotation/name/manual-function editing, export and project state restoration.
- [x] Native render integration tests, Release builds and actual-renderer captures.
- [x] Verify idle CPU, memory and startup against the fixture and real binaries.
- [x] Preserve the v0.4 application for comparison; see the verification report.
- [ ] Complete the frontend-retirement gate, including OS-level 150% DPI,
      GPU/presentation timing and live input/dialog verification.

## Later analysis depth

- Signature scanning for known libraries and patterns.
- PDB loading for symbols and types.
- ELF UI parity review: dynamic symbols, program headers and relocation summaries.
- Binary diffing: sections, symbols and byte-level change maps.
- Bookmark lists and bulk annotation management.
- Scriptable analysis hooks with a constrained, non-executing query language.

## Long-term candidates

- Plugin API with a narrow, audited surface for extending views.
- Type reconstruction and structure overlays for data addresses.
- Multi-tab sessions and side-by-side binaries.
- macOS and Linux host verification (the Rust engine and native GUI are portable).
- Signed installers and automatic updates.

## Explicit non-goals

- Running, debugging, unpacking or patching samples.
- Kernel drivers or anti-cheat bypass functionality.
- Uploading or transmitting binaries to remote services.

## Engineering follow-ups

- CI: `cargo test --workspace`, `cargo fmt --check`, `cargo clippy -D warnings`, frontend build.
- Fuzz the parsers and mapping functions with malformed images.
- Add screenshot-based UI regression tests for the core views.
- Introduce schema migrations when the project format changes; never open newer schemas
  silently. (v1 → v2 implemented for function names.)
- Measure large-file memory use and consider memory-mapped reads for hex and strings.
- Expand integration coverage for ELF x64 disassembly and Mach-O metadata.

## v0.6 — continuation checkpoint

- [x] Recover service/CLI/MCP code and add actual MCP stdio process tests.
- [x] Read-only project attachment without migrations or recorded binary IO.
- [x] Official artwork, reproducible variants and native Windows resources.
- [x] Compact classic light/dark native workspace, menus and graph overview.
- [x] Reject overlapping instruction ranges and section-crossing byte reads.
- [x] Study Ghidra source and record an honest feature/dependency matrix.
- [ ] Semantic IR, additional ISAs, jump tables, type recovery and decompiler.
- [ ] Debugger backend and public scripting/plugin API.

The earlier v0.1-v0.4 sections are historical legacy milestones. Native and
headless release details supersede them; see README and VERIFICATION-0.6.md.
