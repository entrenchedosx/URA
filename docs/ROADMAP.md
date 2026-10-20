# Roadmap

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

## v0.5 — depth

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
- macOS and Linux host support (the Rust engine is portable; the UI is Tauri-native).
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
