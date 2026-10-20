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

## v0.2 — navigation and structure (next)

Priority: help analysts move through an image instead of reading linearly.

- Cross-references: find code and data references to an address or symbol.
- Function boundaries: entry points, prologue heuristics and manual function creation.
- Control-flow view for the selected function, building on the existing branch targets.
- Symbol/annotation navigation history with back and forward.
- Go-to improvements: relative offsets, section-relative input and pasted dumps.
- Annotation export/import as portable JSON alongside the SQLite project.
- Persist view state per project (active view, scroll anchor, filters).

## v0.3 — depth

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
  silently.
- Measure large-file memory use and consider memory-mapped reads for hex and strings.
- Expand integration coverage for ELF x64 disassembly and Mach-O metadata.
