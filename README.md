# URA — Ultimate Reverse Engineer

URA is a native desktop workbench for static analysis of executable images. A Rust analysis
engine does the parsing, mapping, disassembly and scanning; a Tauri 2 shell hosts a React +
TypeScript interface. Every result comes from the bytes on disk — URA never executes or patches
the files you open.

v0.4 adds navigation history, go-to navigation, user-defined functions, data cross-references,
per-project view state and portable annotation export on top of the v0.3 analysis workbench. It
targets Windows PE x64, with static metadata for ELF and Mach-O images and x86/x64 disassembly
for any executable section URA can map.

## Highlights

- **Dockable workspace** — Explorer, Disassembly, Overview, Strings, Hex, Inspector and Messages
  live in resizable panels powered by Dockview. The layout is stored per project, can be reset
  from the toolbar or preferences, and the core views adapt to narrow panels.
- **Binary overview** — format, architecture, bitness, endianness, image base, entry point,
  file size, SHA-256 and section permissions.
- **Function analysis** — recursive-descent discovery from the entry point, exports,
  function symbols, call targets and analyst-defined seeds. Every function is partitioned into
  basic blocks with fall-through, jump and taken edges. The engine runs off the UI thread with
  progress events, cancellation and explicit safety limits; partial results and diagnostics are
  surfaced rather than hidden. User-defined functions survive re-analysis, close and reopen.
- **Functions explorer** — searchable, sortable, paginated function list with origin badges,
  instruction/block/reference counts and selection sync. Double-click opens linear disassembly;
  the context menu opens the CFG, references or rename dialog. Custom names override imported
  symbols and persist in the project.
- **Control-flow graph** — layered, zoomable and pannable graph for the selected function.
  Blocks show their instructions and branch targets; block and instruction selection is shared
  with the rest of the workspace, and double-click jumps to linear disassembly. Large functions
  are capped with a visible partial-result badge.
- **Cross-references** — call, jump, conditional-jump and data references are indexed per
  address and displayed in both the Inspector and a dedicated Xrefs panel, with function-level
  or exact address scope. Data references distinguish RIP-relative and absolute addressing, show
  the mapped target section, and are only recorded when they point inside the image. Indirect
  transfers are labelled as unresolved rather than guessed.
- **Explorer** — functions, sections, symbols, imports and exports with filters and virtualized
  lists. Selecting an entry navigates the workspace to it.
- **Disassembly** — Intel-syntax x86/x64 decoding via `iced-x86`, with instruction bytes,
  flow classification, resolved branch targets and section mapping. Pages are fetched on demand
  (320 instructions) and the list is virtualized; keyboard navigation and branch following are
  built in.
- **Hex viewer** — offset/ASCII gutter with 8, 16 or 32 bytes per row, chunked reads,
  section/address mapping and jump-to-offset. Navigating from strings or disassembly lands on the
  exact row.
- **Strings explorer** — ASCII and UTF-16LE scanning starts when a binary opens and can be re-run
  with a configurable minimum length. Per-encoding filters and substring search are applied
  client-side. Each result can jump to the hex view or, when the string maps to an executable
  section, the disassembly view.
- **Inspector and annotations** — selection facts, project facts, binary identity, and an
  annotation editor (label + note). Annotations are listed and can be edited or deleted.
  Annotations, custom names and manual functions can be exported to a portable JSON document.
- **Navigation** — go-to accepts hexadecimal virtual addresses, explicit file offsets
  (`@0x…`, `file:…` or `offset …`), relative deltas (`+0x10`), section-relative targets
  (`.text+0x30`), pasted hex dumps, and searches functions, sections, symbols, exports and
  annotations. Back and forward history follows every navigation, with deduplication and a
  bounded depth.
- **Analysis projects** — `.ura` files are SQLite databases that record the source binary path
  and SHA-256, the selected address, annotations, custom function names, user-defined functions
  and the saved view state. Reopening restores the working context and verifies the binary
  against the recorded hash. Schema version 3 migrates version 1 and 2 projects automatically.
- **Command palette** — jump to an address, symbol, section, or run a command from one input.
- **Startup argument** — pass a binary path on the command line and URA opens it on launch.

## Status

v0.4 adds navigation history, expanded go-to navigation, user-defined functions, data
cross-references, per-project view state and annotation export. Jump-table recovery was
deliberately deferred: tables live in data sections that the current walker does not read, so
indirect transfers are labelled as unresolved instead of guessed. The deterministic PE64/ELF
fixtures in `tests/fixtures` cover open, metadata, disassembly, hex, strings, projects,
analysis, manual functions, view state and export. Automated Rust tests exercise the engine and
persistence layers; the manual desktop flow is documented in
[DEVELOPMENT.md](docs/DEVELOPMENT.md). See [ROADMAP.md](docs/ROADMAP.md) for what comes next.

## Requirements

- Windows 10/11 with the Evergreen WebView2 runtime (preinstalled on Windows 11).
- Rust 1.80 or newer with the MSVC toolchain.
- Node.js 20 or newer with npm.
- For installers: the standard Tauri 2 Windows bundling prerequisites.

URA was developed and verified with Rust 1.99.1, Node 26.7.0 and npm 11.19.0.

## Build and run

```powershell
npm install

# Development (Vite dev server + Tauri shell)
npm run tauri dev

# Tests
cargo test --workspace
npm run build          # tsc --noEmit && vite build

# Production executable
npm run tauri build
```

To build a standalone debug executable without the Tauri bundler:

```powershell
npm run build
cargo build -p ura-app --features custom-protocol
.\target\debug\ura-app.exe [path\to\sample.exe]
```

The `custom-protocol` feature embeds `dist/` into the executable. Without it, a plain
`cargo build` produces a binary that expects the Vite dev server at `http://localhost:1420`
and will show an empty window when started on its own.

The integration fixtures are generated deterministically:

```powershell
python scripts/generate_fixtures.py
```

`tests/fixtures/ura64.exe` maps `.text` at `0x140001000` (file offset `0x200`) and `.rdata` at
`0x140002000` (file offset `0x400`); strings are reachable at file offsets `0x400` and `0x460`.

## Keyboard shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl+O` | Open a binary |
| `Ctrl+K` | Open the command palette |
| `Ctrl+N` | Create a project for the open binary |
| `Ctrl+Shift+O` | Open an existing project |
| `Ctrl+G` | Go to an address, file offset or symbol |
| `Alt+Left` / `Alt+Right` | Navigate back / forward |
| `Ctrl+,` | Open settings |
| `Ctrl+1` … `Ctrl+4` | Disassembly / Hex / Strings / Overview |
| `Ctrl+Enter` | Save the current annotation from the inspector |
| `F2` | Rename the function containing the selection |
| `Esc` | Close the command palette, preferences or rename dialog |
| `Up` / `Down` | Move the disassembly selection by one instruction |
| `PageUp` / `PageDown` | Move the disassembly selection by 20 instructions |
| `Enter` | Run the highlighted item in the command palette |

Branch targets in the disassembly and string results expose jump buttons that navigate to the
mapped section, or back to the hex view when the target is not executable.

## Projects on disk

A `.ura` project is a single SQLite database (`PRAGMA user_version = 3`) with five tables:

- `project` — name, timestamps, binary path, binary SHA-256, file size, format, architecture
  and the last selected address.
- `annotations` — one row per address with an optional label, a note and timestamps.
- `function_names` — one custom name per function address, with a timestamp. Names override
  imported symbols and are independent of the binary on disk.
- `manual_functions` — addresses explicitly marked as functions by the analyst, with a
  timestamp. They seed every re-analysis.
- `view_state` — one bounded JSON document describing the active panel, address, CFG function
  and navigation history.

Opening a project resolves the recorded binary path. A missing file leaves the project open in
a warning state; a hash mismatch opens the binary with a `modified` status so stale annotations
are obvious. Version 1 and 2 projects are migrated automatically; newer schema versions are
rejected with a clear error. URA only reads the binary and never writes to it.

Annotation export writes a single JSON document with the binary identity, annotations, custom
names and manual functions. It refuses to overwrite the project file or the analyzed binary and
is not an import format.

## Safety model

- Samples are opened read-only. There is no execution, emulation, patching or code injection.
- Binary identity is recorded as SHA-256 and re-checked on every project open.
- Analysis is bounded: 512 MiB files, 50,000 symbols, 20,000 imports/exports, 200,000 strings,
  2,000 instructions per page and, for function analysis, 200,000 instructions, 8,192 functions
  and 150,000 basic blocks.
- The webview runs under a restrictive CSP and talks only to the local Tauri IPC channel.
- All parsing and decoding happens in safe Rust (`object`, `iced-x86`, `rusqlite`).

## Limitations

- Disassembly is x86/x64 only; other architectures are limited to metadata and raw views.
- Function discovery is heuristic: indirect calls, tail calls, jump tables and unreachable code
  are not recovered, so some functions or references can be missing. Indirect jumps are marked
  as unresolved. Results are explicitly marked partial when a safety limit or cancellation is
  hit.
- Data references cover RIP-relative and absolute memory operands. They are recorded only when
  the target lies inside a mapped section; immediates and unmodelled addressing are ignored.
- No debugger, PDB/type support, binary diffing or annotation import yet.
- COFF relocatable objects, WebAssembly and XCOFF are rejected with a clear error.
- The UI is optimized for a desktop window of 1100x680 or larger.

## Repository layout

| Path | Contents |
| --- | --- |
| `crates/ura-core` | Binary parsing, address mapping, disassembly, function/CFG/xref/data-reference analysis, hex reads, string scanning |
| `crates/ura-project` | SQLite project, annotation, function-name, manual-function and view-state persistence |
| `src-tauri` | Tauri application, command layer, session state |
| `src` | React UI, views, inspector, command palette, typed IPC client |
| `tests/fixtures` | Deterministic PE64 and ELF64 samples |
| `scripts` | Fixture generator |
| `docs` | Architecture, development and roadmap notes |

More detail: [Architecture](docs/ARCHITECTURE.md) ·
[Development](docs/DEVELOPMENT.md) · [Roadmap](docs/ROADMAP.md).

## License

MIT. See [LICENSE](LICENSE).
