# Architecture

URA separates binary analysis from presentation. The Rust workspace owns all parsing and
decoding; the React UI only renders projections received over Tauri IPC.

```text
┌──────────────────────────────┐
│ React UI (src/)              │
│ views · inspector · palette  │
└──────────────┬───────────────┘
               │ invoke() / typed JSON        dialogs
┌──────────────▼───────────────┐        ┌────────────────────┐
│ src-tauri                    │◄───────┤ tauri-plugin-dialog │
│ commands · AppState          │        └────────────────────┘
└───────┬──────────────┬───────┘
        │              │
┌───────▼──────┐ ┌─────▼────────┐
│ ura-core     │ │ ura-project  │
│ analysis     │ │ SQLite       │
└──────────────┘ └──────────────┘
```

## Crates

### `crates/ura-core`

Pure analysis library with no Tauri or UI dependencies.

| Module | Responsibility |
| --- | --- |
| `binary/mod.rs` | File size guard, format detection (`object`), PE/ELF/Mach-O parsing, sections, symbols, imports, exports, metadata, SHA-256, `LoadedBinary` |
| `binary/mapping.rs` | Virtual address ↔ file offset mapping through sections, executable-section lookup |
| `address.rs` | Parse and format 64-bit addresses and file offsets as hexadecimal strings |
| `disasm.rs` | `iced-x86` decoder, instruction projection, flow classification, branch targets, warnings |
| `analysis.rs` | Recursive-descent function discovery, basic-block partitioning, call/jump xrefs, bounded CFG projection, cancellation, diagnostics |
| `hex.rs` | Bounded file-offset reads with section/address annotation |
| `strings.rs` | ASCII and UTF-16LE scanning with length/encoding/max-result controls |
| `error.rs` | `UraError` variants used by every fallible operation |

`LoadedBinary` keeps the parsed image and derived tables in memory. The file bytes are opened
read-only, hashed once, and never modified.

### `crates/ura-project`

Persistence for `.ura` files using bundled SQLite (`rusqlite`). It knows nothing about the UI or
the analysis engine beyond the `BinaryIdentity` it stores.

- Schema version 2 is enforced through `PRAGMA user_version`; version 1 projects are migrated
  in place by adding the `function_names` table.
- Creating a project refuses to overwrite an existing file.
- Annotations are upserted per normalized address; timestamps are UTC ISO-8601 strings.
- Custom function names are stored per function address and override imported symbols. They
  are independent of the binary and survive re-analysis, close and reopen.
- Opening a project reports `binaryStatus` as `unchanged`, `modified` or `missing` based on the
  recorded path and SHA-256.
- The selected address is stored on every debounced UI selection change.

### `src-tauri`

The desktop shell and trust boundary.

- `lib.rs` builds the Tauri app, registers commands, initializes the dialog plugin, and captures
  an optional startup binary path from `argv`.
- `commands.rs` exposes the IPC surface. CPU/IO work runs on Tauri's blocking thread pool via
  `spawn_blocking`, so the webview's async runtime is never blocked by parsing or scanning.
- `state.rs` holds a clonable `AppState` with `Arc<LoadedBinary>` behind a `Mutex`, the one-shot
  startup path, a cached `ProgramAnalysis`, an `AtomicBool` cancellation flag, a generation
  counter that discards stale results, and the custom-name overlay used for display.

## IPC contract

| Command | Arguments | Result |
| --- | --- | --- |
| `open_binary` | `path` | `BinaryOpenResult` (info, sections, symbols, imports, exports) |
| `close_binary` | — | `void` |
| `take_startup_path` | — | `string \| null` |
| `disassemble` | `address`, `count` | `DisassemblyPage` |
| `read_hex` | `offset`, `length` | `HexPage` |
| `extract_strings` | `minLength`, `includeAscii`, `includeUtf16` | `StringScanResult` |
| `create_analysis_project` | `projectPath`, `name` | `ProjectInfo` |
| `open_analysis_project` | `projectPath` | `ProjectSnapshot` |
| `save_annotation` | `projectPath`, `address`, `label`, `note` | `Annotation` |
| `set_project_address` | `projectPath`, `address` | normalized address |
| `delete_annotation` | `projectPath`, `annotationId` | `void` |
| `analyze_binary` | `options` | `AnalysisSummary` |
| `cancel_analysis` | — | `boolean` |
| `analysis_state` | — | `AnalysisStateView` |
| `list_functions` | `query` | `FunctionListPage` |
| `function_at` | `address` | `FunctionDetail \| null` |
| `function_cfg` | `address`, `maxBlocks` | `FunctionCfg` |
| `xrefs_to` | `address`, `limit` | `XrefPage` |
| `xrefs_from` | `address`, `limit` | `XrefPage` |
| `rename_function` | `projectPath`, `address`, `name` | `RenameResult` |

Argument names are camelCase at the JavaScript boundary. Payload structs use
`#[serde(rename_all = "camelCase")]`. All addresses cross the boundary as hexadecimal strings so
no 64-bit value is ever truncated by JavaScript numbers. File offsets are safe as `number`
because the supported image size is capped at 512 MiB.

Errors are stringified Rust error messages. The UI logs them in the message panel and shows a
transient toast; commands never panic on malformed input.

## Address model

- **Virtual addresses** are the primary identity for disassembly, symbols, sections and
  annotations. They are formatted as `0x` plus the minimal number of hex digits.
- **File offsets** are used for raw bytes, hex navigation and string locations.
- Mapping is section-driven: `address = image_base + section.address + delta`, while
  `file_offset = section.file_offset + delta` for sections with file-backed data. BSS-like
  sections without file data are readable only through their virtual extent for metadata but
  yield no bytes in the hex view.
- An executable target is followed in the disassembly when it resolves to a mapped executable
  section; otherwise the UI sends the address to the hex view.

## Request and session flow

1. **Open binary** — the dialog (or startup argument) yields a path. `open_binary` parses and
   hashes the file, stores `LoadedBinary` in `AppState`, and returns a projection. The UI resets
   selection, string results and navigation state.
2. **Disassembly** — the view requests a 320-instruction page starting at a virtual address.
   The backend decodes until the page is full or the section ends, classifies flow, and returns
   warnings. Scrolling near the end requests another page; selections update the inspector and
   the debounced project selection autosave.
3. **Hex** — the view caches 8 KiB chunks by file offset and renders virtualized rows with 8, 16
   or 32 bytes per row. A navigation request normalizes an address, offset or section to a file
   offset and scrolls the row into view.
4. **Strings** — a default scan (minimum length 4, ASCII + UTF-16LE) runs when a binary opens.
   The view can re-run it with different settings; results are filtered client-side. Each row
   keeps its file offset and mapped virtual address.
5. **Function analysis** — opening a binary starts `analyze_binary` automatically. The engine
   runs on the blocking pool, emits `analysis-progress` events, and is cancellable through an
   `AtomicBool`. The result (functions, blocks, xrefs, diagnostics, partial flag) is cached in
   `AppState`; reopening the same binary returns a summary instead of re-analyzing. Queries are
   paginated, and a generation counter discards results that arrive after the binary changed.
6. **Renaming** — `rename_function` validates the address against the cached analysis, writes the
   name to the project's `function_names` table and refreshes the display-name overlay. Names are
   applied by the backend, so the Functions list, disassembly, CFG and inspector agree.
7. **Projects** — create/open flows live in the UI; persistence is entirely in `ura-project`.
   Open resolves the recorded binary path, loads it through the same `open_binary` path, checks
   the hash, restores the selected address, annotation list and custom function names.
8. **Startup** — Tauri reads the first non-flag argument that names an existing file. The UI
   consumes it once via `take_startup_path`, so subsequent reloads do not reopen the file.

## UI structure

- `src/App.tsx` composes the providers and shell chrome, and owns global shortcuts, the command
  palette and the preferences dialog. It does not hold analysis state directly.
- `src/state/` contains the contexts: `session` (binary, selection, navigation requests, project,
  strings, analysis state/progress, rename dialog and IPC actions), `settings` (density, code
  font size, byte column, local persistence), `messages` (log and filters) and `workspace` (panel
  intents, active/open panels, reset requests).
- `src/components/workspace/Workbench.tsx` mounts Dockview, builds the default layout, persists
  it to `ura:workspace:v1` (350 ms debounce) and services focus/toggle/reset intents. Layout
  sizes are re-applied through each panel group after creation so the initial geometry matches
  the intended Explorer 330 px / Inspector 300 px / Hex 280 px / Messages 148 px. The Control
  Flow and Xrefs panels are pre-mounted as inactive tabs in the disassembly and inspector groups.
- Views (`Overview`, `Explorer`, `DisassemblyView`, `HexView`, `StringsView`, `Inspector`,
  `MessagesPanel`, `CfgView`, `XrefsPanel`) consume context hooks and render immutable
  projections. Mutating actions call session methods, never `invoke` directly.
- `FunctionExplorer` pages the function list (500 per request), virtualizes rows, supports sort
  direction and infinite scroll, and shares selection with the disassembly. `CfgView` lays out
  blocks in BFS depth columns (pure layout in `src/lib/cfg-layout.ts`) and supports zoom, pan,
  fit, block/instruction selection and double-click navigation. `RenameFunctionDialog` loads the
  function at the selection, validates against the cached analysis and writes through the project.
- Chrome components (`Toolbar`, `StatusBar`, `Welcome`, `CommandPalette`, `SettingsDialog`) use
  the same contexts. The toolbar exposes analysis start/cancel and progress; the status bar shows
  function/block counts and partial results. The palette resolves addresses, `@file-offset` input,
  sections, symbols, exports and annotations.
- `VirtualList` wraps `@tanstack/react-virtual`. Virtualized rows are absolutely positioned,
  which keeps scroll height and jump offsets deterministic.
- The design system lives in `src/index.css`: Obsidian Dark palette tokens, panel/button/input/tab
  component classes, the Dockview theme, and container queries for narrow panels. Icons come
  from `lucide-react`.

## Performance choices

- Binary parsing, scanning and function analysis happen off the UI thread.
- Function analysis decodes linearly into an address-indexed instruction map, then partitions
  blocks and discovers callees in one pass; queries read the cached result and never re-decode.
- Analysis progress is throttled to events rather than per-instruction IPC. Function, CFG and
  xref queries are paginated and capped independently of the analysis limits.
- Instruction pages are capped at 320 rows; the UI never renders the full section at once.
- Hex data is chunked at 8 KiB and cached per view session.
- Strings are capped at 200,000 results and filtered in memory.
- Large file lists use `@tanstack/react-virtual`; only visible rows are mounted.
- Selection persistence is debounced (700 ms) to avoid a write per keystroke.

## Limits and failure behavior

| Limit | Value |
| --- | --- |
| Maximum input file | 512 MiB |
| Symbols | 50,000 |
| Imports / exports | 20,000 each |
| Extracted strings | 200,000 |
| Instructions per request | 2,000 |
| Analysis instructions | 200,000 |
| Discovered functions | 8,192 |
| Basic blocks per analysis | 150,000 |
| CFG blocks per query | 500 |

Reaching a cap produces a warning in the relevant result rather than an incomplete silent
success; analysis marks its result `partial` and the UI displays that state. Cancellation keeps
whatever was completed. Unsupported formats (COFF objects, WebAssembly, XCOFF) fail at open time
with a specific error. A project referencing a missing binary still opens; its metadata and
annotations remain readable, and the UI clears any binary-dependent views.

## Security

- Samples are never executed, loaded as libraries, mapped for execution or patched.
- The webview is sandboxed by Tauri. The CSP allows local IPC and inline styles only.
- No network access is required or used at runtime.
- File paths come from user-driven native dialogs or an explicit command-line argument.
- SQLite access is parameterized; project names and annotations are stored as data, not SQL.
