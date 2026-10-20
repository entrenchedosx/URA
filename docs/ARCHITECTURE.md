# Architecture

## Native desktop (v0.5)

`crates/ura-native` is the default workspace member. Its eframe entry point
renders egui directly through OpenGL and winit; no browser engine or IPC is
involved. It depends on `ura-core` and `ura-project` directly. Those two crates
and their schema migrations are unchanged by the native migration.

- `app.rs`: shared workspace, navigation/selection, project actions, settings,
  stale-result generations, docking and persistence.
- `views.rs`: ten dockable analysis panels, virtualized tables and visible-range
  hex rendering, graph painting, palette and dialogs.
- `worker.rs`: serial background jobs, progress/cancellation and panic recovery.
  Immutable binaries and analysis results are shared with `Arc`. IO, parsing,
  decoding, analysis, string scanning and graph layout stay off the paint path.
- `navigation.rs`: u64 address/offset mapping and bounded history.
- `graph.rs`: deterministic, cycle-safe layered graph geometry with height-aware
  spacing; at most 240 blocks and 12 displayed instructions per block.
- `diagnostics.rs`: opt-in capture of the actual renderer and frame CPU metrics.

Disassembly caches up to 16,000 formatted instructions, fetched in 2,000-row
pages; reaching the cache budget starts a new page. Graph geometry caches up to
16 functions. Filtering/sorting indices update when inputs or results change.
Hex reads borrow the original bytes and format visible rows only. There is no
continuous repaint loop in normal use; background replies request repaints.

Native project view state extends the existing v1 JSON document with a `native`
member containing dock geometry, history, selection and the retained CFG
function. Compatible top-level fields remain readable by v0.4. Global preferences
and window geometry use eframe storage. Saving queues database writes and the
worker drains them on shutdown. Samples remain read-only.

## Preserved v0.4 frontend architecture

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
| `analysis.rs` | Recursive-descent function discovery, basic-block partitioning, call/jump/data xrefs, bounded CFG projection, cancellation, diagnostics |
| `hex.rs` | Bounded file-offset reads with section/address annotation |
| `strings.rs` | ASCII and UTF-16LE scanning with length/encoding/max-result controls |
| `error.rs` | `UraError` variants used by every fallible operation |

`LoadedBinary` keeps the parsed image and derived tables in memory. The file bytes are opened
read-only, hashed once, and never modified.

### `crates/ura-project`

Persistence for `.ura` files using bundled SQLite (`rusqlite`). It knows nothing about the UI or
the analysis engine beyond the `BinaryIdentity` it stores.

- Schema version 3 is enforced through `PRAGMA user_version`; version 1 and 2 projects are
  migrated in place by adding the `function_names`, `manual_functions` and `view_state` tables.
- Creating a project refuses to overwrite an existing file.
- Annotations are upserted per normalized address; timestamps are UTC ISO-8601 strings.
- Custom function names are stored per function address and override imported symbols. They
  are independent of the binary and survive re-analysis, close and reopen.
- Manual functions are stored per address and loaded as user-defined analysis seeds. They
  survive re-analysis even when no call site reaches them.
- `view_state` holds a JSON document bounded to 512 KiB. It is validated before storage and
  restored when the project reopens.
- Annotation export produces a portable JSON document with binary identity and counts; it
  refuses to overwrite the project or binary and verifies the file after writing.
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
| `analyze_binary` | `options`, `projectPath` | `AnalysisSummary` |
| `cancel_analysis` | — | `boolean` |
| `analysis_state` | — | `AnalysisStateView` |
| `list_functions` | `query` | `FunctionListPage` |
| `function_at` | `address` | `FunctionDetail \| null` |
| `function_cfg` | `address`, `maxBlocks` | `FunctionCfg` |
| `xrefs_to` | `address`, `limit` | `XrefPage` |
| `xrefs_from` | `address`, `limit` | `XrefPage` |
| `rename_function` | `projectPath`, `address`, `name` | `RenameResult` |
| `create_manual_function` | `projectPath`, `address` | `AnalysisSummary` |
| `remove_manual_function` | `projectPath`, `address` | `AnalysisSummary` |
| `save_view_state` | `projectPath`, `state` | `void` |
| `load_view_state` | `projectPath` | `string \| null` |
| `export_annotations` | `projectPath`, `destination` | `ExportSummary` |

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
   `AtomicBool`. Before starting, the backend loads user-defined functions from the project and
   passes them as seeds. The result (functions, blocks, call/jump/data xrefs, diagnostics,
   partial flag) is cached in `AppState`; reopening the same binary returns a summary instead of
   re-analyzing. Queries are paginated, and a generation counter discards results that arrive
   after the binary changed.
6. **Renaming and manual functions** — `rename_function` validates the address against the cached
   analysis, writes the name to the project's `function_names` table and refreshes the
   display-name overlay. `create_manual_function` and `remove_manual_function` validate that the
   address is executable, update `manual_functions`, then re-run analysis with the updated seeds.
7. **Navigation** — every successful navigation creates a history entry with the resolved address
   and file offset. Duplicate consecutive entries collapse, history is bounded, and back and
   forward replay the location and infer the view from the target section. The go-to dialog
   accepts virtual addresses, explicit file offsets, relative deltas, section-relative targets,
   pasted hex dumps, and text searches across functions, sections, symbols, exports and
   annotations.
8. **Projects** — create/open flows live in the UI; persistence is entirely in `ura-project`.
   Open resolves the recorded binary path, loads it through the same `open_binary` path, checks
   the hash, restores the selected address, annotations, custom names, manual functions and the
   saved view state (address, CFG function, history and active panel). The workspace layout is
   stored separately in `localStorage` under a scope derived from the project path.
9. **Export** — the UI asks for a destination through the dialog plugin, then
   `export_annotations` writes the portable JSON document and returns its path and counts.
10. **Startup** — Tauri reads the first non-flag argument that names an existing file. The UI
    consumes it once via `take_startup_path`, so subsequent reloads do not reopen the file.

## UI structure

- `src/App.tsx` composes the providers and shell chrome, and owns global shortcuts, the command
  palette and the preferences dialog. It does not hold analysis state directly.
- `src/state/` contains the contexts: `session` (binary, selection, navigation history,
  view-state persistence, project, strings, analysis state/progress, rename dialog, annotation
  export and IPC actions), `settings` (density, code font size, byte column, local persistence),
  `messages` (log and filters) and `workspace` (panel intents, active/open panels, layout scope
  and reset requests). History entries record the address and requested file offset; back and
  forward replay them and infer the view from the target section.
- `src/components/workspace/Workbench.tsx` mounts Dockview, builds the default layout, persists
  it to `ura:workspace:v1:<project scope>` (350 ms debounce) and services focus/toggle/reset
  intents. Switching projects persists the previous scope and restores the new one. Layout sizes
  are re-applied through each panel group after creation so the initial geometry matches the
  intended Explorer 330 px / Inspector 300 px / Hex 280 px / Messages 148 px. The Control Flow
  and Xrefs panels are pre-mounted as inactive tabs in the disassembly and inspector groups.
- Heavy views (disassembly, CFG, hex, strings and xrefs) are loaded through `React.lazy`, so the
  startup bundle only contains the shell, Dockview and the always-visible panels. Vendor chunks
  for React and Dockview are split explicitly.
- Views (`Overview`, `Explorer`, `DisassemblyView`, `HexView`, `StringsView`, `Inspector`,
  `MessagesPanel`, `CfgView`, `XrefsPanel`) consume context hooks and render immutable
  projections. Mutating actions call session methods, never `invoke` directly.
- `FunctionExplorer` pages the function list (500 per request), virtualizes rows, supports sort
  direction and infinite scroll, and shares selection with the disassembly. `CfgView` lays out
  blocks in BFS depth columns (pure layout in `src/lib/cfg-layout.ts`) and supports zoom, pan,
  fit, block/instruction selection and double-click navigation. `RenameFunctionDialog` loads the
  function at the selection, validates against the cached analysis and writes through the project.
- Chrome components (`Toolbar`, `StatusBar`, `Welcome`, `CommandPalette`, `GoToDialog`,
  `SettingsDialog`, `AboutDialog`) use the same contexts. The toolbar exposes back/forward
  navigation, go-to, analysis start/cancel and progress; the status bar shows function/block
  counts and partial results. The palette resolves addresses, `@file-offset` input, sections,
  symbols, exports and annotations; the go-to dialog offers the same address and offset grammar
  plus a searchable candidate list.
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
- Selection persistence is debounced (700 ms) to avoid a write per keystroke. View state is
  saved separately after navigation settles and suppressed while a project is being restored.
- The project view-state document is capped at 512 KiB; oversized or invalid JSON is rejected
  before it reaches SQLite.

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
| Project view state | 512 KiB |

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
