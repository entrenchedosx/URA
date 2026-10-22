# Architecture

## Native desktop (v0.8 development)

`crates/ura-native` is the default workspace member. Its eframe entry point
renders egui directly through OpenGL and winit; no browser engine or IPC is
involved. It depends on `ura-core` and `ura-project` directly. Schema v7 adds debugger definitions after v6 patch history; prior schemas remain readable and migrate on explicit writes. A separate read-only
snapshot API supports headless attachment without migration or binary-path IO.

- `app.rs`: shared workspace, navigation/selection, project actions, settings,
  stale-result generations, docking and persistence.
- `views.rs`: analysis panels, virtualized tables and visible-range
  hex rendering, palette and dialogs.
- `worker.rs`: serial background jobs, progress/cancellation and panic recovery.
  Immutable binaries and analysis results are shared with `Arc`. IO, parsing,
  decoding, analysis, string scanning and graph layout stay off the paint path.
  IR lifting, SSA/dataflow and IR row formatting also run here. Revision-tagged
  replies cannot replace newer analysis. Raw/SSA views reuse one verified bundle.
  ABI/stack/type recovery and high-level rendering run here as revision- and
  project-tagged jobs; call-graph construction is a separate revision-tagged job.
  The Function signature, Stack frame, Types, Call graph and Analysis inspector
  panels follow the workspace's selected function.
- `navigation.rs`: u64 address/offset mapping and bounded history.
- `graph.rs`: deterministic, cycle-safe layered graph geometry with height-aware
  spacing; at most 240 blocks and 32 displayed instructions per block.
- `design.rs`, `menus.rs`, `graph_view.rs`: shared theme/metrics, conventional
  menus and interactive graph/overview rendering.
- `diagnostics.rs`: opt-in capture of the actual renderer and frame CPU metrics.

Disassembly caches up to 16,000 formatted instructions, fetched in 2,000-row
pages; reaching the cache budget starts a new page. Graph geometry caches up to
16 functions. Filtering/sorting indices update when inputs or results change.
Hex reads borrow the original bytes and format visible rows only. There is no
continuous repaint loop in normal use; background replies request repaints.

Native project view state extends the existing v1 JSON document with a `native`
member containing dock geometry, history, selection and the retained CFG
function, plus an optional defaulted IR representation preference. The IR panel
is absent from the default dock. Compatible top-level fields remain readable by v0.4. Global preferences
and window geometry use eframe storage. Saving queues database writes and the
worker drains them on shutdown. Samples remain read-only.

## Headless adapters

`ura-service` owns sessions, normalized analysis options, schema-versioned DTOs,
path restrictions and explicit write permissions. It invokes the same core
analysis and project functions used by the desktop. `ura-cli` is a synchronous
text/JSON adapter; `ura-mcp` routes 55 stdio tools to the service. Neither starts
the desktop. MCP uses rmcp and stderr logging; there is no network listener.
Query pages and byte reads have explicit limits. Address-based byte reads must
fit one file-backed section. Read-only project snapshots support v1-v7 and
compare the supplied binary's hash, without reading a recorded external path.
Service calls are serialized per process; cancellation/progress notifications and
persisted analysis caches are not implemented in MCP. Verified IR bundles are
cached in memory, at most two per handle and eight handles. Normalized options
and binary identity accompany IR pages; reanalysis invalidates the cache. SQLite is schema v7 (v6 adds patch state; v7 debugger definitions); v3-to-v4 adds signature/stack overrides and v4-to-v5 adds the validated user type library. Strings are rescanned per
query; future caching should be keyed by binary identity and scan options.

## Semantic analysis

`ura-core/src/ir` implements typed bit-vector operations, explicit register
regions/flags/memory, decoded-byte lifting, verification, dominators/frontiers,
scalar SSA, propagation and side-effect-aware dead-definition reports. `inspect`
is the shared orchestration and row projection boundary. Each pass is bounded;
core and native calls support cancellation. There is one lifter for all adapters.
See [IR-DESIGN.md](IR-DESIGN.md) for exact semantics and limits.

`ura-core/src/decomp` builds only on that verified IR. Signature recovery
combines platform defaults, observed argument registers, stack accesses and
taint-rooted uses; stack recovery records physical slots and overlaps; type
inference merges SSA constraints with ABI value constraints; the high-level view
is a bounded structural rendering labelled experimental. A user override is kept
separate from inference and applied only after validation. The call graph uses
direct calls and marks indirect calls unresolved. See
[DECOMPILER.md](DECOMPILER.md).

`jumptable.rs` recognizes two narrow guarded switch patterns using a separate
read-only file-backed data image. Targets are validated before CFG recovery.
Recovered edges remain heuristic and indirect transfers remain unresolved.
Tail calls and single-jump thunks are candidates relative to known function
entries. The native graph caches these summaries on the worker and displays
uncertainty. Block-limit stops preserve function ownership and remove dangling
edges. Function lookup requires a retained block rather than an extent alone.

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
| `ir/` | Typed raw/SSA IR, verified lifting and conservative dataflow reports |
| `decomp/` | ABI/signature recovery, stack frames, conservative types, bounded call graph and experimental high-level rendering |
| `jumptable.rs` | Guarded absolute/relative switch candidates, bounded table validation |
| `error.rs` | `UraError` variants used by every fallible operation |

`LoadedBinary` keeps the parsed image and derived tables in memory. The file bytes are opened
read-only, hashed once, and never modified.

### `crates/ura-project`

Persistence for `.ura` files using bundled SQLite (`rusqlite`). It knows nothing about the UI or
the analysis engine beyond the `BinaryIdentity` it stores.

- Schema version 4 is enforced through `PRAGMA user_version`; version 1-3 projects are
  migrated in place by adding `function_names`, `manual_functions`, `view_state`,
  `function_signatures` and `stack_variables` as needed.
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

The v0.8 completion audit is [AUDIT-0.8.md](AUDIT-0.8.md). The current high-level view is text, not a separately typed semantic AST; a whole-program iterative type solver remains future work.

## v0.10 patching

The shared `ura-core::patch` engine provides immutable originals, sparse overlays,
transaction/history validation, protected PE/ELF layout translation, bounded
iced-x86 instruction encoding and verified new-file export. Schema6 stores patch
state independently of annotations/types. Accepted mutations invalidate the entire
analysis snapshot. Generation checks reject old worker results; patch changes and
exports run in workers. See [BINARY-PATCHING.md](BINARY-PATCHING.md).

## Native debugger (v0.11)

`ura-debugger` owns a bounded controller and backend interface. Windows x64 is the
only implemented backend. `windows/mod.rs` owns process/session lifecycle and
command routing; `events.rs` handles actual Windows events; `breakpoints.rs` owns
bytes, displaced instruction stepping and cleanup; `os.rs` contains documented
Windows bindings, aligned context storage, bounded memory and local DbgHelp unwind.

`ura-service::DebugService` is the shared policy boundary. Exact image hashes are
pinned and rechecked with held file handles, including the Windows creation event.
Execution and PID attachment have separate deny-by-default permissions. A failed
authorization allows cleanup only. Controller/session state is separate from file
handles, patch overlays and static caches. Schema7 stores main-module identity/RVA
breakpoint definitions without runtime memory or environment contents.

`ura-native/debugger.rs` dispatches service calls on background threads, uses
nonblocking snapshot access, clears capture caches on stop/thread changes, and
renders the native runtime panels. The event owner waits for commands while paused.
CLI `debug` owns a single local JSON-line session; MCP adds 16 bounded debugger
tools to the existing 39. Neither frontend provides a cross-process controller.
See [DEBUGGER.md](DEBUGGER.md) for exact lifecycle, permissions and limitations.
