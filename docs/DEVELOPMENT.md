# Development

## Prerequisites

- Windows 10/11 with Evergreen WebView2.
- Rust 1.80+ (MSVC toolchain). `rustup default stable-x86_64-pc-windows-msvc` is the expected
  setup.
- Node.js 20+ with npm.
- Python 3 only if you need to regenerate the fixture binaries.

The project was developed with Rust 1.99.1, Node 26.7.0 and npm 11.19.0 on Windows 11 x64.

## Setup

```powershell
npm install
npm run tauri dev
```

`tauri dev` starts Vite on port 1420 and launches the shell with the dev URL. Rust changes
trigger a rebuild of the app; frontend changes hot-reload in the webview.

## Command reference

| Command | Purpose |
| --- | --- |
| `npm run tauri dev` | Full desktop app in development |
| `npm run build` | Type-check the frontend and produce `dist/` |
| `npm run typecheck` | `tsc --noEmit` only |
| `cargo test --workspace` | All Rust unit and integration tests |
| `cargo test -p ura-core` | Analysis engine tests |
| `cargo test -p ura-project` | Project persistence tests |
| `cargo clippy --workspace --all-targets -- -D warnings` | Rust lint gate |
| `cargo fmt --all -- --check` | Rust formatting gate |
| `npm run tauri build` | Release build and installer bundle |
| `python scripts/generate_fixtures.py` | Regenerate deterministic PE/ELF fixtures |

### Standalone executable

```powershell
npm run build
cargo build -p ura-app --features custom-protocol
.\target\debug\ura-app.exe [path\to\sample.exe]
```

The `custom-protocol` feature embeds the built frontend into the executable. A plain
`cargo build -p ura-app` produces a dev binary that points at `http://localhost:1420`; without a
running Vite server it shows an empty window. `npm run tauri build` enables the feature
automatically.

Stop any running `ura-app` process before rebuilding. A live process locks
`target\debug\ura-app.exe` and cargo reports `Access is denied. (os error 5)`.

## Code layout

```text
crates/ura-core/src/
  binary/mod.rs      parsing, metadata, identity
  binary/mapping.rs  address mapping and executable sections
  address.rs         hex parsing/formatting
  disasm.rs          iced-x86 decoding and page projection
  hex.rs             bounded byte reads
  strings.rs         ASCII/UTF-16 scanning
crates/ura-project/src/lib.rs   SQLite schema, projects, annotations
src-tauri/src/
  lib.rs             builder, startup argument, command registration
  commands.rs        IPC wrappers with spawn_blocking
  state.rs           shared session state
src/
  App.tsx            provider composition, shell chrome and global shortcuts
  state/             session, settings, messages and workspace contexts
  components/workspace/Workbench.tsx   Dockview host, default layout, persistence
  components/        views, inspector, palette, settings, shell
  lib/api.ts         typed invoke wrappers
  lib/types.ts       IPC payload types
  lib/format.ts      address/offset helpers
  lib/panels.ts      workspace panel ids and view mapping
  index.css          Obsidian Dark tokens, component classes, Dockview theme
```

## Adding an IPC command

1. Implement the operation in `ura-core` or `ura-project` with unit tests.
2. Add a `#[tauri::command]` function in `src-tauri/src/commands.rs`. Use `run_blocking` for CPU
   or disk work; keep arguments serde-compatible and camelCase.
3. Register it in the `generate_handler!` list in `src-tauri/src/lib.rs`.
4. Add the TypeScript type in `src/lib/types.ts` and a wrapper in `src/lib/api.ts`. Do not call
   `invoke` directly from components.
5. Wire the UI and confirm errors surface through `errorMessage()` and the message log.

## Frontend conventions

- Addresses and offsets are strings at the IPC boundary. Use `src/lib/format.ts`
  (`normalizeAddress`, `formatHex`, `parseAddressInput`, `offsetForAddress`, `sectionForAddress`)
  rather than ad-hoc conversions.
- Views receive immutable projections from context hooks. Analysis state belongs in
  `state/session.tsx`; settings, messages and workspace intents have their own providers.
  Components call session actions rather than `invoke` directly.
- Docked panels are registered in `lib/panels.ts`. Add a view to the Dockview layout in
  `components/workspace/Workbench.tsx` and use a stable panel id so persisted layouts survive.
  After creating a panel, size its group explicitly if the default geometry matters.
- Narrow-panel behaviour uses CSS container queries on `.view-root`, `.explorer-root` and
  `.overview-root`; do not key layout off viewport breakpoints for docked content.
- Styling uses the Obsidian Dark tokens and component classes in `src/index.css`
  (`.panel`, `.btn`, `.input`, `.tab`, `.view-root`, `.disasm-grid`, `.hex-grid`,
  `.strings-grid`). Avoid introducing new color literals.
- Lists that can grow use `VirtualList` or `@tanstack/react-virtual`. Virtualized rows must be
  absolutely positioned with a `translateY` offset; in-flow rows break scroll math.
- Every mutating action must handle errors and leave the UI in a usable state.

## Fixtures and tests

`tests/fixtures/ura64.exe` is a hand-built PE64 image:

- image base `0x140000000`, entry `0x140001000`
- `.text` at VA `0x140001000` / file offset `0x200` (512 bytes)
- `.rdata` at VA `0x140002000` / file offset `0x400` (512 bytes)
- ASCII string `URA fixture string` at file offset `0x400`
- UTF-16LE string `Wide URA` at file offset `0x460`

`ura64.elf` mirrors the layout for ELF mapping tests. Both are generated with fixed timestamps
and bytes, so regenerating them should produce identical content.

Run Rust tests before any frontend work is considered done:

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
npm run build
```

## Manual verification

The following flow was used to validate v0.1 end-to-end:

1. Launch with the fixture path: `ura-app.exe tests\fixtures\ura64.exe`.
2. Confirm the header facts, sections and imports/exports in Overview and Explorer.
3. Open the palette (`Ctrl+K`), enter `0x140001004`, press Enter, and confirm the selection and
   status bar update.
4. Switch to Hex, jump to offset `0x400`, and confirm the ASCII string is on the first row.
5. Switch to Strings, scan, and jump from a result to hex/disassembly.
6. Create a project from the toolbar, save an annotation in the Inspector, close the app.
7. Reopen the app, open the `.ura` project, and confirm the annotation, selected address and
   `binary verified` status.

### Automated inspection tips

- Tauri's webview can expose Chrome DevTools Protocol:
  set `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222` before launch, then
  query `http://127.0.0.1:9222/json` and evaluate JavaScript over the WebSocket. This is useful
  for asserting DOM state without brittle screen coordinates.
- Keyboard injection (`SendKeys`) does not reliably reach the webview; drive the DOM through CDP
  or click with `mouse_event`.
- Native Save/Open dialogs use a DirectUI filename control, not a classic edit. Its UIA type is
  `Pane`; the control id varies between Save and Open. Select the element with class `Edit` and a
  wide bounding rectangle. Focus it with a real mouse click, paste the path, then press Enter.
- Find the main window by enumerating windows for the process and matching class
  `Tauri Window`; `MainWindowHandle` is not always populated for WebView2 windows.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| Blank window after `cargo build` | Frontend assets were not embedded; build with `--features custom-protocol` |
| `Access is denied. (os error 5)` while rebuilding | Stop the running `ura-app` process first |
| `npm run tauri dev` cannot connect | Port 1420 is occupied or Vite failed; check the terminal |
| CDP connection fails | Only one instance may own port 9222; close stale `ura-app` processes |
| Project opens with `binary modified` | The source binary changed since the project was created; annotations may be stale |
| Project opens with `binary missing` | The recorded path no longer exists; relink by opening the correct binary and recreating the project |
| SQLite "unable to open database file" | The target directory is read-only or the path is invalid |
| WebView2 runtime error | Install the Evergreen WebView2 runtime |
