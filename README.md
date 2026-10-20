# URA — Ultimate Reverse Engineer

URA is a native desktop workbench for static analysis of executable images. A Rust analysis
engine does the parsing, mapping, disassembly and scanning; a Tauri 2 shell hosts a React +
TypeScript interface. Every result comes from the bytes on disk — URA never executes or patches
the files you open.

v0.1 targets Windows PE x64, with static metadata for ELF and Mach-O images and x86/x64
disassembly for any executable section URA can map.

## Highlights

- **Dockable workspace** — Explorer, Disassembly, Overview, Strings, Hex, Inspector and Messages
  live in resizable panels powered by Dockview. The layout persists between launches, can be
  reset from the toolbar or preferences, and the core views adapt to narrow panels.
- **Binary overview** — format, architecture, bitness, endianness, image base, entry point,
  file size, SHA-256 and section permissions.
- **Explorer** — sections, symbols, imports and exports with filters and virtualized lists.
  Selecting an entry navigates the workspace to it.
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
- **Analysis projects** — `.ura` files are SQLite databases that record the source binary path
  and SHA-256, the selected address, and annotations. Reopening restores the selection and
  verifies the binary against the recorded hash.
- **Command palette** — jump to an address, symbol, section, or run a command from one input.
- **Startup argument** — pass a binary path on the command line and URA opens it on launch.

## Status

v0.1.0 is complete and has been exercised end-to-end on Windows 11 against the deterministic
PE64/ELF fixtures in `tests/fixtures`: open binary, inspect metadata/sections, disassemble,
navigate (palette, keyboard, branch follow), read hex, scan and jump to strings, create a
project, save an annotation, close, reopen and verify the restored state. The v0.2 workspace
overhaul is complete: dockable/resizable panels, persistent layout, settings, responsive views,
and context-based session/message/workspace state. See [ROADMAP.md](docs/ROADMAP.md) for what
comes next.

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
| `Ctrl+,` | Open preferences |
| `Ctrl+1` … `Ctrl+4` | Disassembly / Hex / Strings / Overview |
| `Ctrl+Enter` | Save the current annotation from the inspector |
| `Esc` | Close the command palette or preferences |
| `Up` / `Down` | Move the disassembly selection by one instruction |
| `PageUp` / `PageDown` | Move the disassembly selection by 20 instructions |
| `Enter` | Run the highlighted item in the command palette |

Branch targets in the disassembly and string results expose jump buttons that navigate to the
mapped section, or back to the hex view when the target is not executable.

## Projects on disk

A `.ura` project is a single SQLite database (`PRAGMA user_version = 1`) with two tables:

- `project` — name, timestamps, binary path, binary SHA-256, file size, format, architecture
  and the last selected address.
- `annotations` — one row per address with an optional label, a note and timestamps.

Opening a project resolves the recorded binary path. A missing file leaves the project open in
a warning state; a hash mismatch opens the binary with a `modified` status so stale annotations
are obvious. URA only reads the binary and never writes to it.

## Safety model

- Samples are opened read-only. There is no execution, emulation, patching or code injection.
- Binary identity is recorded as SHA-256 and re-checked on every project open.
- Analysis is bounded: 512 MiB files, 50,000 symbols, 20,000 imports/exports, 200,000 strings
  and 2,000 instructions per request.
- The webview runs under a restrictive CSP and talks only to the local Tauri IPC channel.
- All parsing and decoding happens in safe Rust (`object`, `iced-x86`, `rusqlite`).

## Limitations

- Disassembly is x86/x64 only; other architectures are limited to metadata and raw views.
- No cross-references, function recovery, CFG, debugger, PDB/type support or binary diffing yet.
- COFF relocatable objects, WebAssembly and XCOFF are rejected with a clear error.
- The UI is optimized for a desktop window of 1100x680 or larger.

## Repository layout

| Path | Contents |
| --- | --- |
| `crates/ura-core` | Binary parsing, address mapping, disassembly, hex reads, string scanning |
| `crates/ura-project` | SQLite project and annotation persistence |
| `src-tauri` | Tauri application, command layer, session state |
| `src` | React UI, views, inspector, command palette, typed IPC client |
| `tests/fixtures` | Deterministic PE64 and ELF64 samples |
| `scripts` | Fixture generator |
| `docs` | Architecture, development and roadmap notes |

More detail: [Architecture](docs/ARCHITECTURE.md) ·
[Development](docs/DEVELOPMENT.md) · [Roadmap](docs/ROADMAP.md).

## License

MIT. See [LICENSE](LICENSE).
