<p align="center"><img src="icon.webp" width="160" alt="URA application artwork"></p>

# URA

Ultimate Reverse Engineer

## Overview

URA is a native Rust static-analysis workbench for executable files. The desktop,
CLI and MCP server use the same analysis engine. Samples are read locally and
are never executed by URA. This is an early engineering release, with explicit
analysis limits; it is not a replacement for the full feature sets of IDA or Ghidra.

## Current capabilities

- Executable metadata, SHA-256 identity, sections, symbols, imports and exports.
- x86/x64 linear disassembly with bytes, flow classification and direct targets.
- Recursive function discovery from entry points, exports, symbols and calls.
- Basic blocks, conditional/loop edges and incoming/outgoing code references.
- Data references for provable RIP-relative and absolute memory operands.
- ASCII/UTF-16LE strings and bounded hex reads.
- SQLite projects with annotations, name overrides, manual function starts,
  navigation history and saved workspace state.
- Native CLI with text/JSON output and a local stdio MCP server with 15 tools.

There is no decompiler, debugger, semantic IR, type recovery, jump-table recovery,
PDB loader or public plugin API. Indirect transfers remain unresolved. Discovery
is conservative and can miss code, reject ambiguous seeds or stop at limits.

## Supported architectures and executable formats

| Input | Support |
|---|---|
| PE, ELF, Mach-O | Metadata and section-based inspection through `object` |
| x86 and x86-64 | Decoding and function/CFG analysis |
| ARM, AArch64, RISC-V, MIPS, PowerPC and other recognized CPUs | Metadata only; no instruction analysis |

PE and ELF x64 fixtures and Windows system binaries are exercised by tests.
Mach-O and other host operating systems need broader validation. Maximum input
size is 512 MiB; resources are also bounded during analysis and string scanning.

## Desktop application

The default application uses eframe, egui and OpenGL. It has no WebView dependency.
Compact native menus and docking provide Functions, Project structure,
Disassembly, Graph, Hex View, Strings, Xrefs, Overview, Inspector, Output and
Graph overview panels. Project structure includes sections, symbols, imports and
exports. Imports without mapped addresses are informational.

Classic light and professional dark themes share one rendering implementation.
Preferences control interface/code/graph fonts, row height, bytes and panel
visibility. Tabs can be moved, closed and reopened from Windows; reset restores
the default layout. The graph uses actual analysis blocks, with pan, zoom, fit,
selection and an interactive overview. Large graphs are capped at 240 displayed
blocks and 32 displayed instructions per block; truncation is shown explicitly.

## Building from source

Windows x64 is the verified host. Install Rust with the MSVC toolchain and Visual
Studio C++ build tools/Windows SDK. The native crate declares Rust 1.95 or newer;
this iteration was verified with Rust 1.99.1. Build dependencies may require a
newer compiler than the older core-crate minimum.

```powershell
cargo build --release -p ura-native -p ura-cli -p ura-mcp
cargo run --release -p ura-native -- path/to/sample.exe
```

Generated icons are committed. Regeneration requires Python and Pillow:

```powershell
python scripts/generate_icons.py
```

## Usage

Open a binary with Ctrl+O or pass its path at startup. Analysis and string
scanning run in a background worker. Create a project with Ctrl+N to persist
comments, renamed functions and manual starts. The Inspector edits annotations;
F2 renames a function. Save/reopen retains analysis seeds and view state;
analysis results themselves are recomputed.

| Shortcut | Action |
|---|---|
| Ctrl+G / Ctrl+K | Address, symbol, offset or command navigation |
| Alt+Left / Alt+Right | Navigation history |
| Space | Switch linear disassembly and graph |
| Arrow / PageUp / PageDown | Select an instruction in the linear view |
| Enter | Follow selected direct branch/call |
| Ctrl+S | Save project workspace |
| Ctrl+, | Preferences |
| Alt+F/E/J/S/V/D/O/W/H | Open the corresponding top menu |

Addresses are hexadecimal, with an optional `0x` prefix. Desktop navigation also
accepts `@200` file offsets, relative deltas and expressions such as `.text+10`.

## Headless CLI

The CLI does not start a GUI. Paths must resolve inside `--allow` roots; the
default root is the current directory. Use repeatable `--allow DIR` for samples
elsewhere. Commands are `info`, `analyze`, `functions`, `disasm`, `strings`,
`xrefs`, `cfg` and `hex`.

```powershell
ura-cli info sample.exe --json
ura-cli functions sample.exe --limit 50 --sort name --json
ura-cli disasm sample.exe --address 140001000 --count 20 --json
ura-cli cfg sample.exe --function 140001020 --json
ura-cli hex sample.exe --offset 200 --length 32 --json
ura-cli functions sample.exe --project analysis.ura --json
```

JSON responses carry `schemaVersion: 1`; addresses are strings. Operation errors
use a structured error object and exit code 1. Invalid command-line syntax uses
Clap's usage errors. `--help` documents per-command limits. The CLI reads project
names/manual starts without migrating the database. Project creation and editing
are currently exposed through the desktop and MCP tools, not CLI subcommands.

## MCP integration

Configure an MCP client to start `ura-mcp` with stdio transport:

```json
{
  "mcpServers": {
    "ura": {
      "command": "C:/tools/URA/ura-mcp.exe",
      "args": ["--allow", "C:/samples"]
    }
  }
}
```

Call `ura_open_binary`, retain the returned handle, call `ura_analyze`, then query
`ura_get_binary_info`, `ura_get_functions`, `ura_get_function`,
`ura_get_disassembly`, `ura_get_cfg`, `ura_get_xrefs`, `ura_search_strings` or
`ura_read_bytes`. Close handles with `ura_close_binary`.

`ura_save_project`, `ura_rename_function`, `ura_add_comment` and
`ura_export_analysis` require the explicit `--enable-writes` process option.
No network listener is started. Stdout contains MCP JSON only; logs go to stderr.
Read-only project attachments support schema v1-v3 without migration or following
the database's recorded binary path. The opened binary's SHA-256 must match.
Allowed roots constrain resolved paths, but are not an operating-system sandbox
against a concurrent local attacker changing files or links.

## Screenshots

Actual captures of URA's native renderer, using the deterministic regression
fixture (not simulated analysis):

![Classic graph workspace](docs/screenshots/classic-graph.png)

![Classic linear disassembly](docs/screenshots/classic-disassembly.png)

![Professional dark graph](docs/screenshots/dark-graph.png)

See [verification](docs/VERIFICATION-0.6.md) for sizes, scaling and remaining
manual checks. The small fixture verifies known instructions and loop edges;
real Windows binaries were inspected separately.

## Project structure and architecture

| Path | Responsibility |
|---|---|
| `crates/ura-core` | Loading, decoding, functions, CFGs, references, strings |
| `crates/ura-project` | SQLite persistence and compatible migrations |
| `crates/ura-native` | Native desktop and background worker |
| `crates/ura-service` | Shared headless sessions, DTOs and path/write policy |
| `crates/ura-cli` | Native command-line interface |
| `crates/ura-mcp` | MCP stdio adapter |
| `tests/fixtures`, `scripts` | Reproducible fixtures, icons and measurements |
| `src`, `src-tauri` | Retained legacy UI for migration comparison |

The desktop calls core/project directly; CLI/MCP share the service adapter over
the same core/project implementation. No analysis engine is duplicated. The
legacy frontend remains for comparison and is not required by the native build.
See [architecture](docs/ARCHITECTURE.md) and [recovery](docs/RECOVERY-2026-10-20.md).

## Testing

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
```

Tests cover deterministic PE/ELF decoding, malformed input, CFG/reference
behavior, database migrations and annotation persistence, service restrictions,
CLI processes, actual MCP handshakes/tool calls, and native-panel tessellation.
Renderer checks are opt-in; see [verification](docs/VERIFICATION-0.6.md).

## Roadmap

Priorities are CFG validation under limits, bounded data-memory access,
relocation/import references and improved function recovery. Architecture-neutral
semantics must precede SSA, type inference and decompilation. See the
[Ghidra source study and feature matrix](docs/GHIDRA-RESEARCH.md) for dependencies,
complexity and verification strategies. OS-level high-DPI, cross-platform input,
packaging and broader executable-format coverage remain follow-ups.

## Contributing

Keep engine code independent of GUI types, preserve existing project schemas,
and add deterministic regression coverage for correctness changes. Run the
workspace checks above. Do not commit proprietary samples, credentials or local
analysis projects. Discuss new architectures and persistence changes before
introducing a new format or dependency.

## License and third-party notices

URA retains its [MIT license](LICENSE). Dependencies retain their own licenses;
see [third-party notices and release generation](THIRD_PARTY.md).
The original `icon.webp` is the user-supplied official artwork; its owner confirmed
permission to redistribute it with URA. Native variants preserve the full image.
No IDA artwork or source is included; Ghidra was studied as a reference only.
