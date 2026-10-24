<p align="center"><img src="icon.webp" width="160" alt="URA application artwork"></p>

# URA

Ultimate Reverse Engineer

Current development is **0.16.0-dev** on `v0.16-python-plugins`: real CPython3.14.9
workers, a versioned Python SDK, atomic project metadata transactions, installable
plugins, attributed analyzers, bounded event hooks, custom loader/processor
foundations and managed batch execution. Desktop, CLI and **69 MCP tools** share
this service. The complete Windows ZIP includes the locked runtime and SDK examples.
**Trusted Python retains the user's OS permissions; the worker is not a sandbox.**
See the [Python SDK](docs/PYTHON-SDK.md), [v0.16 verification](docs/VERIFICATION-0.16.md),
[independent review](docs/REVIEW-0.16.md), [symbolic scope](docs/SYMBOLIC-DEOBFUSCATION.md),
[processor scope](docs/MULTI-ARCHITECTURE.md) and [release policy](docs/RELEASING.md).

The scoped development prerelease requires fresh Desktop/CLI/MCP EXEs, a complete
ZIP, checksums and public download verification. Refer to the
[releases page](https://github.com/entrenchedosx/URA/releases) for published assets;
a source push alone is not a binary release. Native interaction/DPI remains
unverified; WOW64, new-processor live debugging, vector/FP execution and full
processor/IDA/Ghidra parity remain incomplete.

The v0.13 source checkpoint is preserved at
`660e3a02866fce2445a04c80af813da2b7f1d7d4` on
`v0.13-emulation-dynamic-analysis` with its
[historical report](docs/VERIFICATION-0.13.md).

The v0.12 source checkpoint `04ad9125df5f5e67b7a12ef72f8f22ebd7866a85` is
preserved on `v0.12-advanced-debugging`, with its [historical report](docs/VERIFICATION-0.12.md).

The v0.11 source checkpoint is preserved at `0df07cc` on
`v0.11-windows-debugger`. Its [historical verification](docs/VERIFICATION-0.11.md)
and public release status remain unchanged.

The verified v0.10 patching checkpoint is preserved at `5dc489c` on
`v0.10-binary-patching`, including its [local package audit](docs/VERIFICATION-0.10.md).
Its outstanding live acceptance has not been relabelled as passed.

The verified 263-test v0.9 checkpoint is preserved at `61ee8a4` on
`v0.9-c-decompiler`; its remaining live checks are recorded in
[the continuation report](docs/FINALISATION-0.9.md). Existing public releases are
preserved, including [v0.8.0-dev](https://github.com/entrenchedosx/URA/releases/tag/v0.8.0-dev).
Full IDA Pro/Hex-Rays/Ghidra parity remains a long-term requirement; the
[roadmap](docs/ROADMAP.md) and [ledger](docs/FEATURE-PARITY.md) distinguish real
implementation from missing capabilities.

The latest [v0.8 finalisation checkpoint](docs/FINALISATION-0.8.md) adds a
self-contained typed tree, conservative postdominator joins, bounded parameter
type demands and trusted PE import binding. CLI `highlevel --json --ast` and MCP
`ura_get_high_level_ir` with `ast: true` expose the tree. Full release acceptance
remains pending; the existing public ZIP has not been replaced.

The later [semantic engine continuation](docs/ENGINE-COMPLETION-0.8.md) adds
executable semantic HIR, independent IR/HIR comparisons, version-specific type
evidence, forward/return constraints and external import edges. Use `--semantic`
or `--semantic-block` for semantic queries. Live editor/navigation and project
reopening checks passed; current OS-level DPI acceptance remains unverified,
so the corrected public prerelease remains withheld.

## Overview

URA is a native Rust reverse-engineering workbench for executable files and explicitly selected Windows processes. The desktop,
CLI and MCP server use the same analysis engine. Samples are read locally and
are never executed by the static or patching workflows. Debugging executes or
attaches only through explicit actions and separate permissions. Original files stay unchanged;
modified images are exported only through explicit operations. This is an early engineering release, with explicit
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
- Typed raw/SSA IR for a tested scalar x86/x64 subset, with explicit unknown effects.
- Dominators/frontiers, phi nodes, def-use counts, conservative constants and dead definitions.
- Narrow guarded absolute/relative jump-table patterns and tail/thunk candidates.
- Evidence-based ABI/signature recovery, physical stack frames and conservative types.
- Fixed-width symbolic DAGs, persistent byte-array memory, bounded value sets and solver-backed alias queries.
- Isolated, statically packaged Z3 with time/memory limits, cancellation, proof provenance and historical project metadata.
- Optional validated branch pruning through the existing C-like decompiler; original instructions and CFG remain available.
- Bounded interprocedural call graph and experimental C-like high-level rendering.
- Native Windows x64 debugger with explicit launch/attach, software/hardware breakpoints, conditions, stepping and runtime inspection.
- Bounded event/instruction traces, register changes, region queries, memory snapshots/compare/export and matched local PDB lookup.
- Transactional byte/instruction patches, project history, undo/redo and verified new-file export.
- Native CLI with text/JSON output and a local stdio MCP server with 68 tools.

CLI `decompile` and MCP `ura_decompile_function` reconstruct a separate C-like AST from semantic HIR: bounded expressions, edge-specific phi copies, proved nested regions/loops, ordered memory operations and explicit unknowns. The legacy `highlevel` view remains a diagnostic SSA representation. Reconstructed pseudocode uses explicit machine helpers and is not guaranteed to compile; see [decompiler scope](docs/C-DECOMPILER-0.9.md). Local main-image PDB names/lines are supported within a GUID/age-checked subset.
There is no remote/kernel debugger, general C++ debug-type loader or public plugin API. Indirect transfers remain open, including transfers with heuristic
recovered edges. Discovery is conservative and can miss code, reject ambiguous
seeds or stop at limits.

## Debugging

Desktop has a Debugger menu and native runtime panels. Launch/attach is explicit;
file overlays and live memory remain separate. CLI `debug` owns one interactive
JSON-line session. MCP debugging is disabled by default and needs separate
`--enable-debug-launch`/`--enable-debug-attach`, exact `--debug-target` files and,
for attach, explicit `--debug-pid` values. Ordinary `--enable-writes` grants neither.
Bulk capture additionally requires `--enable-debug-capture`; evidence file export
requires `--enable-writes` and an allowed new destination. See
[basic workflows](docs/DEBUGGER.md) and [advanced workflows](docs/ADVANCED-DEBUGGER.md).

## C-like decompilation

```powershell
ura-cli decompile sample.exe --function 140001020
ura-cli decompile sample.exe --function 140001020 --json --ast
ura-cli --enable-writes decompile sample.exe --function 140001020 --output recovered.c
```

`--offset` and `--limit` page lines; `--ast` is opt-in and limited to 2 MiB.
Export writes a new file containing the entire bounded function and preserves
existing files. MCP offers `ura_decompile_function` and
`ura_export_decompiled_function` with the same core and write policy. Floating/vector
semantics, general structure-field syntax, complete switch reconstruction and
full C++ recovery remain incomplete. This checkpoint is not an accepted prerelease.

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
Disassembly, Graph, Hex View, Strings, Xrefs, Overview, Inspector, Output,
Graph overview, Function signature, Stack frame, Types, Call graph and
Pseudocode, Patch Manager and Execution Trace panels. Project structure includes sections, symbols, imports
and exports. Imports without mapped addresses are informational.

The Function signature, Stack frame, Types, Call graph and Pseudocode
panels follow the selected function. They show evidence, confidence, conflicts
and hard-bound truncation, and addresses navigate back to disassembly.
The desktop edits signatures, physical stack-slot names/types and user structures/unions/aliases. Open a project to save edits; double-click a stack name or right-click for references. Schema v8 preserves these overrides separately from inference and stores patch history plus identity/RVA debugger breakpoint definitions. CLI and MCP expose matching guarded writes. Press F5 for Pseudocode. Line numbers, syntax colors, instruction links, variable-use menus, existing signature/stack/type editors and whole-function export share the cached analysis. Pseudocode is reconstructed and partial effects remain visible. Current 150% OS DPI acceptance is still unverified.

Open the optional **IR** panel from Windows or search `IR` in Ctrl+K. It follows
the selected function, offers Raw IR / SSA IR, and links operation addresses back
to source instructions. It stays hidden in the default layout. Exact coverage,
memory/call assumptions and function budgets are in [IR-DESIGN.md](docs/IR-DESIGN.md).

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

Create the portable Windows archive after the Release build with
`./scripts/build-windows-release.ps1 -OutputDirectory target/new-audit`. It checks all three executable
version/product resources, writes per-file checksums, collects dependency license
texts (including bundled font notices) and emits a SHA-256 sidecar for the ZIP.
Publishing the archive is a separate release step.

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
`xrefs`, `cfg`, `ir`, `dominators`, `diagnostics`, `signature`, `stack`, `types`,
`callgraph`, `highlevel` and `hex`.

```powershell
ura-cli info sample.exe --json
ura-cli functions sample.exe --limit 50 --sort name --json
ura-cli disasm sample.exe --address 140001000 --count 20 --json
ura-cli cfg sample.exe --function 140001020 --json
ura-cli ir sample.exe --function 140001020 --limit 50 --json
ura-cli ir sample.exe --function 140001020 --ssa --offset 50 --limit 50 --json
ura-cli dominators sample.exe --function 140001020 --json
ura-cli diagnostics sample.exe --function 140001020 --json
ura-cli signature sample.exe --function 140001020
ura-cli stack sample.exe --function 140001020 --json
ura-cli types sample.exe --function 140001020
ura-cli callgraph sample.exe --function 140001000 --depth 1 --json
ura-cli highlevel sample.exe --function 140001020 --limit 50
ura-cli hex sample.exe --offset 200 --length 32 --json
ura-cli functions sample.exe --project analysis.ura --json
```

JSON responses carry `schemaVersion: 1`; addresses are strings. Operation errors
use a structured error object and exit code 1. Invalid command-line syntax uses
Clap's usage errors. `--help` documents per-command limits. The CLI reads project
names, manual starts and type/signature overrides without migrating the database.
Create projects through the desktop or MCP. CLI signature, stack-variable and
type-library edits require `--enable-writes` and an existing `--project`; use
`set-signature --input FILE`, `set-variable-type --function ADDRESS --offset OFFSET`,
or `type-library --import FILE`. Definition files use the shared structured
signature/type model and are limited to 1 MiB.
Analysis commands accept instruction/function/block limits, `--no-follow-calls`
and `--no-symbol-seeds`. IR pages include `irVersion:1`, binary identity, normalized
analysis options, source operations and the variable definitions referenced by the
page. Requests exceeding a function's IR budget return an explicit error.
Decompiler commands report evidence, conflicts, confidence and truncation; the
high-level command is explicitly labelled experimental.

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

After analysis, `ura_get_ir`, `ura_get_ssa`, `ura_get_dominators` and
`ura_get_analysis_diagnostics` take `handle`, `function`, optional `offset` and
`limit`. IR/diagnostic pages allow 1–500 rows; dominator pages allow 1–200.
Decompiler queries are `ura_get_function_signature`,
`ura_get_calling_convention`, `ura_get_stack_variables`, `ura_get_types`,
`ura_get_structure`, `ura_get_call_graph`, `ura_get_type_constraints` and
`ura_get_high_level_ir`. Overrides use `ura_set_function_signature`, `ura_set_variable_type` and `ura_set_type_library`. `ura_get_types` without `function` reads the project type library. `ura_get_structure` now takes `handle` and `name` and returns a real structure/union definition; the original high-level alias is superseded by `ura_get_high_level_ir`. CLI equivalents include `type-library --name NAME` and `type-library --import FILE`.
`ura_get_function` returns at most 500 blocks per call (`maxBlocks`, default 200)
plus at most 1000 callers/callees, and reports `blocksTruncated`,
`callersTruncated` and `calleesTruncated` when more exist. Requests reuse a
verified least-recently-used function cache, invalidated by reanalysis. At most
eight binary handles and two IR bundles per handle are retained.

`ura_save_project`, `ura_rename_function`, `ura_add_comment`,
`ura_export_analysis`, `ura_set_function_signature`, `ura_set_variable_type` and `ura_set_type_library`
require the explicit `--enable-writes` process option. Signature, stack and type-library
overrides also require that the target project is attached to the binary.
No network listener is started. Stdout contains MCP JSON only; logs go to stderr.
Read-only project attachments support schema v1-v5 without migration or following
the database's recorded binary path. The opened binary's SHA-256 must match.
Allowed roots constrain resolved paths, but are not an operating-system sandbox
against a concurrent local attacker changing files or links.

## Screenshots

Actual captures of URA's native renderer, using the deterministic regression
fixture (not simulated analysis):

The development IR view below was captured at Windows OS 150% scale:

![Native SSA IR at Windows 150% scale](docs/screenshots/ir-ssa-os150.png)

![Classic graph workspace](docs/screenshots/classic-graph.png)

![Classic linear disassembly](docs/screenshots/classic-disassembly.png)

![Professional dark graph](docs/screenshots/dark-graph.png)

See [verification](docs/VERIFICATION-0.8.md) for sizes, scaling and remaining
manual checks. The small fixture verifies known instructions and loop edges;
real Windows binaries were inspected separately.

## Project structure and architecture

| Path | Responsibility |
|---|---|
| `crates/ura-core` | Loading, decoding, functions, CFGs, references, strings, IR, decompiler foundations |
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
behavior, verified IR/SSA, ABI/stack/type/call-graph recovery, database
migrations and annotation persistence, service restrictions, CLI processes,
actual MCP handshakes/tool calls, and native-panel tessellation. Renderer checks
are opt-in; see [v0.8 verification](docs/VERIFICATION-0.8.md) and the
[v0.6 historical measurements](docs/VERIFICATION-0.6.md).

## Roadmap

Priorities are closing the idle-CPU blocker, expanding semantic/ABI validation,
relocation/import references and broader compiler-pattern recovery. Type inference
and structured control flow must precede decompilation. See the
[Ghidra source study and feature matrix](docs/GHIDRA-RESEARCH.md) for dependencies,
complexity and verification strategies. Multi-monitor DPI, cross-platform input
and broader executable-format coverage remain follow-ups.

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
