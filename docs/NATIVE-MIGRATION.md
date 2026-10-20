# URA v0.5 native migration audit

Baseline: `e052fad`, `v0.4-professional-workspace`. Native work lives on
`v0.5-native-rust`. The original frontend remains available until the retirement
gate is satisfied. The untracked `icon.webp` is unrelated to this migration.

## Architecture and reuse

`ura-core` owns read-only PE/ELF/Mach-O parsing, mapping, x86/x64 decoding,
bounded recursive function discovery, CFGs, incoming/outgoing code and data
references, strings and hex reads. It has no Tauri dependency. `ura-project`
owns SQLite schema v3, binary hash verification, annotation and function naming,
manual seeds, JSON export and view state. It also has no Tauri dependency.
Neither engine nor schema needs replacement.

`src-tauri` owns application state, asynchronous command wrappers and progress
events. `commands.rs` exposes open/close, startup path, disassemble, hex, strings,
project create/open, annotations, selected address, view state and export.
`analysis.rs` exposes analysis/cancel/status, functions/query/detail, CFG, xrefs,
rename and manual seeds. Most DTOs stringify addresses for JavaScript; the native
UI can use core references and u64 addresses directly.

React session context owns binary/project, shared selection, current function,
analysis progress, names, strings, annotations and bounded navigation history.
Workspace context routes focus/toggle/reset intents to Dockview. Settings and
Dockview layouts live in WebView localStorage, separately from the project DB.
Dockview provides movable/closable tabs, split resizing and per-project layouts.
The native layout format is different; existing web layouts cannot be interpreted
as egui trees. They remain untouched for baseline comparison.

## Parity inventory

Views: Explorer (sections/symbols/imports/exports/functions), linear disassembly,
function list, CFG, strings, hex, overview, xrefs, inspector/annotations, messages.
Workflows: opening binaries and `.ura` projects, startup argument, background
analysis with progress/cancel and partial-result diagnostics, manual function
seeds, name overrides, annotations/delete, export, symbol/address/offset/relative/
section navigation, pasted hex bytes, navigation history, synchronized selection,
palette, preferences, reset/reopen panels and persistent layouts.

Shortcuts: Ctrl+O binary, Ctrl+Shift+O project, Ctrl+N create project, Ctrl+K palette,
Ctrl+G go-to, Alt+Left/Right history, Ctrl+, settings, Ctrl+1..4 primary views,
Ctrl+Enter annotation save, F2 rename, Escape dismiss, arrows/PageUp/PageDown
instruction selection and Enter palette execution/branch following.

## Persistence contract

Keep every v1/v2/v3 SQLite migration. Keep recorded binary path/hash checks,
missing/modified status and export overwrite protection. Native state extends
the existing v1 JSON view state with a `native` object, retaining compatible
address/fileOffset/history/activePanel/openPanels fields. Native panel trees and
settings use eframe persistence. No writes are made to sample binaries.
Browser-only preferences/layouts remain in localStorage; native defaults start
fresh. Project annotations, names and manual functions remain portable.

## Smallest change

Add `ura-native`, directly depending on core/project plus eframe/egui,
egui_dock, egui_extras and rfd. Use a serial background job queue, shared immutable
binary/analysis data, cancellation tokens, stale-result generations and repaint
notifications. Cache decoding and graph geometry outside paint loops; virtualize
rows and read only visible bytes. Keep engine independent of all GUI types.

## Retirement gate

Do not remove the old application until native parity, real Windows visual/input
checks and comparable Release performance evaluation have passed. Incomplete
measurements or unverified behavior must be reported explicitly. The current
results, including the idle CPU audit and the checks that remain open, are in
[NATIVE-VERIFICATION.md](NATIVE-VERIFICATION.md).
