# URA 0.6 verification — 2026-10-20

Host: Windows x64, Rust 1.99.1. This report supersedes current-behavior claims in
the historical v0.5 report. Source recovery is recorded separately.

## Automated verification

- `cargo fmt --check`: pass.
- `cargo clippy --workspace --all-targets -- -D warnings`: pass.
- `cargo test --workspace`: 55 tests pass, none ignored or disabled.
- `cargo build --workspace --release`: pass, including the retained legacy app.

Coverage includes malformed/truncated PE/ELF inputs, known instruction encodings,
function/CFG/reference analysis, instruction overlap rejection, bounded reads,
v1/v2 migrations, v1 read-only snapshots, annotation/name/manual-seed persistence,
CLI processes and genuine MCP stdio processes. MCP tests perform initialization,
tool discovery, all query tools, errors, root/write denial, project creation,
rename/comment/export and attachment from a fresh read-only server.

Native tests tessellate all eleven panels in both themes at the requested sizes
and scale, and exercise stale-worker/graph rejection and saved-state reopening.
They are render/input-state tests, not substitutes for mouse/keyboard checks.
The legacy library was renamed to `ura_legacy` to avoid the pre-existing Windows
library/binary PDB filename collision; its executable name is unchanged.

## Actual native renderer and input

56 actual OpenGL captures were produced: seven panels × four size/scale cases ×
two themes. Cases: 1280×720, 1440×900, 1920×1080 at 100%, and 1920×1080 at 150%
application zoom. Representative captures are committed under `docs/screenshots`.
Inspected linear, graph and hex captures and the scaled listing; checked both
themes for geometry, text, selection, edges, overview and panel boundaries. The
disassembly heading was widened after inspecting an initial clipped capture.

Live Windows inspection used `ntdll.dll`, navigating from the function browser to
`RtlAppendPathElement` (169 instructions / 42 blocks in this bounded analysis).
Alt+F opened the real menu with project commands disabled when no project existed.
An Escape interception bug found during this check was repaired by explicitly
closing popups. The rebuilt app was rechecked: Escape closes the menu, the 42-block real
function graph renders, and Space returns to linear disassembly.
The binary reached the default 200,000-instruction limit; the UI correctly marked
the analysis partial. Uncertain/overlapping seeds remain diagnostic warnings.

The official artwork was seen in the actual window title/toolbar, and extracted
from the built Windows executable using the shell icon API. Version resources
report URA / Ultimate Reverse Engineer / 0.6.0. ICO entries are 16, 24, 32, 48,
64, 128 and 256 pixels. The image is also in About and the empty workspace.
Taskbar grouping/shortcut caching was not separately captured.

Reproduce renderer checks (use separate directories per theme):

```powershell
$env:URA_DISPLAY_CHECK = "$PWD/target/classic-captures"
.\target\release\ura-native.exe tests/fixtures/ura64.exe
$env:URA_DISPLAY_CHECK = "$PWD/target/dark-captures"
$env:URA_DISPLAY_THEME = 'dark'
.\target\release\ura-native.exe tests/fixtures/ura64.exe
Remove-Item Env:/URA_DISPLAY_CHECK
Remove-Item Env:/URA_DISPLAY_THEME
```

## Release-mode measurements

`cargo run --release -p ura-native --example measure -- tests/fixtures/ura64.exe
C:/Windows/System32/ntdll.dll` runs parsing, identity, analysis, strings and the
first 100 graph layouts three times. Baseline was captured before source edits;
final used the revised sources. Runs shared the desktop with compilation and
other workloads and were not controlled cold-cache experiments.

| Work | Baseline median | Revised median |
|---|---:|---:|
| Fixture parse | 0.130 ms | 0.086 ms |
| Fixture function analysis | 0.022 ms | 0.018 ms |
| ntdll function analysis | 457.092 ms | 230.794 ms |
| ntdll first 100 graph layouts | 2.147 ms | 3.191 ms |

Both ntdll runs reached 200,000 instructions / 2,742 functions and were partial.
No speedup is attributed to the changes: cache state and concurrent load differ.
Graph layout now sizes blocks to operands and includes up to 32 lines instead of
12; its additional measured work remains a few milliseconds for 100 functions.

Actual-renderer diagnostic runs forced repaints for capture only:

| Theme | Content ready | Mean frame UI CPU | Max UI CPU | Mean cached navigation |
|---|---:|---:|---:|---:|
| Classic | 317 ms | 1.267 ms | 8.797 ms | 0.0037 ms |
| Dark | 307 ms | 1.473 ms | 12.187 ms | 0.0041 ms |

These exclude GPU/presentation. Normal operation does not request those repaints.
Theme application is cached by settings, so style maps are not allocated every
frame. Visible rows are virtualized; graph layout remains on the background queue.

`scripts/measure-native.ps1` copies the Release executable, waits for a real HWND,
settles for eight seconds, then samples process CPU for twenty seconds without
input or accessibility polling. Initial measurements: fixture 0.936% of one CPU
core, 89.2 MiB working set; ntdll 1.169–1.560%, 175.8–236.5 MiB. HWND times were
377–419 ms. A separate 238,247,784-byte Code.exe run used 438.75 MiB working
set, opened a window in 394 ms and sampled 3.035% of one core over 10.3 s. Working sets are process measurements, not peak private allocation.

An instrumented run showed variable process CPU (3.737%, and an earlier 9.822%)
despite only one UI frame after the eight-second settle, at shutdown. The main
UI rendered no continuous idle loop; post-startup UI frames stopped near 1.4 s.
Per-thread samples confirmed CPU outside the paint loop. The previous report's
near-zero process CPU was not reproduced consistently. Platform/driver or
background-thread profiling remains required before claiming an idle-CPU
improvement. No sleeps or repaint throttles were added to mask that behavior.
The optional idle recorder never requests a repaint and is disabled normally.

## Separate review and release hygiene

After implementation, reviewed the diff for mapping overflow, overlapping
instructions, database migrations, path/write policy, stale worker results,
misleading menus, graph clipping and resource integration. Fixed section-crossing
reads, read-only migrations/recorded-path IO, menu Escape handling and zoom limits
that prevented fitting large graphs. Existing project schemas remain unchanged.

Reviewed tracked/untracked files and historical diffs for credential/private-key
patterns and local user paths; no matches were found. Only generated PE/ELF
regression fixtures are included. Build outputs, local projects and acquired
system binaries remain ignored. Icon redistribution permission was confirmed by
the owner. Existing MIT licensing was preserved. The native/CLI/MCP dependency
closure has declared licenses; bundled and pinned-upstream notices are collected
by `scripts/collect_licenses.py` for packaging.

## Remaining limits

- 150% is application scaling, not an OS DPI-setting change; real OS-level DPI,
  GPU timing and multi-monitor behavior remain manual checks.
- Dialog typing, tab dragging, focus traversal and platform-specific taskbar
  shortcut caches need broader interactive coverage.
- Linux/macOS and broad Mach-O/non-x86 metadata coverage are not verified here.
- Analysis caches are in memory. Indirect transfers, shared function tails and
  jump tables remain conservative/unresolved. See the research matrix.
- MCP calls are serialized; cancellation/progress and string-scan caching are
  future work. Root checks are not a concurrent local-attacker sandbox.
