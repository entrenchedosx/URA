# URA v0.5 native verification

Date: 2026-10-20. Scope: `ura-native` (eframe/egui) on Windows 11 x64, built in
Release mode with Rust 1.99.1. The legacy `ura-app` was not exercised here; its
retirement gate remains open.

## Automated checks

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets -- -D warnings`: pass.
- `cargo test --workspace`: 37 tests pass (8 core API, 12 analysis, 9 native,
  8 project). No test was skipped or ignored.
- `cargo build --workspace --release`: pass. Current artifact:
  `target/release/ura-native.exe`, 12,897,280 bytes,
  SHA-256 `7C95E92806034A58E935380EA4B934CA3A5B5F9556C441265C4E996F8270AC8A`.
- Fixture `tests/fixtures/ura64.exe`, SHA-256
  `B3AF30012BBCD6FC3186EF5B65D3C8460BC09CADE3870A614FBF2BD3D41EB92D`
  (also shown in the Overview panel).

The native tests cover stale worker results, old-analysis graph rejection,
navigation history bounds, deterministic graph layout, project annotation/name/
manual-seed persistence across reopen, legacy v0.4 view-state restoration, and
tessellation of all ten panels at the required sizes and scales.

## Actual-window renderer check

Display-check mode (`URA_DISPLAY_CHECK`) captured the OpenGL renderer, not a
mock: 28 PNGs (7 panels × 1280x720, 1440x900, 1920x1080 at 1.0, and 1920x1080 at
1.5 application zoom). Output: `target/native-display-check/`.

- Ready after load: 333 ms.
- 2,031 frames sampled; UI CPU 0.57 ms min, 1.52 ms average, 13.65 ms max
  (`eframe` previous-frame value, excluding GPU/presentation).
- 287 cached-navigation samples: 0.008 ms average, 0.109 ms maximum.
- Screenshots were inspected for Disassembly, Functions, Graph, Hex, Strings,
  Overview and Xrefs at 1440x900. Explorer, Inspector and Messages were present
  in the same dock captures. Instructions, blocks, call/data references, mapped
  and unmapped strings, hex rows and the loop CFG render correctly.

The 1.5 case is application zoom, not an operating-system DPI change. The
metrics exclude GPU presentation. These captures do not replace input testing.

## Idle CPU investigation

The v0.5 report listed an unexplained idle CPU spike. The paint path was audited:
normal operation has no unconditional repaint. Background tasks call
`request_repaint` only when a reply or throttled progress update exists
(`worker.rs`); the 16 ms repaint is confined to the opt-in display check
(`diagnostics.rs`). Spinners only animate while their operation is loading.

Measurements use Release builds, a visible main window, an eight-second settle
after the window appears, and `TotalProcessorTime` deltas. Results:

| Input | Sample | CPU (one core) | Working set |
| --- | --- | --- | --- |
| `ura64.exe` (1.5 KiB) | 20 s, ten 2 s intervals | 0.156% average; two intervals at 0.78%, eight at 0.00% | 89.1 MiB |
| `ura64.exe`, minimized | 20 s | 0.000% | 88.2 MiB |
| `ura64.exe`, restored | 10 s | 0.000% | 88.2 MiB |
| `ntdll.dll` (~2.3 MiB) | 20 s | 0.000% | 174.5 MiB |
| VS Code `Code.exe` (~238 MiB) | 20 s | 0.000% | 436.7 MiB |
| `Code.exe`, benchmark environment, first run | 6 s after settle | 0.520% (0.031 s) | 435.4 MiB |
| `Code.exe`, benchmark environment, second run | 6 s after settle | 0.000% | 435.8 MiB |

The fixture's two 0.78% intervals are 15.6 ms of CPU each and recur near the
ten-second auto-save cadence; the 20-second total is 31 ms. The earlier
13.78% first-run sample was not reproducible with warm caches, a fresh copied
238 MiB image, a cold persistence directory, repeated launches, or the current
Release build. It is consistent with first-launch initialization/caching, not a
continuous repaint loop. The historical 100% benchmark rows could not be
reproduced and the original benchmark method did not separate first-launch work
from steady state.

No app code change was required for the current sources. The benchmark should be
treated as a process-level comparison only: it uses a fixed settle interval and
does not prove analysis completion. A first run must not be reported as idle CPU.

## Not verified

- Real OS-level 150% DPI (the 1.5 capture is app zoom only).
- GPU/presentation time and frame pacing.
- Live mouse/keyboard workflow on the current desktop: synthetic focus injection
  reached the window intermittently, so no claim is made for dialogs, drag/drop,
  rename typing, docking gestures or focus traversal. These remain manual checks.
- macOS and Linux hosts.

## Reproduce

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release

$env:URA_DISPLAY_CHECK = "$PWD/target/native-display-check"
.\target\release\ura-native.exe tests/fixtures/ura64.exe
Remove-Item Env:/URA_DISPLAY_CHECK
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for the desktop benchmark script and its
known limits.
