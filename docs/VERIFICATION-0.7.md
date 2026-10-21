# v0.7 development verification

## Decision

Ship the source checkpoint on `v0.7-advanced-analysis`, native version
`0.7.0-dev`. **Do not publish a v0.7.0 prerelease yet.** Variable CPU outside UI
painting remains unexplained. Windows stack profiling could not be enabled on
this host. Kernel/thread wakeup counts, GPU/presentation timing and controlled
input-to-paint latency remain unmeasured. These are explicit release blockers,
not claims that changing the IR fixed performance.

The baseline was clean commit `9d2b83ef2badca211ea37969c7e06adeb539d3ae`, tagged
v0.6.0, with all original 55 tests passing. Work stayed in the existing Rust
workspace. No original feature, icon, legacy source or user project was removed.
Only the requested development branch is pushed; no v0.7 tag, public release,
main-branch push or public build artifact is produced.

## Host and reproduction

Measured 2026-10-20 on Windows 11 Home 10.0.26200, Ryzen 5 7500F (6 cores / 12
threads), NVIDIA GeForce RTX 5060, Rust 1.99.1, MSVC toolchain. Compiler fixtures
use Clang/LLD 22.1.8. The system ntdll.dll file version is 10.0.26100.9549; SHA-256
`651ac9041af8e6b5ebd331d53163244c0a27d36d1433f0f15cac1f28c5f2e82c`.

Required code gates all passed after the final live-layout correction:

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
```

**94 tests pass**, including all original 55. Counts: binary inspection 8,
function/CFG 17, IR semantics 23, switch/flow recovery 7, CLI 6, actual MCP stdio
2, native 10, project persistence 9, service unit/integration 12. Native rendering
tests tessellate all 12 available panels in two themes at four size/scale
configurations, with actual IR rows preloaded. That is CPU-side rendering
verification, distinct from the live OS scaling checks below.

Semantic tests interpret actual lifted operations against independent arithmetic
and Boolean expectations. They cover partial registers/REX aliases, all 16 Jcc
conditions across flag combinations, wrap/overflow/carry/parity/AF, immediate and
register extension, FS memory, 32-bit segmented stack addresses, PUSH/POP ordering,
return adjustment, memory alias conservatism, unknown effects, phi/dominance
invariants and entry loops. Adversarial tests include forged SSA metadata,
invalid source ranges/targets/widths, overlapping jump targets, table truncation,
unbounded high index bits, resource stops and cancellation during finalization.

GUI worker, service, CLI JSON and actual MCP responses are compared to shared
core results. Cache reuse and invalidation, stale replies, read-only policy,
eight-handle limits, old project schemas, annotations and manual starts are tested.

Rebuild the original C switch fixtures with:

```powershell
./scripts/build-switch-fixtures.ps1
```

The four checked-in PE/ELF fixtures reproduced byte-for-byte on this compiler.
They were never executed. Optimized PE `-O1`/`-O2` and ELF `-O2` recover six targets.
The PE `-O0` spilled dispatch deliberately remains unresolved. This does not claim
cross-compiler or arbitrary-switch coverage. Fixture hashes and measurements are
in [the machine-readable record](benchmarks/0.7-development.json).

## Performance investigation

Reviewed eframe/winit repaint handling, AccessKit integration, worker scheduling,
progress channels, view/layout caches and persistence. The worker blocks on a
channel receive; there is no background polling loop, file watcher or recurring
analysis timer. IR work runs only on demand, off the UI thread. Graph uncertainty
summaries are computed with the cached worker layout. Cancellation is available
for IR tasks. No arbitrary sleeps, accessibility removal or forced idle repaints
were introduced as a performance fix.

Windows Performance Recorder was attempted before major feature work:

```text
wpr -start CPU -filemode
Failed to enable the policy to profile system performance.
Profile Id: CPU.Verbose.File
Error code: 0xc5585011
```

No trace was started. The process was not elevated; no system security or profiling
policy was changed. Per-thread CPU and start-module attribution were collected
instead. A thread's start module is **not** its sampled call stack or proof of
the underlying cause.

Each idle sample settled eight seconds, then measured only the selected URA
process without accessibility/screenshot polling during that interval. CPU is a
percentage of **one logical core**, not the entire 12-thread machine.

| Condition | Sample | CPU / one core | Working set |
|---|---:|---:|---:|
| Unchanged v0.6, ntdll, later control run | 12 s | 0.000% | 173.5 MiB |
| Development ntdll, startup selection | 20 s | 2.656% | 175.1 MiB |
| Development ntdll, linear repeat | 12 s | 1.693% | 161.7 MiB |
| Development ntdll, 42-block CFG visible | 12 s | 1.302% | 165.2 MiB |
| Same development process minimized | 12 s | 0.000% | 165.3 MiB |
| Saved fixture project open | 12 s | 1.432% | 83.6 MiB |

Earlier unchanged-baseline fixture/ntdll thread samples also recorded zero CPU.
These runs show variability, not a controlled before/after improvement. In the
20-second development sample, 0.484375 CPU seconds belonged to a thread starting
in `uiautomationcore.dll`, versus 0.046875 in an executable-started thread. In the
saved-project sample those figures were 0.125 and 0.046875 seconds. UI frame logs
recorded **zero painted frames between seconds 8 and 20** in both processes.
This supports investigating accessibility/provider activity outside painting;
it does not establish a root cause. The unchanged control also had a UI Automation
thread with zero measured CPU. Removing accessibility would change functionality
and was not used as a purported fix.

`scripts/profile-idle.py` launches a disposable isolated process and attributes
thread starts; `scripts/sample-idle.py` measures an existing selected process.
`--leave-open` allows native interaction and graceful shutdown afterward so frame
logs can be saved. Those logs count paints, **not OS wakeups**. Full wakeup/stack
profiling remains necessary before this blocker can close.

## Release-mode analysis measurements

```powershell
cargo build -p ura-core --release --example ir_benchmark
python scripts/benchmark-ir.py
python scripts/verify-mcp-release.py
```

Five repetitions per successful function; real-binary runs select the 64 largest
discovered functions. All verification work is included. The desktop was shared
with other applications; file caches were not controlled. These are observations,
not guarantees or cold-start claims. Peak figures are OS peak working sets
observed while polling the process every 5 ms, not peak private allocation.

| Work | CFG | Lift | SSA | Dataflow |
|---|---:|---:|---:|---:|
| Synthetic 101 instructions / 2,205 operations | 1.728 ms | 0.672 ms | 1.146 ms | 1.203 ms |
| Synthetic 1,001 instructions / 22,005 operations | 0.657 ms | 6.079 ms | 12.534 ms | 13.146 ms |
| Largest selected ntdll function: 1,768 instructions / 440 blocks | — | 2.594 ms | 9.622 ms | 12.465 ms |

First CFG rows can include decoder initialization, so the smaller synthetic CFG
is slower here. The 4,001-instruction arithmetic case exceeds 80,000 IR operations
and returns a budget error, not a partial verified function. The synthetic
process's observed peak working set was 23.3 MiB.

ntdll discovery took 249.492 ms for 200,000 instructions / 2,742 functions and was
explicitly partial at the configured instruction budget. Its 64 selected functions
all completed IR/SSA/dataflow; observed process peak working set was 96.5 MiB.
Aggregate lifting throughput was about 667,000 source instructions/s, including
unsupported barriers, not 667,000 fully modeled instructions/s.

Five CLI fixture startup+analysis observations had medians 9.401 ms (unchanged
v0.6) and 9.419 ms (development). The development first observation was 162.5 ms;
no startup speedup is claimed. Actual Release MCP listed 19 tools and returned
schema-1 IR/SSA/dominator/diagnostic results. Fixture query observations were
1.212 / 0.830 / 0.163 / 0.124 ms respectively, with caching after the first query.

## Actual Windows 150% DPI and native interaction

Changed **Windows Settings → System → Display → Scale from 100% to 150%** at
1920×1080 and verified the displayed OS setting. Application zoom was not used to
simulate this. Checked both during development and against the final build:

- Native fonts, File menu, command palette, function tooltips, dock tabs and separators.
- Function selection synchronized to real graph blocks/edges and disassembly.
- Hex byte/ASCII alignment and horizontal scrolling.
- Raw/SSA IR selection, typed rows and source-address navigation.
- Native open-file dialog, application window icon and version resources.

The live check caught IR initially opening in the narrow Functions leaf after a
function click. Initial IR placement now follows the Disassembly/Graph leaf;
existing user docking choices remain respected. A regression test covers that
workflow. The saved native version resource reports URA / Ultimate Reverse
Engineer / `0.7.0-dev`; official icon files have no diff.

The restored window could extend beyond the smaller logical desktop immediately
after changing DPI. Maximizing fit the complete workspace and status bar. This
was not presented as a successful restored-size/clamping test. Multi-monitor DPI
transitions and taskbar shortcut-cache behavior remain unverified. The original
100% Windows setting is restored after verification.

Actual captures are in [screenshots](screenshots/). They show real fixture
operations, not decompiler mockups. Live interaction checks establish usability;
they do not measure GPU time or precise input-to-paint latency.

## Dedicated self-review pass

A separate review pass followed implementation; this was self-review, not an
external human/agent review. Findings fixed and retested include:

- PUSH of SP snapshots the pre-decrement value; POP of SP writes after increment.
- Failed instruction lifts roll back temporary variables as well as operations.
- Missing direct destinations remain exits; a call target is not a function exit.
- Constant jump targets, full escaping state and source ranges are verified.
- Forged dominator metadata, version-0 definitions and invalid initial phi inputs are rejected.
- Def-use counts include terminators and no-output observable operations.
- Table targets are checked against earlier **and later** decoded boundaries.
- Block-budget results retain function ownership and prune dangling edges.
- Discontiguous function lookup and xref attribution use actual block ownership.
- Finalization cancellation is reported, and symbol-seeding configuration is honored.
- Stale IR replies cannot replace newer analysis; Cancel is enabled during IR work.
- Exit-state verification reuses a precomputed architectural set instead of rescanning all temporaries per block.

No runtime dependency was added; generated fixtures use original MIT-licensed
source. Ghidra findings and licensing are documented in [IR-DESIGN.md](IR-DESIGN.md).
No Ghidra implementation was copied. Project schema remains v3; caches rebuild
instead of migrating redundant IR. No secrets, private project databases, raw
host-path frame logs or system binaries are included in the source commits.

Remaining work: obtain usable stack/wakeup profiling and explain/fix idle CPU;
measure presentation/input timing; broaden independent ISA/compiler/ABI validation.
Instruction and jump-table limits remain as documented. A complete decompiler,
alias-sensitive memory SSA, relocation-aware switch recovery, type inference and
public plugin/debugger systems are not claimed.
