# v0.8 audit verification

Verified 2026-10-21 on Windows 11 x64 with Rust 1.99.1/MSVC. Starting source:
`1194403`; baseline: `1d0f484` / `v0.7.0-dev`. Initial working tree was clean
and all initial 122 tests passed. The complete requested v0.8 checklist remains
unfinished; see [AUDIT-0.8.md](AUDIT-0.8.md).

## Code gates

**161 tests pass**, preserving all original tests. The original assertions
expecting an invented integer return and a cdecl Win32 API default were corrected
to assert unknown return provenance and stdcall respectively. No tests were removed.

| Area | Passing tests |
|---|---:|
| Core unit helpers | 14 |
| Binary parsing | 8 |
| Original decompiler integration | 4 |
| Independent decompiler regressions | 26 |
| Type-library/width/layout regressions | 4 |
| Functions/CFG | 17 |
| IR/SSA/dataflow | 25 |
| Jump tables/tail/thunk | 7 |
| CLI process integration | 8 |
| MCP stdio integration | 2 |
| Native worker/navigation/render/editor | 16 |
| Project persistence/migration | 12 |
| Service unit/integration | 18 |
| **Total** | **161** |

Formatting, strict workspace linting, tests and Release builds were run:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
cargo build -p ura-core --release --examples
```

After the live check found small stack-edit fields and missing table scrolling,
explicit field widths and horizontal scrolling were added; native tests and the
Release build were repeated. Independent findings and exact semantic cases are in
[REVIEW-0.8.md](REVIEW-0.8.md).

Tests check loop convergence, SP/FP joins, real x86 frames, dynamic/unsupported
addressing, saved-register provenance, shared ABI registers, self-canceling
instructions, conflicting hints/cleanup, opaque-call returns, repeated call sites,
indirect calls, sign extension and unresolved floating returns. Type tests check
widths, cyclic layouts/aliases, size overflow, alignment and real field extents.
Editor regressions preserve structured types, pointer/enum widths, explicit field
storage/provenance, stack-location widths and unknown variadic state.

## Persistence and adapter checks

Schema v5 adds a validated user type library to the v4 signature/stack overrides.
Tests migrate v1-v4 projects, preserve user data, reject invalid writes without
replacing saved definitions and verify read-only attachment leaves the file intact.
Old executables cannot read a project after it has migrated to v5.

Native workers, service, CLI and MCP still use one core engine. Tests compare
results and exercise explicit write denial, binary/project identity, allowed
roots, cache invalidation, save/reopen and MCP restart. The Release MCP process was
initialized and queried over actual stdio: 30 tools, schema 1, IR/SSA/diagnostics,
decompiler queries, call graph and a real structure save/read round trip.
`ura_get_structure(handle,name)` now returns fields, not a high-level text alias.
The disposable project is `target/v08-audit/fixture.ura`; no user project is used.

A further regression uses two projects for the same binary and verifies that
override writes cannot silently switch projects or mix their inferred contexts.
The target project must already be attached; rejected writes preserve its bytes.

## Live desktop check

The actual rebuilt app opened the disposable project, recovered its functions and
displayed the new panels. The signature editor changed the entry function return
type to `u32`; Save updated the visible declaration and showed a user-authored
signature. A fresh CLI process using the same project and a restarted desktop
loaded the override. The stack editor and instruction references were inspected.
A narrow-window check exposed and prompted the field/scroll fixes above.

Native rendering tests cover all panels in two themes at four size/scale
configurations. This audit did not repeat v0.7's actual OS 150% DPI exercise or
complete a live matrix of every form, keyboard path and complex project. No full
GUI acceptance is claimed. Desktop verification uses isolated preferences.

## Release measurements

Full observations: [benchmarks/0.8-audit.json](benchmarks/0.8-audit.json).
Reproduce with `benchmark-decomp.py`, `profile-idle.py`,
`verify-mcp-release.py` and the Release core examples. Samples are never executed.

NTDLL SHA-256 matches the v0.7 sample:
`651ac9041af8e6b5ebd331d53163244c0a27d36d1433f0f15cac1f28c5f2e82c`.
Discovery reaches the 200,000-instruction budget (2,742 functions), so it is partial.
Five repetitions per isolated pass:

| Measurement | Observed |
|---|---:|
| Discovery in IR harness | 233.409 ms |
| Call graph, 8,728 retained sites | 30.045 ms |
| Largest tested function | 1,768 instructions / 440 blocks |
| Lift / SSA / dataflow | 2.659 / 9.668 / 12.523 ms |
| Stack / ABI / types / structural display | 1.118 / 7.974 / 1.250 / 10.761 ms |
| Display output for that function | 8,198 lines / 2,092 unresolved markers |
| Successful NTDLL IR / decompiler timing cases | 64 / 16 |
| Observed peak working set, IR / decompiler | 96.207 / 97.848 MiB |

Decompiler timings begin with a verified bundle and omit the second stack pass
and constraint merge. Peak working set is observed every 5 ms; a short process
can finish before a sample. PE O0/O2 and optimized ELF switch fixtures were also
measured. A whole-program propagation benchmark is unavailable because that
solver does not exist yet.

Five CLI process invocations per condition, warm OS cache, startup plus query:

| Fixture query | Public v0.7 median | Audit median |
|---|---:|---:|
| Analysis | 8.633 ms | 8.637 ms |
| Raw IR | 9.240 ms | 9.516 ms |

The first new analysis invocation was an outlier at 201.749 ms versus 14.472 ms
for the first already-extracted baseline invocation. These are not controlled
cold-start measurements. No speedup is claimed; the JSON retains all observations.

Single Release MCP fixture queries measured 0.533 ms for initial signature
recovery, 0.160 ms for cached stack and 0.186 ms for cached high-level rows.
These small-fixture examples are not latency distributions.

## Idle CPU risk

The unchanged public v0.7 ZIP matches GitHub's SHA-256
`5006470762f209499da5514d5be722961e51c02119917743cf663d8f78678ed6` and its
annotated tag resolves to `1d0f484`. Both native builds opened the same NTDLL
with isolated default preferences. After eight seconds settling, each was sampled
for 12 seconds, with no GUI polling or compilation during sampling:

| Version | CPU, one logical core | Working set |
|---|---:|---:|
| v0.7 | 0.0% | 172.609 MiB |
| Audit | 0.0% | 170.242 MiB |

Percent is process CPU seconds / wall seconds * 100, not a whole-machine Task
Manager percentage. Zero means no measured delta at Windows counter resolution.
One matched condition does not explain or fix the earlier intermittent CPU issue.

WPR was initially idle. CPU profiling failed again with `0xc5585011`:
"Failed to enable the policy to profile system performance." No session started,
and no policy, security or accessibility setting changed. Start-module attribution
is not a stack trace. OS wakeups, context switches, GPU/presentation and
input-to-paint latency remain unmeasured.

## Artifacts

The existing public `v0.8.0-dev` ZIP was downloaded again; GitHub and sidecar
match SHA-256 `8d484cbf08225816e11f7a9b7f20970da866115aeb708c01a28f841bc9f03af0`.
Its tag still points to `1194403` and the archive predates these repairs.

The corrected package is a local audit artifact under `target/v08-audit`, with
three Release executables and a SHA-256 sidecar. Packaging uses a separate clean
extraction and checks nested file digests, executable resources, CLI JSON and
actual MCP stdio. Generated `package-verification.json` records the final hash
and outcomes. No existing release tag/archive is replaced. A new accepted public
release is withheld while the semantic gaps in AUDIT-0.8.md remain.

At the user's request, final artifact checks do not launch the native application
or use desktop automation. Its packaged image is compared byte-for-byte with the
previously built/tested Release image; clean-extraction desktop startup is not
repeated under that restriction.
