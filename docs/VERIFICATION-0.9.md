# v0.9 engineering checkpoint verification

**Current continuation:** [v0.9 finalisation](FINALISATION-0.9.md) records the
subsequent readability/instruction work, 260 passing tests, updated measurements
and remaining release gates. The results below describe the earlier `bc73e7f`
checkpoint and are preserved as its baseline, not silently applied to later builds.

Version `0.9.0-dev`, branch `v0.9-c-decompiler`, starting from the v0.8
qualification checkpoint `b1a05c7`. Verification date: 2026-10-22. The source
checkpoint is publishable to its development branch; **the v0.9 milestone and
public prerelease are not accepted as complete**. No existing release/tag/asset
is replaced. The exact pushed commit is reported with the final checkpoint.

## Automated gates

| Gate | Result | Evidence |
|---|---|---|
| Formatting | Passed | `cargo fmt --all --check` |
| Strict Clippy, workspace/all targets | Passed | `cargo clippy --workspace --all-targets -- -D warnings` |
| Workspace tests | **251 passed, 0 failed** | All existing 237 retained; final complete workspace run |
| Workspace Release build | Passed | `cargo build --workspace --release` |
| Core Release examples | Passed | `cargo build -p ura-core --release --examples` |
| Independent semantic checks | Passed for documented subset | Raw IR, semantic HIR and C-like AST execution; [scope](C-DECOMPILER-0.9.md) |
| CLI processes | Passed | Text/JSON decompile and exact shared-service comparison; existing CLI suite |
| MCP stdio processes | Passed | 32 tools, unchanged legacy queries, C-like pages/AST/export, denied writes |
| Project persistence | Passed | Signature/stack/type library round trips and native-edited project reopened independently by CLI |
| Native render tests | Passed | All panels in both themes/logical scales; these do not establish OS DPI acceptance |
| Independent review | Completed and fixes tested | Read-only agent review of AST, copies, reducer, emitter, use counts and service/export integration |

Final raw gate logs are retained under `target/v09/`. Build resources on native,
CLI and MCP all report product URA and version `0.9.0-dev`. Compiled C/C++ inputs
are owned fixtures, parsed statically and never launched. Current compiler corpus
is Clang PE/ELF O0/O1/O2/O3; MSVC/GCC/debug-symbol comparison remains unverified.

Review repairs include signed formal operands, call snapshot use counting,
overwritten register identity, repeated name disambiguation, physical jump maps
through linear/diamond reductions, unsupported call formal types, and explicit
non-native pointer widths. The independent reviewer reported no further concrete
execution defect in the restricted reducer; this is not proof of general coverage.

## Live native checks

The Release desktop was actually launched against disposable schema-5 projects
and the PE loop fixture, with isolated application persistence. Existing user
projects and the user's other URA instance were not edited. Current host scaling
is 100%; no display/security/accessibility configuration was changed.

| Workflow | Current evidence |
|---|---|
| Open binary/project, analyze, switch functions | Passed with the owned PE fixture |
| F5 opens Pseudocode | Passed; stable legacy dock identity retained |
| Main-workspace layout | Passed after fixing the inherited narrow inspector default; old saved layouts are preserved and Reset layout adopts the new default |
| Pseudocode → assembly | Arithmetic line navigated to `0x140001026`; assembly selected the matching ADD |
| Assembly → pseudocode | Selected CMP `0x140001029`; F5 highlighted contributing source lines |
| Signature edit/cache refresh | Saved `u64` return override and observed refreshed declaration/status |
| Stack name/type edit | Saved `saved_frame`/`u64` at offset -8; stack view and source store annotation refreshed |
| Structure editor | Edited Header field to `payload_length`; existing offset/width preserved |
| Project save/reopen | Saved workspace, closed app, reopened same project with final build; selected function, source annotation and type library persisted. CLI separately checked all three edits |
| Whole-function native export | File dialog wrote a complete 1391-byte C-like function including declarations/return/closing brace, before the later stack-name edit |
| Themes/window bounds | Classic and dark observed; maximized 1920-wide workspace rendered controls and source correctly |
| Stack/diagnostic controls | Moved above the expanding source viewport; final-build live check confirmed the stack editor buttons remain visible |
| Actual OS 150% | **Unverified**; supported Settings surface remained inaccessible. See the exact [manual checklist](RELEASE-QUALIFICATION-0.8.md) |
| Full drag/resize matrix, large-function live latency, cancellation during an expensive live operation | **Not fully verified**. Automated worker/render/budget checks and headless large-function measurements are separate evidence |

UI Automation sometimes returned pre-layout element indexes or a transient 16px
surface beside the real dialog. Verification recovered from fresh window/screenshot
state and checked final effects independently. These observations are not treated
as application correctness failures or as accepted latency measurements.

## Performance

The retained v0.8 harness and current harness used identical sample hashes,
sequential Release processes, warm file cache and three repetitions per pass.
No Cargo build or UI polling ran during the benchmark. OS peak working set was
sampled at 5ms intervals. [Raw sanitized measurements](benchmarks/0.9-c-decompiler.json)
include unchanged fixture and system-image inputs and executable hashes.

For the same NTDLL function `0x1800AA290`, 1768 instructions/440 blocks:

| Measurement | Retained v0.8 | v0.9 |
|---|---:|---:|
| Legacy HIR construction | 10.29 ms | 9.83 ms |
| Semantic HIR lowering | 8.75 ms | 8.37 ms |
| Program/type propagation | 117.22 ms | 107.85 ms |
| Full function pipeline | 171.61 ms | 188.88 ms |
| C-like construction including formatting | — | 24.55 ms |
| Formatting existing C-like AST | — | 7.43 ms |
| Observed peak working set, entire harness | 169.52 MiB | 181.91 MiB |

Current IR lift/SSA/dataflow measurements were 2.72/9.75/12.02 ms. The pipeline
increase is about 10.1%, with an added C-like AST/line pass; peak working set
rose about 7.3%. The individual timings are isolated measurements, not additive
exclusive pipeline stages. The bounded interprocedural solver remains the
largest measured cost. No claim of overall speed or memory improvement is made.

This function produced 15,585 C-like lines and a 7.86 MB serialized AST; full AST
transport correctly requires the 2 MiB guard, while line queries remain paged.
Large output still exposes many machine temporaries/flags. A subsequent native large-function attempt reached the selected 1768-instruction/440-block function and showed background recovery, but the verification window disappeared before the final pseudocode/scrolling check. No native panic log was present; the live acceptance result remains unverified. A bounded renderer is
not evidence that this output is readable or that live scrolling latency passed.

Five-process fixture CLI medians (startup included): v0.8 signature/highlevel
22.91/22.16 ms; v0.9 signature/highlevel/decompile 22.04/22.76/22.60 ms. Outliers
were retained. MCP fixture queries and full export round trip were exercised in
the actual Release server; timings are process-local, not general service SLAs.
GPU/presentation timing and OS wakeup counts remain unmeasured. The v0.8 idle
record remains separate; current idle observations do not establish a regression
or explain its previously intermittent CPU behavior.

Current loaded-fixture idle samples (12 seconds each after an 8-second settle,
no UI polling/build activity) measured 1.82% of one core focused, 0% unfocused
and 0% minimized, at approximately 94 MiB working set. The v0.8 qualification
sample used an empty workspace, so this is not a matched before/after result.
The intermittent focused CPU behavior remains unexplained. See
[the sanitized idle record](benchmarks/0.9-native-idle.json).

An actual Release CLI query of the 15,585-line NTDLL function returned its
requested 20-line page in about 494 ms including process startup and binary
analysis; requesting its full AST returned `limit_exceeded` at the transport
budget. This confirms the real large-response guard, not live GUI latency.

## Coverage, package and release decision

[FEATURE-PARITY.md](FEATURE-PARITY.md) inventories **129 capabilities**:
**17 Supported, 51 Partial, 57 Missing, 4 Unverified**, within explicitly stated
architecture/platform coverage. These are ledger counts, not a parity percentage.
[ROADMAP.md](ROADMAP.md) retains full parity as a permanent objective and puts
decompiler refinement before patching/debugging/deobfuscation stages.

The local engineering ZIP contains the native Desktop, CLI and MCP Release EXEs,
matching version resources, official icon, documentation and collected dependency
licenses. Clean extraction, all-file hashes, actual extracted CLI/MCP queries and
the package checksum are recorded externally beside the archive by
`scripts/verify-audit-package.py`. Check the final checkpoint report for its exact
path/hash. Local packaging is not GitHub release publication.

The mandatory current 150% OS DPI gate remains unverified, and broader live
large-function/cancellation acceptance is incomplete. Source-local coalescing,
named structure fields, canonical loop/switch/short-circuit syntax, broad call
effects and floating/vector/aggregate semantics also remain partial or missing.
Therefore **no v0.8.0-dev.1 or v0.9.0-dev tag/public prerelease is created**. A
published URL, public ZIP download and re-downloaded checksum are inapplicable.
The existing v0.8 release is preserved. Resume from this verified source checkpoint
and close the documented gates before publishing an accepted artifact.

## Local package audit record

The 16,398,140-byte engineering archive is
`target/v09/checkpoint-package/URA-0.9.0-dev-windows-x64.zip`.
SHA-256: `75976cb1cd1d9ddd0a537dd9c26079c63716561bbd640ca67eaa74b926cb7c09`.
All 576 manifest files/ZIP CRCs passed, 277 dependency packages had bundled
notice files with zero missing texts, and extracted CLI/MCP decompile/AST/export
round trips passed with 32 tools. All three extracted images matched the tested
Release images byte for byte and reported version `0.9.0-dev`.
[Sanitized package record](benchmarks/0.9-package.json) lists individual image
hashes. Native startup from the extraction itself is unverified; its image
identity matches the final build used for the live fixture checks. Archive docs
were frozen before this external audit record, as usual for a package checksum.
This is a local engineering candidate, not an accepted public release.
