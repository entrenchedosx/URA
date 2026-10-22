# v0.10 development checkpoint verification

Date: 2026-10-22. Version `0.10.0-dev`, branch `v0.10-binary-patching`.
The prior 263-test source checkpoint was committed and pushed as
`61ee8a4c67f58f4edb66d6eb4a76a685cfe8b060` on `v0.9-c-decompiler`.
No working tree reset, test deletion, main-branch update or published-release
replacement was performed. The owner's desktop-control restriction remains in
effect. This is a development source checkpoint, not an accepted public release.

## Implemented and verified scope

The shared Rust engine implements immutable originals, sparse byte overlays,
fixed-size proposals, expected-byte/identity/mode/revision guards, atomic
transaction validation, overlap rejection/intentional replacement, stable IDs,
undo/redo, individual revert and undoable sparse revert-all. Original/current
bytes and history remain inspectable. PE32/PE32+, ELF32/ELF64 and explicit raw
file mappings are supported with documented restrictions. Layout tables are
protected; zero-fill, ambiguous/cross-boundary mappings and invalid ranges reject.

Instruction previews use iced-x86's encoder and decode the result to compare
typed operands at the actual origin. Supported text covers the documented
register/immediate operations, direct calls/jumps and all Jcc condition families.
NOP padding is explicit. Memory syntax, labels, relocation rebuilding, section
insertion and live-process patching are not implemented. LLVM-generated owned
32-bit PE/ELF fixtures provide an independent immediate-encoding oracle; fixed
expected branch opcode/displacement vectors cover origin handling.

Schema6 patch history persists separately from annotations/types. It restores
applied and redo history only against the original hash and matching raw settings.
Optimistic revision checks prevent stale handles replacing newer project state.
Save-as/attach transitions preserve or rehydrate the correct overlay. Native
mutation workers invalidate all analysis, block stale-byte requests and reject
old generations; failures reload the persisted project. Fresh disassembly, CFG,
IR and C-like output reflect a changed return instruction. Annotations keep
original address anchors and are labelled for review, without claiming semantic
reattachment to rewritten instructions.

Binary export preserves file length and every untouched byte, streams to a
same-directory temporary file, syncs, verifies, reparses and hashes before
new-file-only publication. Original identity checks are bounded/streamed. Existing
destinations and original-file overwrite are rejected. Cancellation does not
publish a partial executable. Signing/checksums may become invalid; parsing never
establishes successful execution. All samples were parsed, never executed.

Desktop has a functional Patch Manager, selected byte-range editor, instruction
editor, preview/apply/cancel, difference colouring, navigation/history/conflict
state and worker exports. Direct raw-file configuration is currently CLI/MCP;
Desktop can open prepared raw projects. There is no live v0.10 GUI acceptance.
CLI/MCP route to the same core. MCP exposes 39 tools, preserves read-only defaults,
and requires explicit writes, paths, handles and an attached matching project for
mutations. The transport remains serialized with no asynchronous cancellation API.

See [complete design and limits](BINARY-PATCHING.md), [CLI](CLI.md), [MCP](MCP.md)
and [architecture](ARCHITECTURE.md).

## Automated and executable verification

- **287 tests passed, 0 failed** with `cargo test --workspace --locked`.
  The original 263 tests are retained. New tests cover core byte/history/export,
  mappings/encoding, schema migration/corruption, service cache/project boundaries,
  actual CLI/MCP transport and native worker/render behavior.
- Core tests cover stale expected bytes/previews, whole-transaction rollback,
  overlaps, sparse reset, undo/redo tail replay, raw mode/base mismatch, 32-bit
  address limits, lossless high addresses, malformed PE headers, invalid assembly,
  relative calls/jumps, explicit padding, boundaries, cancellation and original
  preservation. PE/ELF 32/64-bit controlled fixtures are parsed statically.
- Native headless tests verify patch/reopen/reanalysis/undo, annotation preservation,
  blocked old-byte reads, failed-transaction recovery, unrelated-job busy state,
  all panels at required themes/scales and a virtualized 4096-transaction list.
- Actual Release CLI/MCP audit passed preview/apply, stale rejection, history,
  exact-byte export/reimport, manifest export, original-file preservation,
  read-only denials, ELF32 and raw project round trips. CLI/MCP exports match.
  [Sanitized evidence](benchmarks/0.10-headless-release.json) includes EXE hashes.
- `cargo fmt --all -- --check`, strict workspace/all-target Clippy with
  `-D warnings`, locked workspace tests and optimized workspace compilation passed.
  Build/test logs are retained locally under `target/v10-*`.

## Independent review and fixes

Separate read-only engineering agents reviewed core/service and native/interface
changes. Findings repaired with regression evidence included: effective metadata
on reopen, save-as/attach history, malformed PE header protection, sparse reset
limits, recursive assembly literals, 32-bit region wrap, high-address JSON,
MSRV compatibility, bounded original reads, raw preview/project interpretation,
stale disassembly jobs, failed-commit recovery, new-project race protection,
paint-path overlap cost and export busy state. The final raw identity and
new-project guards were reviewed locally and regression-tested after the separate
reviews; a further independent pass on those last adjustments is not claimed.
No security/critical corruption finding is knowingly left unresolved.

## Measured performance

[Three sequential Release runs](benchmarks/0.10-patching-performance.json) used a
16 MiB raw original and a 1 MiB changed range, with no Cargo or UI polling during
timing. Median single-byte preview/apply: **0.0086 ms**; undo **0.0014 ms**, redo
**0.0011 ms**. Median 1 MiB preview/apply: **52.93 ms**. Verified 16 MiB export:
**56.84 ms**, about **281.5 MiB/s**. Restore including original hashing: **74.82 ms**.
Observed process peak: **112.55 MiB**, including fixture allocations, overlay,
history, export and reparse; this is not isolated overlay overhead. The small PE
fixture's reparse/CFG/pseudocode took **0.29 ms**, patch-project save **2.32 ms**,
and read **0.82 ms**. No cross-machine speed claim follows from these samples.

[Headless Release Patch Manager rendering](benchmarks/0.10-patch-manager.json)
constructed/tessellated virtualized 4096-transaction views at simulated 1.0/1.5
scale in both themes. First frames: 2.0–4.1 ms; subsequent sampled frames:
0.15–0.35 ms. These are headless CPU timings, not native input/GPU/presentation
measurements or the real OS DPI gate. Sparse editing avoids a full file copy per
byte, while accepted transactions conservatively materialize/reanalyse a whole
snapshot. Larger files, fragmented history and whole-image reanalysis still need
broader workload profiling.

## Parity and outstanding release gates

The ledger now tracks **132 capabilities: 17 Supported, 59 Partial, 52 Missing,
4 Unverified**. Seven patch rows moved Missing to Partial; kernel debugging,
conditional breakpoints and memory capture were added as explicit Missing
obligations. These counts describe the ledger, not an overall competitor parity
percentage. Full assembly syntax, precise incremental invalidation, memory-fault
semantics, live debugging, broader decompilation and future roadmap systems remain.

## Local archive audit

The local `URA-0.10.0-dev-windows-x64.zip` contains all three optimized Windows
executables, matching URA/`0.10.0-dev` version resources, official icon, Cargo.lock,
documentation, project license and third-party notices. Its size is 16,989,176 bytes.
SHA-256:

```text
befb80046869fc1f28ae09a9ea519ba686411208986f8b8931d398ae214b614f
```

Clean extraction passed ZIP CRC, sidecar checksum and all **588** manifest file
hashes. Every packaged file was listed. The EXEs match the tested Release images;
the icon matches the authorized repository artwork. License collection covered
277 workspace/dependency packages, with 271 third-party notice directories and
zero missing license texts. Extracted CLI/MCP versions, existing signature/type/
C-decompiler workflows and all new patching workflows passed, including exact
export bytes, original preservation, raw/ELF32, write denials and stale previews.
The native EXE was not launched. See [sanitized archive evidence](benchmarks/0.10-package.json).

The archive is an unpublished engineering artifact. Its documentation snapshot
precedes this external package audit; this source report records the subsequent
audit without changing the already-verified ZIP. No public download or re-download
verification is claimed.

## Remaining public release gates

Before public prerelease acceptance:

1. Perform real native byte/instruction edits, preview/cancel, undo/redo/revert,
   project save/reopen, file/manifest export dialogs and source-view refresh.
2. Observe actual in-flight cancellation/stale-result behavior through native input.
3. Complete the required current real OS DPI/workflow checklist. The earlier
   partial v0.9 real150 results do not establish the current app's acceptance.
4. After the live gates pass, produce the final release documentation/package,
   repeat its clean-extraction audit, publish a unique prerelease/tag, re-download
   its ZIP and verify SHA-256. The local archive audit above does not satisfy live
   acceptance or public-download verification.

No v0.9 or v0.10 release/tag is accepted while these gates remain incomplete.
Existing releases remain intact. Locally compiled/audited ZIPs are engineering
artifacts, not verified public releases. Source publication may proceed with
these blockers documented. Next major capability: a real Windows debugging
backend with explicit launch/attach, process/thread control, breakpoints, stepping,
registers/memory and stack inspection, separated from file patch permissions.
