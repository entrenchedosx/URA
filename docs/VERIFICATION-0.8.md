# v0.8 development verification

## Decision

Ship the decompiler-foundations checkpoint on `v0.8-decompiler-foundations`,
version `0.8.0-dev`, as the GitHub prerelease `v0.8.0-dev`. This is a development
prerelease: recovered high-level output is explicitly labelled
`experimental-foundations`, and no final `v0.8.0` is claimed.

The baseline is v0.7 commit `1d0f484`, tag `v0.7.0-dev`. All original 97 tests
remain in place. The `main` branch is unchanged by this work.

## Host and reproduction

Verification ran 2026-10-21 on the same Windows 11 x64 host used for
[VERIFICATION-0.7.md](VERIFICATION-0.7.md), with the MSVC toolchain and Rust
1.99. Code gates:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
```

## Test evidence

**122 tests pass**, including all original 97:

| Area | Tests |
|---|---:|
| Binary inspection/analysis | 8 |
| Function/CFG discovery | 17 |
| Verified IR/SSA/dataflow | 25 |
| Switch/tail/thunk recovery | 7 |
| Decompiler core unit tests | 14 |
| Decompiler core integration | 4 |
| CLI (JSON/text parity) | 7 |
| MCP stdio (read/write, restart) | 2 |
| Native workspace | 11 |
| Project persistence/migration | 11 |
| Service unit + integration | 16 |
| **Total** | **122** |

Decompiler-specific coverage:

- ABI table tests for register/stack parameter indices across Win64, SysV64 and
  32-bit conventions, including Win64 shadow space and SysV register order.
- Taint-root resolution terminates on cycles and respects its budget.
- Stack frames recover real slots and reject nonexistent overrides.
- Type parsing round-trips bounded C spellings, every curated prototype
  instantiates at 32/64 bits, and unknown API names are rejected.
- HIR identifier sanitization and text rendering preserve indentation and mark
  the experimental status.
- Signature overrides validate names/parameter counts and replace inferred
  parameters while retaining evidence.
- Core integration tests compare entry signature/frame/types/HIR, call-graph
  paths, override application and curated API lookup against the fixtures.
- Native worker results are serialized and compared field-for-field with direct
  core decompilation and call-graph construction.
- Service tests cover signature, stack, types, high-level and call-graph pages,
  limit errors, write gating, project requirement and reopen persistence.
- CLI tests compare new JSON responses with the shared service and exercise text
  rendering.
- MCP stdio tests assert the 29-tool listing, read-only hints, new outputs,
  write-tool refusal without `--enable-writes`, and signature/stack-variable
  survival across a fresh server.

`cargo test --workspace` also runs the native tessellation test, which renders
all 17 panels in two themes at four size/scale configurations with real
analysis and IR rows loaded.

## Schema and compatibility

Project schema is now v4. The migration adds `function_signatures` and
`stack_variables`; schema v1/v2/v3 projects migrate sequentially. A migration
test opens a v3 project, verifies the original annotations/names remain, and
reads the new empty tables. Future schemas are still rejected. v0.7 projects
open without user action.

Service response schema remains 1. New decompiler DTOs preserve camelCase JSON,
hex-string addresses and explicit `truncated`/totals fields.

## Shared-engine parity

There is one decompiler implementation in `ura-core`. The native app calls it on
its background worker with revision-tagged replies; the service caches up to four
functions per handle (LRU) and invalidates on reanalysis/override changes; the
CLI and MCP route to the service. Tests compare:

- native worker output vs. direct core calls;
- CLI JSON vs. service responses;
- MCP decompiler responses vs. the shared service;
- saved overrides vs. a fresh server/service reopen.

No adapter contains a second decompiler or fabricated placeholder output.

## Commands

```powershell
ura-cli --allow . signature  tests\fixtures\ura64.exe --function 140001020
ura-cli --allow . stack      tests\fixtures\ura64.exe --function 140001020 --json
ura-cli --allow . types      tests\fixtures\ura64.exe --function 140001020
ura-cli --allow . callgraph  tests\fixtures\ura64.exe --function 140001000 --depth 1
ura-cli --allow . highlevel  tests\fixtures\ura64.exe --function 140001020 --limit 20
```

The fixture's recovered entry signature is `int64 sub_140001020()` under Win64
with low convention confidence from platform defaults; tests assert this exact
evidence rather than a prettier but unsupported result.

## Known limitations

- The variable process CPU outside UI painting observed in v0.7 remains
  unexplained. Windows stack profiling was unavailable on this host, so no
  performance improvement is claimed.
- Decompiler output is structural, not compilable source; see the hard bounds
  in [DECOMPILER.md](DECOMPILER.md).
- No PDB/C++/exception/structure-from-data recovery, and no cross-compiler
  semantic validation beyond the checked fixtures.
- The native decompiler panels are read-only. Edits are available through CLI/
  MCP/service APIs that require a project; the native app applies saved
  overrides to its decompilation context after project refresh.
- Samples are never executed anywhere in the verification flow.

## Release artifacts

Push the branch and tag, build the optimized Windows x64 binaries, package the
ZIP with licenses and checksums, extract it into a clean directory, compare the
extracted binaries' `--version`/help output, and publish the verified GitHub
prerelease. The final report records the commit, tag, artifact SHA-256, test
count and these limitations. Hashes are not written before the artifacts exist.
