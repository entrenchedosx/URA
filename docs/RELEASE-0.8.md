# Release status — 2026-10-21

**The Windows ZIP attached to `v0.8.0-dev` is the original `1194403` build.
The newer development work described here is not included in that download
or in this release tag's automatic source archives.**

Latest verified engine source:
[`a42633b4e5602a171d547227e696041d6c0f4941`](https://github.com/entrenchedosx/URA/commit/a42633b4e5602a171d547227e696041d6c0f4941)
on [`v0.8-decompiler-foundations`](https://github.com/entrenchedosx/URA/tree/v0.8-decompiler-foundations).

| Verification / capability | Published ZIP | Latest verified engine source |
|---|---|---|
| Engine commit | `1194403` | `a42633b` |
| Passing workspace tests | 122 | 237 |
| MCP tools | 29 | 30 |
| Project schema | v4 | v5, preserving existing edits and migrations |

The latest source adds indexed executable semantic HIR with exact SSA provenance,
independent bounded IR/HIR execution comparisons (including compiled PE/ELF O0/O2
fixtures), SSA-specific type evidence, forward argument and return constraints,
verified external import-call edges, and bounded semantic block queries. It also
repairs native editor field sizing. Unsupported effects, conflicting types and
partial analysis remain explicit; the C-like view is still experimental.

Formatting, strict all-target workspace Clippy, all 237 tests and the Windows
Release build pass. Actual CLI/MCP queries, clean package extraction, checksums,
dependency notices and extracted desktop startup passed. Live native signature,
stack/type and structure edits, HIR-to-assembly navigation, and save/reopen
persistence were verified.

**A corrected public `v0.8.0-dev.1` prerelease has not been published.** Current
OS-level DPI acceptance remains unverified because Windows Settings did not
expose a controllable window. Intermittent idle CPU remains unexplained. The
existing release's tag and downloadable assets retain their original identity;
`main` remains unchanged.

See the [engineering and live verification report](https://github.com/entrenchedosx/URA/blob/a42633b4e5602a171d547227e696041d6c0f4941/docs/ENGINE-COMPLETION-0.8.md),
[measured performance and test results](https://github.com/entrenchedosx/URA/blob/a42633b4e5602a171d547227e696041d6c0f4941/docs/benchmarks/0.8-completion.json),
and [local package verification](https://github.com/entrenchedosx/URA/blob/a42633b4e5602a171d547227e696041d6c0f4941/docs/benchmarks/0.8-completion-package.json).

---

The notes below describe the original published ZIP, not the newer source.

# URA v0.8.0-dev prerelease

Published as a GitHub prerelease from `v0.8-decompiler-foundations`. This is a
development checkpoint, not a final `v0.8.0` release. High-level output is
labelled experimental, and variable idle CPU outside UI painting remains an
unexplained limitation.

Implemented:

- Evidence-based ABI/signature recovery for Win64, SysV64, cdecl, stdcall,
  fastcall and thiscall, including register and stack parameters, return values,
  caller-observed arguments, confidence and conflicts.
- Physical stack-frame recovery with slots, overlaps, saved registers, alignment,
  locals, incoming argument bytes and hard bounds.
- Conservative type system and SSA-constraint inference, plus 41 curated
  documented API prototypes. Unknown names and unproven types are not invented.
- Bounded interprocedural call graph with direct/tail calls, roots, leaves,
  cycles, unresolved indirect counts and focused path queries.
- Experimental C-like high-level rendering from verified SSA with source
  addresses and explicit unresolved markers; not decompiled source.
- Guarded signature/stack-variable overrides persisted in project schema v4;
  v1-v3 projects migrate forward. Existing v0.7 projects open without action.
- Native Function signature, Stack frame, Types, Call graph and Analysis
  inspector panels with selection synchronization and source navigation.
- CLI `signature`, `stack`, `types`, `callgraph` and `highlevel`; ten new MCP
  tools (29 total). Writes require `--enable-writes` and an attached project.

The portable Windows archive contains `ura-native.exe`, `ura-cli.exe`,
`ura-mcp.exe`, the documentation, the original `icon.webp`, per-file checksums and
dependency notices. All three executables carry the URA icon, product and version
resources; the workspace uses one package version.

Validation: formatting, strict workspace Clippy, 122 workspace tests and a
Release workspace build pass on Windows x64. Tests compare native worker, service,
CLI JSON and actual MCP responses with direct core decompilation. The packaged
executables are exercised from a clean temporary extraction; the MCP archive
binary returns 29 tools and decompiler schema 1, and the CLI decodes the PE
fixture and prints all recovered views.

Known limits: idle CPU is not explained or fixed, and no wakeup/GPU/presentation
timing claims are made. The high-level view is structural and non-compilable.
There is no PDB/C++/exception recovery. Supported semantics, conventions and
bounds are explicit. Read [DECOMPILER.md](DECOMPILER.md),
[verification](VERIFICATION-0.8.md) and the [roadmap](ROADMAP.md) before relying
on this checkpoint.
