# Current source audit status

The release notes below describe the historical `1194403` archive published as
`v0.8.0-dev`. Current branch source adds correctness repairs, native editing and
schema v5 user type libraries. Those changes are **not in the published ZIP**.
The full supplied v0.8 checklist is incomplete; [AUDIT-0.8.md](AUDIT-0.8.md)
records the remaining work. No existing tag/artifact is replaced and no new
accepted prerelease is claimed by the audit checkpoint.

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
