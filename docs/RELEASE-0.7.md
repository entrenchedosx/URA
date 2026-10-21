# URA v0.7.0-dev prerelease

Published as a GitHub prerelease from `v0.7-advanced-analysis`. This is a
development checkpoint, not a final `v0.7.0` release. Variable idle CPU outside
UI painting remains an unexplained limitation.

Implemented:

- Original typed IR and tested scalar x86/x64 lifting, including overlapping
  registers, relevant flags, explicit memory/call effects and unsupported barriers.
- Verified dominators/frontiers, scalar SSA, def-use, conservative constants,
  branch proofs and side-effect-aware dead definitions; no code is rewritten.
- Narrow guarded absolute/relative jump tables, candidate tails/thunks, and CFG
  consistency when resource limits stop analysis.
- Hidden-by-default native IR panel with Raw/SSA selection and source navigation.
- CLI `ir`, `dominators`, `diagnostics` and four matching MCP tools (19 total).
- Bounded LRU analysis caches with invalidation and exact binary/configuration
  metadata. Existing SQLite schema v3 projects remain compatible.
- Deterministic byte and compiled PE/ELF fixtures, protocol/parity tests, native
  rendering checks, performance harnesses and a source-backed design document.

The portable Windows archive contains `ura-native.exe`, `ura-cli.exe`,
`ura-mcp.exe`, the documentation, the original `icon.webp`, per-file checksums and
dependency notices. All three executables carry the URA icon, product and version
resources; the workspace uses one package version.

Validation: formatting, strict workspace Clippy, 97 workspace tests and a Release
workspace build pass on Windows x64. The packaged executables were exercised from
a clean temporary extraction. The MCP archive binary returned 19 tools and
verified IR rows; the CLI reported version `0.7.0-dev` and decoded the PE fixture.

Known limits: idle CPU is not explained or fixed, and no wakeup/GPU/presentation
timing claims are made. There is no decompiler or pseudocode generator. Supported
semantics and compiler patterns are explicitly limited. Read
[IR-DESIGN.md](IR-DESIGN.md), [verification](VERIFICATION-0.7.md) and the
[roadmap](ROADMAP.md) before relying on this checkpoint.
