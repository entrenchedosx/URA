# URA v0.7 development checkpoint

**Not a published v0.7.0 release.** The native version is `0.7.0-dev`; the latest
public release remains v0.6.0. Variable idle CPU outside UI painting remains a
release blocker. No v0.7 tag, prerelease, main-branch update or public binary
artifact is created by this checkpoint.

Implemented:

- Original typed IR and tested scalar x86/x64 lifting, including overlapping
  registers, relevant flags, explicit memory/call effects and unsupported barriers.
- Verified dominators/frontiers, scalar SSA, def-use, conservative constants,
  branch proofs and side-effect-aware dead definitions; no code is rewritten.
- Narrow guarded absolute/relative jump tables, candidate tails/thunks, and CFG
  consistency when resource limits stop analysis.
- Hidden-by-default native IR panel with Raw/SSA selection and source navigation.
- CLI `ir`, `dominators`, `diagnostics` and four matching MCP tools (19 total).
- In-memory analysis caches with invalidation and exact binary/configuration
  metadata. Existing SQLite schema v3 projects remain compatible.
- Deterministic byte and compiled PE/ELF fixtures, protocol/parity tests, native
  rendering checks, performance harnesses and a source-backed design document.

There is no decompiler or pseudocode generator. Supported semantics and compiler
patterns are explicitly limited. No runtime dependency or icon replacement was
introduced. Read [IR-DESIGN.md](IR-DESIGN.md), [verification](VERIFICATION-0.7.md)
and the [roadmap](ROADMAP.md) before treating this branch as a release candidate.
