# URA v0.15.0-dev — bounded symbolic analysis and deobfuscation

URA now proves supported opaque branches with real fixed-width Z3 queries and
uses separately validated conclusions to improve the existing C-like decompiler.
Original bytes, CFG, instructions and pseudocode remain available alongside the
derived reconstruction and its proof evidence.

- Typed expression DAGs, persistent byte-array memory, bounded SSA path exploration,
  finite value sets, SAT models and solver-backed alias queries.
- Prefix-scoped dispatcher transitions and finite indirect branch/call targets;
  unsupported effects, unknown results and timeouts never justify branch removal.
- Background native Deobfuscation controls, an interactive JSON `symbolic` CLI,
  and one shared `ura_symbolic` MCP tool (68 tools total).
- Windows Job memory limits, kill/reap cancellation, bounded sessions/results,
  stale byte/context/request rejection and compatible historical SQLite metadata.
- Verified x86 NOT/NEG scalar lifting; ARM64, RV32/RV64 and uniform ARM/Thumb
  retain their documented scalar subsets.

The owned symbolic corpus passes 873 input cases, 1,746 original/derived C-like
AST comparisons, 1,746 original/derived IR comparisons and 41,862 defined
register/flag comparisons against pinned independent Unicorn execution. Four
opaque edges are pruned, 16 prefix dispatcher transitions recovered, and no
branch is incorrectly pruned in the designated adversarial families. This is
bounded evidence, not a general equivalence or accuracy theorem.

Local qualification passes 393 Rust tests, formatting, strict all-target lint
checks and a locked workspace Release build. The retained processor oracle also
passes 767 machine comparisons, 671 C-like AST executions and 290 static analyses.
The local package audit covers 642 files and 284 dependency packages with zero
missing license texts; the exact-source tag workflow repeats qualification.

For the same 80 x64 compiler functions, the genuine downloaded v0.14 baseline
has 2,108 pseudocode lines versus 1,958 derived v0.15 lines. Some gains come from
NOT/NEG semantics; the solver's branch-only contribution is reported separately
in [verification](VERIFICATION-0.15.md). Three independent static review passes
found issues that were repaired and regression-tested; see [review scope](REVIEW-0.15.md).

Windows x64 Desktop, CLI and MCP are freshly compiled from the exact tagged
source. Z3 5.1.0.0 and the C/C++ runtime are statically linked; no developer solver
installation or runtime download is required. Individual EXEs, complete ZIP,
licenses/provenance and SHA-256 checksums are required assets. The workflow gates
publication on clean-source tests, packaging and downloaded-artifact verification.

This is an early scoped prerelease. Calls stop symbolic paths, arbitrary
flattened functions are not fully restructured, and general taint, whole-program
equivalence, OS/heap/concurrency models, floating/vector state and full ISA/ABI
coverage remain incomplete. No live native input, real DPI or GPU acceptance is
claimed. Remote/kernel debugging and full IDA/Hex-Rays/Ghidra parity remain future
work. See [scope and limits](SYMBOLIC-DEOBFUSCATION.md) and the
[228-capability ledger](FEATURE-PARITY.md): 23 Supported, 148 Partial, 49 Missing,
8 Unverified within the ledger's explicit scopes.
