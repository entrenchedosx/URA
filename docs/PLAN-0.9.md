# v0.9 implementation and acceptance gates

Starting source: `b1a05c7` after the verified v0.8 qualification record. Development
branch: `v0.9-c-decompiler`; version: `0.9.0-dev`. No automatic main update.

The finalisation continuation starts from `bc73e7f`, retains its Release tools
for matched measurements, and records current evidence in
[FINALISATION-0.9.md](FINALISATION-0.9.md). It stays within v0.9 until acceptance.

Execution priorities are: preserve the verified engine and projects; establish
executable C-like AST semantics; validate transformations independently; expose
the same output through desktop/CLI/MCP; review and measure; package; publish
only if current release acceptance passes. An inaccessible DPI check must not
stop implementation or silently become a pass. See RELEASE-QUALIFICATION-0.8.md.

## Scope gates

1. **Representation:** C-like output originates from the existing indexed
   semantic HIR, with typed expressions/statements, source links, explicit
   unknown effects and bounded construction. The old diagnostic HIR interface
   remains compatible. Text formatting does not drive analysis.
2. **SSA destruction:** edge-specific simultaneous phi assignments become
   ordered copies with scratch variables for cycles. Critical edges are handled
   on the selected branch, never by unconditionally assigning both successors.
3. **Expressions and variables:** safe single-use pure expression inlining;
   no duplicated/reordered loads, stores or calls; exact bit widths and guarded
   machine operations. SSA lifetimes stay distinct unless a merge is justified.
4. **Control:** independently tested if/else and supported loops; explicit
   labels/gotos for unproved or irreducible regions. For/switch/short-circuit
   syntax requires additional semantic evidence, not attractive pattern guesses.
5. **Observable contract:** the C-like function describes ABI result, memory
   effects and explicit control exits. Architectural flags are retained when
   consumed; dead pure flag calculations can be omitted. It does not promise
   original source text, recompilation, or a complete CPU/OS emulator. Existing
   full machine-state semantic HIR remains independently inspectable.
6. **Annotations/memory:** effective signatures and verified physical stack/type
   annotations affect the proper source locations. Named field syntax requires
   exact layout/width evidence; otherwise keep explicit memory operations.
7. **Product:** native Pseudocode view, mapped navigation, real editor actions,
   export and cancellation use shared background analysis. CLI/MCP report
   diagnostics, partial status and lossless addresses with bounded responses.
8. **Verification:** preserve all 237 tests; add independent raw IR/semantic
   HIR/C-like AST comparisons, phi-cycle/critical-edge regressions, compiled
   fixtures, protocol/export/persistence tests and native verification. Perform
   independent agent review of implemented changes and fix material findings.
9. **Resources:** compare the retained v0.8 executable/harness on unchanged
   inputs, distinguish added work, report memory and large-function limits.
10. **Release:** formatting, strict Clippy, workspace tests and Release build;
    clean extraction of all three matching-version EXEs, licences, real CLI/MCP
    and native checks; current mandatory DPI acceptance; unique tag and download
    checksum verification. If blocked, push a coherent source checkpoint and
    precisely identify unverified gates. Do not label a partial milestone done.

## Permanent product requirement

Full IDA Pro/Hex-Rays and Ghidra feature parity is a multi-release objective,
audited capability by capability in FEATURE-PARITY.md. Neither a new panel nor
an API establishes support. Debugging, patching and unrelated analysis systems
are tracked for later releases, not implemented as v0.9 scope expansion.
