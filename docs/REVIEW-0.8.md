# Independent adversarial review of v0.8 foundations

Reviewed on 2026-10-21, starting from `1194403` on
`v0.8-decompiler-foundations`. This review examined the core ABI, stack,
signature, scalar type, call-graph and high-level rendering code separately
from the initial implementation. It found correctness gaps in code whose
original fixture tests passed. The findings below describe repaired behavior,
not evidence that the full v0.8 roadmap is complete.

## Findings and changes

| Finding | Trigger before repair | Result after repair |
| --- | --- | --- |
| Stack dataflow did not converge monotonically | A back edge that subtracts from SP repeatedly replaced a known delta with another known delta and could run indefinitely. A diamond with different deltas selected one predecessor. | Separate SP and FP states merge differing facts to unknown, including the implicit function-entry edge. The finite lattice converges and unresolved accesses do not become physical slots. |
| Frame-pointer information crossed control-flow paths | One mutable function-wide FP delta was reused in unrelated blocks, even after conflicting definitions. | FP is part of each block's incoming dataflow state. Unsupported/partial writes and conflicting predecessors invalidate its relation to entry SP. |
| x86 registers were canonicalized as x64 registers | `ESP.full_register()` produced RSP, while the stack code compared against ESP. | Native x86 canonicalization uses the 32-bit register family. Original x86 bytes exercise prologue allocation and positive/negative frame offsets. |
| Unmodeled address components became fixed stack slots | Indexed, segmented, or address-size-overridden accesses were treated as a plain SP/FP plus displacement. | Dynamic indexes, nonnative address widths and nonflat segments are counted as unresolved access candidates. Checked arithmetic prevents delta overflow. |
| Unsupported stack writes retained stale facts | MOV SP from an unknown register, POP SP, partial writes, XCHG and other writes could retain an earlier delta. | Instruction register-access metadata invalidates relations for writes the transfer function cannot model. |
| Stack summary invented types and sizes | Incoming stack slots became pointers solely from their offset; Win64 home space looked like arguments; frame size missed allocations without accesses. | Slots retain observed integer widths, home space has its own kind, and frame size tracks proven stack decrements within blocks. Alignment is reported as unknown (`1`), not an unproved platform default. |
| Stored nonvolatile values were called saved incoming registers | A register overwritten before its store was still labeled as a saved caller value. | Saved-register labels require a native-width incoming value stored in the entry block before that register is overwritten. A note explicitly says restoration is not proved. |
| Shared x64 registers selected the wrong ABI | A System V function reading RCX, R8 or R9 could be reported as Win64 with high confidence; saving Win64 RDI/RSI could suggest System V arguments. | Register reads alone do not override the container ABI. Platform defaults remain low-confidence assumptions. Positive System V argument reads and Windows nonvolatile prologues have separate regressions. |
| Mechanical IR reads invented parameters | Alias-extraction temporaries from `xor ecx, ecx` counted as reads of an incoming argument. | Recovery counts roots of completed architectural outputs and memory/call consumers. Self-canceling operations do not invent input parameters. |
| Weak evidence silently became a pointer type | A zero comparison or every contributor to an indexed address could become a pointer parameter. | Zero comparisons preserve integer types. Address evidence follows direct values, copies and constant offsets; dynamic arithmetic does not make every index a pointer. |
| Unchanged or partly unknown return registers became definite return types | Untouched RAX became `void`; copied/phi-joined call effects could become integer returns; one defined path masked an unchanged path. | Return provenance is checked through definitions and phi inputs. Missing, cyclic, bounded-out, call or unsupported provenance stays unknown. Absence of RET does not establish void or nonreturning behavior. |
| Conflicting evidence was silently selected | Different RET cleanup immediates selected the maximum; disagreeing callee parameter types selected the first type. | Conflicting cleanup does not establish a cleanup value. Conflicting parameter hints produce unknown type, unknown confidence and an explicit signature conflict. |
| Stack writes invented incoming parameters | A store to an incoming stack offset counted as an input argument read. | Signature recovery accepts only read-only observed incoming slots. This deliberately misses some arguments whose slots are reused. |
| Call-graph edges lost repeated call sites | Several calls from one function to the same callee became a single edge with only one source address. | The primary implementation now preserves each direct call site and counts distinct caller/callee functions separately. An independent byte-level regression checks two calls to the same callee. |
| Sign extension lost its source width in the high-level view | An 8-to-64-bit extension was printed as a cast to the destination width. | Rendering explicitly prints `sign_extend<8, 64>(...)`. |
| Known-but-incomplete call arguments did not count as unresolved | A known signature with omitted stack, unknown-location or variadic arguments printed placeholders but returned `unresolved = false`. | Those calls increase the unresolved count. A regression compares the same call with complete and incomplete signatures. |

The high-level and call-graph fixes were applied by the primary implementer
after the review findings; their regressions are in the independent review
test file. Other fixes above are in `decomp/stack.rs` and `decomp/abi.rs`.

## Resource and cancellation limits

- Direct stack recovery rejects more than 2,048 blocks or 50,000 instructions.
  The ordinary decompiler pipeline has the stricter upstream IR limits of
  1,024 blocks and 10,000 machine instructions.
- Stack output retains at most 20,000 access records and 2,048 slots. Excess
  records/slots set `truncated`. Physical slot offsets are restricted to
  plus/minus `0x100000`. Overlap checks are bounded by the retained slots.
- SP and FP each have a known delta or unknown state, with unvisited blocks
  represented separately. At a join, each component can only lose information.
- ABI signatures have at most 64 parameters. Root traversal has a shared
  20,000-visit budget, depth 64 and a 32-root stopping threshold per value.
  Reaching a root traversal limit adds an explicit incomplete-evidence note.
- Return provenance has a 20,000-visit budget per return and active depth 64.
  Reaching either bound leaves the return type unknown.
- Controlled stack and ABI entry points check cancellation during their work.
  The combined pipeline also checks after the bounded type/high-level passes;
  those latter passes do not yet poll cancellation per statement.
- High-level rendering remains bounded at 20,000 lines, nesting depth 64,
  2,048 visited nodes per join search and 512 displayed characters per line.
  The line-character limit can shorten a displayed expression; this view is
  not compilable source or a semantic round-trip representation.
- The primary implementation bounds the call graph at 8,192 functions and
  20,000 call sites, with truncation reported. This review does not constitute
  a worst-case performance or memory proof for all graph queries.

## Verification performed for this review

`crates/ura-core/tests/decomp_review.rs` contains 26 semantic regressions. They
use original machine-code sequences in memory, a minimal linked PE32 image,
and the existing original PE64/ELF64 fixture containers. No sample is executed.
The assertions check exact facts or intentional uncertainty; they do not
merely check that output exists.

The dedicated 26-test suite passes. A full `cargo test -p ura-core` run also
passed at the 100-test checkpoint, before the final two high-level regressions;
the later dedicated run includes both high-level tests. Core all-target linting
passes with warnings denied. Formatting checks on the three review-owned Rust
files and whitespace checks on the modified stack/ABI files pass.
Final workspace checks and the final test total belong in
`VERIFICATION-0.8.md`, because other development continued during this review.

## Residual gaps and deliberate uncertainty

- Container ABI defaults are assumptions. Custom conventions, vector argument
  classes, hidden structure-return parameters and complete argument counts are
  not established by the tests above. Unobserved ABI slots remain explicitly
  unobserved. Inferred variadic state and caller-observed argument count are
  still unknown unless other supplied knowledge establishes them.
- x86 calls invalidate the SP delta because callee cleanup is not available to
  stack recovery. x64 calls retain the standard ABI stack-preservation
  assumption. FP relations survive calls under the supported ABI assumptions.
  This is not a proof for arbitrary custom callees.
- Indexed stack locations, realigned dynamic frames and unsupported stack
  instructions remain unresolved. Saved-register labels establish an incoming
  value store, not matching restoration on every exit.
- Stack slots are physical locations. Read-only slot filtering is conservative
  and can omit real parameters. Frame/local-byte summaries do not reconstruct
  source declarations or distinguish every compiler spill from a local.
- Scalar bit width and address use do not establish signedness, source-level
  pointer validity, pointee structure, ownership or floating-point types.
  Callee constraints are evidence, not a complete interprocedural type solver.
- The high-level view still contains SSA temporaries, phi operations, explicit
  unknown effects and gotos. No compilation, source equivalence or complete
  structured-control recovery is claimed.
- The 26 tests do not replace a broad compiler/optimization/ABI corpus,
  fuzzing, whole-program equivalence checks, latency profiling or native
  display/DPI verification. The earlier performance release blockers must be
  evaluated separately; semantic regressions do not clear them.

A final follow-up review also found and repaired native editor round-trip loss. Three additional native regressions preserve enum underlying widths, mixed-width pointers, callback types, stack-location widths, field size/provenance and unknown variadic state. The final workspace results are in VERIFICATION-0.8.md. Curated size_t widths were corrected by the primary implementer after this review.
