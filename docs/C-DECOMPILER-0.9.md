# C-like decompiler: implemented contract and limits

This source checkpoint adds `decomp/source` after the existing indexed semantic
HIR. It does not replace the lifter, SSA, type solver, legacy high-level AST or
project database. Construction reads semantic nodes, never rendered strings.
The output is reconstructed C-like pseudocode, not original source and not a
promise of compilable C. No LLM participates in decompilation.

## Representation and transformations

The version-1 C-like AST contains typed scalar expressions, ordered loads and
stores, calls, explicit unknown effects, assignments, labels/gotos, conditions,
loops, returns and unresolved exits. A single source catalog retains instruction,
block, ordinal, original operation and synthetic provenance. Variables retain
SSA identity and inferred types; line metadata lists all contributing instruction
addresses and referenced/written variable IDs. Callees carry navigation addresses
only when the machine target is established. Synthetic copies never acquire an
invented instruction address.

Liveness begins at observable ABI results/control transfers and ordered effects.
Unconsumed pure flags can disappear. A pure expression is inlined only for one
same-block use, within 24 nodes and depth 8, and never if it feeds a phi. Loads
remain assignments and are never duplicated or moved across effects. Call
snapshots count as uses even before a prototype is recovered; this prevents an
address-order-dependent dangling temporary. This conservative policy retains
more machine temporaries around calls than an advanced decompiler would.

Each phi becomes edge-specific parallel copies. Acyclic destinations are written
only after their old values are no longer needed. Cycles save an old source into
a width-correct scratch and substitute every remaining use, including fan-out.
Copies execute inside the chosen branch, so critical edges do not run copies
for an untaken successor. Entry phi values are initialized before the root label.
Names are sanitized and repeatedly disambiguated, including parameter/scratch
collisions; they do not pretend to be recovered original local names.

The bounded reducer repeatedly merges uniquely entered linear blocks, closed
two-arm diamonds, and exact self-loop regions. Reductions can expose nested
regions and multi-block loops. Execution trace markers and ordered effects stay
in their original order. Closed branches retain exact joins/terminators, and
removed physical jumps retain provenance markers. Loops currently render as
`while (true)` with explicit exit tests/copies/breaks. Irreducible, open or
unproved regions retain labels and gotos. There is no guessed `for`, `do-while`,
short-circuit operator, complete switch or exception structure.

## Types, calls and memory

Machine expressions operate in an unsigned bit-vector storage domain. Signed
formal parameters are converted to that domain before arithmetic or unsigned
comparison, preventing signed overflow/comparison changes in printed C-like
syntax. Add/subtract/bitwise expressions preserve widths and precedence;
sign-extension, parity, guarded shifts and partial-register insertion use explicit
helpers. Non-native pointer widths use width-bearing pointer pseudotypes.

Exact entry registers can use established formal names. A low-bit extraction
can use a narrower formal without inventing its high bits. Narrow scalar return
types explicitly truncate the ABI register candidate. Unsupported floating or
aggregate return types stay unknown. A return-register candidate alone does not
establish an original source return type.

Calls use direct targets or the existing verified binary import-slot resolver
for prototype names. Supported scalar register argument snapshots are recovered;
unsupported stack/vector/aggregate argument locations/types remain explicit
unknowns. Call memory/clobber effects remain conservative. There is no executable
external-call model or general return-value correlation/coalescing yet.

Memory helpers denote explicit unaligned little-endian machine loads/stores.
Stack store annotations use exact recovered instruction/width evidence and the
existing user name overrides. Physical stack names/types remain editable in the
same project schema 5. Automatic scalar stack-local reconstruction, named
structure-field expressions, general arrays, alias sets, C++ classes/vtables/RTTI,
floating/vector semantics, multiplication/division and many optimized idioms are
not complete. User structures are preserved as evidence, not used to invent
unproved field accesses. Instruction comments remain in the existing Inspector.

## Product integration and bounds

`FunctionDecompilation.pseudocode` is cached with the existing function result.
Native analysis stays in the cancellable worker; project revisions invalidate
the cache. Service rename also invalidates declarations and hints. The existing
`highlevel` interfaces remain compatible. No project schema migration is needed.

The native Pseudocode panel retains the old `highlevel` dock identity, opens with
F5, virtualizes rows and shows line numbers/colors/status. Line selection links
to assembly; assembly selection highlights and scrolls mapped source. Context
menus expose established callees, cross references and bounded variable uses.
Existing signature/parameter and physical stack/type editors remain available.
Arbitrary SSA-local renaming and exact token-level navigation are not implemented.

CLI `decompile` and MCP `ura_decompile_function` page lines (1–2000); optional
AST responses are capped at 2 MiB before serialization allocation. Addresses use
lossless hexadecimal strings. Whole-function exports require explicit write
enablement in headless tools, honor allowed roots, create a new file and refuse
truncated output. Native export uses the same core rendering and runs its file
dialog/write in the worker. Exported helpers are pseudocode, not a runtime header.

Construction is capped at 1024 blocks/80,000 operations and formatting at 20,000
lines. Rendering/execution have nesting budgets; execution is capped at 100,000
steps and never runs the inspected executable. Resource-limit errors are explicit.
Truncated line output is visibly marked and cannot be exported as complete.

## Independent verification

`source/evaluate.rs` independently implements AST arithmetic, byte memory and
structured control. It calls neither the raw IR evaluator nor semantic-HIR
executor. Successful supported paths compare ABI result, memory, return/external
destination and block trace against both models. The old raw/HIR comparison
still checks the complete tracked machine state. Unknown effects and infinite
paths must remain non-concrete or hit a budget.

The corpus includes 1280 bounded arithmetic/partial-register cases, diamond and
nested/irreducible loops, 1024 simultaneous-copy patterns over four widths,
memory ordering, unsupported effects, signed/narrow parameters, call snapshot
regressions, source mapping, and deterministic rendering. Owned Clang C/C++
PE/ELF fixtures span O0/O1/O2/O3: 256 known-behavior executions plus 48 C++
function-class reconstruction checks. C++ members/switches/nested loops are
included as honest partial cases, not claims of general C++ support. Scripts
reproduce fixtures without executing them. MSVC, GCC and debug-symbol oracle
coverage remain unverified. CLI/MCP tests compare actual process output to the
shared service and exercise denied writes, export completeness and persistence.

Independent agent review found and prompted repairs to signed parameter printing,
call use counts/register identity, names, removed-jump provenance, unsupported
call formals and pointer-width declarations. See [VERIFICATION-0.9.md](VERIFICATION-0.9.md)
for measured gates and [FEATURE-PARITY.md](FEATURE-PARITY.md) for remaining work.
