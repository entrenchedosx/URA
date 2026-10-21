# Decompiler foundations (v0.8)

The later [finalisation checkpoint](FINALISATION-0.8.md) describes the new typed
tree/source metadata, postdominator join proof, bounded parameter-demand solver,
import binding and AST protocol option. It supersedes the corresponding missing
capabilities below for its documented subset; remaining broad items stay open.

URA v0.8 recovers calling conventions, stack frames, conservative types, an
interprocedural call graph and a C-like high-level view from the verified
bit-vector IR introduced in v0.7. The status of the high-level view is
`experimental-foundations`: it is a structural rendering of verified SSA, not
reconstructed source, and it is never claimed to compile.

Nothing in this layer guesses to fill a gap. Every recovered fact carries a
confidence and evidence, and a missing or contradictory fact is reported as
missing or conflicting. Sample code is never executed.

## Pipeline

`ura_core::decomp::analyze_function` runs the following bounded passes:

1. Lift and verify the function's IR (`ir::inspect`). If verification fails,
   decompilation fails with the verifier diagnostic.
2. Recover stack accesses and slots, first without a signature.
3. Recover candidate convention, register/stack parameters and return provenance
   from entry values and their roots. Supplied callee signatures add constraints;
   caller-observed argument counts are not computed and remain unknown.
4. Apply a user signature override when one is supplied and valid.
5. Recover the final stack frame using the recovered signature.
6. Apply stack-slot name/type overrides.
7. Infer conservative types from SSA constraints and merge ABI value
   constraints.
8. Render the recovered high-level IR from SSA, dataflow, the signature and the
   frame.

The call graph is a separate program-wide pass over the existing analysis.
IR, stack and ABI passes poll `AnalysisControl`; the bounded type/HIR passes are checked at their boundaries. MCP transport cancellation remains unimplemented. Cancellation returns an error rather than partial typed output.

The result (`FunctionDecompilation`) groups the signature, frame, type
inference, high-level function and diagnostics. Addresses remain `u64` in the
core; adapters serialize them as `0x`-prefixed strings.

## Calling conventions and signatures

Supported conventions are Win64, SysV64, cdecl, stdcall, fastcall, thiscall and
unknown. The platform default is Win64 for PE x64, SysV64 for ELF/Mach-O x64 and
cdecl for 32-bit x86. Shared x64 register reads do not override that low-confidence default. Supported x86 cleanup/register evidence can distinguish candidates; conflicting evidence stays explicit. XMM and aggregate classifications are not implemented.

Recovery records:

- parameter index, name, location (register, stack offset or unknown), type,
  width, confidence, use count and evidence;
- return location and type;
- stack parameter bytes, caller-observed argument count and variadic state when
  known;
- convention confidence, conflicts and evidence.

Register arguments are recognized only from reads of the entry value in the
lifted IR. Win64 shadow space and SysV red-zone rules are applied explicitly.
Fastcall/stdcall/thiscall cleanup immediates are retained as evidence.
x64 cleanup immediates are noted but do not change Win64/SysV64 conventions.

`signature::describe_override` converts a saved override into a call-site hint
for callees that have not themselves been decompiled. Overrides are stored
separately from inference, are limited to 64 parameters, and are validated
before use; invalid overrides are rejected rather than silently sanitized.

A curated helper database of 41 C and Windows API prototypes can instantiate explicitly requested signatures. It is not automatically bound to imported functions or inserted into the native/service hints. `size_t` follows target width; `time_t` remains incomplete without a data model. Unknown names are rejected. Imported graph nodes and reliable library binding remain open work.

## Stack frames

`stack::recover` follows stack-pointer and frame-pointer deltas through the
verified CFG and records physical slots, not fabricated variables. Slots expose
offset, width, name, kind, type, user name/type, reads/writes, first/last
instruction, saved register, overlaps and confidence. Saved registers, alignment,
frame size, local bytes, incoming argument bytes and the return-address offset
are reported. Overlapping slot accesses are preserved so callers can see the
aliasing instead of receiving a clean but false layout.

Limits: 20,000 stack accesses and 2,048 slots per function. Hitting either bound
marks the frame truncated. Unresolved stack deltas remain unknown.

## Types

The type system covers void, bool, integers of 1-64 bits with signedness only
when observed, floats (32/64/80), pointers, arrays, structs, unions and named
aliases. Parsing accepts bounded C-style spellings; `char` aliases `u8` and
therefore normalizes to `u8` in display.

Inference derives constraints from SSA operations (loads/stores, pointer
arithmetic, comparisons, calls, shifts and extension) rather than from source
patterns. A type is widened only when the constraints justify it; conflicting
constraints are counted and reported. User stack-slot type overrides take
precedence for display while the recovered type remains available separately.

Limits: 5,000 inferred variables per function, 512 fields per structure, and
structure/typedef validation errors are surfaced. Truncation is explicit.

## High-level view

`hir::build` renders loops, conditionals, selections, comparisons, calls, loads
and stores in C-like syntax with stable labels. Every line keeps its source
address where one exists. Unsupported instructions, unresolved branches and
calls without signatures are marked, not guessed. Output is bounded at 20,000
lines and nesting depth 64. The view reports `experimental-foundations` and
`unresolved` counts alongside its notes.

## Call graph

`callgraph::build` uses direct call xrefs from program analysis, preserves indirect
calls as unresolved counts and computes roots, leaves and strongly connected
components. Self-loops and cycles are reported explicitly. Focused subgraphs
(depth 1-16) and bounded path queries are available; the complete graph is
limited to 8,192 functions and 20,000 call sites and marks truncation. Every retained direct call site has its own edge; indirect calls and jumps are counted separately. Imported external nodes are not yet represented.

Service/CLI/MCP queries additionally bound focused expansion to 2,000 nodes and
20,000 edges. JSON pages use explicit node/edge totals so a client can tell a
complete answer from a truncated one.

## Persistence and adapters

Project schema v4 introduced `function_signatures(address, signature_json,
updated_at)` and `stack_variables(function_address, slot_offset, name,
type_json, updated_at)`. Schema v5 adds `type_library(id, library_json)` for user structures/unions/aliases. Existing schema v1-v4 projects migrate forward; newer schemas are rejected. Older URA builds cannot read a migrated v5 project. Signature and stack overrides survive save/reopen and are
reloaded into decompilation hints.

Headless access is shared:

- CLI: `signature`, `stack`, `types`, `callgraph`, `highlevel` (text or
  `--json`), plus `type-library`, `set-signature` and `set-variable-type`. The latter editing commands require a project and `--enable-writes`.
- MCP: eight decompiler read tools and three decompiler write tools
  (`ura_set_function_signature`, `ura_set_variable_type`, `ura_set_type_library`), 30 tools total. `ura_get_structure` takes a type name and returns actual fields; `ura_get_types` without a function reads the library. Writes require
  `--enable-writes` and an attached, matching project.
- Native: Function signature, Stack frame, Types, Call graph and Analysis
  inspector panels. Selection follows the function selected in the rest of the
  workspace; recovered addresses navigate back to disassembly/IR. Signature forms, stack name/type forms and structure/alias forms save user-authored data to the attached project.

Service decompilations are cached per handle (four functions, LRU) and
invalidated by reanalysis or override changes. Golden tests compare the native
worker, service, CLI JSON and MCP responses with direct core calls.

## Explicit limits

- Only functions discovered by URA's analysis can be decompiled.
- No debug symbols, PDB types, exception metadata, C++ reconstruction or
  structure recovery from global data is implemented.
- No claim of compilable output, original variable names or original source
  fidelity.
- Bounds above are hard stops with diagnostics; they are not tuned for
  adversarial worst cases.
- Samples remain read-only; nothing in this layer executes them.

See [VERIFICATION-0.8.md](VERIFICATION-0.8.md) for the exact gates and tests.

## Checklist scope

This is not the entire requested v0.8 architecture. High-level rendering is still text coupled to structuring, without a typed expression AST or true postdominator pass. Inferred signatures are not solved across the whole program to a fixed point. See [AUDIT-0.8.md](AUDIT-0.8.md) for the complete distinction between implemented foundations, repaired defects and remaining work.
