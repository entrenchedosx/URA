# Analysis architecture research

Inspected official Ghidra source on 2026-10-20, pinned to
[`b8e9917e4c01959fe97ba94954731ed8cf2d201c`](https://github.com/NationalSecurityAgency/ghidra/tree/b8e9917e4c01959fe97ba94954731ed8cf2d201c).
This is an architectural study, not an embedded Ghidra implementation. No Ghidra
code, processor definitions, binaries or artwork were incorporated into URA.
The inspected Java files have Apache-2.0 headers; the repository also has
component-specific notices. Any future adaptation needs a fresh file/dependency
license review and preserved notices. URA retains its existing MIT license.

## Findings and concrete consequences

- [DisassembleCommand](https://github.com/NationalSecurityAgency/ghidra/blob/b8e9917e4c01959fe97ba94954731ed8cf2d201c/Ghidra/Features/Base/src/main/java/ghidra/app/cmd/disassemble/DisassembleCommand.java)
  separates requested starts from allowed address ranges, checks executable
  memory, and avoids existing code/data. URA already bounds executable reads.
  This iteration adds rejection of a new instruction that would consume a later
  decoded start, with a deterministic reverse-traversal regression test.
- [BasicBlockModel](https://github.com/NationalSecurityAgency/ghidra/blob/b8e9917e4c01959fe97ba94954731ed8cf2d201c/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/block/BasicBlockModel.java)
  distinguishes local control transfers from calls when ending blocks. URA's
  current block builder follows this distinction. Future work should validate
  edge completeness under resource limits and explicitly model external exits.
- [CreateFunctionCmd](https://github.com/NationalSecurityAgency/ghidra/blob/b8e9917e4c01959fe97ba94954731ed8cf2d201c/Ghidra/Features/Base/src/main/java/ghidra/app/cmd/function/CreateFunctionCmd.java)
  computes bodies by following flow and reconciles overlapping bodies. URA
  conservatively assigns instruction ownership and reports ambiguous seeds;
  it does not implement shared tails or Ghidra's reconciliation policy.
- [Memory](https://github.com/NationalSecurityAgency/ghidra/blob/b8e9917e4c01959fe97ba94954731ed8cf2d201c/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/mem/Memory.java)
  distinguishes initialized bytes from unknown memory and supports mapped and
  overlay blocks. URA has flat section mapping only. Headless address reads now
  reject requests that cross a section's file-backed extent; raw offset reads
  remain available. Checked mapping additions avoid malformed-range overflow.
- [AddressSpace](https://github.com/NationalSecurityAgency/ghidra/blob/b8e9917e4c01959fe97ba94954731ed8cf2d201c/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/address/AddressSpace.java)
  models address identity and addressable-unit size separately. Before adding
  embedded processors, URA needs typed space identifiers rather than interpreting
  every u64 as a flat virtual byte address.
- [AbstractProgramLoader](https://github.com/NationalSecurityAgency/ghidra/blob/b8e9917e4c01959fe97ba94954731ed8cf2d201c/Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/AbstractProgramLoader.java)
  pairs a language with a compiler specification when constructing a program.
  URA should keep executable-format loading independent of decoder and ABI
  selection. More formats alone do not provide more instruction semantics.
- [PcodeOp](https://github.com/NationalSecurityAgency/ghidra/blob/b8e9917e4c01959fe97ba94954731ed8cf2d201c/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/pcode/PcodeOp.java)
  has explicit memory operations, direct/indirect transfers and later-stage
  dataflow operations. URA currently retains decoded flow and operands, not a
  semantic IR. A proposed IR needs bit widths, register slices, memory effects,
  flags, source-address provenance and an explicit unsupported operation. SSA,
  propagation and type recovery depend on a tested semantic lifter. This design
  note does not claim an IR or a decompiler has been implemented.
- [ProgramDB](https://github.com/NationalSecurityAgency/ghidra/blob/b8e9917e4c01959fe97ba94954731ed8cf2d201c/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/ProgramDB.java)
  separates read-only, update and upgrade modes and organizes persistent managers.
  URA now has a genuinely read-only v1-v3 snapshot reader; desktop migration
  remains explicit through its existing opener. References and analysis results
  are still in memory and recomputed after reopening.
- [AutoAnalysisManager](https://github.com/NationalSecurityAgency/ghidra/blob/b8e9917e4c01959fe97ba94954731ed8cf2d201c/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/AutoAnalysisManager.java)
  schedules analyzers by type, priority and changed address sets. URA's next
  extensibility step should be cancellable, revision-tagged passes with declared
  inputs/outputs. A public plugin ABI and arbitrary scripting should follow a
  stable internal pass contract, not precede it.

## Feature and dependency matrix

Reference column describes established disassembler workflows, not measured
parity with a particular commercial edition. Complexity is relative engineering
effort, not a delivery estimate. P0 is correctness, P1 foundational, P2 later.

| Feature | Current URA | IDA/Ghidra reference | Dependencies | Complexity | Verification | Priority |
|---|---|---|---|---|---|---|
| Loading and mapping | PE/ELF/Mach-O sections; flat u64 mapping | Rich loaders and memory spaces | Typed ranges, loader tests | High | Truncation, overflow, overlapping segments | P0 |
| x86/x64 decoding | iced-x86; paged listing | Processor-specific decoding | Decoder boundary contract | Medium | Known encodings, malformed regions | P0 |
| Function discovery | Entry/export/symbol/call seeds, manual starts | Function bodies, thunks, tails | CFG ownership, ABI metadata | High | Optimized real binaries and seeded fixtures | P1 |
| Code/data references | Direct branches/calls; proven RIP/absolute operands | Persistent typed reference database | Memory model, relocations | High | Exact source/target assertions | P1 |
| CFG correctness | Reachable blocks, loops; overlap fix | Mature block/flow models | Ownership and edge validator | Medium | All edges resolve; malformed flow fixtures | P0 |
| Indirect transfers | Reported unresolved | Heuristic jump-table recovery | Bounded data reads, bounds proofs, relocation model | High | Compiler switch fixtures and rejected decoys | P1 |
| UI graph/navigation | Real blocks, pan/zoom/fit, overview, history | Dense docked listing and graph | Layout cache, shared selection | Medium | Renderer sizes, live input | P1 |
| Names/comments/projects | SQLite v3, legacy migration, read-only snapshots | Transactional program database | Schema compatibility | Medium | v1/v2/v3 save/reopen and no-write checks | P0 |
| Headless automation | CLI JSON and 15 stdio MCP tools | Headless batch analysis and scripting | Shared core, bounded DTOs, path policy | Medium | Actual process/protocol tests | P1 |
| More architectures | Metadata only outside x86/x64 | Broad processor coverage | Architecture trait, instruction semantics | Very high | Per-ISA encoding suites | P2 |
| Semantic IR | Proposed design only | P-code / microcode pipelines | Typed operands, flags, memory/ABI model | Very high | Differential execution of supported instructions | P1 |
| SSA/dataflow | Absent | SSA and propagation passes | Tested IR, dominance, alias model | Very high | CFG/dataflow invariants | P2 |
| Types and decompilation | Absent | Types, calling conventions, C-like output | IR, SSA, ABI, structure recovery | Very high | Source-paired binaries, semantic checks | P2 |
| Debugging | Absent; disabled menu | Debugger integration varies by product | OS backend, live address translation | Very high | Controlled debuggee integration tests | P2 |
| Passes/plugins/scripts | No public API | Analysis extensions and scripting | Pass contracts, cancellation, capability policy | High | Determinism, failures, compatibility | P2 |

The next iteration should prioritize CFG invariants under limits, a bounded
data-memory reader and relocation-aware import references before jump tables.
Decompiler work remains dependent on instruction semantics; formatting operands
into C would not satisfy that requirement.
