# URA v0.14.0-dev — scalar multi-architecture analysis

This development prerelease adds real AArch64 scalar decoding, register effects,
CFG/IR/SSA, AAPCS64 evidence, physical stack slots, deterministic C-like pseudocode
and bounded isolated execution. ARM32/Thumb and RV32I/RV64I add verified scalar
subsets through the same engine. Native, CLI and the existing 67 MCP tools share
the implementation. Explicit raw processor metadata survives project resaves.

The debugger now serializes a foreign software displacement while retaining an
ordinary TF step's owner. Rollback preserves parked work; newly created threads
are suspended only for actual software displacement, and exited peer ownership
cannot transfer to a reused TID. True nested/rearm cases and uncertain cleanup
remain safely stopped.

Validation includes the complete existing regression suite plus processor/stack/
ownership tests, compiler-generated O0–O3 PE/ELF fixtures and 767 successful
Unicorn comparisons, with671 independent executions of the generated C-like AST. Another 36 ARM/Thumb IT/conditional-transfer cases verify
explicit unsupported boundaries. Reports and measured Release performance are
included in the ZIP. See [verification](https://github.com/entrenchedosx/URA/blob/v0.14.0-dev/docs/VERIFICATION-0.14.md).

Distribution is **Windows x64**: Desktop, CLI and MCP are individually downloadable,
with a complete ZIP and SHA-256 manifest built from the tagged source. The release
workflow verifies a draft, publishes, then downloads and verifies the public assets.

This is scoped development software. It does not provide full ARM/RISC-V ISA,
floating/vector/system or OS emulation, compressed RISC-V execution, mixed ARM/
Thumb mode transitions, ARM64-host executables, a new-processor live debugger or
instruction assembler. WOW64 remains explicitly unsupported. Native input, real
OS DPI, GPU/presentation and idle desktop CPU acceptance remain unverified under
the owner's desktop-control restriction. These are not reported as passed.

Historical releases and the v0.9–v0.13 source checkpoints are preserved; none is
retroactively relabelled accepted. Full IDA/Hex-Rays/Ghidra parity remains a
multi-release obligation, tracked in the feature ledger.
