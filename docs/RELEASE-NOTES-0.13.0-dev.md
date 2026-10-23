# URA 0.13.0-dev — unqualified engineering checkpoint

**Not approved for publication.** This source adds genuine isolated scalar
x86/x64 execution, indexed recorded trace replay, provenance-bearing observed
CFG overlays and sparse captured-memory CFG/IR/SSA/scoped pseudocode analysis.
It adds shared INC/DEC/shift semantics, separate default-denied emulation grants,
bounded async cancellation and fresh-three-EXE/ZIP/checksum release automation.
Targeted hardware breakpoints retire safely when their owning thread exits.
Native, CLI and MCP share the engine; MCP exposes67 functional tools.

Platform: Windows x64 build/host, with scoped x86/x64 static/emulated semantics;
live debugger x64 only. No arbitrary Windows-program/OS emulation, full ISA,
relocations/import loader, historical memory recovery, reverse execution, general
unpacker or reconstructed portable executable. WOW64 and interrupted cross-thread
software/TF cleanup remain incomplete. Native input/DPI acceptance is unverified
under the owner's restriction. Publication eligibility remains false.

See [verification](VERIFICATION-0.13.md), [coverage and permissions](EMULATION-DYNAMIC-ANALYSIS.md)
and [release policy](RELEASING.md). A future qualified version requires new notes,
a unique version/tag, all build/package gates and actual downloaded asset checks.
This file does not announce a public software release.
