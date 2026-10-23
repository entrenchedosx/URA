# CLI patching (v0.10)

`ura-cli --version` reports `0.14.0-dev.1`. Existing analysis/decompiler commands
remain available. `ura-cli patch --help` lists the shared-engine patch workflows:
`init`, `list`, `read`, `preview`, `apply`, `instruction`, `history`, `export`,
`manifest`. The binary is the first positional argument before the subcommand.
Patch commands return JSON; use `--json` to request structured errors as well.

All paths must resolve inside `--allow` roots. Read/list/preview needs no write
permission. Mutation, project creation, export and manifests require explicit
`--enable-writes`; patch edits target the attached `--project FILE`. Original
executables stay unchanged and existing export destinations are always refused.

Addresses use `--space offset|va|rva --address HEX`. Assembly uses numeric hex
operands (or explicit `0d` decimal). Raw images require `--raw`, a 32/64-bit mode
and an optional explicit `--base HEX`; base omission permits file-offset reads
and byte edits, without inventing virtual addresses. Reopening a raw project uses
its saved mode/base. Other files are never silently treated as raw after a parse error.

For a reviewed byte edit, run `preview --expected "55" --replacement "C3"` with
the exact space/address, save the resulting JSON, inspect it, then use
`apply --preview FILE`. The revision and expected bytes are rechecked at commit.
Instruction preview uses `instruction --budget N --assembly "..."`; explicit
`--pad` allows NOP padding and `--apply` commits the validated result. Run
`history --action undo|redo|revert|revertAll`; individual revert also requires `--id`.
`export --destination NEWFILE` writes the effective image; `manifest` exports the
history and original identity. No command executes the inspected/exported binary.

See [design, examples and exact assembler scope](BINARY-PATCHING.md). Full textual
x86 assembly, relocation rebuilding and live-memory patches are not implemented.

## v0.11 debugger

The static/patch commands remain available. `debug` runs one interactive JSON-line
controller with schemaVersion/result replies; another CLI invocation cannot access
its in-memory session. Separate launch/attach flags and exact targets/PIDs are
required. See [commands, ownership, shutdown and permissions](DEBUGGER.md).

## v0.12 advanced debugger

The same interactive `debug` process now accepts `capabilities`,
`configureBreakpoint`, `setCondition`, `stepOut`, `runTo`, `trace`,
`memoryRegions`, `snapshot` and `symbols`. Addresses are hexadecimal strings.
Launch/attach, bulk capture and file output have separate permissions. Complete
JSON-line examples, bounds and cleanup limitations are in
[ADVANCED-DEBUGGER.md](ADVANCED-DEBUGGER.md). These are runtime commands, not
operations on the static file overlay.

## v0.13 isolated execution and evidence

Run `ura-cli --allow DIR --enable-emulation --enable-writes dynamic` for the
bounded JSON-line interface. The emulation grant is independent of live debugger
launch/attach/capture; export separately requires writes. Emulator, replay and
image actions use the shared dynamic service. See the complete
[schemas, example and limits](EMULATION-DYNAMIC-ANALYSIS.md#interfaces-and-permissions).
Source is a development checkpoint; no live desktop or WOW64 acceptance is claimed.


## v0.14 processor selection

Native ARM64 PE/ELF, uniform ARM/Thumb ELF and RV32/RV64 ELF analysis use loader
processor metadata. Existing functions, CFG, IR, SSA, types, stack and decompile
commands use the same scalar engine. Explicit raw analysis adds `--processor NAME` (aarch64, arm, thumb, riscv32, riscv64, x86 or x86-64) with `--raw` and an aligned
`--base`. Existing bitness-only raw commands retain their x86/x64 meaning.

Dynamic JSON accepts `config.processor` and matching `config.bitness`. This
also selects a raw path's processor. Native-image mode must agree with explicit
configuration. Emulated disassembly uses the selected processor. No new live
processor debugger or instruction assembler is implied. See
[MULTI-ARCHITECTURE.md](MULTI-ARCHITECTURE.md) for precise ISA/ABI/loader limits.
