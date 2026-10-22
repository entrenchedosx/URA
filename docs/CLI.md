# CLI patching (v0.10)

`ura-cli --version` reports `0.10.0-dev`. Existing analysis/decompiler commands
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
