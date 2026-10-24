# v0.16 scripting and extension verification

2026-10-24. Source version **0.16.0-dev**, branch `v0.16-python-plugins`.
Baseline: accepted `v0.15.0-dev.1`, commit
`6c6aaf24d9fe4fd04f4a2b1c4afc0c8298560bc3`, clean, **393 passing tests**.
Main and historical releases/tags are preserved. This report's containing commit
identifies the checkpoint; the final clean tagged BUILD-INFO/public download receipts
identify the exact accepted source and all artifact hashes. A source push alone is
not release acceptance.

## Implemented scope

Bundled maintained CPython3.14.9 amd64; versioned worker protocol/API1 and annotated
Python SDK1.0.0; native console/history/files/output/errors/cancel; real analysis
queries; atomic project names/comments/signatures/stack types/type-library edits;
ZIP plugin install/discover/explicit grants/enable/disable/uninstall; verified private
code snapshots; attributed analyzer findings; ordered finite event hooks; declarative
native commands/results/navigation; file-backed URA0 loader into existing analysis;
Toy8 decoder into existing core CFG; managed bounded batch/cancel/resume/exports;
CLI and **69 MCP tools** sharing the host. See [full API/scope](PYTHON-SDK.md).

Python is **trusted code with user OS permissions, not an OS sandbox**. No AppContainer,
restricted token, network restriction or hostile native-code safety is claimed.
The Windows JobObject/worker protocol provides crash/resource containment. Startup
execution is disabled; script content pinning, explicit snippets/plugin management,
declared capabilities and underlying host path/write/debug/emulation permissions
are separately checked. No runtime downloads or automatic pip/dependency install.

The locked official archive is12,609,248 bytes, SHA256
`3c01d7cfc666f746a6f064f60fb2156ab0ec464d3d738ab796371a46a9bb24a2`.
All distribution files have pinned hashes; original CPython/DLL notices accompany
the ZIP. There is no hidden developer Python/solver runtime dependency. Windows
x64 is the qualified distribution. Generic wheel compatibility is unverified.

## Actual checks

- Baseline full workspace:393 passed (`target/v16-baseline.log`).
- Later complete workspace:414 passed after the debugger detach cleanup correction
  (`target/v16-qualified-tests.log`), then the additional real virtual-emulation and
  denied-write SDK test passed, bringing the combined current test inventory to415.
  Exact-source qualification reruns the entire415-test suite before packaging.
- Strict workspace formatting and all-target clippy with warnings denied passed.
- `cargo build --workspace --release --locked` passed. All three final EXE roots
  are rebuilt with unique metadata by the clean qualification helper; stale EXEs
  are never package inputs.
- Real CPython tests: persistent globals, ordinary file main/file/args, function/CFG/
  IR/SSA/source/type queries, metadata persistence and rollback, export, exceptions,
  worker os._exit, loops, explicit cancellation, memory allocation, output/control
  characters, blocked protocol writes, service contention and fresh-session recovery.
- Genuine ZIP plugins: attributed findings, dataclass imports, command calls, private
  snapshots, changed-code revocation, traversal/device/ADS paths, malformed packages,
  grants/config bounds, disable/uninstall, ordered fast events and detached closure.
- Loader custom container really feeds mapped bytes and executable entry into core
  analysis; Toy8 uses core blocks/edges and real decoded-address navigation. Unsupported
  external IR/SSA/source/emulation/symbolic capabilities explicitly remain false.
- Batch tests cover mixed malformed input isolation, completed resume, cancelled
  active-script resume preserving prior attempts, no overwrite and explicit grants.
- CLI/MCP real processes cover execution default denial, content-trusted scripts,
  inline-code denial, JSON protocol correctness, exit statuses and malformed input.
- Existing independent symbolic oracle: **873 cases /80 functions**, passed.
  Existing processor oracle: **767 machine executions,671 source AST executions,
  290 static analyses**, zero failures,36 explicit unsupported boundaries. Owned
  fixture code is emulated/parsed; it is not launched as a native sample.
- License preflight collected **288 locked packages, zero missing notice files**.
  CPython's original runtime license is additional and included in the package.
- Headless Release scripting verifier exercises real package runtime/import isolation,
  analysis, transactions/export, symbolic SDK session, plugins, loader/processor,
  events, batch and uninstall. Full extracted-ZIP audits rerun it from actual assets.

One later full run exposed a genuine intermittent debugger double-close after detach;
it was repaired, not waived. The narrow detach test and complete13-test debugger
unit suite pass after correction. See [independent review](REVIEW-0.16.md) for the
failure evidence, three reviewer scopes, repaired findings and review limitations.

## Measurements

Warm Release headless results (small owned x64 fixture; not a general throughput
guarantee): interpreter startup72–93 ms; metadata API job median12.2–15.5 ms;
100 ms deadline observed return106–126 ms; discovery3.2–4.0 ms;
analyzer113–136 ms; analysis plus two ordered callbacks250–555 ms;
one-input batch272–276 ms. Sampled aggregate host/children working set about47 MiB without a symbolic worker,
or110 MiB when the SDK solver check is included.
Memory uses20 ms sampling and may miss short peaks. The exact structured report is
in [0.16-scripting-release.json](benchmarks/0.16-scripting-release.json).

Five alternating fresh-process CLI comparisons to the SHA-verified public v0.15.0-dev.1
CLI measured medians: analysis26.37→27.35 ms, disassembly26.32→25.99 ms,
IR26.88→26.31 ms and decompile26.49→26.52 ms. Startup is included; outliers are
retained and scripting is disabled. The small mixed results do not establish a
material core regression or broad parity. See [raw controlled results](benchmarks/0.16-core-controlled.json).
Native idle CPU/input/DPI/GPU responsiveness was not measured in this run.

## Limitations and acceptance

The full ledger tracks **252 capabilities:33 Supported,165 Partial,46 Missing,
8 Unverified**. These inventory statuses are not an IDA/Ghidra completion percentage.
Scripting/SDK/events/loader/processor/batch breadth remains partial. No general
external processor IR/ABI/stack/effect provider, arbitrary custom widgets, full
debugger Python parity, cross-process registry transaction service or general batch
parallel scheduler is advertised. Batch is sequential, max64 inputs/32 MiB per input;
bounded static input analysis may finish before cancellation. Already admitted Rust
API calls may finish after Python termination; metadata transactions remain atomic.
Historical findings retain their original identity and are marked stale after changes.

No desktop automation, desktop launch, manual native input,150% DPI or clean physical
machine visual test occurred. Headless native tests render the existing Rust panels.
This development release is scoped accordingly; visual acceptance remains unverified.

Public acceptance requires exact-tag clean-source build, fresh separate Desktop/CLI/
MCP EXEs, full runtime+SDK ZIP, checksums, complete license/text audit, real clean-folder
CLI/MCP/Python/plugin checks and independent redownload of all five public assets.
The final engineering receipt records completion or failure of those gates without
changing historical releases or replacing an existing tag.
