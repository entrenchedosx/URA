# URA v0.16 — programmable analysis foundations

Real CPython3.14.9 workers and Python SDK1 make the existing engine programmable:
functions, disassembly, bytes/mappings, CFG, IR/SSA, source, types, symbolic and virtual
emulation sessions. The native Rust console has persistent variables/history,
file loading, stdout/stderr, exceptions and cancellation. Project metadata mutations
use atomic compare-and-swap transactions and retain effective-byte/project identity.

Plugins can be installed from real ZIP packages, inspected without execution,
explicitly enabled with grants, run as analyzers/commands and disabled/uninstalled.
Code changes revoke enablement; callbacks use a verified private snapshot. Ordered
bounded event hooks carry generations and gaps. Native command menus and result
navigation use host-rendered controls. A URA0 loader feeds the existing core analysis;
Toy8 demonstrates external decoding, real core CFG construction and navigation.
Managed batch jobs isolate malformed inputs, support cancellation/resume and retain
non-overwritten per-attempt evidence plus summaries. CLI and69 MCP tools share the host.

**Python executes trusted code with the user's OS permissions. The worker is not an
OS sandbox.** Execution, snippets, plugin management, SDK grants and underlying host
writes/debugging/emulation permissions require explicit local configuration. There
is no automatic pip install or application-startup runtime download.

Download the full Windows ZIP for scripting: it includes the pinned interpreter,
required DLLs/standard library/licenses, SDK and eight real tested example categories.
All three EXEs are also separately downloadable. Checksums and BUILD-INFO identify
the exact clean source and fresh builds; source availability alone is not acceptance.

415-test inventory preserves393 baseline tests. Existing873 symbolic oracle cases
and767 processor executions/671 AST executions remain covered. Three separate review
agents found and helped resolve protocol, cancellation, registry, identity, event,
batch and native-state defects. Debugger detach no longer double-closes system event
handles. See [verification](https://github.com/entrenchedosx/URA/blob/v0.16-python-plugins/docs/VERIFICATION-0.16.md),
[SDK](https://github.com/entrenchedosx/URA/blob/v0.16-python-plugins/docs/PYTHON-SDK.md) and
[parity ledger](https://github.com/entrenchedosx/URA/blob/v0.16-python-plugins/docs/FEATURE-PARITY.md).

Scoped development limitations: no external processor IR/SSA/decompiler/execution
provider, arbitrary widget ABI, complete Python debugger parity or strong OS sandbox.
Batch parallelism is1, custom loader inputs64 KiB. Native visual/input/DPI/GPU and
broader third-party wheel compatibility remain unverified. Full IDA/Hex-Rays/Ghidra
parity is an ongoing objective, not a claim of this release.
