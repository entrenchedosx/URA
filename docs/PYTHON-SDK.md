# Python SDK 1 and plugin API 1

URA 0.16 uses the maintained **CPython 3.14.9 Windows x64** embeddable distribution.
Extract the complete Windows ZIP. Its `runtime/python` contains the interpreter,
standard library, required DLLs, original `LICENSE.txt` and an exact SHA256 inventory.
Individual EXEs retain static analysis without Python; scripting requires the complete
runtime directory. URA never downloads Python, runs pip or installs packages at startup.

## Trust and deployment

**Scripts and plugins are trusted code with the user's OS permissions. A Python
subprocess is not an OS sandbox.** Direct Python filesystem, network, subprocess and
native-library APIs are not restricted by SDK capabilities or allowed analysis roots.
Use only code you authorize. SDK grants constrain the host API, not arbitrary Python.
No stronger AppContainer, restricted token or network sandbox is claimed.

A worker was selected over in-process embedding to contain interpreter crashes,
terminate loops, retain persistent console variables and avoid embedding CPython's
ABI/GIL lifetime into the native UI. Each interpreter uses `-I -S -B -u`, a private
compiled SDK copy, isolated module search paths, bounded JSON lines and Windows Job
Object process/job memory limits with kill-on-close. Python runs off the paint thread.
Vendored plugin modules are explicitly trusted; there is no automatic dependency
resolution. The standard library works; pip, Tk and arbitrary wheels are not promised.

Default limits: 30 seconds/job, 256 MiB/interpreter JobObject, 256 KiB combined JSON-escaped output,
2,000 host calls. Configurable ranges: 10–120,000 ms, 64–1,024 MiB, 1–10,000 calls;
memory is fixed when the session opens and each job must use the same `memoryMb`.
Four interpreters, two running jobs and sixteen retained results per host; call
`scripts/forget` after retaining a completed result. Plugin jobs are one-shot and
completed plugin results can be evicted at capacity. Result JSON is capped at256 KiB,
findings total128 KiB, host replies1 MiB, request JSON64 KiB, script source64 KiB.
Printed output is bounded; large source/IR must use pages.

Cancellation terminates the **owned Python process tree**, including blocked protocol
input. The supervisor also enforces deadlines while a host API task runs. Already
admitted bounded Rust analysis or atomic metadata calls can finish independently;
cancellation is not a rollback of committed edits. At most four such calls are in
flight globally. A failed/cancelled interpreter is replaced, not resumed. Final
identity validation is supervised too. Interpreter startup is measured separately
and has a ten-second ready handshake limit. Shutdown never kills unrelated processes.

## Run a real script

From an extracted package, with paths adjusted to your owned fixture:

```powershell
./ura-cli.exe --allow C:/owned --allow . --enable-scripting `
  --trust-script ./sdk/examples/inventory.py `
  script C:/owned/sample.exe --script ./sdk/examples/inventory.py
```

`--trust-script` pins both canonical path and current content SHA256 at startup.
Changing a file after startup denies execution. A file runs as `__main__` with
`__file__` and arguments (`--script-arg`). No startup flags are granted by a manifest
or MCP request. `--python-runtime DIR` selects another copy of the exact locked
distribution; there is no PATH/system-Python fallback. `--extensions-dir DIR` selects
the local registry (default `%LOCALAPPDATA%/URA/extensions`).

Exit statuses: 0 success; 1 invalid input/project or general service error;
2 command syntax; 3 Python exception; 4 timeout; 5 cancellation; 6 worker/protocol
crash; 7 stale identity; 8 other script resource failure; 9 execution permission
denial. Interactive CLI/MCP encode individual request failures and keep the transport
alive; EOF is normal shutdown. Plugin incompatibility is an explicit request error.

The native **Python console** and **Plugins** panels are available in the existing
View/restore-panel menus. Enable a trusted session explicitly; choose grants before
enabling. The console supports indented code, persistent variables, history, file
loading, stdout/stderr, exceptions, cancellation and output copying. Loading a file
does not run it until Run. History stores at most64 text commands; Python objects
are never serialized. Opening/reanalyzing/patching another binary invalidates the
session. Native script writes reload project metadata and invalidate derived views.
A Plugins host can start without an existing supported binary for custom loaders.
Visual/DPI/input acceptance remains unverified; only headless native tests were run.

## Typed Python objects and real analysis

The annotated package is at `sdk/python/ura` with `py.typed`. It is injected into
workers and can be indexed by an editor; standalone `import ura` cannot access a
host until URA installs its transport. Basic blocks, operands, references, IR/SSA,
types, stack variables and source lines currently use typed method signatures with
bounded **versioned dictionaries**, retaining the core response schema and provenance.
There are no fabricated domain values or unstable Rust binary-ABI promises.

```python
import ura
p = ura.current_project()
for f in p.functions(limit=128):
    print(hex(f.address), f.name)
    print(f.cfg(max_blocks=64))
    print(f.ir(ssa=True, offset=0, limit=32))
    print(f.pseudocode_page(offset=0, limit=64))
```

| Object/method | Actual result and scope |
|---|---|
| `Project.metadata()`, `binary()` | Original identity/format/processor/base/entry; effective SHA; sections; first256 imports/exports with partial flag |
| `Binary.info/sections/imports/exports`, `Segment`, `Symbol` | File metadata wrappers; original symbols distinct from user names |
| `Project.symbols(offset,limit)` | Paged original file symbols, max256 |
| `functions(offset,limit)`, `function_at(address)` | Real discovered functions; explicit page, unknown function raises UraError |
| `instructions(address,count)` | Real instruction address/bytes/length/mnemonic/operands/flow/target/invalid fields |
| `read_bytes(address,length,space=...)` | 1–8,192 wholly file-backed bytes; original/effective spaces only; no reading across mapping ends |
| `mapping(address)` | Valid mapping, RVA, file offset, section and explicit address space |
| `Function.details/cfg/ir/dataflow` | Shared function, CFG, typed IR/SSA and analysis-diagnostic service; source addresses retained |
| `pseudocode_page`, `pseudocode` | Shared C-like output and limitations; convenience string rejects both core and pagination truncation |
| `signature`, `stack`, `inferred_types`, `Project.type_library` | Recovered evidence/user overrides; inference is not ground truth |
| `xrefs(direction='incoming'/'outgoing')` | Real bounded direct/data references; no exhaustive indirect-flow claim |
| `symbolic(options)` → `AnalysisTask` | Existing real solver sessions; status/page/cancel/close; interpreter-owned IDs only |
| `EmulationSession.create(config)` | Explicit virtual mappings; bounded step/run/status/memory/trace/close; requires emulation.execute **and** host --enable-emulation |
| `DebuggerSession(session).query(action,...)` | Existing session status/registers/threads/breakpoints; pause/continue/stepInto/stepOver/stepOut additionally require debugger.control |

Debugger launch/attach/live-memory writes are unavailable through this SDK. A script's
emulator grant cannot launch a native target. Native scripting uses its own static
snapshot Service; it does not acquire the native debugger's separate session. MCP
shares the existing debugger Service and can inspect sessions created through that
server's separately authorized debugger tools. No generic Python debugger callback
blocks Windows event continuation.

## Atomic project mutations

Require `project.write`, host writes (`--enable-writes`) and an attached saved project:

```python
with p.transaction() as tx:
    for f in p.functions(limit=4):
        tx.rename(f, "reviewed_" + hex(f.address)[2:])
        tx.comment(f.address, "Reviewed by owned script", label="review")
```

The host checks immutable effective bytes, analysis generation, project path and
persisted metadata revision. External annotation/type/signature/patch/manual-function
changes invalidate the binding. An immediate SQLite transaction checks its expected
revision again, applies1–128 edits and rolls back every edit on validation/SQL failure.
The database schema is unchanged. Python never receives a direct SQLite connection.

Transaction methods also include `signature(function, signature_dict)`,
`stack_variable(function, offset, name=..., ty=...)` and `type_library(library_dict)`.
Corresponding single-edit Project methods are `set_signature`, `set_stack_variable`
and `set_type_library`. They use the existing core SignatureOverride/TypeRef/
TypeDatabase JSON contracts, processor/width validation and cache invalidation.
No name or type inference is silently promoted to a proof. A comment label can mark
a review/bookmark; there is no separate bookmark database or generic symbol-alias API.
Metadata transactions do not create binary patch history entries or edit executable
bytes. Binary patching and live-memory writes remain separate APIs/permissions.

## Versioned controller (CLI and MCP)

`ura-cli extensions [--binary FILE] [--project FILE]` accepts JSON lines, emits a ready
record, then `{schemaVersion:1,result:...}` or an explicit error for each request.
MCP exposes **69 useful tools**; `ura_extensions` takes `{request:{...}}` with exactly
the same controller. Scripting is disabled by default. Inline code additionally
requires `--allow-script-snippets`. Ordinary logs never go to MCP stdout.

| operation | actions / required data |
|---|---|
| `projects` | open(path,project optional), analyze(handle), close(handle) |
| `scripts` | open(handle,capabilities,limits); run(session,path OR code,args,limits); status/result/cancel/forget(job); close(session); list |
| `plugins` | list; inspect(id); install(path ZIP); enable(id,capabilities,configuration); disable/uninstall(id); run(id,handle,kind='analyzer' OR command); accept(job) for decoder/loader results |
| `events` | page(after), returns next sequence, gap, bounded events, dropped count and recent dispatch errors |
| `processor` | page(handle,address optional,limit), close(handle); other actions explicitly unsupported |
| `image` | Existing memory-image info/analyze(entry)/memory/disassembly/close operations |
| `batch` | start(paths OR directory,script,destination,analysis,limits,resume,parallelism); status/cancel/close(id) |

Results include job/session IDs, start time, interpreter, grants, duration, startup,
source plugin/version/digest/parameter identity, project identity and identityStatus.
Historical job findings become `stale` after changes; a busy service reports unchecked
status. Native navigation clears project-bound results when context changes.

## Package and lifecycle

ZIP root contains `ura-plugin.json`, Python entrypoint, LICENSE and optional vendored
files. See the four complete example manifests. Required fields are id/name/version/
author/description/license/entrypoint/apiVersion/minimumUraVersion/requiredCapabilities/
platforms/architectures. Optional fields: optionalCapabilities, configurationSchema,
commands, events, analyzer, loader, processor, dependencies (must be empty).

Installation validates paths, Windows device names/ADS, duplicates/case collisions,
links/reparse points, expanded bytes, file/node/depth limits, manifest/API/version,
entrypoint and declared registrations **without running code**. New installs are
disabled. Explicit management permission and declared startup grants are required
to enable. Code-tree digest and config/grants persist atomically; changed code
disables execution. Each callback imports a verified private snapshot. Disable
revokes future admission, cancels current workers, removes event subscriptions;
uninstall removes only the checked registry child. Third-party code is neither
signed nor reviewed by URA. Concurrent management from separate URA processes is
not a transactional registry service; avoid sharing one writable registry between
simultaneous managers.

API1 compatibility is exact for protocol/API; SDK1.0.0 is distinct from app0.16.0-dev
and plugin package SemVer. Minimum app comparison uses numeric major/minor/patch,
allowing the current development prerelease for examples. Unsupported platforms,
architectures/capabilities and nonempty dependency declarations are rejected.
Configuration supports bounded objects with scalar string/integer/boolean properties,
enum and required keys; it is not a complete JSON Schema implementation.

`on_load(context)` and `on_unload(context)` surround each one-shot callback. Context
has project, arguments, event, configuration and apiVersion. Detached loader/processor
or historical/closed-project events have `project=None`. Plugin commands are declared
menu entries in the native Plugins panel; results/finding links use host rendering,
never native pointers. There is no arbitrary third-party egui ABI/custom widget system.

## Findings and events

`ura.emit_finding(title, at, explanation, category=..., severity=..., confidence=...,
evidence=..., related=...)` attributes source plugin and project identity. Allowed
confidence values: candidate, observed, unverified. Plugin text cannot create a
host-proven solver fact or automatically authorize an executable patch.

Events: binary.loaded, analysis.started, analysis.completed, function.renamed,
comment.changed, metadata.changed, project.closed. Ordered sequence/generation is
retained in a256-row ring, pages32, payloads8 KiB (large payload explicitly omitted).
Gaps/drops are reported. Subscription callbacks run outside Service locks, with
bounded admission retries and a5-second worker deadline. Events produced by a plugin
do not recursively schedule plugins. Project closure or newer generations deliver
historical event metadata detached rather than rebinding to a different project.
Not every existing debugger/patch/type UI operation publishes this event family;
those additional hooks are future work. Findings persist only when explicitly
exported; interpreter memory and arbitrary Python objects never enter project tables.

## Loader and processor examples

`container_loader` consumes an owned **URA0** format: magic4, u64 little-endian base,
u32 entry offset, then x64 code. Run with kind loader and path; poll the job, then
plugins/accept(job). The host validates all file-backed ranges, overflow, permissions,
mapped executable entry and overlap before inserting the actual memory image into
the existing core. Return includes image handle and real function/CFG analysis.
Image disassembly/navigation uses known bytes and never fills unmapped gaps.
Imports/relocations/symbols and large custom containers are not yet generalized;
this is a64 KiB file-backed extension foundation, not an OS executable loader.

`toy_processor` decodes Toy8:00 NOP,10 imm MOV r0,20 imm ADD r0,30 off JNZ,
40 off JMP,FF RET. Branch offsets are unsigned byte offsets from the input base.
Descriptor carries registers, endianness, addressBits, entry, lengths, text and flow.
Host validates full ordered byte coverage and branch boundaries; shared Rust core
constructs real blocks/edges/xrefs. Processor/page navigates decoded addresses.
Capability negotiation explicitly rejects external IR, SSA, decompilation, symbolic
execution and emulation; calling conventions/stack/IR-effect providers remain future
API extensions. Arbitrary instruction semantic truth cannot be proved by structural
validation of a plugin's claims.

## Batch and examples

Batch selects up to64 files or a nonrecursive allowed directory. One active input
per batch (parallelism1); at most two retained batches. Input bound32 MiB, analysis
default16,384 instructions/2,048 functions/16,384 blocks; `analysis` config supports
bounded maxInstructions/maxFunctions/maxBlocks/followCalls/seedSymbols. Separate
read-only Services preserve interactive handles. SDK host capabilities follow the
explicit startup grants; batch project writes stay disabled. Output requires
files.export and host writes. A malformed input records a failure and the next runs.

Exports use no-clobber persistence. Resume compares input/script/version/runtime/API/
analysis/limits/grants contract; matching completed files skip. Failed/cancelled runs
retain evidence and create numbered attempts; they never overwrite prior records.
A unique JSON summary retains the input list, counters, errors, options and output
paths. Cancellation interrupts Python; a bounded initial static load/analysis can
finish before noticing cancellation. CSV, general parallel scheduling and persistent
cross-process job-control resumption are not implemented.

All eight example categories run in real tests: inventory, function report/batch,
renamer, xref export, attributed analyzer, ordered event observer, custom container
loader and Toy8 processor. See `sdk/examples/README.md`. Test runtime setup:

```powershell
python scripts/prepare-python-runtime.py
cargo test -p ura-extensions -p ura-service
```

Build-time setup fetches only the locked official archive; range requests, archive
SHA256, exact member hashes and CRC are checked. It never changes system Python.
Runtime discovery/import failures identify missing/mismatched package files; extract
the full ZIP rather than installing unrelated Python packages.

Primary runtime sources: [CPython3.14.9 release](https://www.python.org/downloads/release/python-3149/),
[embeddable package](https://www.python.org/ftp/python/3.14.9/),
[official Windows distribution documentation](https://docs.python.org/3/using/windows.html#the-embeddable-package).
