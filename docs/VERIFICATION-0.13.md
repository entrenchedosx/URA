# v0.13 emulation and dynamic-analysis engineering verification

Date: 2026-10-23. Version `0.13.0-dev`, branch
`v0.13-emulation-dynamic-analysis`. Baseline source:
`04ad9125df5f5e67b7a12ef72f8f22ebd7866a85` on
`v0.12-advanced-debugging`, initially clean and equal to fetched origin, with323
passing tests and64 MCP tools. This report is committed with the implementation;
the containing Git commit identifies its exact source tree. Historical releases,
branches, tags and reports were preserved. No main update or history rewrite.

**Status: substantial verified source checkpoint; incomplete v0.13 milestone.**
No public v0.13 release/tag/download is accepted. This is not a source-only
published software update. `release-qualification.json` explicitly denies
publication while critical carried debugger work is incomplete. The source
checkpoint allowance in the owner's prompt applies; emulation itself is a
meaningful implemented subsystem. Remaining work is listed below, not hidden
behind the new GUI/API. Desktop control remained prohibited: no native window,
unknown sample or UI automation was launched. Executed native target code was
freshly compiled repository-owned windowless test fixtures only.

## Implemented engine and boundaries

The new `ura-core/src/dynamic` module executes real decoded scalar instructions
against isolated virtual registers/memory. `ir/lift.rs` shares semantics with
static analysis; CALL uses concrete CPU stack/transfer semantics without abstract
ABI clobbers. Shared INC/DEC and SHL/SHR/SAR were added; the two deliberately
changed HIR snapshots now represent semantics instead of unsupported barriers.

Meaningful x86/x64 scalar coverage includes MOV/extensions, LEA, add/sub/logic,
compare/test, INC/DEC, push/pop, supported near call/return/jump/Jcc, shifts/rotates,
multiply/divide, scalar sign extension, CMOV/SETcc and NOP. Register aliases,
zero extension, RIP-relative addressing, address-size override, wrapping, defined
arithmetic flags, zero-count preservation and divide faults use shared IR rules.
Only six arithmetic flags plus reserved bit1 are known in RFLAGS/EFLAGS; the
known mask and unknown values are exposed. Nonflat x86 CS/DS/ES/SS is rejected.
This is not full ISA/CPU/Windows program emulation. Unsupported encodings, vector,
FPU, system/privileged/string operations and LOCK/REP stop explicitly.

Memory is sparse by mapped region, with bounded allocated backing, permissions,
transactional stores, execute-only fetch and re-decode after self-modification.
All memory belongs to the emulator; external calls never invoke host APIs. An
explicit exact-target scalar-return assumption is separately recorded. Preferred
PE sections, ELF PT_LOAD and explicit raw/captured code are supported; architecture,
endianness, size and overlap are validated before execution. ELF filesz/memsz
consistency is checked before copying segment backing bytes, and snapshot chunks
must follow ascending nonoverlapping ranges matching their hash-scope contract. Native rebasing,
relocations, imports/TLS/dynamic linking and general OS models remain absent.

Run/step/breakpoint/run-to/stop/reset and COW checkpoint restore operate real CPU
state. Default limits:100k lifetime instructions,1s/run,8MiB memory,64 call depth,
2048 events/1MiB serialized trace payload and2 checkpoints. Hard ceilings:1m/10s,
16MiB/256depth,10k events/4MiB payload and4 checkpoints. Four sessions/replays/images,
16MiB imports,64KiB command/read bounds,512-event pages and8MiB reply bounds
constrain interfaces. Counters do not measure total COW/trace heap. CPU workers
publish cached state; cancellation is atomic between instructions. Native
analysis avoids the paint thread; synchronous bounded CLI/MCP image analysis
can delay another request on the same service.

## Replay, CFG evidence and captured images

Schema1 observed and emulated traces import once with strict ordered sequence,
identity, address/module/RVA/hash and resource validation. Per-thread indexes
and128-observation register checkpoints support efficient seeks. The thread/IP
regression is fixed: selecting another thread never uses the selected event's IP
for that thread's register bank. Emulated values are after the instruction;
observed values are paused-boundary captures. Gaps, as-of sequence, incomplete
registers and unavailable historical memory stay explicit. This is browsing,
not reverse execution or reconstruction of uncaptured state.

CFG overlays require matching original module SHA and valid RVA, count instruction
samples per block/at entries and return consecutive captured transition candidates
with sequences and static-disagreement evidence. They retain512 candidates and
report total/retained/truncated counts; no silent truncation or CFG mutation.
Matching on-disk identity does not prove unchanged runtime bytes. Emulated traces
currently lack module identities, so automatic emulated/static overlays are
incomplete. Original-image mapping rejects active static patch overlays.

Sparse image bundles preserve known bytes, permissions, missing ranges and
provenance. Captured session/PID, event/time and module metadata survive as
bounded imported evidence; emulated image exports include the actual captured
virtual state metadata. Imported legacy captures verify hashes/counts and label assumed CPU
mode; explicit32/64 mode can be supplied. Hex/disassembly/discovery/CFG/IR/SSA use
captured VAs. Pseudocode currently covers the selected contiguous executable
range; discovery is capped at5000 instructions/256 functions/2048 blocks. Images
can derive from effective patched sessions, original files, observations or
virtual emulator memory. Comparison counts known/changed/missing bytes with at
most256 individual differences and unknown causes. No relocation-aware rebasing,
automated unpacking/OEP recovery or rebuilt portable EXE is claimed.

## Debugger and integration

A targeted hardware point now disables itself when its owning runtime thread
exits, preventing a dead binding from blocking unrelated resumes or authorizing
TID reuse. A freshly compiled two-thread fixture proves retirement and safe
hardware readiness before a subsequent main-thread software breakpoint.
Existing cleanup, trace cancellation, breakpoint ownership, detach/terminate,
patching and decompiler regressions remain in the full test suite.

The Windows backend still supports x64 only. **WOW64 is Missing**, not merely
claimed untestable: a real Wow64Get/SetThreadContext adapter, x86 stepping and
unwinding were not implemented/qualified here. The available x86 compiler and
static/emulated x86 coverage do not establish WOW64. The carried ordinary-TF /
foreign-thread displaced-software handoff still fails closed and requires
explicit detach/termination; arbitrarily blocked instruction cleanup is bounded
and may retain ownership for retry. These limitations prevent claiming full
v0.12/v0.13 debugger completion and keep publication eligibility false.

Native adds a functional Emulation view, real changed-register display, checkpoint
controls, virtual decode/history selection, memory/image controls, imported replay
and cached observed CFG colors. Existing layout is retained;29 panels are tested
headlessly. No live input, desktop GPU/presentation, real OS DPI or latency
acceptance is claimed. CLI interactive dynamic JSON and three new functional
MCP tools reuse the same service: **67 tools** total. Emulation requires a new
separate default-denied `--enable-emulation`; file export still needs writes and
allowed new destinations. Debugger launch/attach/capture/termination permissions
are independent. Existing project schema8/migrations are preserved; runtime
sessions/images/traces are not persisted into projects.

## Independent verification and review

Baseline323 tests were retained. New tests cover concrete32/64 loops, arithmetic,
partial-register writes/CF, shifts across5 byte values ×256 counts ×3 operations,
CALL prefix/address wrapping/segmentation rejection, nested stacks/returns,
transactional RMW, divide/unsupported/unmapped/NX faults, self-modifying fetch,
COW reset/restore, instruction/time/depth/event limits and cancellation.

An independently compiled owned x64 PE exports an assembly arithmetic function
(IMUL/SAR/ROR/CMP/CMOV). Its six real hardware results are compared with emulation
of that exact exported function from its actual PE bytes. Expected results come
from the hardware fixture, not the emulator. This is a scoped differential corpus,
not exhaustive silicon/encoding coverage. Independently computed Rust signed/
unsigned shift expectations provide a separate oracle for3840 short sessions.

Replay tests cover300-event checkpoint seeks, thread isolation, sequence gaps,
invalid identities/versions/addresses, after-instruction timing, original mapping
and600 transition candidates with visible truncation. Image tests cover holes,
hashes, known bytes, PE/ELF virtual mapping and non-x86 rejection. Service tests
cover real async execution/cancel, handles, path/output denial, trace/image
round-trip, checkpoint counts, virtual decode and explicit legacy capture mode.
Native controller workers/rendering run headlessly. Release transports perform
the same virtual42/reset/restore/replay/image workflows and prove default-denied
execution, read-only export denial, limits, stale handles and no-clobber output.

A **separate read-only adversarial agent** reviewed CPU, prefix/stack/memory,
replay/image and service boundaries; it did not author code, execute targets or
control the desktop. All concrete findings were repaired: prefix scanning must
ignore CALL displacement bytes, CALL must honor address-size overrides, nonflat
x86 stacks must be rejected, thread-selected IP must match its bank, cached
checkpoint counts must refresh, transition truncation must be explicit, observed
identity/emulated next-IP validation must be required, and native architecture/
endianness must be checked. This is independent agent review, not third-party
external certification. The release path received a second separate read-only review. Its findings were
fixed: recheck clean source/HEAD during qualification, confirm failed-release
demotion or report potentially-public status, fail closed when Python optimization
would disable assertions, and validate/package the current qualification evidence.
The GitHub publication workflow has not run remotely.

## Required gates and measurements

The local qualification helper passed `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets --locked -- -D warnings`,
`cargo test --workspace --locked` (**352 passed,0 failed;323 baseline retained**),
and `cargo build --workspace --release --locked`. It then freshly compiled each
of the three executable roots and passed Release CLI/MCP emulation, patching,
static/decompiler, owned debugger and advanced debugger audits. Historical verification files are
not edited to imply newer binary hashes or acceptance. Current measurements:
[Release microbenchmarks](benchmarks/0.13-dynamic-release.json). Three sequential
local10k-instruction runs measured a median approximately137k instructions/sec
and0.0059ms indexed register seek. Trace JSON was1,548,055 bytes/10k events;
median overlay construction was3.5344ms for10k observations and
6-byte image analysis1.5402ms. Median instruction cost was7.29223us, hot four-byte
virtual read49.39ns, COW checkpoint creation0.0073ms and10k-event load37.3615ms. Exact per-sample values are in the JSON. Decode cache
is deliberately absent. Sampled whole-benchmark peak working set is about124MiB;
CPU time includes parsing/replay/analysis, not only instruction interpretation.
Per-snapshot private allocation, GUI idle CPU and GPU latency remain unmeasured.
Transport cancellation was under1ms in initial local tiny-loop samples; this is
not a worst-case or live debugger latency guarantee.

## Release status and remaining work

The permanent policy and tag-triggered Windows workflow now require a unique
version, all three freshly compiled EXEs individually plus a complete ZIP and
checksums, license audit, exact source/version resources and re-download checks.
Only a separate publish job obtains repository write permission. Existing
releases/tags/assets are never overwritten. Local helper checks and negative
publication gating are exercised; a public run/download cannot be claimed while
this source remains unqualified. No fake release URL or asset is provided.

The initial working-tree package audit passed ZIP CRC, complete608-member
hash accounting, zero missing license texts, icon equality, all-three-binary
identity, CLI/MCP versions, static/decompiler/type workflows and extracted MCP
transport. Its working-tree receipt explicitly marks dirtySource, so this is
local evidence and cannot authorize publication. A final committed-source audit
is written under `target/v13-final-package` without changing this report's
containing commit; consult that package's BUILD-INFO and verification JSON for
its exact source/binary/archive hashes. No source-only checkpoint is advertised
as a published software release. Public accepted release,
individual EXE links, ZIP link and remote downloaded hashes are **absent**.

Remaining priorities are genuine WOW64, interrupted cross-thread software/TF
handoff and blocked-step cleanup, broader independently verified semantics/loader
models, complete captured-state replay, persistent runtime evidence, cross-range
pseudocode/relocation-aware comparison, automated unpacking and live acceptance
when permitted. Remote/kernel debugging, symbolic execution, Python/plugins,
advanced C++/types/debug metadata, binary diffing and collaboration remain future
obligations. Current ledger: **181 capabilities:17 Supported,115 Partial,43 Missing,
6 Unverified**. These counts are inventory statuses, not competitor parity scores.
