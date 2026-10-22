# v0.9 finalisation continuation

Version `0.9.0-dev`, branch `v0.9-c-decompiler`, baseline `bc73e7f`.
Verification date: 2026-10-22. This is a verified source continuation; public
release acceptance still requires the current live gates. Existing tags and
releases are preserved, and v0.10/patching has not started.

## Readability and semantics

Source reconstruction counts uses after the observable slice, consumes constants
from the same verified SSA dataflow, substitutes constant phi inputs and keeps
nonconstant edge copies. Loads, calls, stores and conditional faults remain
ordered. Folded/dead pure instructions and removed structured jumps retain
navigation markers that attach to the next surviving line or closing brace.
The printer no longer adds a separate comment line for each removed transfer.
SSA locals remain distinct; this is not general lifetime or structure recovery.

CMP operands are immutable snapshots for direct signed/unsigned conditions
within a block, including across intervening flag-preserving register writes.
Flag writes, opaque effects and calls invalidate the cached relation. All 16
CMOV/SETcc conditions are lifted; a false CMOV still reads its memory source,
and a 32-bit CMOV destination clears the upper register bits in x64 mode.

MUL and one/two/three-operand IMUL retain full high/low products and defined
CF/OF. The emitter converts multiplication operands to unsigned 64-bit values
before truncation, avoiding signed integer-promotion overflow for 16-bit values.
DIV/IDIV retain quotient/remainder, with an observable ordered #DE guard for
zero divisors and quotient overflow. Both outputs are computed before overlapping
register writes; byte division preserves the AL/AH relationship. Sign-extension
preparation CBW/CWDE/CDQE/CWD/CDQ/CQO is supported. Undefined flags stay unknown.
ROL/ROR mask counts correctly, distinguish masked count from modulo-width count,
preserve flags at masked zero and leave OF unknown above one. Select uses only
its chosen scalar value; unconditional memory reads remain separate effects.

These are scalar bit-vector semantics. General memory faults, OS exception
delivery, RCL/RCR, floating point, SIMD and aggregate ABI reconstruction remain
outside the model. The legacy high-level presentation explicitly marks divide
guards as unsupported presentation; semantic HIR and C-like output preserve them.
Helper expressions are pseudocode, without a supplied recompilation runtime.
Specification references: Intel [Volume 2A](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf)
and [Volume 2B](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).

## Automated verification

- Workspace: **260 tests passed, 0 failed**, retaining all prior 251 tests.
- Formatting and strict workspace/all-target Clippy passed.
- Independent raw IR, semantic HIR and C-like AST execution checks compare ABI
  result, destination, byte memory and control trace; raw/HIR also compare tracked
  machine registers/flags. No inspected sample is executed.
- New expected-result cases cover all conditional codes, signed boundaries,
  8/16/32/64-bit multiply/divide forms, sign extension, masked rotate counts
  0–255, division faults before later stores, false-CMOV memory reads, and
  representative x86 instruction forms. Existing Clang PE/ELF O0–O3 corpus stays.
- Semantic multiply high uses a separate shift/add oracle, and semantic divide
  uses signed-magnitude long division instead of the raw evaluator's host-wide
  arithmetic. The C-like evaluator has its own implementation.
- New source checks cover constant propagation, every instruction's navigation
  address, deterministic re-rendering and 16-bit multiplication promotion.
- Independent read-only agent review found the integer-promotion defect; it was
  fixed and tested. No further concrete correctness finding remained in the
  reviewed constant/phi/effect/CMP/conditional/multiply/divide/rotate paths.

Workspace Release build and core Release examples passed. All three executables
carry product URA and version `0.9.0-dev`; package validation checks those
resources again. Actual Release MCP transport passed 32-tool discovery,
legacy/semantic/typed AST queries, C-like paging/AST/export and type/project
round trips. Existing CLI/service/persistence tests passed in the workspace run.
Build logs and local artifacts are retained under `target/v09-final/`.

## Matched performance investigation

The baseline Release EXEs/harness were retained before building. Both versions
parsed identical fixture/system-image hashes. Two sequential runs used three
repetitions per pass: baseline first, then current first in a separate run, with
no Cargo or UI polling during timing. All observations and executable hashes are
in [the measurement record](benchmarks/0.9-finalisation-performance.json).

NTDLL `0x1800AA290` remains 1768 instructions/440 blocks:

| Measurement | Baseline first: bc73e7f → current | Current first: bc73e7f → current |
|---|---:|---:|
| C-like lines | 15,585 → 12,867 | 15,585 → 12,867 |
| Serialized C-like AST | 7,860,920 → 7,514,974 bytes | Same sizes |
| C-like construction, including formatting | 36.47 → 39.63 ms | 38.25 → 35.72 ms |
| Semantic HIR lowering | 9.40 → 18.86 ms | 12.68 → 13.38 ms |
| Program/type propagation | 149.00 → 172.90 ms | 163.75 → 159.37 ms |
| Full pipeline | 260.93 → 351.02 ms | 290.06 → 283.23 ms |
| Observed harness peak working set | 180.37 → 180.33 MiB | 182.56 → 181.93 MiB |

Lines decreased **17.4%**, and serialized AST size decreased **4.4%**. These
improvements are deterministic for this input. The initial 34.5% pipeline
slowdown did not reproduce with reversed order (current was 2.4% faster).
Host/order variability is material; these samples establish neither a general
speedup nor a stable 35% regression. Pass profiling identifies the bounded
program/type solver as the largest measured cost in both versions. The current
pipeline also lifts previously opaque scalar instructions. Further controlled
profiling is appropriate before making broader performance claims.

Fixture CLI `decompile` medians, including fresh-process startup: baseline/current
25.97/28.45 ms in the first run, 28.57/29.04 ms in the reversed run. Individual
startup outliers remain in the record. No GPU, wakeup or presentation latency
claim is made.

## Current native checks and idle CPU

The exact final Release native image was launched with isolated persistence at
the actual **100%** primary-monitor scale (read-only OS scale query returned 100).
The NTDLL function above opened in Pseudocode with 1922 explicit unresolved
effects/transfers. Wheel scrolling and scrollbar dragging moved from declarations
through later body lines to the final closing brace at line **12,867**. The window
remained responsive. This is a real interaction check, without a frame-time SLA.
The owned loop fixture opened and displayed the new direct signed condition,
constant zero initializer and 27-line output, with assembly source highlighting.
Earlier detailed native editor/project checks remain historical evidence in
[VERIFICATION-0.9.md](VERIFICATION-0.9.md); they are not repeated claims for this build.

Cancellation was attempted on NTDLL, a larger system DLL and an owned static
stress PE with 200,000 conditional instructions. The stress analysis reached its
configured 150,000-block limit in 468 ms. The observed Cancel button disappeared
before the input could be applied; a fresh state confirmed Ready. Therefore
**live in-flight cancellation remains unverified**, despite automated cancellation
and worker-state checks. The stress binary was parsed only, never executed. No
test delay was added to manufacture a cancellation pass.

Matched idle conditions used the same owned fixture/function, classic theme,
Pseudocode/signature panels, 1480×920 client window, isolated persistence and
normal scheduling. Each process sample followed an 8-second settle and measured
20 seconds with no UI polling or builds. [The sanitized record](benchmarks/0.9-finalisation-idle.json)
excludes a failed minimize-input attempt that was repeated after fresh geometry.

| Condition | bc73e7f, % of one core | Current, % of one core |
|---|---:|---:|
| Focused | 0.31% | 0.00% |
| Unfocused | 0.00% | 0.08% |
| Minimized | 0.00% | 0.00% |

Working set stayed about 93 MiB in these samples. These controlled observations
do not explain or disprove previously intermittent focused CPU usage, and do not
establish universal zero idle CPU. Frame instrumentation never requests repaint.

The local engineering ZIP contains native Desktop, CLI and MCP, matching Windows
resources, the official artwork, docs and dependency license texts. The archive
freezes documentation before its external clean-extraction/native-startup audit;
the final audit record and checksum are published separately with the source
checkpoint, avoiding a circular checksum inside the archive itself.

## Parity and release boundary

[FEATURE-PARITY.md](FEATURE-PARITY.md) tracks **129 capabilities: 17 Supported,
52 Partial, 56 Missing, 4 Unverified**. D-06 moved from Missing to Partial with
explicit forms, tests and gaps. Counts describe this ledger's scope, not an
overall parity percentage. Complete locals, fields, loops, switches, aliasing,
calls, floats/vectors, debug metadata and other architectures remain future work.

The mandatory real 150% Windows DPI check is still unverified: an explicit
Settings launch again exposed no targetable window, and a fresh inventory
confirmed that absence. No display/security/accessibility settings were changed.
App zoom and headless scale tests do not substitute for this gate. No new public
tag/release is accepted while mandatory real DPI and in-flight cancellation
verification remain unperformed. The public Releases list was checked: existing
`v0.8.0-dev`, `v0.7.0-dev` and `v0.6.0` prereleases are preserved. No new empty or
misleading v0.9 release is created.
