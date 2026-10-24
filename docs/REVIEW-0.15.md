# v0.15 review scope and findings

Two separate read-only reviewing agents examined the live source. They ran no
builds and made no edits. Their conclusions apply to the source/scope they read,
not automatically to every later interface, test, documentation or release edit.

`c_ast_review` examined expressions, Z3 translation, poison, persistent-array
memory, finite value sets and worker/Windows Job cleanup. It identified:

1. Deserialized arenas lacked builder caches and could panic on mutation. Fixed
   with checked deserialization/rebuilding and mutation cache repair.
2. Malformed pure nodes could allocate huge operand/type vectors before checking
   arity. Fixed with early operand-count rejection, including the builder API.
3. Value-set cancellation was checked too coarsely. Fixed with inner traversal /
   combination polling and a total work cap, widening incomplete facts to top.

It reread those fixes and reported no remaining concrete finding in that scope.

`decomp_review` examined SSA execution, proof scope, CFG refinement, preserved
effects/faults, dispatcher and indirect-target provenance, and resource coverage.
It identified:

1. Unresolved external/indirect terminal queries could leave `complete=true`.
   Fixed by explicitly marking those boundaries incomplete.
2. Feasible fault/return paths could be truncated while retaining `complete=true`.
   Fixed by invalidating completeness when any captured result is omitted, with
   a final-load / one-path-buffer regression.
3. Dispatcher discovery rescanned statements for every phi outside cancellation
   and time/work checks. Fixed with a comparison index and bounded preprocessing.

That review found no concrete CFG-refinement soundness blocker in its pass.
An initial later interface-review request was unavailable because of an agent
service usage limit. A subsequent separate read-only `v15_interface_review`
completed on October 24. It examined service permissions/identity/bounds,
native job integration and release scripts and identified two more findings:

1. Historical metadata load bypassed the response cap and could copy arbitrarily
   large externally edited SQLite text before parsing. Fixed with the response
   cap and a SQL byte-length check before copying into Rust. A Unicode oversized
   project regression verifies read rejection and preservation on failed merge.
2. A queued native completion could match a newer same-function request after
   clear/restart. Fixed with a unique request ID through task/error/completion
   keys. The native test queues both old and new replies and requires the new
   request/options to survive.

That reviewer reread both fixes and found no missed integration or further
concrete issue in those fixes. All three reviews were static; no reviewer ran
tests, desktop automation or native GUI processes.

The implementing agent additionally audited and tested cancellation/completion
races, stale context/byte identity, metadata merging, retained-state accounting,
actual solver timeouts, and Windows static-runtime packaging. Those checks are
self-review and automated evidence. NOT/NEG lifting and value-set target
suggestions additionally rely on their stated independent execution/semantic
tests; static reviews do not substitute for those tests.
