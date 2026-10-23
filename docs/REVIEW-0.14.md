# Independent v0.14 review

Two separate reviewing agents inspected the current implementation read-only
on2026-10-23, as requested by the owner. They did not change files, run builds,
control the desktop or publish releases. Review is distinct from the Unicorn
machine-code oracle and the independent source-AST executor.

The processor/IR reviewer identified ARM post-index omission, A64 constrained
alias/pair forms, Call state layout and clobbers, Thumb entry/stub low bits,
ARM register aliases, trap/PC-write CFG boundaries and above-entry stack extent
overclaim. The ownership/integration reviewer identified raw project resave mode
loss, odd explicit ARM-base ambiguity, parked-step rollback double release and
new-thread ordinary-TF suspension. The primary engineer repaired these and
added targeted regressions; reviewers re-read the relevant fixes.

The new-thread issue was independently reproduced by a full-suite race failure;
its policy regression measures actual SuspendThread counts on an owned stopped
fixture. Eight separate foreign-step stress runs then passed. Genuine nested
software displacement remains explicitly rejected rather than silently resumed.

The stack reviewer re-read the bounded affine SSA proof and found no additional
concrete join/cycle/width blocker; its final incoming-byte overclaim was corrected
and tested with a write-only above-entry-SP store. This is not exhaustive review
or formal proof. See VERIFICATION-0.14.md for test/oracle counts and scope.
