# Corrected v0.8 release qualification — 2026-10-21

Source inspected: `e9088342a52b828314d5da0fa51d0de7f07ea286`, including engine
commit `a42633b`. The incoming tree was clean. Formatting and all 237 workspace
tests passed again before v0.9 work. The previous strict Clippy, Release,
CLI/MCP, package and live editor records remain in ENGINE-COMPLETION-0.8.md;
there were no intervening engine changes. The three original Release EXEs and
benchmark harness were retained under the ignored `target/v09/baseline` folder.

## DPI decision

A fresh read-only Windows `GetScaleFactorForMonitor` query reported one monitor
at **100%** (successful HRESULT). The current v0.8 desktop started and its
workspace was inspected at that scale. This does not establish 150% behavior.
The supported computer-use launch routes for `SystemSettings.exe` (prior pass)
and `control.exe` (this pass) did not expose targetable windows. The latter
returned `launched app did not expose a targetable window:
Microsoft.Windows.AdministrativeTools`. A fresh inventory exposed neither a
Settings nor Control Panel window. No display configuration, security policy,
registry value or accessibility setting was changed.

The new editors still need an actual 100%/150% comparison. No old v0.7 screenshot
is substituted for that test. `v0.8.0-dev.1` remains unpublished and unused.
The original `v0.8.0-dev` tag/assets remain intact. This bounded qualification
attempt ends here; development proceeds on a separate v0.9 branch.

## Manual DPI acceptance checklist

Use the matching corrected v0.8 desktop, not the older public ZIP. Record its
SHA-256 (`9a8af2a0571212754a415a2f16c0e5616e56afbbe584e989a09aa6f37d4ff044`).
Use a disposable copy of a project and the owned `ura64.exe` fixture.

1. Record the original Windows Display Scale and resolution. Set Windows scale
   to 100%; open the fixture and the saved signature/stack/structure edits.
2. Check menu labels, dock headers, tooltips and native dialogs. Scroll the
   high-level view and Types panel; click a mapped line and confirm assembly.
3. Open signature, stack-variable and structure editors. Verify all values and
   Save/close controls remain readable and reachable; resize each window.
4. Save/reopen the project and verify names/types/signatures and selected address.
5. Change **Windows Display → Scale** to 150% (not app zoom). Repeat steps 2–4.
   Check both restored and maximized windows, screen bounds and dock resizing.
6. Restore the original Windows scale/resolution. Record results, any clipping,
   machine/display context and screenshots containing no private files.

Only mark this gate passed after recording the actual observations. A v0.9
release requires its own current UI check, including the new Pseudocode panel.

## Idle CPU scope

The same retained v0.8 native image was sampled for 12 seconds per requested
focused, unfocused and minimized condition, after settling. The workspace was
empty; no fixture was loaded. No UI Automation polling or compilation occurred
during each interval. A second pre-existing URA window supplied the focus change;
only the isolated verification image was measured. The native tool confirmed
the minimized state by refusing to capture it while minimized.

Exact process CPU deltas and working sets are in
`benchmarks/0.8-release-qualification.json`. Percent is process CPU/wall time for
one logical core, not whole-machine percentage. These short observations do not
explain the intermittent issue. They are not a matched comparison against the
old public release or the earlier loaded-fixture measurements, and do not justify
removing accessibility or inserting sleeps. No idle-CPU fix is claimed.
