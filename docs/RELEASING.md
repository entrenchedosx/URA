# Permanent binary release policy

Every **published software update** requires a new Cargo version and unique Git
tag, three freshly compiled Windows x64 EXEs (`ura-native.exe`, `ura-cli.exe`,
`ura-mcp.exe`) individually downloadable, a ZIP containing all three plus assets,
usage/docs/licenses/provenance, and a SHA256 manifest covering each EXE and ZIP.
A source push or local audit package is not a published update. Historical tags,
assets, reports and releases are immutable; never force-push, reuse a tag/version,
overwrite an old asset or alter main automatically.

## Qualification and local builds

`release-qualification.json` is a checked-in publication gate. Set its version
to the Cargo version, document evidence and set `publishable:true` only after
critical correctness/safety/package gates are resolved. Current0.13.0-dev is
**false/source-checkpoint** because WOW64 and interrupted cross-thread software
cleanup remain incomplete. Manual desktop restrictions are recorded separately;
headless rendering must not be called live desktop acceptance.

From committed clean source, run:

```powershell
./scripts/build-windows-release.ps1 -OutputDirectory target/my-new-build
```

For an explicitly unqualified working-tree audit only, use `-AllowDirty`. Its
receipt marks the source dirty and the publisher rejects it. Use a new empty
output folder every time. The helper rechecks clean HEAD/source before sealing and after packaging, and
verification fails immediately if Python optimization disables assertions.
The helper runs fmt, strict all-target Clippy, all
workspace tests, a locked workspace Release build, and **fresh compilation of
each executable root** with a unique compiler metadata input. Existing dependency
artifacts may be cached; previous EXEs/ZIPs are never build inputs. It checks
Windows product/version resources, performs dynamic/static/decompiler/patching/
debugger checks on headless owned fixtures, collects dependency licenses and
fails if texts are missing, creates a no-replacement ZIP, then verifies every
extracted file/hash and CLI/MCP transport. `BUILD-INFO.json` records the exact
source commit, dirty state, profile, toolchain, target and binary hashes.
The external `SHA256SUMS.txt` covers exactly the three EXEs and ZIP. The ZIP also
has its own internal complete file manifest. Source acceptance precedes tag
publication; audits remain local until the complete release contract succeeds.

## Tag automation

`.github/workflows/windows-release.yml` triggers for version tags, including
dev/RC/stable/hotfix suffixes, and never arbitrary branch pushes. The helper
requires exact Cargo/tag/HEAD agreement, a clean tree and publication eligibility.
The Windows2025 build job uses Rust1.99.1 with fmt/clippy and locked dependencies.
Checkout/upload actions are pinned to full upstream commit hashes. Build has
read-only contents permissions; only the separate publish job has contents write.
No credentials persist in the checkout and no network-service credentials enter
the package.

The approved source branch must first be committed/pushed without rewriting
history. Check remote tags/releases before choosing a new version, then create
and push that unique tag. Tagging a source checkpoint is not a bypass for the
eligibility gate. The workflow preserves build/download audit artifacts and
GitHub step logs. The local helper is exercised here; remote Actions execution
and public artifact download are unverified until an approved tag actually runs.

`publish-windows-release.ps1` rejects an existing release and checks the remote
tag against the exact clean build receipt. It creates a **new draft**, uploads
the three EXEs, ZIP and checksum manifest together, verifies downloads, publishes,
then downloads/verifies the public assets again. A failure attempts to demote that newly created release to draft/incomplete and
fails the job. The script verifies demotion; if it cannot confirm it, the error
explicitly warns that the new release may still be public. It never replaces assets,
moves tags or modifies an older release. A draft/upload failure is not success.
Prerelease Cargo versions are marked GitHub prereleases. The notes must describe
features, fixes, platform, security boundaries, limitations and actual evidence.

`verify-github-release.ps1` checks remote source/tag, exact nonempty asset set,
downloads from GitHub to new storage, verifies hashes, safely extracts the ZIP,
checks all members/licenses/version resources/provenance and individual-vs-ZIP
EXE identity, and runs CLI/MCP smoke checks on downloaded programs. It does not
launch a native desktop window under the current restriction. Release/download
links may be reported as successful only after these steps pass. Failures require
a new unique version once repaired; never recycle historical versioned binaries.
