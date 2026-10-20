# URA 0.6.0 — native workspace and headless continuation

This engineering prerelease recovers the interrupted headless work and adds a
compact native analysis workspace. The default desktop is entirely Rust/egui.

- Conventional compact menus, classic light/dark themes, dense function browser,
  improved disassembly geometry, variable-width CFG blocks and graph overview.
- Original official icon in the window, executable resources and documentation,
  with reproducible PNG/multi-size ICO generation.
- Native CLI and 15-tool stdio MCP server over the existing shared analysis core.
- Read-only v1-v3 project attachment without migration or recorded-path access;
  write tools require `--enable-writes`.
- Regression fixes for overlapping instruction ranges, address overflow and
  address-based reads crossing file-backed sections.
- Actual renderer screenshots, Ghidra architecture study, feature dependency
  matrix, measured performance and dependency notices.

Validation: formatting, strict workspace Clippy, 55 workspace tests and Release
workspace build pass on Windows x64. MCP integration tests launch the actual
server and exercise handshake, queries, denied writes and persistent edits.

The portable Windows archive contains `ura-native.exe`, `ura-cli.exe`,
`ura-mcp.exe`, documentation, the icon, checksums and dependency notices. Open a
sample with the native app or consult `ura-cli --help` / `ura-mcp --help`.

Known limits: no debugger, decompiler, semantic IR, type recovery or jump-table
recovery. Non-x86 CPUs have metadata support only. Analysis can be partial and
indirect transfers remain unresolved. Real OS-level 150% DPI and broader
interactive/cross-platform validation remain open. Variable process idle CPU
was measured despite no continuous paint loop; platform/background-thread
profiling remains an explicit follow-up, with no low-CPU performance claim.

See [verification](VERIFICATION-0.6.md) and [research](GHIDRA-RESEARCH.md).
