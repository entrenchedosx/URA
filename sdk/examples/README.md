# Tested examples

Scripts execute only inside an explicitly enabled URA worker with a real analyzed
fixture/project. `inventory.py` guarded main prints real binary metadata/function
names; `function_report.py` prints disassembly/CFG/IR/SSA/source/type evidence;
`rename_functions.py` commits up to4 reviewed names; `xref_export.py` writes an
argument-selected nonexisting JSON file. The renamer needs project.write, attached
project and host writes; export needs files.export and host writes.

Package each plugin subfolder's files at ZIP root. Install disabled, inspect, then
explicitly enable its declared capabilities. Expected results:

| Example | Expected evidence | Real automated test |
|---|---|---|
| Inventory | Nonempty address/name list, metadata | extensions/tests/worker.rs; CLI/MCP scripting tests |
| Function report / batch | Core pages and per-file report, errors/resume | worker.rs; batch.rs |
| Function renamer | Persisted reviewed_* names | worker.rs; service/tests/extensions.rs |
| Xref explorer/export | Outgoing reference JSON at explicit destination | worker.rs |
| candidate_analyzer | Observed conditional-flow findings with plugin ID/version/digest | extensions/tests/plugins.rs |
| event_observer | Ordered started/completed/closed event sequences | plugins.rs |
| container_loader | URA0 bytes mapped to x64 core analysis, MOV then RET | plugins.rs |
| toy_processor | Toy8 instructions, two conditional CFG edges, navigation; no IR | plugins.rs |

The release verifier runs real examples from the extracted ZIP with the bundled
runtime and a disposable owned project. This code runs with user OS permissions;
it is not a sandbox demonstration. Full API, protocol, format and limitations:
`docs/PYTHON-SDK.md` in the package/repository.
