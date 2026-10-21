"""Release v0.8 audit measurements. Samples are read, never executed.

Build ura-cli, ir_benchmark and decomp_benchmark in Release first. The v0.7
baseline is the verified public ZIP extracted to target/v08-audit-baseline.
Requires psutil. All raw/private results stay in target/v08-audit.
"""
import json
from pathlib import Path
import statistics
import subprocess
import time

import psutil

folder = Path('target/v08-audit')
folder.mkdir(parents=True, exist_ok=True)
records = []
for sample in ['tests/fixtures/ura64.exe', 'tests/fixtures/switch-O0.exe',
               'tests/fixtures/switch-O2.exe', 'tests/fixtures/switch-O2.elf',
               'C:/Windows/System32/ntdll.dll']:
    if not Path(sample).is_file():
        continue
    for harness in ['ir_benchmark', 'decomp_benchmark']:
        output = folder / f'{Path(sample).name}-{harness}.jsonl'
        with output.open('w', encoding='utf-8') as stream:
            child = subprocess.Popen([f'target/release/examples/{harness}.exe', sample, '5'], stdout=stream)
            process = psutil.Process(child.pid)
            peak = 0
            while child.poll() is None:
                try:
                    memory = process.memory_info()
                    peak = max(peak, getattr(memory, 'peak_wset', memory.rss))
                except psutil.NoSuchProcess:
                    break
                time.sleep(.005)
            if child.wait() != 0:
                raise RuntimeError(f'{harness} failed for {sample}')
        records.append({'sample':Path(sample).name, 'harness':harness,
                        'observedPeakWorkingSetMiB':peak/(1024*1024) if peak else None,
                        'rows':[json.loads(line) for line in output.read_text().splitlines()]})

cli = []
for version, executable in [('v0.7.0-dev', 'target/v08-audit-baseline/ura-cli.exe'),
                            ('v0.8-audit', 'target/release/ura-cli.exe')]:
    for command in [['analyze', 'tests/fixtures/ura64.exe', '--json'],
                    ['ir', 'tests/fixtures/ura64.exe', '--function', '140001020', '--json']]:
        measurements = []
        for _ in range(5):
            start = time.perf_counter()
            result = subprocess.run([executable, *command], capture_output=True, check=True)
            json.loads(result.stdout)
            measurements.append((time.perf_counter()-start)*1000)
        cli.append({'version':version, 'command':command[0], 'sample':'ura64.exe',
                    'startupAndQueryMs':measurements, 'medianMs':statistics.median(measurements)})

result = {'method':'Release; warm OS cache; five repetitions per pass and CLI command. 16 largest functions for decompiler passes, 64 for IR. OS peak working set observed at 5 ms intervals (short processes can finish before a sample). Decompiler timings isolate each pass after a verified bundle; final stack reconstruction and constraint merging are not included. No whole-program interprocedural solver exists, so no propagation benchmark is claimed.',
          'core':records, 'cli':cli}
(folder/'benchmark.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
for record in records:
    rows = [r for r in record['rows'] if 'function' in r and not r.get('error')]
    print(record['sample'], record['harness'], len(rows), 'functions', record['observedPeakWorkingSetMiB'], 'MiB')
print(json.dumps(cli, indent=2))
