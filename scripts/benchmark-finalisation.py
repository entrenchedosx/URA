"""Read-only Release measurements for the finalisation checkpoint; no GUI.

Build workspace Release and ura-core Release examples first. The previous
audit CLI is the retained, checksum-verified local package, not the old public
v0.8 ZIP. Raw results are written under target; only sanitized summaries go
in documentation. None of the input binaries are executed.
"""
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import time

import psutil

folder = Path('target/v08-finalisation')
folder.mkdir(parents=True, exist_ok=True)
core = []
for sample in ['tests/fixtures/ura64.exe', 'tests/fixtures/switch-O0.exe',
               'tests/fixtures/switch-O2.exe', 'tests/fixtures/switch-O2.elf',
               'C:/Windows/System32/ntdll.dll']:
    sample = Path(sample)
    if not sample.is_file():
        continue
    output = folder / f'{sample.name}-decomp.jsonl'
    with output.open('w', encoding='utf-8') as stream:
        process = subprocess.Popen(['target/release/examples/decomp_benchmark.exe', str(sample), '3'], stdout=stream,
                                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        observed = psutil.Process(process.pid)
        peak = 0
        while process.poll() is None:
            try:
                info = observed.memory_info()
                peak = max(peak, getattr(info, 'peak_wset', info.rss))
            except psutil.NoSuchProcess:
                break
            time.sleep(.005)
        if process.wait() != 0:
            raise RuntimeError(f'benchmark failed for {sample.name}')
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    for row in rows:
        if 'program' in row:
            report = row.pop('program')
            row['program'] = {'functions':len(report['functions']), 'edges':len(report['edges']),
                              'parameters':len(report['parameters']), 'updates':report['updates'],
                              'converged':report['converged'], 'truncated':report['truncated']}
    core.append({'sample':sample.name, 'sha256':hashlib.sha256(sample.read_bytes()).hexdigest(),
                 'observedPeakWorkingSetMiB':peak/1048576 if peak else None, 'rows':rows})
    print(sample.name, len(rows)-1, 'functions', peak/1048576, 'MiB', flush=True)

cli = []
for label, executable in [('d85b7cd-audit-local', Path('target/v08-audit/URA-0.8.0-dev-windows-x64/ura-cli.exe')),
                          ('finalisation-checkpoint', Path('target/release/ura-cli.exe'))]:
    if not executable.is_file():
        continue
    for command in ['analyze', 'signature', 'highlevel']:
        args = [str(executable), command, 'tests/fixtures/ura64.exe', '--json']
        if command != 'analyze':
            args += ['--function', '140001020']
        times = []
        for _ in range(5):
            start = time.perf_counter()
            result = subprocess.run(args, capture_output=True, check=True,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            json.loads(result.stdout)
            times.append((time.perf_counter()-start)*1000)
        cli.append({'version':label,'executableSha256':hashlib.sha256(executable.read_bytes()).hexdigest(),
                    'command':command,'startupAndQueryMs':times,'medianMs':statistics.median(times)})

result = {'method':'Release, warm file cache, three repetitions per isolated pass and full pipeline for up to 16 largest functions. Pipeline includes lifting/SSA, import hydration, bounded program demand solver, final ABI/stack/types/HIR. AST serialization is measured for size outside pipeline timing. Five fresh CLI processes per command, startup included; outliers retained. OS peak working set observed at 5 ms intervals. Program counts show whether there were supplied seeds and any propagated claims; a converged empty demand set is not recovered type coverage. No GUI or idle CPU measurement.',
          'core':core,'cli':cli,
          'seededDemand':json.loads(subprocess.run(['target/release/examples/demand_benchmark.exe'],capture_output=True,check=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)).stdout)}
(folder/'benchmark.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(cli,indent=2))
