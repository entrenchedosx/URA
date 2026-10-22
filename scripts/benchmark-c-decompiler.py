"""Compare retained v0.8 and current Release tools without executing samples.

Run after workspace/examples Release builds, with no Cargo or UI polling active.
Uses psutil only for read-only process measurements. Raw data stays under target.
"""
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import time
import psutil

folder = Path('target/v09/performance')
folder.mkdir(parents=True, exist_ok=True)
flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
samples = ['tests/fixtures/ura64.exe', 'tests/fixtures/semantic-O0.exe',
           'tests/fixtures/semantic-O3.elf', 'tests/fixtures/decompiler-O0.exe',
           'tests/fixtures/decompiler-O3.elf', 'C:/Windows/System32/ntdll.dll']
records = []
for label, executable in [('v0.8-retained', Path('target/v09/baseline/decomp_benchmark.exe')),
                          ('v0.9-source', Path('target/release/examples/decomp_benchmark.exe'))]:
    for sample in samples:
        sample = Path(sample)
        output = folder / f'{label}-{sample.name}.jsonl'
        with output.open('w', encoding='utf-8') as stream:
            child = subprocess.Popen([str(executable), str(sample), '3'], stdout=stream, creationflags=flags)
            process = psutil.Process(child.pid)
            peak = 0
            while child.poll() is None:
                try:
                    memory = process.memory_info()
                    peak = max(peak, getattr(memory, 'peak_wset', memory.rss))
                except psutil.NoSuchProcess:
                    break
                time.sleep(.005)
            assert child.wait() == 0, sample
        rows = [json.loads(line) for line in output.read_text().splitlines()]
        for row in rows:
            row.pop('program', None)
        records.append({'version': label, 'sample': sample.name,
                        'sampleSha256': hashlib.sha256(sample.read_bytes()).hexdigest(),
                        'executableSha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
                        'observedPeakWorkingSetMiB': peak / 1048576, 'rows': rows})
        print(label, sample.name, round(peak/1048576, 2), 'MiB', flush=True)
cli = []
for label, executable in [('v0.8-retained', Path('target/v09/baseline/ura-cli.exe')),
                          ('v0.9-source', Path('target/release/ura-cli.exe'))]:
    for command in ['signature', 'highlevel'] + (['decompile'] if label == 'v0.9-source' else []):
        values = []
        for _ in range(5):
            start = time.perf_counter()
            result = subprocess.run([str(executable), command, 'tests/fixtures/ura64.exe',
                                     '--function', '140001020', '--json'], capture_output=True,
                                    check=True, creationflags=flags)
            json.loads(result.stdout)
            values.append((time.perf_counter()-start)*1000)
        cli.append({'version':label,'command':command,'startupAndQueryMs':values,'medianMs':statistics.median(values)})
ir_output = subprocess.run(['target/release/examples/ir_benchmark.exe','C:/Windows/System32/ntdll.dll','3'],
                           capture_output=True, check=True, text=True, creationflags=flags).stdout
(folder/'ir-ntdll.jsonl').write_text(ir_output, encoding='utf-8')
result = {'method':'Sequential Release harnesses, warm file cache, three pass/pipeline repetitions, up to 16 largest functions; 5ms OS peak-working-set sampling. Same sample hashes for baseline/current. Current pipeline also builds C-like AST/lines. Separate C construction includes formatting; C render consumes an already-built AST. Five fresh CLI processes including startup. No inspected sample executes. No UI latency, GPU, or wakeup inference.',
          'core':records,'cli':cli,'ir':[json.loads(line) for line in ir_output.splitlines()]}
(folder/'benchmark.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps(cli,indent=2))
