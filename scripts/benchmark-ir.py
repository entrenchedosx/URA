"""Release static-analysis measurements; never executes a sample.

Run from the repo root after building the workspace and ir_benchmark example.
Outputs reproducible JSON under target/v07-profile, outside source control.
Requires the same optional psutil dependency as profile-idle.py.
"""
import json
from pathlib import Path
import statistics
import subprocess
import time
import psutil

folder = Path('target/v07-profile')
folder.mkdir(parents=True, exist_ok=True)
records = []
for sample in ['tests/fixtures/ura64.exe', 'tests/fixtures/switch-O2.exe', 'synthetic', 'C:/Windows/System32/ntdll.dll']:
    if sample != 'synthetic' and not Path(sample).exists():
        continue
    name = Path(sample).name
    output = folder / (name + '-ir.jsonl')
    with output.open('w', encoding='utf-8') as stream:
        started = time.perf_counter()
        child = subprocess.Popen(['target/release/examples/ir_benchmark.exe', sample, '5'], stdout=stream)
        process = psutil.Process(child.pid)
        peak = None
        while child.poll() is None:
            try:
                memory = process.memory_info()
                size = getattr(memory, 'peak_wset', memory.rss)
                peak = max(peak or 0, size)
            except psutil.NoSuchProcess:
                break
            time.sleep(.005)
        if child.wait() != 0:
            raise RuntimeError('benchmark failed: ' + name)
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    successful = [r for r in rows if 'function' in r and r['error'] is None]
    instructions = sum(r['instructions'] for r in successful)
    lift_ms = sum(r['liftMs'] for r in successful)
    records.append({'sample': name, 'processWallMs': (time.perf_counter()-started)*1000,
                    'observedPeakWorkingSetMiB': peak/(1024*1024) if peak else None,
                    'functionsMeasured': len(successful), 'rejected': sum(bool(r.get('error')) for r in rows),
                    'instructionsPerSecondDuringLift': instructions/lift_ms*1000 if lift_ms else None})

startup = []
for version, exe in [('v0.6', 'target/v07-baseline/ura-cli.exe'), ('development', 'target/release/ura-cli.exe')]:
    if not Path(exe).exists():
        continue
    times = []
    for _ in range(5):
        start = time.perf_counter()
        completed = subprocess.run([exe, 'analyze', 'tests/fixtures/ura64.exe', '--json'], capture_output=True, check=True)
        times.append((time.perf_counter()-start)*1000)
        assert json.loads(completed.stdout)['report']['instructionCount'] == 15
    startup.append({'version': version, 'sample': 'ura64.exe', 'startupAndAnalysisMs': times,
                    'medianMs': statistics.median(times)})
result = {'method': 'Release; five repetitions/pass; 64 largest discovered functions; all verification included. Peak is OS peak working set observed during a 5 ms polling interval. No cold-file-cache claim.',
          'core': records, 'cli': startup}
(folder/'benchmark-summary.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result, indent=2))
