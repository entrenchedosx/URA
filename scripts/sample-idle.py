"""Sample an already selected verification process without polling its UI.
Usage: python scripts/sample-idle.py PID OUTPUT [seconds]
Use native controls to select the workspace condition before starting this.
"""
import json
from pathlib import Path
import sys
import time
import psutil

process = psutil.Process(int(sys.argv[1]))
time.sleep(8)
before = sum(process.cpu_times()[:2])
threads = {t.id: t.user_time+t.system_time for t in process.threads()}
start = time.perf_counter()
time.sleep(float(sys.argv[3]) if len(sys.argv) > 3 else 20)
elapsed = time.perf_counter()-start
result = {'seconds': elapsed, 'cpuOneCorePercent': (sum(process.cpu_times()[:2])-before)/elapsed*100,
          'workingSetMiB': process.memory_info().rss/(1024*1024),
          'threads': [{'id': t.id, 'cpuSeconds': t.user_time+t.system_time-threads.get(t.id,0)} for t in process.threads()]}
Path(sys.argv[2]).write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps({k:v for k,v in result.items() if k!='threads'}))
