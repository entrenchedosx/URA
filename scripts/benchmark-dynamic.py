"""Measure a freshly built owned, windowless Release benchmark; no GUI or sample execution."""
import argparse,ctypes,json,statistics,subprocess,time
from ctypes import wintypes as w
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('--exe',type=Path,default=Path('target/release/examples/dynamic-bench.exe'));parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
class Counters(ctypes.Structure):
 _fields_=[('cb',w.DWORD),('PageFaultCount',w.DWORD)]+[(name,ctypes.c_size_t) for name in ['PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage','QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage']]
get_memory=ctypes.WinDLL('psapi').GetProcessMemoryInfo;get_memory.argtypes=[w.HANDLE,ctypes.POINTER(Counters),w.DWORD];get_memory.restype=w.BOOL
get_times=ctypes.WinDLL('kernel32').GetProcessTimes;get_times.argtypes=[w.HANDLE]+[ctypes.POINTER(w.FILETIME)]*4;get_times.restype=w.BOOL
samples=[]
for _ in range(3):
 start=time.perf_counter();child=subprocess.Popen([str(args.exe.resolve())],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,creationflags=subprocess.CREATE_NO_WINDOW);peak=0
 while child.poll() is None:
  memory=Counters();memory.cb=ctypes.sizeof(memory)
  if get_memory(w.HANDLE(int(child._handle)),ctypes.byref(memory),memory.cb):peak=max(peak,memory.PeakWorkingSetSize)
  assert time.perf_counter()-start<30
  time.sleep(.005)
 out,error=child.communicate(timeout=5);assert child.returncode==0,error;wall=time.perf_counter()-start
 created,exited,kernel,user=[w.FILETIME() for _ in range(4)]
 assert get_times(w.HANDLE(int(child._handle)),ctypes.byref(created),ctypes.byref(exited),ctypes.byref(kernel),ctypes.byref(user))
 ticks=lambda value:(value.dwHighDateTime<<32)|value.dwLowDateTime
 cpu=(ticks(kernel)+ticks(user))/10000000
 result=json.loads(out);result.update({'processWallMs':wall*1000,'processCpuMs':cpu*1000,'averageCpuPercentOneCore':cpu/wall*100,'sampledPeakWorkingSetBytes':peak});samples.append(result)
report={'samples':samples,'medianInstructionsPerSecond':statistics.median(s['instructionsPerSecond'] for s in samples),'medianSeekMs':statistics.median(s['averageSeekMs'] for s in samples),'scope':'Three sequential local Release microbenchmarks. Working set sampled every5ms across the whole benchmark; CPU from Windows GetProcessTimes including replay/analysis. No GPU/native presentation/idle CPU or per-snapshot private-heap claim.'}
args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
