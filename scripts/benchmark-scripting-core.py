"""Compare headless CLI startup+core queries to a verified prior release; no UI."""
from release_common import ROOT,CURRENT_VERSION
import argparse,hashlib,json,statistics,subprocess,time
from pathlib import Path
def measure(baseline,current,output):
    rows=[]; sample=ROOT/'tests/fixtures/ura64.exe';flags=getattr(subprocess,'CREATE_NO_WINDOW',0)
    cases=[['analyze',str(sample),'--json'],['disasm',str(sample),'--address','140001020','--count','64','--json'],
           ['ir',str(sample),'--function','140001020','--json'],['decompile',str(sample),'--function','140001020','--json']]
    executables=[('v0.15.0-dev.1',baseline), (CURRENT_VERSION,current)]
    for args in cases:
        times={label:[] for label,_ in executables}
        for _ in range(5):
            for label,path in executables:
                start=time.perf_counter();result=subprocess.run([str(path),'--allow',str(ROOT),*args],capture_output=True,check=True,timeout=30,creationflags=flags);json.loads(result.stdout);times[label].append((time.perf_counter()-start)*1000)
        rows.append({'command':args[0],'startupAndQueryMs':times,'medianMs':{label:statistics.median(values) for label,values in times.items()}})
    report={'version':CURRENT_VERSION,'baselineSha256':hashlib.sha256(baseline.read_bytes()).hexdigest(),'currentSha256':hashlib.sha256(current.read_bytes()).hexdigest(),
            'fixtureSha256':hashlib.sha256(sample.read_bytes()).hexdigest(),'method':'Five alternating fresh CLI process runs per version/query; warm cache, Release, scripting disabled, startup included. Small owned x64 fixture; no broad performance parity/idle CPU claim.','rows':rows}
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--baseline',type=Path,required=True);p.add_argument('--current',type=Path,default=ROOT/'target/release/ura-cli.exe');p.add_argument('--output',type=Path,required=True);a=p.parse_args();measure(a.baseline.resolve(),a.current.resolve(),a.output.resolve())
