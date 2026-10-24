"""Headless exact-package scripting qualification. Never launches a desktop UI."""
from release_common import CURRENT_VERSION,ROOT
import argparse, hashlib, json, os, queue, statistics, subprocess, threading, time, zipfile
from pathlib import Path
import psutil
FLAGS=getattr(subprocess,'CREATE_NO_WINDOW',0)
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
class Client:
    def __init__(self,binary,output,sdk,project):
        args=[str(binary/'ura-cli.exe'),'--allow',str(ROOT),'--allow',str(output),'--allow',str(sdk),
              '--enable-scripting','--allow-script-snippets','--enable-plugin-management','--enable-writes',
              '--extensions-dir',str(output/'plugins')]
        for cap in ['project.write','analysis.symbolic','files.export','loader.register','processor.register','events.subscribe','ui.commands']:
            args+=['--script-capability',cap]
        args+=['--trust-script',str(sdk/'examples/inventory.py'),'extensions','--binary',str(ROOT/'tests/fixtures/ura64.exe'),'--project',str(project)]
        env=os.environ.copy();env['PYTHONHOME']=str(output/'does-not-exist');env['PYTHONPATH']=str(output/'does-not-exist')
        self.child=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,cwd=output,env=env,creationflags=FLAGS)
        self.memory_peak=0;self.monitor_stop=threading.Event()
        def monitor():
            observed=psutil.Process(self.child.pid)
            while not self.monitor_stop.is_set():
                try:
                    processes=[observed]+observed.children(recursive=True)
                    total=0
                    for process in processes:
                        try:total+=process.memory_info().rss
                        except (psutil.NoSuchProcess,psutil.AccessDenied):pass
                    self.memory_peak=max(self.memory_peak,total)
                except (psutil.NoSuchProcess,psutil.AccessDenied):break
                self.monitor_stop.wait(.02)
        self.monitor=threading.Thread(target=monitor,daemon=True);self.monitor.start()
        self.replies=queue.Queue()
        def reader():
            try:
                for line in self.child.stdout:self.replies.put(json.loads(line))
            except BaseException as error:self.replies.put(error)
        self.reader=threading.Thread(target=reader,daemon=True);self.reader.start();self.header=self.receive()
        assert self.header['ready'],self.header
    def receive(self):
        value=self.replies.get(timeout=20)
        if isinstance(value,BaseException):raise value
        return value
    def rpc(self,operation,action,**params):
        self.child.stdin.write(json.dumps(dict(operation=operation,action=action,**params))+'\n');self.child.stdin.flush()
        reply=self.receive()
        if 'error' in reply:raise RuntimeError(reply['error'])
        return reply['result']
    def job(self,job):
        start=time.monotonic()
        while True:
            result=self.rpc('scripts','status',job=job['job'])
            if result['state']!='running':
                if result.get('sourcePlugin') is None:self.rpc('scripts','forget',job=job['job'])
                return result
            assert time.monotonic()-start<20,result
            time.sleep(.01)
    def close(self):
        self.child.stdin.close()
        try:self.child.wait(timeout=10)
        except subprocess.TimeoutExpired:self.child.kill();self.child.wait();raise
        self.monitor_stop.set();self.monitor.join(timeout=2)
        assert self.child.returncode==0,self.child.stderr.read()
def verify(binary,output):
    binary=binary.resolve();output=output.resolve();output.mkdir(parents=True,exist_ok=True)
    sdk=binary/'sdk' if (binary/'sdk').is_dir() else ROOT/'sdk'
    lock=json.loads((ROOT/'scripts/python-runtime.lock.json').read_text(encoding='utf-8-sig'));runtime=binary/'runtime/python'
    manifest=json.loads((runtime/'URA-RUNTIME.json').read_text(encoding='utf-8-sig'));assert manifest==lock
    for name,sha in lock['files'].items():assert digest(runtime/name)==sha,name
    version=subprocess.run([str(runtime/'python.exe'),'-I','-S','-c','import sys,ssl,sqlite3,json,hashlib; print(sys.version.split()[0])'],capture_output=True,text=True,check=True,timeout=10,creationflags=FLAGS).stdout.strip()
    assert version==lock['version']
    for name in ['python/worker.py','python/ura/__init__.py','python/ura/py.typed']:
        assert digest(sdk/name)==digest(ROOT/'sdk'/name),name
    project=output/'fixture.ura'
    subprocess.run([str(binary/'ura-cli.exe'),'--allow',str(ROOT),'--allow',str(output),'--enable-writes','patch',str(ROOT/'tests/fixtures/ura64.exe'),'init','--destination',str(project)],capture_output=True,text=True,check=True,timeout=20,creationflags=FLAGS)
    client=Client(binary,output,sdk,project);checks={};timings={};started=time.perf_counter()
    try:
        session=client.rpc('scripts','open',handle=client.header['handle'],capabilities=['project.read','analysis.read','project.write','files.export','analysis.symbolic'])['session']
        first=client.job(client.rpc('scripts','run',session=session,code="import ura\np=ura.current_project()\nf=next(p.functions())\nprint(f.name, f.pseudocode())\nx=41"))
        assert first['state']=='complete' and 'return' in first['stdout'],first
        timings['interpreterStartupMs']=first['startupMs'];checks['realEnginePseudocode']=True
        symbolic="import time\nt=p.function_at(0x140001020).symbolic()\nfor _ in range(500):\n    state=t.status()\n    if state['state']!='running':break\n    time.sleep(0.01)\nassert state['state']=='complete',state\nprint(t.page('paths',limit=1))\nt.close()"
        r=client.job(client.rpc('scripts','run',session=session,code=symbolic));assert r['state']=='complete',r;checks['pythonSymbolicSession']=True

        latencies=[]
        for _ in range(8):
            start=time.perf_counter();r=client.job(client.rpc('scripts','run',session=session,code='p.metadata()'))
            assert r['state']=='complete',r;latencies.append((time.perf_counter()-start)*1000)
        timings['apiJobMedianMs']=statistics.median(latencies)
        result=client.job(client.rpc('scripts','run',session=session,code='x+1'));assert result['stdout']=='42\n';checks['persistentVariables']=True
        for source in ['rename_functions.py','xref_export.py']:
            code=(sdk/'examples'/source).read_text(encoding='utf-8')
            if source=='xref_export.py':code='import sys\nsys.argv=["xref_export.py",'+repr(str(output/'xrefs.json'))+']\n'+code
            r=client.job(client.rpc('scripts','run',session=session,code=code));assert r['state']=='complete',r
        checks['metadataWritesAndExport']=True
        before=client.rpc('events','page',after=0);assert any(e['kind']=='function.renamed' for e in before['events'])
        r=client.job(client.rpc('scripts','run',session=session,code="raise ValueError('owned fixture')"));assert r['state']=='pythonError' and 'ValueError' in r['error'];checks['exceptions']=True
        start=time.perf_counter();r=client.job(client.rpc('scripts','run',session=session,code='while True: pass',limits={'timeoutMs':100}));assert r['state'] in ('timeout','timeoutOrCancelled'),r;timings['timeoutAndReapObservedMs']=(time.perf_counter()-start)*1000;checks['deadline']=True
        client.rpc('scripts','close',session=session)
        discovered=[]
        for name in ['candidate_analyzer','container_loader','toy_processor','event_observer']:
            path=output/(name+'.zip')
            with zipfile.ZipFile(path,'x',zipfile.ZIP_DEFLATED) as package:
                for member in (sdk/'examples/plugins'/name).iterdir():
                    if member.is_file():package.write(member,member.name)
            start=time.perf_counter();plugin=client.rpc('plugins','install',path=str(path));assert plugin['enabled'] is False
            timings[name+'InstallMs']=(time.perf_counter()-start)*1000;discovered.append(plugin['manifest']['id'])
            start=time.perf_counter();client.rpc('plugins','enable',id=plugin['manifest']['id'],capabilities=plugin['manifest']['requiredCapabilities']);timings[name+'EnableMs']=(time.perf_counter()-start)*1000
        start=time.perf_counter();inventory=client.rpc('plugins','list');timings['discoveryMs']=(time.perf_counter()-start)*1000;assert len(inventory['plugins'])==4
        start=time.perf_counter();r=client.job(client.rpc('plugins','run',id=discovered[0],kind='analyzer',handle=client.header['handle']));timings['analyzerMs']=(time.perf_counter()-start)*1000;assert r['state']=='complete' and r['findings'],r;assert r['pluginVersion']=='1.0.0' and len(r['pluginDigest'])==64
        checks['externalPluginFindings']=True
        container=output/'container.ura0';container.write_bytes(b'URA0'+(0x1000).to_bytes(8,'little')+bytes(4)+bytes([0xb8,42,0,0,0,0xc3]))
        job=client.rpc('plugins','run',id=discovered[1],kind='loader',path=str(container));assert client.job(job)['state']=='complete';accepted=client.rpc('plugins','accept',job=job['job']);assert accepted['entry']=='0x1000'
        disasm=client.rpc('image','disassembly',handle=accepted['image'],address='0x1000');assert disasm['instructions'][0]['mnemonic']=='mov';checks['customLoaderCoreAnalysisAndNavigation']=True
        toy=output/'fixture.toy';toy.write_bytes(bytes([16,1,48,7,32,2,255,0,255]))
        job=client.rpc('plugins','run',id=discovered[2],kind='processor',path=str(toy));assert client.job(job)['state']=='complete';accepted=client.rpc('plugins','accept',job=job['job']);assert not accepted['capabilities']['ir']
        page=client.rpc('processor','page',handle=accepted['handle'],address='0x7');assert page['instructions'][0]['mnemonic']=='nop' and any(len(b['successors'])==2 for b in page['blocks']);checks['toyProcessorSharedCfgAndNavigation']=True
        # A fast analysis emits both notifications; event callbacks preserve sequence.
        start=time.perf_counter();client.rpc('projects','analyze',handle=client.header['handle'])
        deadline=time.monotonic()+10;seen=[]
        while time.monotonic()<deadline:
            seen=[]
            for job in client.rpc('scripts','list')['jobs']:
                r=client.rpc('scripts','status',job=job)
                if r['sourcePlugin']==discovered[3] and r['state']=='complete':seen.append(r['value']['kind'])
            if 'analysis.completed' in seen:break
            time.sleep(.02)
        assert 'analysis.started' in seen and 'analysis.completed' in seen,seen;timings['analysisPlusEventDeliveryMs']=(time.perf_counter()-start)*1000;checks['orderedEventHooks']=True
        for id in discovered:client.rpc('plugins','disable',id=id)
        results=output/'batch';results.mkdir()
        start=time.perf_counter();batch=client.rpc('batch','start',paths=[str(ROOT/'tests/fixtures/ura64.exe')],script=str(sdk/'examples/inventory.py'),destination=str(results))
        while True:
            r=client.rpc('batch','status',id=batch['id'])
            if r['state']!='running':break
            assert time.perf_counter()-start<20;time.sleep(.02)
        assert r['rows'][0]['state']=='complete',r;timings['singleInputBatchMs']=(time.perf_counter()-start)*1000;checks['batch']=True
        for id in discovered:client.rpc('plugins','uninstall',id=id)
        assert client.rpc('plugins','list')['plugins']==[];checks['uninstall']=True
    finally:client.close()
    report={'version':CURRENT_VERSION,'runtime':version,'runtimeArchiveSha256':lock['archiveSha256'],'checks':checks,'timings':timings,'peakAggregateWorkingSetBytes':client.memory_peak,'memoryMethod':'Maximum sampled sum of host and owned child RSS at20ms intervals; may miss short peaks','elapsedSeconds':time.perf_counter()-started,
            'security':'Trusted Python with user OS permissions; process/JobObject resource containment is not an OS sandbox. No UI or debugger/sample native execution.'}
    (output/'verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--binary-directory',type=Path,default=ROOT/'target/release');p.add_argument('--output',type=Path,default=ROOT/'target/v16-scripting-release');a=p.parse_args();verify(a.binary_directory,a.output)
