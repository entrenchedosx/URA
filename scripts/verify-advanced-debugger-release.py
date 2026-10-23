"""Release CLI/MCP real-process advanced audit. No desktop or unrelated attach."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import time
import psutil
from debugger_client import compile_owned_fixture, driver_factory

parser = argparse.ArgumentParser()
parser.add_argument('--bin-dir', type=Path, default=Path('target/release'))
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
folder = args.output.resolve()
folder.mkdir(parents=True, exist_ok=False)
bin_dir = args.bin_dir.resolve()
fixture = compile_owned_fixture(folder, root)
metrics = {}
Driver = driver_factory(bin_dir, folder, fixture, metrics)
import subprocess
info = json.loads(subprocess.run([str(bin_dir/'ura-cli.exe'), '--allow', str(folder), 'info',
                                 str(fixture), '--json'], capture_output=True, text=True, check=True,
                                timeout=30, creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)).stdout)
preferred = int(info['info']['imageBase'], 16)
exports = {e['name']: int(e['address'],16)-preferred for e in info['exports']}
reports = []
for mcp in [False, True]:
    mode = 'mcp' if mcp else 'cli'
    denied = Driver(mcp, writes=True)
    denied.rpc('launch', success=False, executable=str(fixture))
    denied.close()
    driver = Driver(mcp, launch=True, capture=True, writes=True)
    caps = driver.rpc('capabilities')
    assert caps['hardwareSlotsPerThread'] == 4 and not caps['wow64'] and not caps['remote']
    session = driver.rpc('launch', executable=str(fixture))['session']
    entry = driver.wait(session, 'paused')
    base = int(entry['modules'][0]['base'],16)
    nested = hex(base+exports['ura_nested'])
    marker = hex(base+exports['ura_marker'])
    watched = hex(base+exports['ura_watch'])
    driver.rpc('trace',session=session,action='start',config={'mode':'events','maxEvents':512})
    driver.rpc('runTo',session=session,address=nested)
    driver.wait(session,'paused')
    driver.rpc('configureBreakpoint',session=session,address=marker,kind='hardwareExecute',condition='ecx == 2')
    driver.rpc('configureBreakpoint',session=session,address=watched,kind='readWrite',length=8,condition='0')
    driver.rpc('continue',session=session)
    hit = driver.wait(session,'paused')
    assert hit['reason']=='hardwareBreakpoint' and int(hit['registers']['values']['rcx'],16)==2
    execution = next(p for p in hit['breakpoints'] if p['kind']=='hardwareExecute')
    assert execution['hits']==2 and len(execution['threads'])>=2
    regions = driver.rpc('memoryRegions',session=session,address=marker,limit=8)
    assert regions['regions'][0]['readable']
    capture = driver.rpc('snapshot',session=session,action='capture',address=marker,length=32)
    live = driver.rpc('readMemory',session=session,address=marker,length=32)
    assert capture['chunks'][0]['bytes']==live['bytes']
    second = driver.rpc('snapshot',session=session,action='capture',address=marker,length=32)
    compared = driver.rpc('snapshot',session=session,action='compare',id=capture['id'],other=second['id'])
    assert compared['changedBytes']==0 and compared['completeComparison']
    decoded = driver.rpc('snapshot',session=session,action='disassembly',id=capture['id'],address=marker,count=8)
    assert decoded['instructions']
    large = driver.rpc('snapshot',session=session,action='capture',address=marker,length=65536)
    driver.rpc('snapshot',session=session,action='capture',address=marker,length=1048577,success=False)
    destination = folder/(mode+'-capture.json')
    receipt = driver.rpc('snapshot',session=session,action='export',id=large['id'],destination=str(destination))
    data = destination.read_bytes()
    assert hashlib.sha256(data).hexdigest()==receipt['sha256']
    assert json.loads(data)==large
    driver.rpc('snapshot',session=session,action='export',id=large['id'],destination=str(destination),success=False)
    assert destination.read_bytes()==data
    symbols = driver.rpc('symbols',session=session,action='load',base=hex(base),pdb=str(fixture.with_suffix('.pdb')))
    assert symbols['identityMatched'] and not symbols['network']
    for _ in range(3):
        found = driver.rpc('symbols',session=session,action='lookup',address=hex(int(marker,16)+1))
        assert found['found'] and 'ura_marker' in found['name']
    driver.rpc('trace',session=session,action='stop')
    event_trace = driver.rpc('trace',session=session,action='read',limit=512)
    assert any(e['kind']=='hardwareBreakpoint' for e in event_trace['events'])
    event_path = folder/(mode+'-events.json')
    event_export = driver.rpc('trace',session=session,action='export',destination=str(event_path))
    assert hashlib.sha256(event_path.read_bytes()).hexdigest()==event_export['sha256']
    assert not json.loads(event_path.read_text())['summary']['completeExecution']
    stack = driver.rpc('callStack',session=session,limit=4)
    caller = stack['frames'][1]['instructionPointer']
    driver.rpc('stepOut',session=session)
    out = driver.wait(session,'paused')
    assert out['registers']['values']['rip']==caller
    watched_point = next(p for p in out['breakpoints'] if p['kind']=='readWrite')
    driver.rpc('setCondition',session=session,id=watched_point['id'],condition='1')
    driver.rpc('continue',session=session)
    watched_hit = driver.wait(session,'paused')
    assert watched_hit['reason']=='hardwareBreakpoint'
    observed_watch = next(p for p in watched_hit['breakpoints'] if p['id']==watched_point['id'])
    assert observed_watch['hits']>=1
    assert driver.rpc('readMemory',session=session,address=watched,length=8)['bytes'][:2]==[0xEF,0xBE]
    for point in out['breakpoints']:
        driver.rpc('breakpoints',session=session,action='remove',id=point['id'])
    # Measure a separate freshly launched entry path, so the sample is not
    # dependent on how near step-out happened to land to a blocking join/syscall.
    driver.rpc('terminate',session=session)
    driver.wait(session,'exited')
    session = driver.rpc('launch',executable=str(fixture))['session']
    driver.wait(session,'paused')
    started = time.perf_counter()
    driver.rpc('trace',session=session,action='start',
               config={'mode':'instructions','maxSteps':100,'maxEvents':1024,'maxDurationMs':5000})
    traced = driver.wait(session,'paused')
    elapsed = time.perf_counter()-started
    assert traced['trace']['steps']==100, traced['trace']
    assert traced['trace']['stopReason']=='stepLimit'
    for _ in range(5):
        instructions = driver.rpc('trace',session=session,action='read',limit=512)
    assert any(e['kind']=='instruction' and e['address'] for e in instructions['events'])
    assert any(e['detail'].get('changedRegisters') for e in instructions['events'] if e['kind']=='instruction')
    trace_path = folder/(mode+'-instructions.json')
    driver.rpc('trace',session=session,action='export',destination=str(trace_path))
    imported = json.loads(trace_path.read_text())
    assert imported['events']==instructions['events']
    driver.rpc('trace',session=session,action='clear')
    assert not driver.rpc('trace',session=session,action='read',limit=10)['events']
    driver.rpc('trace',session=session,action='start',config={'mode':'instructions','maxSteps':100000,'maxDurationMs':5000})
    driver.rpc('trace',session=session,action='stop')
    stopped = driver.wait(session,'paused')
    assert not stopped['trace']['instructionInFlight']
    process = psutil.Process(driver.process.pid)
    before = process.cpu_times()
    time.sleep(1)
    after = process.cpu_times()
    idle_cpu = 100*((after.user+after.system)-(before.user+before.system))
    peak = getattr(process.memory_info(),'peak_wset',process.memory_info().rss)
    driver.rpc('terminate',session=session)
    driver.wait(session,'exited')
    driver.close()
    no_capture = Driver(mcp,launch=True)
    restricted = no_capture.rpc('launch',executable=str(fixture))['session']
    paused = no_capture.wait(restricted,'paused')
    no_capture.rpc('snapshot',session=restricted,action='capture',address=paused['registers']['values']['rip'],length=32,success=False)
    no_capture.rpc('trace',session=restricted,action='export',destination=str(folder/(mode+'-denied.json')),success=False)
    no_capture.rpc('terminate',session=restricted)
    no_capture.wait(restricted,'exited')
    no_capture.close()
    reports.append({'interface':mode,'hardwareExecution':True,'falseConditionContinuedToRcx2':True,
                    'readWriteWatchpoint':True,'observedDataWatchHits':observed_watch['hits'],'boundThreads':len(execution['threads']),
                    'runTo':True,'validatedStepOut':True,'regions':True,
                    'snapshotCapturedBytes':large['captured'],'snapshotRequestedBytes':large['requested'],
                    'snapshotExportRoundTrip':True,'capturedDisassembly':True,
                    'matchedLocalPdbAndLookup':True,'eventTraceExport':True,
                    'instructionSteps':100,'instructionTraceSeconds':elapsed,
                    'observedStepsPerSecond':100/elapsed,'traceSerializedBytes':imported['summary']['serializedBytes'],
                    'traceRetainedEvents':len(imported['events']),'traceStop':True,'traceClear':True,
                    'captureAndExportDeniedWithoutFlags':True,'existingFilePreserved':True,
                    'pausedCpuOneCorePercentOneSecondSample':idle_cpu,'serverPeakWorkingSetBytes':peak})
summary = {'version':'0.12.0-dev','mcpTools':64,'controlledFixturesExecuted':True,'nativeDesktopLaunched':False,
           'workflows':reports,'rpcMedianMs':{k:statistics.median(v) for k,v in metrics.items()},
           'measurementScope':'Sequential transport-inclusive local samples;100 debugger-driven steps, not Intel PT, complete coverage, general hardware slowdown or real GUI latency. CPU one-second sample at Windows timer resolution; trace bytes are serialized payload, not total heap.',
           'sourceSha256':hashlib.sha256((root/'tests/fixtures/debuggee.rs').read_bytes()).hexdigest(),
           'executableSha256':{name:hashlib.sha256((bin_dir/name).read_bytes()).hexdigest() for name in ('ura-native.exe','ura-cli.exe','ura-mcp.exe')}}
(folder/'verification.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print(json.dumps(summary,indent=2))
