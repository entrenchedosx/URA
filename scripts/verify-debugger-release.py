"""Audit real Release CLI/MCP against freshly compiled owned windowless targets.

Does not start the native desktop, control UI, or attach to unrelated processes.
Python/psutil are verification dependencies, never executable runtime dependencies.
"""
import argparse
import hashlib
import json
from pathlib import Path
import queue
import shutil
import statistics
import subprocess
import threading
import time
import psutil

parser = argparse.ArgumentParser()
parser.add_argument('--bin-dir', type=Path, default=Path('target/release'))
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
folder = args.output.resolve()
folder.mkdir(parents=True, exist_ok=False)
bin_dir = args.bin_dir.resolve()
flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
source = root/'tests/fixtures/debuggee.rs'
fixture = folder/'owned-debuggee.exe'
compiler = shutil.which('rustc') or str(Path.home()/'.cargo/bin/rustc.exe')
subprocess.run([compiler, '--edition=2021', '-C', 'opt-level=1', '-C', 'debuginfo=0',
                '-C', 'link-arg=/EXPORT:ura_marker', '-C', 'link-arg=/EXPORT:ura_nested',
                '-C', 'link-arg=/EXPORT:ura_existing_int3,DATA', str(source), '-o', str(fixture)],
               check=True, capture_output=True, timeout=60, creationflags=flags)
metrics = {}


def record(name, elapsed):
    metrics.setdefault(name, []).append(elapsed * 1000)


def cli(*arguments):
    return json.loads(subprocess.run([str(bin_dir/'ura-cli.exe'), '--allow', str(folder),
                                     '--enable-writes', *map(str, arguments)],
                                    capture_output=True, text=True, check=True,
                                    timeout=30, creationflags=flags).stdout)


info = cli('info', fixture, '--json')
preferred = int(info['info']['imageBase'], 16)
marker_rva = next(int(e['address'], 16) - preferred for e in info['exports'] if e['name'] == 'ura_marker')


class Driver:
    def __init__(self, mcp, launch=False, attach_pid=None, writes=False):
        self.mcp = mcp
        self.id = 0
        options = ['--allow', str(folder)]
        if writes:
            options += ['--enable-writes']
        if launch:
            options += ['--enable-debug-launch']
        if attach_pid:
            options += ['--enable-debug-attach', '--debug-pid', str(attach_pid)]
        if launch or attach_pid:
            options += ['--debug-target', str(fixture)]
        if mcp:
            options += ['--log', 'off']
        else:
            options += ['debug']
        self.process = subprocess.Popen([str(bin_dir/('ura-mcp.exe' if mcp else 'ura-cli.exe')), *options],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, creationflags=flags)
        self.replies = queue.Queue()
        def reader():
            for line in self.process.stdout:
                self.replies.put(json.loads(line))
        threading.Thread(target=reader, daemon=True).start()
        if mcp:
            initialized = self.request('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
                                                       'clientInfo': {'name': 'ura-debug-audit', 'version': '1'}})
            assert initialized['serverInfo']['version'] == '0.11.0-dev'
            self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
            tools = self.request('tools/list', {})['tools']
            assert len(tools) == 55
            assert len([t for t in tools if t['name'].startswith('ura_debug_')]) == 16

    def send(self, value):
        self.process.stdin.write(json.dumps(value) + '\n')
        self.process.stdin.flush()

    def request(self, method, params):
        self.id += 1
        self.send({'jsonrpc': '2.0', 'id': self.id, 'method': method, 'params': params})
        deadline = time.monotonic() + 8
        while True:
            response = self.replies.get(timeout=max(.01, deadline - time.monotonic()))
            if response.get('id') == self.id:
                assert 'error' not in response, response
                return response['result']

    def rpc(self, operation, success=True, **parameters):
        start = time.perf_counter()
        if self.mcp:
            name = {'readMemory': 'read_memory', 'callStack': 'call_stack'}.get(operation, operation)
            result = self.request('tools/call', {'name': 'ura_debug_' + name, 'arguments': parameters})
            error = result.get('isError', False)
            response = result.get('structuredContent', {})
        else:
            self.send({'operation': operation, **parameters})
            response = self.replies.get(timeout=8)
            error = 'error' in response
        assert error != success, response
        record(('mcp_' if self.mcp else 'cli_') + ('' if success else 'denied_') + operation, time.perf_counter() - start)
        return response.get('result', response)

    def wait(self, session, state):
        deadline = time.monotonic() + 10
        while True:
            response = self.rpc('status', session=session)
            if response['state'] == state:
                return response
            assert time.monotonic() < deadline, response
            time.sleep(.01)

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=8)
        assert self.process.returncode == 0, self.process.stderr.read()


evidence = []
for mcp in (False, True):
    mode = 'mcp' if mcp else 'cli'
    denied = Driver(mcp, writes=True)
    denied.rpc('launch', success=False, executable=str(fixture))
    denied.close()
    driver = Driver(mcp, launch=True, writes=True)
    session = driver.rpc('launch', executable=str(fixture))['session']
    paused = driver.wait(session, 'paused')
    assert paused['reason'] == 'breakpoint'
    assert int(paused['registers']['values']['rip'],16)==int(paused['modules'][0]['entryPoint'],16)
    address = hex(int(paused['modules'][0]['base'], 16) + marker_rva)
    driver.rpc('breakpoints', session=session, action='set', address=address)
    driver.rpc('continue', session=session)
    hit = driver.wait(session, 'paused')
    assert int(hit['registers']['values']['rip'], 16) == int(address, 16)
    assert hit['breakpoints'][0]['hits'] == 1
    assert int(hit['registers']['values']['rcx'],16)==1
    for _ in range(3):
        registers = driver.rpc('registers', session=session)
        memory = driver.rpc('readMemory', session=session, address=address, length=4096)
        stack = driver.rpc('callStack', session=session, limit=32)
        assert registers['thread'] == hit['selectedThread']
        assert memory['read'] > 0 and len(stack['frames']) >= 2
        driver.rpc('modules', session=session)
    process = psutil.Process(driver.process.pid)
    before = process.cpu_times()
    start = time.perf_counter()
    time.sleep(1)
    after = process.cpu_times()
    idle_cpu = 100 * ((after.user + after.system) - (before.user + before.system)) / (time.perf_counter() - start)
    start = time.perf_counter()
    driver.rpc('step', session=session)
    stepped = driver.wait(session, 'paused')
    record(mode + '_step_to_observed_pause', time.perf_counter() - start)
    assert stepped['reason'] == 'singleStep' and stepped['breakpoints'][0]['armed']
    bp_id = stepped['breakpoints'][0]['id']
    driver.rpc('breakpoints', session=session, action='disable', id=bp_id)
    assert driver.rpc('readMemory', session=session, address=address, length=1)['bytes'][0] == hit['breakpoints'][0]['originalByte']
    driver.rpc('breakpoints', session=session, action='enable', id=bp_id)
    driver.rpc('continue', session=session)
    hit2 = driver.wait(session, 'paused')
    assert hit2['breakpoints'][0]['hits'] == 2
    assert int(hit2['registers']['values']['rcx'],16)==2
    project = folder/(mode + '.ura')
    cli('patch', fixture, 'init', '--destination', project)
    assert driver.rpc('breakpoints', session=session, action='save', project=str(project))['saved'] == 1
    driver.rpc('breakpoints', session=session, action='remove', id=bp_id)
    assert driver.rpc('breakpoints', session=session, action='restore', project=str(project))['restored'] == 1
    driver.rpc('continue', session=session)
    last = driver.wait(session, 'paused')
    assert int(last['registers']['values']['rcx'],16)==3, 'restore must execute the displaced second call before stopping at the third'
    driver.rpc('breakpoints', session=session, action='remove', id=last['breakpoints'][0]['id'])
    driver.rpc('continue', session=session)
    exited = driver.wait(session, 'exited')
    assert exited['exitCode'] == 42
    driver.rpc('status', success=False, session='stale-session')
    peak = getattr(process.memory_info(), 'peak_wset', process.memory_info().rss)
    evidence.append({'interface': mode, 'realLaunch': True, 'repeatHits': 2, 'singleStep': True,
                     'registersMemoryStackModules': True, 'breakpointEnableDisable': True,
                     'identityRvaPersistence': True, 'normalExitCode': 42, 'staleSessionDenied': True,
                     'pausedCpuOneCorePercentOneSecondSample': idle_cpu, 'serverPeakWorkingSetBytes': peak,
                     'retainedEvents': len(exited['events']), 'serializedEventBytes': len(json.dumps(exited['events']).encode())})
    driver.close()
    child = subprocess.Popen([str(fixture), '--attach'], creationflags=flags)
    attached = Driver(mcp, attach_pid=child.pid)
    session = attached.rpc('attach', pid=child.pid, executable=str(fixture))['session']
    attached.wait(session, 'paused')
    attached.rpc('terminate', success=False, session=session)
    attached.rpc('continue', session=session)
    attached.rpc('pause', session=session)
    assert attached.wait(session, 'paused')['reason'] == 'pause'
    attached.rpc('detach', session=session)
    assert child.wait(timeout=8) == 42
    attached.close()
    evidence[-1].update({'ownedPidAttach': True, 'pause': True, 'detachPreservedTarget': True,
                         'attachedTerminationDenied': True})

summary = {'version': '0.11.0-dev', 'mcpTools': 55, 'controlledFixturesExecuted': True,
           'nativeDesktopLaunched': False, 'sourceSha256': hashlib.sha256(source.read_bytes()).hexdigest(),
           'fixtureSha256': hashlib.sha256(fixture.read_bytes()).hexdigest(), 'workflows': evidence,
           'rpcMedianMs': {key: statistics.median(values) for key, values in metrics.items()},
           'measurementScope': 'Transport-inclusive local samples. Paused CPU uses one second and Windows timer resolution. No real GUI, OS event occurrence latency, GPU timing or general target slowdown claim.',
           'executableSha256': {name: hashlib.sha256((bin_dir/name).read_bytes()).hexdigest()
                                for name in ('ura-native.exe', 'ura-cli.exe', 'ura-mcp.exe')}}
(folder/'verification.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
print(json.dumps(summary, indent=2))
