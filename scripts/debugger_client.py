"""Shared bounded audit transport. Only explicitly supplied owned fixtures execute."""
from release_common import CURRENT_VERSION, MCP_TOOLS
import json
import queue
import shutil
import subprocess
import threading
import time
from pathlib import Path


def compile_owned_fixture(folder, root):
    fixture = folder/'owned-debuggee.exe'
    compiler = shutil.which('rustc') or str(Path.home()/'.cargo/bin/rustc.exe')
    options = [compiler, '--edition=2021', '-C', 'opt-level=1', '-C', 'debuginfo=2']
    for name in ['ura_marker', 'ura_nested', 'ura_existing_int3,DATA', 'ura_watch,DATA', 'ura_store']:
        options += ['-C', 'link-arg=/EXPORT:'+name]
    subprocess.run([*options, str(root/'tests/fixtures/debuggee.rs'), '-o', str(fixture)], check=True,
                   capture_output=True, timeout=60, creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    return fixture


def driver_factory(bin_dir, folder, fixture, metrics):
    flags = getattr(subprocess,'CREATE_NO_WINDOW',0)
    def record(name, elapsed):
        metrics.setdefault(name,[]).append(elapsed*1000)

    class Driver:
        def __init__(self, mcp, launch=False, attach_pid=None, writes=False, capture=False):
            self.mcp = mcp
            self.id = 0
            options = ['--allow', str(folder)]
            if capture:
                options += ['--enable-debug-capture']
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
                assert initialized['serverInfo']['version'] == CURRENT_VERSION
                self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
                tools = self.request('tools/list', {})['tools']
                assert len(tools) == MCP_TOOLS
                assert len([t for t in tools if t['name'].startswith('ura_debug_')]) == 25

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
                name = {'readMemory':'read_memory','callStack':'call_stack','configureBreakpoint':'configure_breakpoint','setCondition':'set_condition','stepOut':'step_out','runTo':'run_to','memoryRegions':'memory_regions'}.get(operation, operation)
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

    return Driver
