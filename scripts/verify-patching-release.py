"""Headless verification of Release CLI/MCP patching. Never launches a GUI/sample."""
import argparse
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import threading

parser = argparse.ArgumentParser()
parser.add_argument('--bin-dir', type=Path, default=Path('target/release'))
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
folder = args.output.resolve()
folder.mkdir(parents=True, exist_ok=False)
bin_dir = args.bin_dir.resolve()
flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


def cli(*arguments, writes=False, success=True):
    command = [str(bin_dir/'ura-cli.exe'), '--allow', str(root), '--allow', str(folder)]
    if writes:
        command += ['--enable-writes']
    result = subprocess.run(command + list(map(str, arguments)), capture_output=True,
                            text=True, timeout=30, creationflags=flags)
    assert (result.returncode == 0) == success, (result.stdout, result.stderr)
    return json.loads(result.stdout)


sample = root/'tests/fixtures/ura64.exe'
original = sample.read_bytes()
project = folder/'cli.ura'
cli('patch', sample, 'init', '--destination', project, writes=True)
base = ['patch', sample, '--project', project, '--json']
preview = cli(*base, 'instruction', '--space', 'va', '--address', '140001020',
              '--budget', '1', '--assembly', 'ret')
assert preview['patch']['edits'][0]['after'] == [195]
reviewed = folder/'reviewed.json'
reviewed.write_text(json.dumps(preview))
assert cli(*base, 'apply', '--preview', reviewed, success=False)['error']['code'] == 'write_disabled'
cli(*base, 'apply', '--preview', reviewed, writes=True)
assert cli(*base, 'apply', '--preview', reviewed, writes=True, success=False)['error']['code'] == 'invalid_argument'
assert cli(*base, 'read', '--space', 'offset', '--address', '220', '--length', '1')['current'] == [195]
out = folder/'cli-patched.exe'
report = cli(*base, 'export', '--destination', out, writes=True)
assert out.read_bytes() == original[:0x220] + bytes([195]) + original[0x221:]
assert report['sha256'] == hashlib.sha256(out.read_bytes()).hexdigest()
cli(*base, 'export', '--destination', out, writes=True, success=False)
cli(*base, 'history', '--action', 'undo', writes=True)
assert cli(*base, 'read', '--space', 'offset', '--address', '220', '--length', '1')['current'] == [85]
cli(*base, 'history', '--action', 'redo', writes=True)

# Independent compiler-generated 32-bit ELF and raw-image persistence workflows.
elf = root/'tests/fixtures/patch32.elf'
elf_info = cli('info', elf, '--json')['info']
elf_project = folder/'elf.ura'
cli('patch', elf, 'init', '--destination', elf_project, writes=True)
elf_base = ['patch', elf, '--project', elf_project]
cli(*elf_base, 'instruction', '--space', 'va', '--address', elf_info['entryPoint'],
    '--budget', '5', '--assembly', 'mov eax, 2a', '--apply', writes=True)
cli(*elf_base, 'export', '--destination', folder/'patched.elf', writes=True)
raw = folder/'sample.bin'
raw.write_bytes(bytes([144, 144, 195]))
raw_project = folder/'raw.ura'
cli('patch', raw, '--raw', '--bitness', '32', '--base', '1000', 'init', '--destination', raw_project, writes=True)
raw_base = ['patch', raw, '--project', raw_project]
cli(*raw_base, 'instruction', '--space', 'va', '--address', '1000', '--budget', '1', '--assembly', 'ret', '--apply', writes=True)
cli(*raw_base, 'export', '--destination', folder/'raw-patched.bin', writes=True)
assert (folder/'raw-patched.bin').read_bytes() == bytes([195, 144, 195])


class Client:
    def __init__(self, writes):
        command = [str(bin_dir/'ura-mcp.exe'), '--allow', str(root), '--allow', str(folder), '--log', 'off']
        if writes:
            command += ['--enable-writes']
        self.child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      text=True, creationflags=flags)
        self.replies = queue.Queue()
        self.number = 0

        def reader():
            for line in self.child.stdout:
                self.replies.put(json.loads(line))
        threading.Thread(target=reader, daemon=True).start()
        self.request('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
                                  'clientInfo': {'name': 'ura-patch-release-check', 'version': '1'}})
        self.child.stdin.write(json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'})+'\n')
        self.child.stdin.flush()

    def request(self, method, params):
        self.number += 1
        self.child.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': self.number, 'method': method, 'params': params})+'\n')
        self.child.stdin.flush()
        while True:
            reply = self.replies.get(timeout=30)
            if reply.get('id') == self.number:
                assert 'error' not in reply, reply
                return reply['result']

    def tool(self, name, arguments, success=True):
        result = self.request('tools/call', {'name': name, 'arguments': arguments})
        assert bool(result.get('isError')) != success, result
        return result['structuredContent']

    def close(self):
        self.child.terminate()
        self.child.wait(timeout=10)


writer = Client(True)
reader = None
try:
    assert len(writer.request('tools/list', {})['tools']) == 39
    handle = writer.tool('ura_open_binary', {'binary': str(sample)})['handle']
    mcp_project = folder/'mcp.ura'
    writer.tool('ura_save_project', {'handle': handle, 'project': str(mcp_project)})
    writer.tool('ura_analyze', {'handle': handle})
    preview = writer.tool('ura_preview_instruction_patch', {'handle': handle, 'space': 'va', 'address': '140001020', 'budget': 1, 'assembly': 'ret'})
    writer.tool('ura_apply_patch', {'handle': handle, 'project': str(mcp_project), 'preview': preview})
    writer.tool('ura_patch_history', {'handle': handle, 'project': str(mcp_project), 'action': 'undo'})
    writer.tool('ura_patch_history', {'handle': handle, 'project': str(mcp_project), 'action': 'redo'})
    current = writer.tool('ura_read_effective_bytes', {'handle': handle, 'space': 'offset', 'address': '220', 'length': 1})
    assert current['current'] == [195]
    mcp_out = folder/'mcp-patched.exe'
    writer.tool('ura_export_patched_binary', {'handle': handle, 'destination': str(mcp_out)})
    assert mcp_out.read_bytes() == out.read_bytes()
    writer.tool('ura_export_patched_binary', {'handle': handle, 'destination': str(folder/'patches.json'), 'manifest': True})
    reader = Client(False)
    handle = reader.tool('ura_open_binary', {'binary': str(sample), 'project': str(mcp_project)})['handle']
    reader.tool('ura_list_patches', {'handle': handle})
    preview = reader.tool('ura_preview_byte_patch', {'handle': handle, 'space': 'offset', 'address': '220', 'expected': 'C3', 'replacement': '90'})
    for tool, parameters in [
        ('ura_apply_patch', {'handle': handle, 'project': str(mcp_project), 'preview': preview}),
        ('ura_patch_history', {'handle': handle, 'project': str(mcp_project), 'action': 'undo'}),
        ('ura_export_patched_binary', {'handle': handle, 'destination': str(folder/'denied.exe')})
    ]:
        assert reader.tool(tool, parameters, success=False)['error']['code'] == 'write_disabled'
finally:
    writer.close()
    if reader:
        reader.close()

assert sample.read_bytes() == original
summary = {'version': '0.10.0-dev', 'mcpTools': 39, 'cliPatchWorkflow': True,
           'mcpPatchWorkflow': True, 'readOnlyDenied': True, 'originalUnchanged': True,
           'exactUntouchedBytes': True, 'reimportedExports': True, 'stalePreviewRejected': True,
           'undoRedo': True, 'manifestExport': True, 'cliMcpByteEquality': True,
           'elf32Workflow': True, 'rawProjectRoundTrip': True, 'nativeLaunched': False,
           'executableSha256': {name: hashlib.sha256((bin_dir/name).read_bytes()).hexdigest()
                                for name in ['ura-native.exe', 'ura-cli.exe', 'ura-mcp.exe']}}
(folder/'verification.json').write_text(json.dumps(summary, indent=2)+'\n')
print(json.dumps(summary, indent=2))
