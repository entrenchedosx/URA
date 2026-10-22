"""Verify an audit ZIP without starting or controlling any desktop app.

Only CLI/MCP child processes run. All extraction and disposable projects stay
under the archive's output folder. The native image is compared byte-for-byte
with the previously built/tested image; GUI startup is deliberately not repeated.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import uuid
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('archive', type=Path)
parser.add_argument('--version', default='0.9.0-dev')
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
archive = args.archive.resolve()
extraction = archive.parent / ('package-check-' + uuid.uuid4().hex)
extraction.mkdir()

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

archive_hash = digest(archive)
sidecar_hash, sidecar_name = archive.with_suffix(archive.suffix + '.sha256').read_text(encoding='utf-8-sig').split()
assert sidecar_hash.lower() == archive_hash
assert sidecar_name == archive.name
with zipfile.ZipFile(archive) as package:
    assert package.testzip() is None
    entries = package.infolist()
    names = set()
    for entry in entries:
        name = PurePosixPath(entry.filename)
        assert not name.is_absolute() and '..' not in name.parts
        target = (extraction / entry.filename).resolve()
        assert target.is_relative_to(extraction)
        assert entry.filename.lower() not in names
        names.add(entry.filename.lower())
    package.extractall(extraction)

checked = set()
for line in (extraction / 'SHA256SUMS.txt').read_text(encoding='utf-8-sig').splitlines():
    expected, name = line.split('  ', 1)
    assert digest(extraction / name) == expected.lower(), name
    checked.add(name.replace('\\', '/'))
actual = {str(p.relative_to(extraction)).replace('\\', '/') for p in extraction.rglob('*') if p.is_file()}
assert checked == actual - {'SHA256SUMS.txt'}
assert not (extraction / 'licenses/MISSING-TEXTS.txt').read_text().strip()
assert digest(extraction / 'icon.webp') == digest(root / 'icon.webp')
binary_hashes = {}
for name in ['ura-native.exe', 'ura-cli.exe', 'ura-mcp.exe']:
    binary_hashes[name] = digest(extraction / name)
    assert binary_hashes[name] == digest(root / 'target/release' / name)
for name in ['README.md', 'LICENSE', 'THIRD_PARTY.md', 'docs/AUDIT-0.8.md', 'docs/VERIFICATION-0.8.md']:
    assert (extraction / name).is_file()

def run(executable, *arguments):
    return subprocess.run([str(extraction / executable), *map(str, arguments)], cwd=extraction,
                          capture_output=True, text=True, check=True, timeout=30,
                          creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)).stdout

assert run('ura-cli.exe', '--version').strip() == 'ura-cli ' + args.version
assert run('ura-mcp.exe', '--version').strip() == 'ura-mcp ' + args.version
sample = root / 'tests/fixtures/ura64.exe'
cli = json.loads(run('ura-cli.exe', '--allow', root, 'signature', sample,
                     '--function', '140001020', '--json'))
assert cli['schemaVersion'] == 1 and cli['function'] == '0x140001020'
decompiled = json.loads(run('ura-cli.exe', '--allow', root, 'decompile', sample,
                            '--function', '140001020', '--json', '--ast'))
assert decompiled['syntax'] == 'c-like' and decompiled['ast']['address'] == '0x140001020'
mcp_process = subprocess.run([sys.executable, str(root / 'scripts/verify-mcp-release.py'),
                              '--exe', str(extraction / 'ura-mcp.exe'),
                              '--output', str(extraction / 'headless-check')], cwd=root,
                             capture_output=True, text=True, check=True, timeout=60,
                             creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
mcp = json.loads(mcp_process.stdout)
assert mcp['tools'] == 32 and mcp['typeLibraryRoundTrip']
report = {
    'version': args.version,
    'archive': archive.name,
    'sha256': archive_hash,
    'bytes': archive.stat().st_size,
    'extraction': str(extraction),
    'zipCrcPassed': True,
    'checkedFiles': len(checked),
    'allFilesListed': True,
    'binarySha256': binary_hashes,
    'binaryIdentityMatchesTestedRelease': True,
    'iconMatches': True,
    'missingLicenseTexts': 0,
    'cliVersionAndJsonPassed': True,
    'mcpVersionAndStdioPassed': True,
    'mcpTools': mcp['tools'],
    'typeLibraryRoundTrip': mcp['typeLibraryRoundTrip'],
    'cDecompileRoundTrip': mcp['cDecompileRoundTrip'],
    'cExportRoundTrip': mcp['cExportRoundTrip'],
    'nativeStartup': 'Not exercised by this headless verifier. Image matches the tested Release executable; consult the separate live desktop verification record.',
}
(archive.parent / 'package-verification.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report, indent=2))
