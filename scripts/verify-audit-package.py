"""Verify an audit ZIP without starting or controlling any desktop app.

Only CLI/MCP child processes run. All extraction and disposable projects stay
under the archive's output folder. The native image is compared byte-for-byte with the freshly built image.
No native desktop window is launched.
"""
from release_common import CURRENT_VERSION, MCP_TOOLS
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
parser.add_argument('--version', default=CURRENT_VERSION)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
if args.version != CURRENT_VERSION:
    raise ValueError('Audit must use the checked-out Cargo version')
qualification = json.loads((root / 'release-qualification.json').read_text(encoding='utf-8'))
if qualification.get('version') != args.version:
    raise ValueError('Qualification version mismatch')
evidence = qualification.get('requiredEvidence')
if not isinstance(evidence,str) or not evidence:
    raise ValueError('Qualification requiredEvidence is missing')
evidence_path = (root / evidence).resolve()
if not evidence_path.is_relative_to(root) or not evidence_path.is_file() or Path(evidence).is_absolute():
    raise ValueError('Qualification evidence must name a real source file within the repository')
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
    entries = package.infolist()
    if len(entries)>16384 or sum(e.file_size for e in entries)>512*1024*1024:
        raise ValueError('Audit archive exceeds bounded entry/expanded-size limits')
    names = set()
    for entry in entries:
        name = PurePosixPath(entry.filename)
        assert not name.is_absolute() and '..' not in name.parts
        target = (extraction / entry.filename).resolve()
        assert target.is_relative_to(extraction)
        assert entry.filename.lower() not in names
        names.add(entry.filename.lower())
    assert package.testzip() is None
    package.extractall(extraction)

checked = set()
for line in (extraction / 'SHA256SUMS.txt').read_text(encoding='utf-8-sig').splitlines():
    expected, name = line.split('  ', 1)
    member=(extraction / name).resolve()
    assert member.is_relative_to(extraction) and member.is_file(),name
    assert digest(member) == expected.lower(), name
    checked.add(name.replace('\\', '/'))
actual = {str(p.relative_to(extraction)).replace('\\', '/') for p in extraction.rglob('*') if p.is_file()}
assert checked == actual - {'SHA256SUMS.txt'}
assert not (extraction / 'licenses/MISSING-TEXTS.txt').read_text().strip()
for name in ['capstone-0.14.0/LICENSE','capstone-sys-0.18.0/LICENSE','capstone-sys-0.18.0/capstone/LICENSE.TXT','capstone-sys-0.18.0/capstone/LICENSE_LLVM.TXT']:
    assert (extraction/'licenses'/name).is_file(),name
for name in ['z3-0.21.1/LICENSE.txt','z3-sys-0.13.1/LICENSE.txt','z3-src-501.0.1/z3/LICENSE.txt']:
    assert (extraction/'licenses'/name).is_file(),name


assert digest(extraction / 'icon.webp') == digest(root / 'icon.webp')
binary_hashes = {}
for name in ['ura-native.exe', 'ura-cli.exe', 'ura-mcp.exe']:
    binary_hashes[name] = digest(extraction / name)
    assert binary_hashes[name] == digest(root / 'target/release' / name)
# Launch only after byte-for-byte comparison with the freshly built images.
# The native executable runs solely its windowless worker entry point.
subprocess.run([sys.executable,str(root/'scripts/verify-symbolic-release.py'),'--binary-directory',str(extraction),
                '--output',str(archive.parent/('solver-package-check-'+uuid.uuid4().hex))],cwd=root,check=True,timeout=120,
               creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
for name in ['README.md', 'LICENSE', 'THIRD_PARTY.md', 'release-qualification.json', 'docs/AUDIT-0.8.md', 'docs/VERIFICATION-0.8.md',
             'docs/BINARY-PATCHING.md', 'docs/ADVANCED-DEBUGGER.md', 'docs/DEBUGGER.md', 'docs/CLI.md', 'docs/MCP.md', 'docs/VERIFICATION-0.12.md',
             'docs/FEATURE-PARITY.md', 'docs/ROADMAP.md', evidence, 'docs/MULTI-ARCHITECTURE.md',
             'docs/SYMBOLIC-DEOBFUSCATION.md', 'docs/REVIEW-0.15.md',
             'docs/benchmarks/0.15-symbolic-baseline-release.json',
             'docs/benchmarks/0.15-symbolic-headless-release.json',
             'docs/benchmarks/0.15-processor-oracle.json',
             'docs/examples/0.15/ura_opaque_even.original.c', 'docs/examples/0.15/ura_opaque_even.simplified.c',
             'docs/benchmarks/0.14-processors-release.json', 'docs/benchmarks/0.14-processor-oracle.json',
             'docs/benchmarks/0.14-dynamic-release.json', 'docs/benchmarks/0.14-baseline-controlled.json',
             'docs/EMULATION-DYNAMIC-ANALYSIS.md', 'docs/RELEASING.md', f'docs/RELEASE-NOTES-{args.version}.md',
             'docs/benchmarks/0.13-dynamic-release.json', 'docs/benchmarks/0.12-headless-release.json',
             'docs/benchmarks/0.12-debugger-release.json', 'docs/benchmarks/0.12-advanced-release.json',
             'docs/benchmarks/0.12-trace-view-release.json', 'docs/benchmarks/0.12-condition-release.json']:
    assert (extraction / name).is_file()
    assert digest(extraction / name) == digest(root / name), name

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
assert mcp['tools'] == MCP_TOOLS and mcp['typeLibraryRoundTrip']
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
    'nativeStartup': 'Fixed windowless SMT worker exercised; GUI startup/input/DPI acceptance remains unverified.',
}
(archive.parent / 'package-verification.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report, indent=2))
