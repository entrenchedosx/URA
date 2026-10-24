"""Check hash-manifested sources after Windows Git checkout filters, before builds."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
manifest = json.loads((ROOT / 'tests/fixtures/symbolic/manifest.json').read_text(encoding='utf-8-sig'))
for name, key in (
    ('tests/samples/symbolic.c', 'sourceSha256'),
    ('tests/samples/symbolic-flat.S', 'dispatcherSourceSha256'),
):
    expected = manifest[key]
    if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
        raise ValueError('Working fixture source hash mismatch: ' + name)
    checkout = subprocess.check_output(
        ['git', '-c', 'core.autocrlf=true', 'cat-file', '--filters', 'HEAD:' + name],
        cwd=ROOT, timeout=15, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
    )
    if hashlib.sha256(checkout).hexdigest() != expected:
        raise ValueError('Windows checkout changes fixture source: ' + name)
print('Symbolic source hashes survive Windows Git checkout')
