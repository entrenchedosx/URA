"""Build-time only: verify and stage the locked official CPython x64 package.
The product never downloads a runtime or installs Python packages at startup.
"""
import argparse, hashlib, io, json, os, shutil, tempfile, urllib.request, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(data): return hashlib.sha256(data).hexdigest()
def prepare(destination):
    lock=json.loads((ROOT/'scripts/python-runtime.lock.json').read_text(encoding='utf-8-sig'))
    expected=lock['files']; destination=destination.resolve()
    if destination.exists():
        valid=all((destination/n).is_file() and sha((destination/n).read_bytes())==h for n,h in expected.items())
        if valid:
            (destination/'URA-RUNTIME.json').write_text(json.dumps(lock,indent=2)+'\n',encoding='utf-8'); return
        raise RuntimeError('Existing runtime differs from the lock; choose a new output directory')
    size=lock['archiveBytes']; data=bytearray(); chunk=1024*1024
    cache=ROOT/'target'/('python-'+lock['version']+'-embed-amd64.zip')
    if cache.exists():
        if cache.stat().st_size!=size:raise RuntimeError('Cached runtime size mismatch')
        data=bytearray(cache.read_bytes())
    else:
        for start in range(0,size,chunk):
            end=min(start+chunk,size)-1
            request=urllib.request.Request(lock['source'],headers={'Range':f'bytes={start}-{end}','User-Agent':'URA-runtime-builder/1'})
            for attempt in range(3):
                try:
                    with urllib.request.urlopen(request,timeout=45) as response:
                        block=response.read(end-start+2)
                        if response.status!=206 or response.headers.get('Content-Range')!=f'bytes {start}-{end}/{size}' or len(block)!=end-start+1:raise RuntimeError('Runtime range/length mismatch')
                    data.extend(block);break
                except Exception:
                    if attempt==2:raise
    if len(data)!=size or sha(data)!=lock['archiveSha256']:raise RuntimeError('Runtime archive hash mismatch')
    if not cache.exists():cache.parent.mkdir(parents=True,exist_ok=True);cache.write_bytes(data)
    destination.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='ura-python-',dir=destination.parent) as staging:
        staging=Path(staging)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names=archive.namelist()
            if len(names)!=len(set(names)) or set(names)!=set(expected):raise RuntimeError('Runtime member inventory mismatch')
            for name in names:
                if '/' in name or '\\' in name or ':' in name or name in ('.','..'):raise RuntimeError('Unsafe runtime path')
                member=archive.getinfo(name)
                if member.file_size>64*1024*1024:raise RuntimeError('Runtime member too large')
                content=archive.read(name)
                if sha(content)!=expected[name]:raise RuntimeError('Runtime member hash mismatch: '+name)
                (staging/name).write_bytes(content)
        (staging/'URA-RUNTIME.json').write_text(json.dumps(lock,indent=2)+'\n',encoding='utf-8')
        os.rename(staging,destination)
    print(json.dumps({'runtime':str(destination),'version':lock['version'],'sha256':lock['archiveSha256']}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'target/python-runtime-3.14.9');args=p.parse_args();prepare(args.output)
