"""Qualify solver loading and real shared-service adapters without any desktop UI.

The Desktop EXE is invoked ONLY with its fixed SMT worker flag, intercepted
before application startup. Inspected raw fixture bytes are never host-executed.
"""
from release_common import CURRENT_VERSION, MCP_TOOLS
import argparse
import hashlib
import json
from pathlib import Path
import queue
import struct
import subprocess
import threading
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
FLAGS=getattr(subprocess,'CREATE_NO_WINDOW',0)

def pe_imports(path):
    data=path.read_bytes(); pe=struct.unpack_from('<I',data,0x3c)[0]
    assert data[pe:pe+4]==b'PE\0\0'
    count=struct.unpack_from('<H',data,pe+6)[0]; size=struct.unpack_from('<H',data,pe+20)[0]; optional=pe+24
    assert struct.unpack_from('<H',data,optional)[0]==0x20b,'Windows x64 required'
    address,_=struct.unpack_from('<II',data,optional+120)
    sections=[]
    for index in range(count):
        vs,va,rs,rp=struct.unpack_from('<IIII',data,optional+size+index*40+8)
        sections.append((va,max(vs,rs),rp))
    def offset(address):
        return next(rp+address-va for va,size,rp in sections if va<=address<va+size)
    result=[]; cursor=offset(address)
    while any(data[cursor:cursor+20]):
        name=offset(struct.unpack_from('<I',data,cursor+12)[0])
        result.append(data[name:data.index(0,name)].decode('ascii').lower()); cursor+=20
    return sorted(set(result))

class Lines:
    def __init__(self,arguments,cwd):
        self.child=subprocess.Popen(list(map(str,arguments)),cwd=cwd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,text=True,encoding='utf-8',creationflags=FLAGS)
        self.queue=queue.Queue()
        def read():
            try:
                for line in self.child.stdout:self.queue.put(json.loads(line))
            except Exception as error:self.queue.put(error)
        self.reader=threading.Thread(target=read,daemon=True);self.reader.start()
    def send(self,value):
        self.child.stdin.write(json.dumps(value)+'\n'); self.child.stdin.flush()
    def receive(self):
        value=self.queue.get(timeout=20)
        if isinstance(value,Exception):raise value
        return value
    def close(self):
        self.child.stdin.close()
        try:self.child.wait(timeout=10)
        except subprocess.TimeoutExpired:self.child.kill();self.child.wait();raise
        assert self.child.returncode==0,self.child.stderr.read()[:2000]

def query():
    return {'arena':{'nodes':[{'sort':{'kind':'bits','width':8},'kind':{'kind':'symbol','name':'x','poison':None}}],
        'max_nodes':100,'max_depth':20},'assertions':[],'observables':{'x':0},
        'limits':{'timeoutMs':500,'resourceLimit':2000000,'memoryMb':256}}

def workers(directory,folder):
    result={}
    for name in ('ura-native.exe','ura-cli.exe','ura-mcp.exe'):
        path=directory/name
        # Refuse to launch any image that lacks this newly built early entry
        # point. In particular, never pass the flag to an older GUI executable.
        assert b'--ura-smt-worker' in path.read_bytes(),f'{name} has no verified SMT worker entry point'
        imports=pe_imports(path)
        assert not any('z3' in name or name.startswith(('msvcp','vcruntime','concrt')) for name in imports),imports
        def call(request):
            before=set(folder.iterdir());start=time.perf_counter()
            child=subprocess.run([str(path),'--ura-smt-worker'],input=json.dumps(request),capture_output=True,text=True,
                encoding='utf-8',cwd=folder,timeout=10,creationflags=FLAGS)
            assert child.returncode==0,(name,child.stderr)
            assert set(folder.iterdir())==before,'solver worker created unexpected files'
            value=json.loads(child.stdout);assert value['solver']=='Z3 5.1.0.0',value
            return value,(time.perf_counter()-start)*1000
        sat,latency=call(query());assert sat['status']=='sat' and sat['model']['x'].startswith('0x'),sat
        invalid=query();invalid['assertions']=[999999]
        bad,_=call(invalid);assert bad['status']=='error',bad
        poison=query();poison['arena']['nodes'][0]['kind']['poison']='undefined flag'
        unsupported,_=call(poison);assert unsupported['status']=='unsupported',unsupported
        result[name]={'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'imports':imports,'satMs':latency,
            'solver':sat['solver'],'malformedStatus':bad['status'],'undefinedStatus':unsupported['status']}
    return result

def wait(call,session):
    deadline=time.monotonic()+25
    while time.monotonic()<deadline:
        status=call({'action':'status','session':session})
        if status.get('state')!='running':return status
        time.sleep(.02)
    raise TimeoutError('symbolic session did not finish')

def cli(directory,folder,sample):
    process=Lines([directory/'ura-cli.exe','--allow',folder,'symbolic',sample,'--raw','--base','0x1000','--processor','x86-64'],folder)
    try:
        banner=process.receive();assert banner['ready'],banner
        def call(value,error=False):
            process.send(value);response=process.receive();assert response['schemaVersion']==1,response
            if error:assert 'error' in response,response;return response['error']
            assert 'error' not in response,response
            return response['result']
        session=call({'action':'start','function':'0x1000'})['session']
        assert wait(call,session)['state']=='complete'
        summary=call({'action':'summary','session':session});assert summary['prunedEdges']==1,summary
        predicate=call({'action':'page','session':session,'category':'predicates'})['items'][0]
        assert predicate['classification']=='alwaysFalse' and predicate['validationEvidence'] is not None,predicate
        proof=call({'action':'proof','session':session,'index':predicate['validationEvidence']})
        assert proof['evidence']['outcome']['status']=='unsat',proof
        assert call({'action':'export','session':session,'destination':str(folder/'denied.json')},True)['code']=='write_disabled'
        assert call({'action':'page','session':session,'limit':99999},True)['code']=='invalid_argument'
        for category in ('paths','queries','dispatchers','targets','edges','expressions','valueSets','original','simplified','cfg'):
            page=call({'action':'page','session':session,'category':category,'limit':1});assert len(page['items'])<=1
        assert call({'action':'cancel','session':session})['state']=='cancelling'
        assert call({'action':'summary','session':session},True)['code']=='invalid_argument'
        call({'action':'close','session':session})
        return summary
    finally:process.close()

def mcp(directory,folder,sample):
    process=Lines([directory/'ura-mcp.exe','--allow',folder,'--enable-writes','--log','off'],folder);number=0
    def request(method,params):
        nonlocal number
        number+=1;process.send({'jsonrpc':'2.0','id':number,'method':method,'params':params})
        while True:
            result=process.receive()
            if result.get('id')==number:
                assert 'error' not in result,result
                return result['result']
    def tool(name,args,error=False):
        result=request('tools/call',{'name':name,'arguments':args})
        if error:assert result.get('isError'),result;return result['structuredContent']['error']
        assert not result.get('isError'),result
        return result['structuredContent']
    try:
        request('initialize',{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'ura-symbolic-qualification','version':'1'}})
        process.send({'jsonrpc':'2.0','method':'notifications/initialized'})
        tools=request('tools/list',{})['tools'];assert len(tools)==MCP_TOOLS and any(t['name']=='ura_symbolic' for t in tools)
        opened=tool('ura_open_binary',{'binary':str(sample),'raw':True,'base':'0x1000','processor':'x86-64'});handle=opened['handle']
        tool('ura_analyze',{'handle':handle})
        def call(value,error=False):return tool('ura_symbolic',value,error).get('result') if not error else tool('ura_symbolic',value,True)
        session=call({'action':'start','handle':handle,'function':'0x1000'})['session'];assert wait(call,session)['state']=='complete'
        summary=call({'action':'summary','session':session});assert summary['prunedEdges']==1,summary
        destination=folder/'symbolic-report.json';export=call({'action':'export','session':session,'destination':str(destination)})
        report=json.loads(destination.read_text(encoding='utf-8'));assert export['sha256']==hashlib.sha256(destination.read_bytes()).hexdigest()
        assert report['removedEdges'] and report['queries']
        assert call({'action':'export','session':session,'destination':str(destination)},True)['code']=='io_error'
        project=folder/'symbolic.ura';tool('ura_save_project',{'handle':handle,'project':str(project),'name':'symbolic qualification'})
        # A declaration rename changes the decompiler context; old results must be rejected.
        tool('ura_rename_function',{'handle':handle,'project':str(project),'address':'0x1000','name':'verified_opaque'})
        assert call({'action':'status','session':session})['state']=='stale'
        call({'action':'close','session':session});tool('ura_analyze',{'handle':handle})
        session=call({'action':'start','handle':handle,'function':'0x1000'})['session'];assert wait(call,session)['state']=='complete'
        start=time.perf_counter();assert call({'action':'save','session':session,'project':str(project)})['saved']
        save_ms=(time.perf_counter()-start)*1000
        start=time.perf_counter();historical=call({'action':'load','project':str(project)})
        load_ms=(time.perf_counter()-start)*1000;assert historical['authoritative'] is False
        assert historical['metadata']['identity']
        tool('ura_analyze',{'handle':handle})
        assert call({'action':'status','session':session})['state']=='stale'
        assert call({'action':'summary','session':session},True)['code']=='invalid_argument'
        call({'action':'close','session':session})
        # Cancellation must be independent of a pending expensive solver query.
        stress=folder/'cancellation-stress.bin'
        stress.write_bytes(bytes.fromhex('89c88d51010fafc2a80175029090')*20+b'\xc3')
        stress_handle=tool('ura_open_binary',{'binary':str(stress),'raw':True,'base':'0x1000','processor':'x86-64'})['handle']
        tool('ura_analyze',{'handle':stress_handle})
        session=call({'action':'start','handle':stress_handle,'function':'0x1000','options':{'totalMs':120000,'maxQueries':256}})['session']
        time.sleep(.05)
        assert call({'action':'status','session':session})['state']=='running','stress session must still be active before cancellation'
        start=time.perf_counter();call({'action':'cancel','session':session});call({'action':'close','session':session})
        cancellation=(time.perf_counter()-start)*1000;assert cancellation<2500,cancellation
        tool('ura_close_binary',{'handle':stress_handle})
        return {'summary':summary,'cancellationMs':cancellation,'cancelledWhileRunning':True,'historicalSaveMs':save_ms,'historicalLoadMs':load_ms,'historicalMetadata':True,'staleGenerationRejected':True}
    finally:process.close()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary-directory',type=Path,default=ROOT/'target/release')
    parser.add_argument('--output',type=Path);args=parser.parse_args()
    directory=args.binary_directory.resolve();folder=(args.output or ROOT/'target'/('symbolic-check-'+uuid.uuid4().hex)).resolve()
    folder.mkdir(parents=True,exist_ok=False)
    # Actual multiply identity survives into this owned assembled scalar fixture.
    sample=folder/'opaque.bin';sample.write_bytes(bytes.fromhex('89c88d51010fafc2a8017506b801000000c3b802000000c3'))
    result={'version':CURRENT_VERSION,'workers':workers(directory,folder),'cli':cli(directory,folder,sample),'mcp':mcp(directory,folder,sample)}
    (folder/'verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'evidence':str(folder/'verification.json')}))
if __name__=='__main__':main()
