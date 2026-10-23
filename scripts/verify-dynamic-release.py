"""Headless CLI/MCP execution of the same bounded isolated machine; never launches a target."""
import argparse,hashlib,json,queue,subprocess,threading,time
from pathlib import Path
from release_common import CURRENT_VERSION,MCP_TOOLS,ROOT
parser=argparse.ArgumentParser()
parser.add_argument('--bin-dir',type=Path,default=Path('target/release'))
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args();folder=args.output.resolve();folder.mkdir(parents=True,exist_ok=True);bins=args.bin_dir.resolve()
class Client:
 def __init__(self,mcp,enabled=True,writes=True):
  self.mcp=mcp;self.counter=0;self.queue=queue.Queue()
  command=[str(bins/('ura-mcp.exe' if mcp else 'ura-cli.exe')),'--allow',str(folder)]
  if enabled:command+=['--enable-emulation']
  if writes:command+=['--enable-writes']
  command+=['--log','off'] if mcp else ['dynamic']
  self.child=subprocess.Popen(command,cwd=folder,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
  def reader():
   for line in self.child.stdout:
    try:self.queue.put(json.loads(line))
    except Exception as error:self.queue.put(error)
  threading.Thread(target=reader,daemon=True).start()
  if mcp:
   assert self.request('initialize',{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'ura-dynamic-qualification','version':'1'}})['serverInfo']['version']==CURRENT_VERSION
   self.child.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\n');self.child.stdin.flush()
   assert len(self.request('tools/list',{})['tools'])==MCP_TOOLS
 def request(self,method,params):
  self.counter+=1;number=self.counter
  self.child.stdin.write(json.dumps({'jsonrpc':'2.0','id':number,'method':method,'params':params})+'\n');self.child.stdin.flush()
  while True:
   reply=self.queue.get(timeout=20)
   assert isinstance(reply,dict),reply
   if reply.get('id')==number:
    assert 'error' not in reply,reply
    return reply['result']
 def rpc(self,operation,action,ok=True,**fields):
  if self.mcp:
   name={'emulation':'ura_emulation','replay':'ura_trace_replay','image':'ura_memory_image'}[operation]
   reply=self.request('tools/call',{'name':name,'arguments':{'action':action,**fields}})
   if not ok:assert reply.get('isError'),reply;return reply
   assert not reply.get('isError'),reply
   return reply['structuredContent']['result']
  self.child.stdin.write(json.dumps({'operation':operation,'action':action,**fields})+'\n');self.child.stdin.flush();reply=self.queue.get(timeout=20)
  if not ok:assert 'error' in reply,reply;return reply
  assert 'result' in reply,reply
  return reply['result']
 def wait(self,session):
  start=time.perf_counter()
  while True:
   reply=self.rpc('emulation','status',session=session)
   if not reply['busy']:return reply['state']
   assert time.perf_counter()-start<10
   time.sleep(.002)
 def close(self):
  self.child.stdin.close()
  try:self.child.wait(timeout=10)
  finally:
   if self.child.poll() is None:self.child.kill();self.child.wait()
config={'entry':'0x1000','mappings':[{'base':'0x1000','bytes':[184,42,0,0,0,195],'size':6,'permissions':{'read':True,'write':False,'execute':True}}]}
results={}
for mcp in [False,True]:
 name='mcp' if mcp else 'cli';client=Client(mcp)
 try:
  session=client.rpc('emulation','create',config=config)['session']
  client.rpc('emulation','run',session=session,steps=20)
  state=client.wait(session);assert state['registers']['rax']=='0x2A' and state['status']=='returned',state
  checkpoint=client.rpc('emulation','snapshot',session=session)['id']
  assert client.wait(session)['snapshots']==1
  client.rpc('emulation','reset',session=session)
  assert client.wait(session)['registers']['rax']=='0x0'
  client.rpc('emulation','restore',session=session,id=checkpoint)
  assert client.wait(session)['registers']['rax']=='0x2A'
  client.rpc('emulation','run',session=session,steps=1000001,ok=False)
  client.rpc('emulation','reset',session=session);client.rpc('emulation','run',session=session,steps=20);client.wait(session)
  trace=folder/(name+'-trace.json');receipt=client.rpc('emulation','exportTrace',session=session,destination=str(trace))
  assert receipt['sha256']==hashlib.sha256(trace.read_bytes()).hexdigest()
  client.rpc('emulation','exportTrace',session=session,destination=str(trace),ok=False)
  replay=client.rpc('replay','open',path=str(trace))['handle']
  page=client.rpc('replay','events',handle=replay,offset=0,limit=128)
  assert page['events']
  captured=client.rpc('replay','state',handle=replay,index=0)
  assert not captured['memoryAvailable'] and not captured['registersComplete']
  image=client.rpc('emulation','memoryImage',session=session)['handle']
  analysis=client.rpc('image','analyze',handle=image,entry='0x1000')
  assert analysis['ir'] and analysis['pseudocode'] and not analysis['portableExecutableReconstructed']
  bundle=folder/(name+'-image.json');client.rpc('image','export',handle=image,destination=str(bundle))
  other=client.rpc('image','open',path=str(bundle))['handle']
  comparison=client.rpc('image','compare',handle=image,other=other,address='0x1000',length=6)
  assert comparison['changedBytes']==0 and comparison['unknownBytes']==0
  client.rpc('emulation','close',session=session)
  client.rpc('emulation','status',session=session,ok=False)
  loop={**config,'mappings':[{'base':'0x1000','bytes':[235,254],'size':2,'permissions':{'read':True,'write':False,'execute':True}}]}
  session=client.rpc('emulation','create',config=loop)['session']
  client.rpc('emulation','run',session=session,steps=100000)
  start=time.perf_counter();client.rpc('emulation','stop',session=session);assert client.wait(session)['stopReason']=='cancelled'
  results[name]={'virtualResult':42,'traceReplay':True,'imageAnalysis':True,'noClobber':True,'resetRestore':True,'staleHandleRejected':True,'cancelMs':(time.perf_counter()-start)*1000}
 finally:client.close()
 denied=Client(mcp,enabled=False,writes=False)
 try:denied.rpc('emulation','create',config=config,ok=False)
 finally:denied.close()
 readonly=Client(mcp,writes=False)
 try:
  session=readonly.rpc('emulation','create',config=config)['session']
  readonly.rpc('emulation','exportTrace',session=session,destination=str(folder/'denied.json'),ok=False)
  assert not (folder/'denied.json').exists()
 finally:readonly.close()
report={'version':CURRENT_VERSION,'mcpTools':MCP_TOOLS,'workflows':results,'nativeDesktopLaunched':False,'nativeTargetLaunched':False,'executableSha256':{name:hashlib.sha256((bins/name).read_bytes()).hexdigest() for name in ['ura-native.exe','ura-cli.exe','ura-mcp.exe']}}
(folder/'verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
