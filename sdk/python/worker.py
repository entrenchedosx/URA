"""Versioned trusted-code worker; JSON stdout is exclusively host protocol."""
import sys, json, struct, traceback, threading, importlib.util
if sys.version_info[:3] != (3, 14, 9) or struct.calcsize('P') != 8:
    raise RuntimeError('URA requires bundled CPython3.14.9 x64')
# Host creates this private directory with the exact compiled SDK, independent
# of CWD, site-packages, PYTHONPATH and plugin-controlled sibling modules.
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ura
wire_out=sys.stdout; wire_in=sys.stdin; lock=threading.Lock(); sequence=0
def send(value):
    text=json.dumps(value,ensure_ascii=True,separators=(',',':'))
    if len(text)>1024*1024: raise RuntimeError('Worker message exceeds1MiB')
    with lock: wire_out.write(text+'\n'); wire_out.flush()
def receive():
    line=wire_in.readline(1024*1024+1)
    if not line or len(line)>1024*1024 or not line.endswith('\n'): raise EOFError('Bounded protocol input ended')
    return json.loads(line)
def call(method,params):
    global sequence
    if threading.current_thread() is not threading.main_thread():raise ura.UraError('Host API calls require the worker main thread')
    sequence+=1; send({'protocol':1,'kind':'call','id':sequence,'method':method,'params':params})
    reply=receive()
    if reply.get('protocol')!=1 or reply.get('id')!=sequence:raise ura.UraError('Host reply identity mismatch')
    if 'error' in reply:raise ura.UraError(reply['error'])
    return reply['result']
ura._transport=call
class Output:
    def __init__(self,channel):self.channel=channel;self.used=0
    encoding='utf-8'
    def write(self,text):
        if not isinstance(text,str):raise TypeError('write requires str')
        size=len(text.encode('utf-8')); self.used+=size
        if self.used>262144:raise RuntimeError('Script output limit exceeded')
        for offset in range(0,len(text),4096):send({'protocol':1,'kind':'output','channel':self.channel,'text':text[offset:offset+4096]})
        return len(text)
    def flush(self):pass
    def isatty(self):return False
globals_={'__name__':'__ura_console__','ura':ura}
send({'protocol':1,'kind':'ready','python':sys.version.split()[0],'bits':64,'sdk':ura.__version__})
while True:
    try:command=receive()
    except EOFError:break
    if command.get('protocol')!=1:raise RuntimeError('Protocol version mismatch')
    if command['kind']=='close':break
    if command['kind']!='run':raise RuntimeError('Unknown worker command')
    sys.stdout=Output('stdout');sys.stderr=Output('stderr');result=None;error=None
    try:
        sys.argv=[command.get('filename','<ura>')]+command.get('args',[])
        if command.get('plugin'):
            folder=Path(command['plugin']); entry=folder/command['entrypoint']
            # Local package dependencies are bundled and explicitly trusted.
            sys.path.insert(1,str(folder)); module_name='ura_plugin_'+command['pluginId'].replace('.','_'); previous_module=sys.modules.get(module_name)
            try:
                spec=importlib.util.spec_from_file_location(module_name,entry)
                module=importlib.util.module_from_spec(spec);sys.modules[module_name]=module;spec.loader.exec_module(module)
                context={'project':None if command.get('detached') else ura.current_project(),'arguments':command.get('parameters',{}),'event':command.get('event'),
                         'configuration':command.get('configuration',{}),'apiVersion':1}
                if hasattr(module,'on_load'):module.on_load(context)
                try:result=getattr(module,command['callback'])(context)
                finally:
                    if hasattr(module,'on_unload'):module.on_unload(context)
            finally:
                sys.path.remove(str(folder))
                if previous_module is None:sys.modules.pop(module_name,None)
                else:sys.modules[module_name]=previous_module
        else:
            code=command['code'];filename=command.get('filename','<ura>')
            globals_['__name__']='__ura_console__' if filename.startswith('<') else '__main__'
            if not filename.startswith('<'):globals_['__file__']=filename
            else:globals_.pop('__file__',None)
            try:compiled=compile(code,filename,'eval')
            except SyntaxError:compiled=compile(code,filename,'exec');exec(compiled,globals_)
            else:
                value=eval(compiled,globals_)
                if value is not None:print(repr(value))
    except BaseException:
        error=traceback.format_exc(limit=20)[-16384:]
    finally:sys.stdout=wire_out;sys.stderr=sys.__stderr__
    try:send({'protocol':1,'kind':'done','result':result,'error':error})
    except Exception as failure:send({'protocol':1,'kind':'done','result':None,'error':'Plugin result is not bounded JSON: '+str(failure)[:512]})
