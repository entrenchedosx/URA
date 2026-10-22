"""Exercise the built Release MCP transport and prepare a disposable project.
Samples are parsed statically. Only the selected disposable output folder is written.
"""
import argparse
import json
from pathlib import Path
import queue
import subprocess
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument('--exe', default='target/release/ura-mcp.exe')
parser.add_argument('--output', default='target/v08-audit')
args = parser.parse_args()
root = Path.cwd().resolve()
folder = Path(args.output).resolve()
folder.mkdir(parents=True, exist_ok=True)
child = subprocess.Popen([str(Path(args.exe).resolve()),'--allow',str(root),'--allow',str(folder),'--enable-writes','--log','off'],cwd=Path(args.exe).resolve().parent,stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
replies = queue.Queue()
def reader():
    for line in child.stdout:
        replies.put(json.loads(line))
threading.Thread(target=reader,daemon=True).start()
number = 0
def request(method,params):
    global number
    number += 1
    child.stdin.write(json.dumps({'jsonrpc':'2.0','id':number,'method':method,'params':params})+'\n');child.stdin.flush()
    while True:
        data = replies.get(timeout=15)
        if data.get('id') == number:
            assert 'error' not in data,data
            return data['result']
def tool(name,args):
    data = request('tools/call',{'name':name,'arguments':args})
    assert not data.get('isError'),data
    return data['structuredContent']
try:
    request('initialize',{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'ura-release-check','version':'1'}})
    child.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\n');child.stdin.flush()
    assert len(request('tools/list',{})['tools']) == 55
    opened = tool('ura_open_binary',{'binary':str(root/'tests/fixtures/ura64.exe')})
    handle = opened['handle'];tool('ura_analyze',{'handle':handle})
    timings = {}
    for name in ['ura_get_ir','ura_get_ssa','ura_get_dominators','ura_get_analysis_diagnostics']:
        start = time.perf_counter()
        data = tool(name,{'handle':handle,'function':'140001020','limit':50})
        timings[name] = (time.perf_counter()-start)*1000
        assert data['irVersion'] == 1
    decompiler = {}
    for name in ['ura_get_function_signature','ura_get_calling_convention','ura_get_stack_variables','ura_get_types','ura_get_type_constraints','ura_get_high_level_ir']:
        start = time.perf_counter()
        decompiler[name] = tool(name,{'handle':handle,'function':'140001020','limit':20})['schemaVersion']
        timings[name] = (time.perf_counter()-start)*1000
    typed = tool('ura_get_high_level_ir', {'handle':handle,'function':'140001020','limit':20,'ast':True})
    assert typed['ast']['function'] == '0x140001020'
    assert typed['ast']['source']['variables']
    assert typed['ast']['source']['blocks']
    assert typed['program']['converged']
    semantic = tool('ura_get_high_level_ir', {'handle':handle,'function':'140001020','limit':5,'semantic':True})['semantic']
    assert semantic['complete'] and semantic['nodes'] and semantic['values']
    page = tool('ura_get_high_level_ir', {'handle':handle,'function':'140001020','limit':5,'semanticBlock':semantic['blocks'][0]['address']})['semantic']
    assert not page['complete'] and page['totalNodes'] == semantic['totalNodes']
    source = tool('ura_decompile_function', {'handle':handle,'function':'140001020','limit':3,'ast':True})
    assert source['syntax'] == 'c-like' and source['ast']['version'] == 1
    assert source['ast']['address'] == '0x140001020' and source['returned'] == 3
    tail = tool('ura_decompile_function', {'handle':handle,'function':'140001020','offset':3,'limit':2000})
    assert source['returned'] + tail['returned'] == source['total']
    destination = folder/'decompiled.c'
    exported = tool('ura_export_decompiled_function', {'handle':handle,'function':'140001020','destination':str(destination)})
    text = destination.read_text(encoding='utf-8')
    expected = ''.join('    '*line['indent']+line['text']+'\n' for line in source['lines']+tail['lines'])
    assert text == expected and exported['bytes'] == len(text.encode('utf-8'))
    repeated = request('tools/call',{'name':'ura_export_decompiled_function','arguments':{'handle':handle,'function':'140001020','destination':str(destination)}})
    assert repeated['isError'] and destination.read_text(encoding='utf-8') == expected
    graph = tool('ura_get_call_graph',{'handle':handle,'function':'140001000','depth':1,'maxNodes':50})
    assert graph['schemaVersion'] == 1
    project = folder/'fixture.ura'
    project.parent.mkdir(parents=True,exist_ok=True)
    tool('ura_save_project',{'handle':handle,'project':str(project)})
    library = {'addressBits':64,'structures':{'Header':{'name':'Header','size':4,'alignment':4,'union':False,'source':'user','fields':[{'name':'length','offset':0,'ty':{'kind':'int','bits':32,'signed':False},'source':'user','size':None}]}},'typedefs':{}}
    tool('ura_set_type_library',{'handle':handle,'project':str(project),'database':library})
    assert tool('ura_get_structure',{'handle':handle,'name':'Header'})['structure']['fields'][0]['name'] == 'length'
    assert tool('ura_get_types',{'handle':handle})['database'] == library
    result = {'tools':55,'irSchema':1,'decompilerSchema':decompiler,'callGraphNodes':graph['returnedNodes'],'fixtureQueryMs':timings,'projectPrepared':project.name,'typeLibraryRoundTrip':True,'cDecompileRoundTrip':True,'cExportRoundTrip':True,'typedAstRoundTrip':True,'semanticRoundTrip':True,'semanticBlockPage':True,'programConverged':typed['program']['converged']}
    (project.parent/'mcp-release.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))
finally:
    child.terminate();child.wait(timeout=10)
