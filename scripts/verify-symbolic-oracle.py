"""Independent Unicorn comparisons of original/derived IR and C-like AST.

Owned C/assembly fixtures are parsed/emulated, never launched by the host OS.
The adapter uses real Z3. Direct backend timings exclude subprocess startup;
product isolation/permissions are separately gated by verify-symbolic-release.py.
"""
from release_common import ROOT, CURRENT_VERSION
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import queue
import statistics
import subprocess
import sys
import threading
import time
import uuid
sys.path.insert(0,str(ROOT/'target/release-verification-python'))
sys.path.insert(0,str(ROOT/'target/processor-reference'))
import psutil
import unicorn
from unicorn import x86_const, arm64_const, arm_const, riscv_const

FLAGS=getattr(subprocess,'CREATE_NO_WINDOW',0)
def address(value):return int(value,16) if isinstance(value,str) else value
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def percentile(values,fraction):return sorted(values)[max(0,math.ceil(len(values)*fraction)-1)] if values else None

class Adapter:
    def __init__(self,path):
        self.child=subprocess.Popen([str(path)],cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            text=True,encoding='utf-8',creationflags=FLAGS)
        self.replies=queue.Queue();self.peak=0;self.stop=threading.Event()
        def read():
            try:
                for line in self.child.stdout:self.replies.put(json.loads(line))
            except Exception as error:self.replies.put(error)
        def sample():
            process=psutil.Process(self.child.pid)
            while not self.stop.wait(.005):
                try:self.peak=max(self.peak,process.memory_info().rss+sum(p.memory_info().rss for p in process.children(recursive=True)))
                except (psutil.NoSuchProcess,psutil.AccessDenied):pass
        self.reader=threading.Thread(target=read,daemon=True);self.reader.start()
        self.sampler=threading.Thread(target=sample,daemon=True);self.sampler.start()
    def request(self,value,allow_error=False):
        start=time.perf_counter();self.child.stdin.write(json.dumps(value)+'\n');self.child.stdin.flush()
        result=self.replies.get(timeout=140)
        if isinstance(result,Exception):raise result
        if 'error' in result and not allow_error:raise AssertionError(result['error'])
        result['adapterWallMs']=(time.perf_counter()-start)*1000
        return result
    def close(self):
        self.child.stdin.close();self.child.wait(timeout=15);self.stop.set();self.sampler.join(timeout=1)
        assert self.child.returncode==0,self.child.stderr.read()[:2000]

def execute_x86(reply,case,bits):
    cpu=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64 if bits==64 else unicorn.UC_MODE_32)
    pages={0};stack=address(case['stackBase']);pages.update(range(stack,stack+case['stackSize'],4096))
    for mapping in reply['mappings']:
        start=address(mapping['base']);pages.update(range(start&~4095,(start+mapping['size']+4095)&~4095,4096))
    for page in sorted(pages):cpu.mem_map(page,4096)
    for mapping in reply['mappings']:
        cpu.mem_write(address(mapping['base']),bytes(mapping['bytes']))
    flags=2
    flag_bits={'cf':0,'pf':2,'af':4,'zf':6,'sf':7,'of':11}
    for name,value in case['initialRegisters'].items():
        if bits==32 and name.endswith('_base'):continue # Unicorn does not implement these direct base registers in 32-bit mode.
        if name in flag_bits:flags|=(value&1)<<flag_bits[name]
        else:
            register=getattr(x86_const,'UC_X86_REG_'+name.upper(),None)
            if register is not None:cpu.reg_write(register,value)
    cpu.reg_write(x86_const.UC_X86_REG_EFLAGS,flags)
    cpu.hook_add(unicorn.UC_HOOK_CODE,lambda machine,pc,size,data:machine.emu_stop() if pc==0 else None)
    cpu.emu_start(address(reply['function']),0xfff,count=100000)
    pc=cpu.reg_read(x86_const.UC_X86_REG_RIP if bits==64 else x86_const.UC_X86_REG_EIP)
    assert pc==0,('oracle did not return',hex(pc))
    returned=cpu.reg_read(x86_const.UC_X86_REG_RAX if bits==64 else x86_const.UC_X86_REG_EAX)
    eflags=cpu.reg_read(x86_const.UC_X86_REG_EFLAGS)
    # Compare every defined architectural IR register/flag, not undefined flags.
    registers=0
    for representation in ('irOriginal','irSimplified'):
        output=case[representation];assert output['exit']['kind']=='return',output
        assert output['exit']['destination'] in (None,'0x0'),output
        for name,value in output['registers'].items():
            if bits==32 and name.endswith('_base'):continue
            if name in flag_bits:expected=(eflags>>flag_bits[name])&1
            else:
                register=getattr(x86_const,'UC_X86_REG_'+name.upper(),None)
                if register is None:continue
                expected=cpu.reg_read(register)
            assert address(value)==expected,(representation,name,value,hex(expected))
            registers+=1
        for base,byte in output['changedBytes']:
            assert cpu.mem_read(address(base),1)[0]==byte,(representation,'memory',base,byte)
    for representation in ('original','simplified'):
        output=case[representation];assert output['exit']['kind']=='return',output
        assert output['exit']['destination'] in (None,'0x0'),output
        assert output['exit']['result'] is not None and address(output['exit']['result'])&0xffffffff==returned&0xffffffff,(representation,output,hex(returned))
        for base,byte in output['changedBytes']:
            assert cpu.mem_read(address(base),1)[0]==byte,(representation,'memory',base,byte)
    assert case['original']==case['simplified'],'derived AST changed return or memory effects'
    assert case['irOriginal']==case['irSimplified'],'derived IR changed defined architectural state/memory'
    return registers

def execute_processor(reply,case,symbol,bits):
    processor=reply['processor'];arm32=processor in ('arm','thumb')
    constants=arm64_const if processor=='aarch64' else arm_const if arm32 else riscv_const
    prefix='UC_ARM64_REG_' if processor=='aarch64' else 'UC_ARM_REG_' if arm32 else 'UC_RISCV_REG_'
    register=lambda name:getattr(constants,prefix+name.upper(),None)
    cpu=(unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM) if processor=='aarch64' else
         unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_THUMB if processor=='thumb' else unicorn.UC_MODE_ARM) if arm32 else
         unicorn.Uc(unicorn.UC_ARCH_RISCV,unicorn.UC_MODE_RISCV64 if bits==64 else unicorn.UC_MODE_RISCV32))
    stack=address(case['stackBase']);pages={0};pages.update(range(stack,stack+case['stackSize'],4096))
    for segment in reply['mappings']:
        base=address(segment['base']);pages.update(range(base&~4095,(base+segment['size']+4095)&~4095,4096))
    for page in sorted(pages):cpu.mem_map(page,4096)
    if processor.startswith('riscv'):cpu.mem_write(0,bytes.fromhex('13000000')*1024)
    for segment in reply['mappings']:cpu.mem_write(address(segment['base']),bytes(segment['bytes']))
    if arm32:cpu.reg_write(register('cpsr'),0x10 | (0x20 if processor=='thumb' else 0))
    if processor=='aarch64':cpu.reg_write(register('nzcv'),0)
    for name,value in case['initialRegisters'].items():
        if name in ('n','z','c','v'):continue # Fixture flags are initially zero.
        key=register(name)
        if key is not None:cpu.reg_write(key,value)
    cpu.hook_add(unicorn.UC_HOOK_CODE,lambda machine,pc,size,data:machine.emu_stop() if pc==0 else None)
    cpu.emu_start(address(reply['function']) | (1 if processor=='thumb' else 0),0xfff,count=100000)
    assert cpu.reg_read(register('pc'))==0,'oracle did not return'
    returned=cpu.reg_read(register('x0' if processor=='aarch64' else 'r0' if arm32 else 'a0'))
    comparisons=0
    for representation in ('irOriginal','irSimplified'):
        output=case[representation];assert output['exit']['kind']=='return',output
        assert output['exit']['destination'] in (None,'0x0'),output
        for name,value in output['registers'].items():
            if name in ('n','z','c','v'):
                expected=(cpu.reg_read(register('cpsr' if arm32 else 'nzcv'))>>dict(n=31,z=30,c=29,v=28)[name])&1
            else:
                key=register(name)
                if key is None:continue
                expected=cpu.reg_read(key)
            assert address(value)==expected,(processor,representation,name,value,hex(expected))
            comparisons+=1
        for base,byte in output['changedBytes']:assert cpu.mem_read(address(base),1)[0]==byte
    mask=(1<<(32 if symbol=='ura_width' else bits))-1
    for representation in ('original','simplified'):
        output=case[representation];assert output['exit']['kind']=='return',output
        assert output['exit']['destination'] in (None,'0x0'),output
        assert output['exit']['result'] is not None and address(output['exit']['result'])&mask==returned&mask,(processor,representation,output,hex(returned))
        for base,byte in output['changedBytes']:assert cpu.mem_read(address(base),1)[0]==byte
    assert case['original']==case['simplified']
    assert case['irOriginal']==case['irSimplified']
    return comparisons


def expected(symbol,x,alias=False):
    x&=0xffffffff
    if symbol=='ura_opaque_even':return ((x^0x12345678)+17)&0xffffffff
    if symbol=='ura_opaque_odd':return (x+23)&0xffffffff
    if symbol=='ura_nonopaque':return (x^0x55) if x&1 else (x+3)&0xffffffff
    if symbol=='ura_wrap':return (x+11 if x!=0xffffffff else x-9)&0xffffffff
    if symbol=='ura_signed':return (x^0x87654321) if x&0x80000000 else (x+31)&0xffffffff
    if symbol=='ura_alias':return (x+int(alias))&0xffffffff
    if symbol=='ura_flattened':return ((x+7)^0x55)&0xffffffff
    if symbol=='ura_complement':return ~x&0xffffffff
    if symbol=='ura_negate':return -x&0xffffffff
    value=x
    for i in range((x&3)+1):value=(value*3+i)&0xffffffff
    return value

def baseline(path,sample,function):
    start=time.perf_counter()
    child=subprocess.run([str(path),'--allow',str(ROOT),'decompile',str(sample),'--function',function,'--limit','2000','--json'],
        cwd=ROOT,capture_output=True,text=True,encoding='utf-8',timeout=30,check=True,creationflags=FLAGS)
    result=json.loads(child.stdout);assert result['returned']==result['total'] and not result['truncated'],result
    text=''.join('    '*line['indent']+line['text']+'\n' for line in result['lines'])
    return {'lines':result['total'],'unresolved':result['unresolved'],'textSha256':hashlib.sha256(text.encode()).hexdigest(),
            'cliWallMs':(time.perf_counter()-start)*1000}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--release',action='store_true');parser.add_argument('--baseline',type=Path)
    parser.add_argument('--output',type=Path);args=parser.parse_args()
    assert unicorn.__version__=='2.1.4' and psutil.__version__=='7.2.2'
    folder=(args.output or ROOT/'target'/('symbolic-oracle-'+uuid.uuid4().hex)).resolve();folder.mkdir(parents=True,exist_ok=False)
    manifest=json.loads((ROOT/'tests/fixtures/symbolic/manifest.json').read_text(encoding='utf-8-sig'))
    assert digest(ROOT/manifest['source'])==manifest['sourceSha256']
    assert digest(ROOT/'tests/samples/symbolic-flat.S')==manifest['dispatcherSourceSha256']
    for fixture in manifest['files']:assert digest(ROOT/'tests/fixtures/symbolic'/fixture['name'])==fixture['sha256']
    if args.baseline:
        args.baseline=args.baseline.resolve()
        version=subprocess.check_output([str(args.baseline),'--version'],text=True,creationflags=FLAGS).strip()
        assert version=='ura-cli 0.14.0-dev.2',version
    adapter=Adapter(ROOT/('target/release/examples/symbolic-verify.exe' if args.release else 'target/debug/examples/symbolic-verify.exe'))
    records=[];processor_records=[];budget_records=[];compared=0;registers=0;solver_latencies=[];failure=None
    try:
        inputs=[0,1,2,3,7,0x7fffffff,0x80000000,0xfffffffe,0xffffffff]
        for level in range(4):
            for extension in ('exe','elf'):
                sample=ROOT/f'tests/fixtures/symbolic/x64-O{level}.{extension}'
                for symbol in ('ura_opaque_even','ura_opaque_odd','ura_nonopaque','ura_wrap','ura_signed','ura_loop','ura_alias','ura_flattened','ura_complement','ura_negate'):
                    cases=[];arguments=[]
                    for x in inputs:
                        if symbol=='ura_alias':
                            for alias in (False,True):
                                names=('rcx','rdx','r8') if extension=='exe' else ('rdi','rsi','rdx')
                                cases.append({'registers':dict(zip(names,(0x70000200,0x70000200 if alias else 0x70000210,x)))})
                                arguments.append((x,alias))
                        else:
                            cases.append({'registers':{('rcx' if extension=='exe' else 'rdi'):x}});arguments.append((x,False))
                    reply=adapter.request({'path':str(sample),'symbol':symbol,'backend':'direct','cases':cases})
                    (folder/'current-case.json').write_text(json.dumps({'fixture':str(sample),'symbol':symbol,'reply':reply}),encoding='utf-8')
                    for case,(x,alias) in zip(reply['executions'],arguments):
                        registers+=execute_x86(reply,case,64);compared+=1
                        assert address(case['simplified']['exit']['result'])&0xffffffff==expected(symbol,x,alias),(symbol,x,case['simplified'])
                    report=reply['report'];old=reply['original'];new=reply['simplified']
                    if level==0 and extension=='exe' and symbol in ('ura_opaque_even','ura_flattened'):
                        (folder/(symbol+'.original.c')).write_text(old['text'],encoding='utf-8')
                        (folder/(symbol+'.simplified.c')).write_text(new['text'],encoding='utf-8')
                    if symbol in ('ura_nonopaque','ura_wrap','ura_signed'):assert not report['removedEdges'],(symbol,report['predicates'])
                    solver_latencies.extend(q['outcome']['elapsedUs']/1000 for q in report['queries'])
                    record={'fixture':str(sample.relative_to(ROOT)),'symbol':symbol,'function':reply['function'],'cases':len(cases),
                        'opaque':sum(p['classification'] in ('alwaysTrue','alwaysFalse') for p in report['predicates']),
                        'prunedEdges':len(report['removedEdges']),'queries':len(report['queries']),'paths':len(report['paths']),
                        'complete':report['complete'],'operations':report['operations'],'states':report['exploredStates'],
                        'expressions':len(report['expressions']['nodes']),'elapsedMs':reply['elapsedUs']/1000,'symbolicMs':report['elapsedUs']/1000,'adapterWallMs':reply['adapterWallMs'],
                        'originalLines':old['lines'],'simplifiedLines':new['lines'],'originalUnresolved':old['unresolved'],'simplifiedUnresolved':new['unresolved'],
                        'peakStateBytes':report['peakStateBytes'],'dispatcherTransitions':sum(len(d['transitions']) for d in report['dispatchers']),
                        'solverOutcomes':{status:sum(q['outcome']['status']==status for q in report['queries']) for status in ('sat','unsat','unknown','timeout','unsupported','error','cancelled','limit')}}
                    if args.baseline:
                        record['v014']=baseline(args.baseline,sample,reply['function'])
                        record['v014']['sameUnrefinedText']=record['v014']['textSha256']==hashlib.sha256(old['text'].encode()).hexdigest()
                        assert old['unresolved']<=record['v014']['unresolved'],('unrefined reconstruction gained unresolved operations',record)
                    records.append(record)
        # Explicit x86 raw-mode identity crosses the 32-bit register/pointer path.
        raw=folder/'x86-opaque.bin';raw.write_bytes(bytes.fromhex('89c88d51010fafc2a8017506b801000000c3b802000000c3'))
        reply=adapter.request({'path':str(raw),'rawProcessor':'x86','function':'0x1000','backend':'direct','cases':[{'registers':{'ecx':x}} for x in inputs]})
        assert len(reply['report']['removedEdges'])==1
        for case in reply['executions']:registers+=execute_x86(reply,case,32);compared+=1
        # Reuse hash-checked owned compiler fixtures for shared symbolic IR on
        # every retained processor subset; no foreign executable is launched.
        processors=json.loads((ROOT/'tests/fixtures/processors/manifest.json').read_text(encoding='utf-8-sig'))
        assert digest(ROOT/'tests/samples/processors.c')==processors['sourceSha256']
        for processor,extension in (('aarch64','elf'),('aarch64','exe'),('riscv64','elf'),('riscv32','elf'),('arm','elf'),('thumb','elf')):
            bits=32 if processor in ('riscv32','arm','thumb') else 64;mask=(1<<bits)-1
            names=('x0','x1') if processor=='aarch64' else ('r0','r1') if processor in ('arm','thumb') else ('a0','a1')
            sample=ROOT/f'tests/fixtures/processors/{processor}-O0.{extension}'
            entry=next(f for f in processors['files'] if f['name']==sample.name);assert digest(sample)==entry['sha256']
            for symbol in ('ura_scalar','ura_select','ura_width'):
                cases=[{'registers':{names[0]:a&mask,names[1]:b&mask}} for a,b in ((0,0),(5,7),(mask-6,2),(1<<(bits-1),mask))]
                reply=adapter.request({'path':str(sample),'symbol':symbol,'backend':'direct','cases':cases})
                (folder/'current-case.json').write_text(json.dumps({'fixture':str(sample),'symbol':symbol,'reply':reply}),encoding='utf-8')
                for case in reply['executions']:registers+=execute_processor(reply,case,symbol,bits);compared+=1
                solver_latencies.extend(q['outcome']['elapsedUs']/1000 for q in reply['report']['queries'])
                processor_records.append({'processor':processor,'fixture':str(sample.relative_to(ROOT)),'symbol':symbol,'cases':len(cases),
                    'queries':len(reply['report']['queries']),'paths':len(reply['report']['paths']),'complete':reply['report']['complete'],
                    'elapsedMs':reply['elapsedUs']/1000,'prunedEdges':len(reply['report']['removedEdges'])})
        # Independent input bits create a real combinatorial branch family.
        # Small state/path budgets must stop it with incomplete coverage.
        stress=folder/'path-explosion.bin'
        stress.write_bytes(b''.join(b'\xf7\xc1'+(1<<bit).to_bytes(4,'little')+b'\x74\x02\x90\x90' for bit in range(16))+b'\xc3')
        reply=adapter.request({'path':str(stress),'rawProcessor':'x86-64','function':'0x1000','backend':'direct',
            'options':{'maxStates':4,'maxPaths':2,'maxQueries':128}})
        report=reply['report'];assert report['complete'] is False and report['exploredStates']<=4 and len(report['paths'])<=2,report
        budget_records.append({'case':'independent-bit path explosion','elapsedMs':reply['elapsedUs']/1000,'states':report['exploredStates'],
            'paths':len(report['paths']),'operations':report['operations'],'peakStateBytes':report['peakStateBytes'],'complete':report['complete'],'diagnostics':report['diagnostics']})
        large=folder/'large-cfg.bin';large.write_bytes(bytes.fromhex('85c974029090')*300+b'\xc3')
        reply=adapter.request({'path':str(large),'rawProcessor':'x86-64','function':'0x1000','backend':'direct'},allow_error=True)
        assert 'function capacity' in reply.get('error',''),reply
        budget_records.append({'case':'over-capacity CFG rejection','adapterWallMs':reply['adapterWallMs'],'error':reply['error']})
    except Exception as error:
        failure=repr(error);raise
    finally:
        adapter.close()
        hardware={'platform':platform.platform(),'processor':platform.processor(),'logicalCpus':os.cpu_count(),'physicalCpus':psutil.cpu_count(logical=False),'ramBytes':psutil.virtual_memory().total}
        if sys.platform=='win32':
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as key:hardware['cpuModel']=winreg.QueryValueEx(key,'ProcessorNameString')[0].strip()
        result={'version':CURRENT_VERSION,'profile':'release' if args.release else 'debug','solver':'Z3 5.1.0.0','backend':'DirectZ3 in owned test adapter; product process isolation checked separately',
            'oracle':{'unicorn':unicorn.__version__,'psutil':psutil.__version__},'hardware':hardware,'fixtureCompiler':manifest['compiler'],
            'baseline':{'version':'0.14.0-dev.2','sha256':digest(args.baseline)} if args.baseline else None,
            'functions':len(records),'processorFunctions':len(processor_records),'processorRecords':processor_records,'budgetRecords':budget_records,'executionCases':compared,'astComparisons':compared*2,'irComparisons':compared*2,'definedRegisterFlagComparisons':registers,
            'peakAdapterAndChildrenRssBytes':adapter.peak,'solverMedianMs':statistics.median(solver_latencies) if solver_latencies else None,
            'solverP95Ms':percentile(solver_latencies,.95),'falsePositiveBranchEliminations':0 if failure is None else None,'failure':failure,'records':records}
        (folder/'verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'functions':len(records),'cases':compared,'evidence':str(folder/'verification.json')}))
if __name__=='__main__':main()
