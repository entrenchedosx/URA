"""Compare owned compiler fixtures with Unicorn 2.1.4 (test-only dependency).
Build fixtures with build-processor-fixtures.ps1 and the processor-verify example first.
No fixture is executed by the host OS.
"""
import json
import hashlib
import pathlib
import subprocess
import sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "target/processor-reference"))
import unicorn
from unicorn import arm64_const, riscv_const, arm_const

def address(value):
    return int(value, 16) if isinstance(value, str) else value

def compare(reply):
    if "error" in reply:
        raise AssertionError(reply["error"])
    processor=reply["processor"]
    bits=reply["config"]["bitness"]
    arm32=processor in ("arm","thumb")
    constants=arm64_const if processor=="aarch64" else (arm_const if arm32 else riscv_const)
    prefix="UC_ARM64_REG_" if processor=="aarch64" else ("UC_ARM_REG_" if arm32 else "UC_RISCV_REG_")
    register=lambda name:getattr(constants,prefix+name.upper())
    cfg, state = reply["config"], reply["state"]
    assert state["status"] == "returned", state
    machine = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM) if processor=="aarch64" else (unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_THUMB if processor=="thumb" else unicorn.UC_MODE_ARM) if arm32 else unicorn.Uc(unicorn.UC_ARCH_RISCV,unicorn.UC_MODE_RISCV64 if bits==64 else unicorn.UC_MODE_RISCV32))
    pages = set()
    for segment in cfg["mappings"]:
        base = address(segment["base"])
        pages.update(range(base & ~4095, (base + segment["size"] + 4095) & ~4095, 4096))
    stack = address(cfg["stackBase"])
    pages.update(range(stack, stack + cfg["stackSize"], 4096))
    pages.add(0)
    for page in sorted(pages):
        machine.mem_map(page, 4096)
    if processor.startswith("riscv"):
        machine.mem_write(0,bytes.fromhex("13000000")*1024)
    for segment in cfg["mappings"]:
        machine.mem_write(address(segment["base"]), bytes(segment["bytes"]))
    if arm32:
        machine.reg_write(register("cpsr"),0x10 | (0x20 if processor=="thumb" else 0))
    machine.reg_write(register("sp"), stack + cfg["stackSize"])
    if processor=="aarch64":
        machine.reg_write(register("nzcv"), 0)
    for key, value in cfg["registers"].items():
        machine.reg_write(register(key), address(value))
    def stop_at_root(uc, pc, size, data):
        if pc == 0: uc.emu_stop()
    machine.hook_add(unicorn.UC_HOOK_CODE,stop_at_root)
    machine.emu_start(address(reply["entry"]) | (1 if processor=="thumb" else 0), 0xfff, count=100000)
    assert machine.reg_read(register("pc")) == 0, "oracle did not return"
    for name, value in state["registers"].items():
        if name in ("n", "z", "c", "v"):
            shift = dict(n=31, z=30, c=29, v=28)[name]
            expected = (machine.reg_read(register("cpsr") if arm32 else register("nzcv")) >> shift) & 1
        else:
            expected = machine.reg_read(register(name))
        assert value is not None and address(value) == expected, (name, value, hex(expected), state)
    final_bytes = {}
    for event in reply["trace"]["events"]:
        for base, data in event["writes"]:
            final_bytes.update((address(base) + i, byte) for i, byte in enumerate(data))
    for base, byte in final_bytes.items():
        assert machine.mem_read(base, 1)[0] == byte, ("memory", hex(base), byte)
    source=reply.get('sourceExecution')
    if source is not None:
        assert 'error' not in source['exit'],source
        assert source['exit']['destination'] in (None,'0x0'),source
        result=source['exit']['result']
        root='x0' if processor=='aarch64' else ('r0' if arm32 else 'a0')
        width=source['returnType'].get('bits',bits)
        mask=(1<<width)-1
        assert result is not None and address(result)&mask == machine.reg_read(register(root))&mask,('source result',source,hex(machine.reg_read(register(root))))
        for base,byte in source['changedBytes']:
            assert machine.mem_read(address(base),1)[0]==byte,('source memory',base,byte)
    return len(final_bytes)

def main():
    assert unicorn.__version__ == "2.1.4", "qualification requires pinned Unicorn2.1.4"
    fixture_root=ROOT/'tests/fixtures/processors'
    manifest=json.loads((fixture_root/'manifest.json').read_text(encoding='utf-8-sig'))
    assert hashlib.sha256((ROOT/'tests/samples/processors.c').read_bytes()).hexdigest()==manifest['sourceSha256']
    assert hashlib.sha256((ROOT/'tests/samples/aarch64-edges.s').read_bytes()).hexdigest()==manifest['edgesSourceSha256']
    for fixture in manifest['files']:
        assert hashlib.sha256((fixture_root/fixture['name']).read_bytes()).hexdigest()==fixture['sha256'],fixture['name']
    adapter = ROOT / ("target/release/examples/processor-verify.exe" if "--release" in sys.argv else "target/debug/examples/processor-verify.exe")
    proc = subprocess.Popen([str(adapter)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8", cwd=ROOT,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    failures, unsupported, passed, analysis_count, memory_bytes, source_count = [], [], 0, 0, 0, 0
    try:
        for processor,ext in (("aarch64","elf"),("aarch64","exe"),("riscv64","elf"),("riscv32","elf"),("arm","elf"),("thumb","elf")):
            for opt in range(4):
                for symbol in ("ura_scalar", "ura_select", "ura_width", "ura_loop", "ura_pointer", "ura_stack", "ura_nested", "ura_literal"):
                    inputs = [(0, 0), (5, 7), (0xfffffffffffffff9, 2), (0x8000000000000000, 0xffffffffffffffff)]
                    for a, b in inputs:
                        if symbol == "ura_loop":
                            b &= 15
                        if symbol == "ura_pointer":
                            a = 0x70000000
                        names=("x0","x1") if processor=="aarch64" else (("r0","r1") if processor in ("arm","thumb") else ("a0","a1"))
                        width_mask=(1<<32)-1 if processor in ("riscv32","arm","thumb") else (1<<64)-1
                        request = dict(path=f"tests/fixtures/processors/{processor}-O{opt}.{ext}", symbol=symbol, registers={names[0]:a & width_mask,names[1]:b & width_mask}, trace=True, analyze=(a == 5 or symbol == "ura_pointer"))
                        request["sourceExecute"]=symbol!="ura_nested" and not ((processor=="arm" and symbol=="ura_loop" and opt>0) or (processor=="thumb" and symbol in ("ura_select","ura_loop") and opt>0))
                        proc.stdin.write(json.dumps(request) + "\n")
                        proc.stdin.flush()
                        reply = json.loads(proc.stdout.readline())
                        try:
                            gated=(processor=="arm" and symbol=="ura_loop" and opt>0) or (processor=="thumb" and symbol in ("ura_select","ura_loop") and opt>0)
                            if gated:
                                state=reply["state"]
                                assert state["status"]=="faulted" and state["fault"]["kind"]=="unsupported",state
                                assert "IT/interworking/system" in state["fault"]["message"]
                                assert state["instructionPointer"]==state["fault"]["address"]
                                if request["analyze"]:
                                    assert reply["analysis"]["ir"]["raw"]["diagnostics"],"unsupported instruction disappeared from IR"
                                unsupported.append(dict(path=request["path"],symbol=symbol,reason=state["fault"]["message"]))
                                continue
                            memory_bytes += compare(reply)
                            source_count+=int(request["sourceExecute"])
                            if request["analyze"]:
                                assert reply["analysis"]["pseudocode"], "missing pseudocode"
                                assert not reply["analysis"]["ir"]["raw"].get("diagnostics", []), reply["analysis"]["ir"]["raw"].get("diagnostics", [])
                                analysis_count += 1
                            passed += 1
                        except Exception as error:
                            failures.append(dict(request=request, error=str(error)[:2000]))
        for symbol in ("ura_udiv","ura_sdiv","ura_flags","ura_rotate","ura_wide"):
            for a,b in ((0,0),(5,7),(0xffffffffffffffff,1),(0x7fffffffffffffff,1),(0x8000000000000000,0xffffffffffffffff),(0x0123456789abcdef,64),(0x80000000ffffffff,255)):
                request=dict(path="tests/fixtures/processors/aarch64-edges.elf",symbol=symbol,registers=dict(x0=a,x1=b),trace=True,analyze=True,sourceExecute=True)
                proc.stdin.write(json.dumps(request)+"\n");proc.stdin.flush();reply=json.loads(proc.stdout.readline())
                try:
                    memory_bytes+=compare(reply)
                    assert reply["analysis"]["pseudocode"],reply["analysis"]["pseudocodeError"]
                    assert not reply["analysis"]["ir"]["raw"].get("diagnostics",[])
                    passed+=1;analysis_count+=1;source_count+=1
                except Exception as error:
                    failures.append(dict(request=request,error=str(error)[:2000]))
    finally:
        proc.stdin.close()
        proc.wait()
    report = dict(oracle="Unicorn", oracleVersion=unicorn.__version__, compiler=manifest["compiler"], passed=passed, explicitlyUnsupported=unsupported, failures=failures, staticAnalyses=analysis_count,sourceAstExecutions=source_count, comparedWrittenBytes=memory_bytes, nativeForeignProcessesLaunched=False)
    out = ROOT / "target/v14-processor-oracle.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k not in ("failures","explicitlyUnsupported")}))
    print("Explicit unsupported boundaries:",len(unsupported))
    print("Failures:", len(failures), "report:", out)
    for failure in failures[:8]:
        print(failure["request"], failure["error"][:450])
    if failures:
        sys.exit(1)
if __name__ == "__main__":
    main()
