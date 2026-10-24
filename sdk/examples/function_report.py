"""Bounded analysis pages preserve source addresses and core limitations."""
import json
import ura
p=ura.current_project()
f=next(p.functions())
print(json.dumps({'function':f.details(),'instructions':[i.data for i in p.instructions(f.address,8)],
                  'cfg':f.cfg(),'ir':f.ir(),'ssa':f.ir(ssa=True),'dataflow':f.dataflow(),
                  'source':f.pseudocode_page(),'signature':f.signature(),'stack':f.stack(),
                  'types':f.inferred_types(),'xrefs':f.xrefs()},indent=2))
