"""Requires files.export, host writes, allowed destination and one script argument."""
import sys
import ura
p=ura.current_project()
data=[{'function':f.name,'address':hex(f.address),'outgoing':f.xrefs()} for f in p.functions(limit=16)]
print(p.export_json(sys.argv[1],data))
