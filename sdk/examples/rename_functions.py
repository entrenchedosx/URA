"""Requires project.write, host writes and a saved project. Atomic metadata only."""
import ura
p=ura.current_project()
with p.transaction() as tx:
    for f in p.functions(limit=4):tx.rename(f,'reviewed_'+hex(f.address)[2:])
print('Committed reviewed names')
