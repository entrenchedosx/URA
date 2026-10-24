from __future__ import annotations
from dataclasses import dataclass
import ura
@dataclass
class Options:
    limit: int = 16
def analyze(context):
    p=context['project']
    for f in p.functions(limit=Options().limit):
        blocks=f.cfg()['blocks']
        if any(len(b['successors'])>1 for b in blocks):
            ura.emit_finding('Conditional control flow',f.address,'CFG contains a conditional successor pair; this is an observation, not proof of malicious or opaque behavior.',confidence='observed',evidence={'blocks':len(blocks)})
    return {'analyzed':True}
def inventory(context):return {'names':[f.name for f in context['project'].functions(limit=32)]}
