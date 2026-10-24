"""Toy8 decoding/CFG demonstration. No IR, decompiler, emulation or symbolic lift."""
def decode(context):
    args=context['arguments'];data=bytes.fromhex(args['bytesHex']);base=int(args['base'],16)
    cursor=0;instructions=[]
    while cursor<len(data):
        op=data[cursor];size=1;flow='next';mnemonic='invalid';operands='';target=None;invalid=False
        if op==0:mnemonic='nop'
        elif op==255:mnemonic='ret';flow='return'
        elif op in (16,32,48,64) and cursor+1<len(data):
            size=2;mnemonic={16:'mov',32:'add',48:'jnz',64:'jmp'}[op];operand=data[cursor+1]
            if op in (48,64):target=hex(base+operand);flow='conditionalJump' if op==48 else 'jump';operands=target
            else:operands='r0, '+str(operand)
        else:invalid=True
        instructions.append({'address':hex(base+cursor),'length':size,'mnemonic':mnemonic,'operands':operands,'flow':flow,'target':target,'invalid':invalid});cursor+=size
    return {'processor':'toy8','entry':hex(base),'endianness':'little','addressBits':16,'registers':['r0','pc','zf'],'instructions':instructions}
