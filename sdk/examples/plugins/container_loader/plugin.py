"""URA0 custom container: magic4, base u64 LE, entry offset u32 LE, x64 code."""
def load(context):
    data=bytes.fromhex(context['arguments']['bytesHex'])
    if len(data)<17 or data[:4]!=b'URA0':raise ValueError('Expected URA0 container with code')
    base=int.from_bytes(data[4:12],'little');entry=int.from_bytes(data[12:16],'little')
    if entry>=len(data)-16:raise ValueError('Container entry outside code')
    return {'processor':'x86-64','entry':hex(base+entry),'segments':[{'address':hex(base),'fileOffset':16,'size':len(data)-16,'permissions':'rx'}]}
