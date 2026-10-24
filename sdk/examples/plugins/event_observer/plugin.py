def observe(context):
    event=context['event']
    print('event',event['sequence'],event['kind'],event['generation'])
    return {'sequence':event['sequence'],'kind':event['kind'],'generation':event['generation']}
