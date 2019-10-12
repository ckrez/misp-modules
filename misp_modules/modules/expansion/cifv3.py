import json
from cifsdk.client.http import HTTP as Client

moduleinfo = {
    'version': '3.1',
    'author': 'Cal Krzywiec',
    'description': 'Collective Intelligence Framework (v3) Expansion Module',
    'module-type': ['hover']
}

moduleconfig = ['remote', 'token', 'verify_ssl', 'nolog', 'limit']

misperrors = {'error': 'Error'}

mispattributes = {
    'input': ['domain', 'hostname', 'ip-src', 'ip-dst', 'url', 'md5', 'sha1', 'sha256'],
    'output': ['text']
}

def handler(q=False):
    if not q:
        return False

    request = json.loads(q)

    # set defaults
    verify_ssl = True
    nolog = False
    limit = 5

    if (request.get('config')):
        if (request['config'].get('token') is None):
            misperrors['error'] = 'CIF token is required'
            return misperrors

        if (request['config'].get('remote') is None):
            misperrors['error'] = 'CIF remote is required'
            return misperrors

        if (request['config'].get('verify_ssl') in ['0','False']):
            verify_ssl = False

        if (request['config'].get('verify_ssl') in ['1','True']):
            verify_ssl = True


        if (request['config'].get('nolog') in ['0','False']):
            nolog = False

        if (request['config'].get('nolog') in ['1','True']):
            nolog = True

        if (request['config'].get('limit') is not None):
            limit = request['config']['limit']


    q = None
    for t in mispattributes['input']:
        q = request.get(t)
        if q:
            break

    if not q:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    cli = Client(token=request['config']['token'], remote=request['config']['remote'], verify_ssl=verify_ssl)

    filter = {'indicator': q, 'limit': limit, 'nolog': nolog}

    try:
        rv = cli.indicators_search(filter)
    except Exception as e:
        misperrors['error'] = "CIF search error: {}".format(e)
        return misperrors

    if len(rv) > 0:
        res = ['provider, confidence, [tags], firsttime, lasttime, description\n']
        for r in rv:
            res.append('{}, {}, [{}], {}, {}, {}\n'.format(r['provider'], r['confidence'], ','.join(r['tags']),
                                                           r['firsttime'], r['lasttime'], r['description']))
        return {'results': [{'types': mispattributes['output'], 'values': res}]}
    else:
        return {'results': [{'types': mispattributes['output'], 'values': 'Not found'}]}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
