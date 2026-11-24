#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# End to end against a Hermes checkout that has ctx.register_a2a_peer_authenticator: this plugin is
# installed as a USER plugin into a temp HERMES_HOME, loaded by Hermes' own plugin discovery, and the
# real A2A adapter serves HTTP on loopback (the agent's reply is an echo stub: no model). A real sigelo
# identity logs in: GET challenge -> sign -> POST /peer-auth -> message/send with the minted Bearer.
#   HERMES_SRC=~/.cache/sigelo-scratch/hermes-upstream python3 apps/integrations/hermes/peer-auth/e2e.py
# Prints every assertion it ran; exit 0 = all passed (or SKIP with the reason).
import asyncio, json, os, shutil, socket, sys, tempfile, urllib.error, urllib.request
sys.dont_write_bytecode = True  # no __pycache__ in the checkout
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import sigelo_fixture as fx

SRC = os.path.expanduser(os.environ.get('HERMES_SRC', '~/.cache/sigelo-scratch/hermes-upstream'))
hook = os.path.join(SRC, 'hermes_cli', 'plugins_context.py')
if not os.path.exists(hook) or 'register_a2a_peer_authenticator' not in open(hook).read():
    print(f'SKIP e2e: {SRC} has no ctx.register_a2a_peer_authenticator (set HERMES_SRC)'); sys.exit(0)
if (why := fx.missing()): print('SKIP e2e:', why); sys.exit(0)
ran, fails = [], 0
def ok(cond, what, extra=''):
    global fails; fails += not cond; ran.append(what)
    print(('ok   ' if cond else 'FAIL ') + what + ('' if cond else f'  {extra}'[:400]), flush=True)

ids = fx.make(); A, B = ids['A'], ids['B']
home = tempfile.mkdtemp(prefix='sigelo-e2e-hermes-')
dest = os.path.join(home, 'plugins', 'sigelo-peer-auth'); os.makedirs(dest)
for f in ('plugin.yaml', '__init__.py', 'sigelo_accept.py'): shutil.copy(os.path.join(HERE, f), dest)  # what an operator installs
open(os.path.join(home, 'config.yaml'), 'w').write('plugins:\n  enabled: [sigelo-peer-auth]\n')
s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
for k in [k for k in os.environ if k.startswith(('A2A_', 'SIGELO_PEER_', 'SIGELO_REQUIRED_'))]: del os.environ[k]
os.environ.update(HERMES_HOME=home, SIGELO_VERIFY=fx.verifier(), A2A_PORT=str(port), SIGELO_PEER_CTX=f'127.0.0.1:{port}',
                  A2A_PEER_TOKENS='alice:tok-a', A2A_TRUSTED_PEERS=f"{A['did']},alice")  # B is NOT trusted
sys.path.insert(0, SRC); os.chdir(SRC)

from hermes_cli.plugins import discover_plugins
from plugins.platforms.a2a import protocol, security
from plugins.platforms.a2a.adapter import A2AAdapter
from gateway.config import PlatformConfig
discover_plugins(force=True)
names = [p.name for p in security.peer_authenticators.merged().values()]
ok(names == ['sigelo'], 'Hermes plugin discovery loaded the user plugin and registered provider "sigelo"', names)
adapter = A2AAdapter(PlatformConfig(enabled=True, extra={'port': port, 'agents': {'helper': {'profile': 'default'}}}))
ok([p.name for p in adapter._security_context.peer_authenticators] == ['sigelo'], 'adapter captured the provider at startup')
async def echo(event): await adapter.send(event.source.chat_id, 'ECHO: ' + event.text, metadata={'notify': True})
adapter.handle_message, adapter._message_handler = echo, object()  # the agent: an echo stub, no model
base = f'http://127.0.0.1:{port}'

def http(method, path, body=None, token=None):
    hdr = {'Content-Type': 'application/json', **({'Authorization': 'Bearer ' + token} if token else {})}
    req = urllib.request.Request(base + path, None if body is None else json.dumps(body).encode(), hdr, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r: return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b'{}')

def send(token, path='/'):
    msg = protocol.text_message(protocol.ROLE_USER, 'hello', context_id='')
    return http('POST', path, {'jsonrpc': '2.0', 'id': '1', 'method': 'message/send', 'params': {'message': msg}}, token)

def login(who, path=''):
    code, c = http('GET', f"{path}/peer-auth/challenge?did={who['did']}")
    if code != 200: return code, c, None
    code, r = http('POST', f'{path}/peer-auth', fx.answer(who, c))
    return code, r, c

def exercise():
    code, r, c = login(A)
    ok(code == 200 and c['ctx'] == f'127.0.0.1:{port}/default' and c['did'] == A['did'], 'GET /peer-auth/challenge -> 200, ctx "<host>/default" (root agent)', c)
    ok(code == 200 and r.get('identity') == A['did'] and r.get('token', '').startswith('sgl1_') and r.get('expires_in') == 3600,
       'POST /peer-auth with a real signature + bundle -> 200 {identity: DID, token sgl1_, expires_in 3600}', r)
    tok = r.get('token')
    code, rep = send(tok)
    ok(code == 200 and rep.get('result', {}).get('status', {}).get('state') == 'TASK_STATE_COMPLETED', 'message/send with the minted Bearer -> 200, task completed', (code, rep))
    ok('served_agents' in http('GET', '/', token=tok)[1], 'authenticated GET / with the minted Bearer lists served agents')
    ok(send('tok-a')[0] == 200, 'static A2A_PEER_TOKENS token still works -> 200')
    ok(send('garbage-token')[0] == 401, 'garbage Bearer -> 401')
    ok(send('sgl1_' + 'x' * 43)[0] == 401, 'unknown sgl1_ Bearer -> 401 (no fall-through)')
    ok(send(None)[0] == 401, 'no Authorization -> 401')
    ok(send(tok, '/helper/')[0] == 401, 'minted token on another served agent (/helper) -> 401 (audience)')
    ok(http('POST', '/peer-auth', fx.answer(A, c))[0] == 401, 'replayed challenge answer -> 401 (single use)')
    code, r, c = login(A, '/helper')
    ok(code == 200 and c['ctx'] == f'127.0.0.1:{port}/helper' and send(r['token'], '/helper/')[0] == 200, 'login on /helper -> ctx "<host>/helper", its token works there -> 200', (code, r))
    code, r, _ = login(B)
    ok(code == 200 and r.get('identity') == B['did'], 'untrusted DID still logs in (authentication != authorization)', r)
    code, rep = send(r.get('token'))
    ok(code == 403, 'DID not in a2a.trusted_peers -> 403', (code, rep))
    ok(http('GET', '/peer-auth/challenge?did=did:web:x')[0] == 400, 'malformed DID on the challenge route -> 400 (the plugin\'s ValueError)')
    ok(http('POST', '/peer-auth', {'challenge': 'n'})[0] == 400, 'accept body without a bundle -> 400')

async def run():
    if not await adapter.connect(): ok(False, 'adapter.connect()'); return
    try: await asyncio.to_thread(exercise)
    finally: await adapter.disconnect()
asyncio.run(run())
shutil.rmtree(home, ignore_errors=True)
print(f'{len(ran)} assertions ran; ' + ('ALL PASS' if not fails else f'{fails} FAILURE(S)')); sys.exit(1 if fails else 0)
