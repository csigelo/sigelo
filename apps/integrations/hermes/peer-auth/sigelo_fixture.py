# SPDX-License-Identifier: MIT
# Test helper (not loaded by Hermes): real sigelo identities, bundles and challenge signatures from the
# TS reference library (ts/dist/sigelo.js, or $SIGELO_TS), and a local sigelo-verify ($SIGELO_VERIFY, else
# PATH, else `go build` from go/). Used by test_peer_auth.py and e2e.py.
import json, os, shutil, subprocess, tempfile
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), *['..'] * 4))
TS = os.environ.get('SIGELO_TS') or os.path.join(REPO, 'ts', 'dist', 'sigelo.js')
JS = '''import { keygen, attest, sign } from %s;
const [cmd, arg] = process.argv.slice(1), hex = (b) => Buffer.from(b).toString('hex');
const now = Math.floor(Date.now() / 1000), out = {};
if (cmd === 'make') {
  const W = keygen({ recovery: null }); out.world = { did: W.did, genesis: W.genesis };
  for (const name of ['A', 'B']) {
    const k = keygen({ recovery: null });
    const atts = name === 'A' ? [attest({ secret: W.secret, iss: W.did, sub: k.did, iat: now - 60, exp: now + 86400,
      ctx: 'peer-auth.test', admission: 'open', claims: { tasks: 1 } })] : [];
    out[name] = { did: k.did, genesis: k.genesis, secret: hex(k.secret), bundle: { v: 'sigelo/0', typ: 'bundle',
      genesis: k.genesis, rotations: [], bindings: [], attestations: atts, issuers: atts.length ? [W.genesis] : [] } };
  }
} else { const a = JSON.parse(arg); out.sig = sign(Uint8Array.from(Buffer.from(a.secret, 'hex')), a.challenge); }
console.log(JSON.stringify(out));'''

def missing():  # why the fixture cannot run here, or None
    if not shutil.which('node'): return 'node not found'
    if not os.path.exists(TS): return f'{TS} missing (cd ts && npm ci && npx tsc, or set SIGELO_TS)'
    return None if verifier() else 'no sigelo-verify (set SIGELO_VERIFY, or install go)'

def node(*args):
    p = subprocess.run(['node', '--input-type=module', '-e', JS % json.dumps('file://' + TS), *args],
                       capture_output=True, text=True, timeout=60)
    if p.returncode: raise RuntimeError(p.stderr)
    return json.loads(p.stdout)

def make(): return node('make')  # {world, A (attested by world), B (no attestation)}
def sign(who, challenge): return node('sign', json.dumps({'secret': who['secret'], 'challenge': challenge}))['sig']
def answer(who, challenge, bundle=None):  # the POST /peer-auth body
    return {'challenge': challenge, 'did': who['did'], 'sig': sign(who, challenge), 'bundle': bundle or who['bundle']}

_built = []
def verifier():  # a LOCAL verifier path: never a URL, so verification needs no network
    v = os.environ.get('SIGELO_VERIFY') or shutil.which('sigelo-verify')
    if v and not v.startswith('https://'): return v
    if _built: return _built[0]
    if not shutil.which('go'): return None
    out = os.path.join(tempfile.mkdtemp(prefix='sigelo-verify-'), 'sigelo-verify')
    subprocess.run(['go', 'build', '-o', out, './cmd/sigelo-verify'], cwd=os.path.join(REPO, 'go'), check=True)
    _built.append(out); return out
