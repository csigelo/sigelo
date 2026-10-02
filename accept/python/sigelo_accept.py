# SPDX-License-Identifier: MIT
# Accept a sigelo identity (SPEC §5.2 + §9) in any Python web stack. One dependency: cryptography.
# The bundle is checked by the sigelo-verify binary ($SIGELO_VERIFY, default on PATH) or, opt-in and
# zero-install, by a remote verifier: SIGELO_VERIFY=https://sigelo.io/world/verify. The challenge
# signature is always checked here (sigelo-verify has no signature subcommand).
import hashlib, json, os, secrets, subprocess, time, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TTL, PENDING = 300, {}  # nonce -> (challenge, expiry). In memory, one process: replace with your session store.
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
jcs = lambda o: json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()  # RFC 8785 for these ASCII bodies

def unmb(s, max_len=100):  # z + base58btc -> bytes (SPEC §2)
    if not isinstance(s, str) or s[:1] != 'z' or len(s) > max_len or s[1:].strip(B58): raise ValueError('not z + base58btc')
    n = sum(B58.index(ch) * 58 ** i for i, ch in enumerate(reversed(s[1:])))
    return b'\0' * (len(s) - 1 - len(s[1:].lstrip('1'))) + n.to_bytes((n.bit_length() + 7) // 8, 'big')

def did_of(genesis):  # "did:sigelo:" + multibase(SHA-256(JCS(genesis))) (SPEC §4)
    h = hashlib.sha256(jcs(genesis)).digest(); n, out = int.from_bytes(h, 'big'), ''
    while n: n, r = divmod(n, 58); out = B58[r] + out
    return 'did:sigelo:z' + '1' * (len(h) - len(h.lstrip(b'\0'))) + out

def challenge(did, ctx):
    if not isinstance(did, str) or not did.startswith('did:sigelo:z'): raise ValueError('did: want did:sigelo:z... in full')
    for n in [n for n, (_, exp) in PENDING.items() if exp <= time.time()]: del PENDING[n]
    c = {'v': 'sigelo/0', 'typ': 'challenge', 'did': did, 'ctx': ctx, 'nonce': secrets.token_urlsafe(16)}
    PENDING[c['nonce']] = (c, time.time() + TTL)
    return c

def verify_bundle(bundle, now):  # SPEC §9 -> the §9.1 result, or raises
    if (v := os.environ.get('SIGELO_VERIFY', 'sigelo-verify')).startswith('https://'):
        return json.load(urllib.request.urlopen(urllib.request.Request(v, json.dumps({'bundle': bundle, 'now': now}).encode(), {'content-type': 'application/json'}), timeout=10))
    p = subprocess.run([v, '-', '--now', str(now)], input=jcs(bundle), capture_output=True, timeout=10)
    if p.returncode != 0: raise ValueError(p.stderr.decode().strip() or 'REJECT')
    return json.loads(p.stdout)

def accept(chal, answer, bundle, now=None):
    """chal: the issued challenge (or its nonce); answer: {did, sig}; bundle: the agent's §8 bundle or current genesis."""
    c, exp = PENDING.pop(chal if isinstance(chal, str) else (chal or {}).get('nonce'), (None, 0))  # single use, whatever happens next
    if c is None or exp <= time.time(): raise ValueError('challenge unknown, expired or already answered')
    if isinstance(chal, dict) and jcs(chal) != jcs(c): raise ValueError('challenge differs from the one issued')
    if (answer or {}).get('did') != c['did']: raise ValueError('did is not the DID this challenge was issued to')
    if bundle.get('typ') == 'bundle':
        result = verify_bundle(bundle, int(now or time.time()))
        key = next(g['key'] for g in [bundle['genesis']] + [r['next_genesis'] for r in bundle['rotations']] if did_of(g) == result['did'])
    elif bundle.get('typ') == 'genesis' and sorted(bundle) == ['created', 'key', 'nonce', 'recovery', 'typ', 'v']: result, key = {'did': did_of(bundle)}, bundle['key']
    else: raise ValueError('want the agent bundle (typ bundle) or its current genesis')
    if result['did'] != c['did']: raise ValueError(f"the bundle's current DID is {result['did']}, not {c['did']}")
    pub = unmb(key, 64)  # multicodec 0xed01 + 32 key bytes
    try: Ed25519PublicKey.from_public_bytes(pub[2:] if pub[:2] == b'\xed\x01' else b'').verify(unmb(answer.get('sig')), b'sigelo\n' + jcs(c))
    except Exception: raise ValueError('sig does not verify under the current key')
    return result  # accepted: result['did'] is who they are
