#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# DID -> current key for a sigelo peer, for an A2A delegation hook (Tenuo's pinned public_key_b64).
# SPEC §9 runs in the sigelo-verify binary ($SIGELO_VERIFY, default on PATH); the rest is stdlib.
# card_lookup's signature check needs `cryptography`.
#   python3 sigelo_lookup.py bundle.json | --card card.json [--now N]
import base64, hashlib, json, os, subprocess, sys, time

URI = 'https://github.com/csigelo/sigelo/tree/main/integrations/a2a'  # as verify.mjs
LISTS = ('rotations', 'bindings', 'attestations', 'issuers')
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


class LookupRefused(Exception):
    def __init__(self, check, message):
        super().__init__(f'{check}: {message}')
        self.check, self.message = check, message


def jcs(o, depth=0):
    """RFC 8785 bytes, as SPEC §3 asks: UTF-16 key order, integers only (±2^53-1)."""
    return _jcs(o, depth).encode('utf-8')


def _jcs(o, depth):
    if depth > 512: raise ValueError('nested deeper than 512')
    if o is None or isinstance(o, bool): return {None: 'null', True: 'true', False: 'false'}[o]
    if isinstance(o, int):
        if abs(o) > 2 ** 53 - 1: raise ValueError('integer out of range')
        return str(o)
    if isinstance(o, str): return json.dumps(o, ensure_ascii=False)
    if isinstance(o, list): return '[' + ','.join(_jcs(x, depth + 1) for x in o) + ']'
    if isinstance(o, dict):
        ks = sorted(o, key=lambda k: k.encode('utf-16-be'))
        return '{' + ','.join(json.dumps(k, ensure_ascii=False) + ':' + _jcs(o[k], depth + 1) for k in ks) + '}'
    raise ValueError(f'not signable: {type(o).__name__}')  # floats included (SPEC §3)


def b58(b):
    n, out = int.from_bytes(b, 'big'), ''
    while n: n, r = divmod(n, 58); out = B58[r] + out
    return '1' * (len(b) - len(b.lstrip(b'\0'))) + out


def unb58(s):  # "z" + base58btc -> bytes
    if not isinstance(s, str) or s[:1] != 'z' or len(s) > 200 or s[1:].strip(B58): raise ValueError('not z + base58btc')
    n = 0
    for ch in s[1:]: n = n * 58 + B58.index(ch)
    return b'\0' * (len(s) - 1 - len(s[1:].lstrip('1'))) + n.to_bytes((n.bit_length() + 7) // 8, 'big')


def did_of(genesis):  # SPEC §4: a DID is the digest of its genesis, not a key
    return 'did:sigelo:z' + b58(hashlib.sha256(jcs(genesis)).digest())


def verify(bundle, now):
    """SPEC §9 by the sigelo-verify binary -> the §9.1 result, or LookupRefused('bundle', <its REJECT>)."""
    exe = os.environ.get('SIGELO_VERIFY', 'sigelo-verify')
    try:
        text = json.dumps(bundle, ensure_ascii=False, separators=(',', ':')).encode()
        p = subprocess.run([exe, '-', '--now', str(int(now))], input=text, capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired, TypeError, ValueError) as e:
        raise LookupRefused('verifier', f'cannot run {exe}: {e}') from e
    if p.returncode == 1: raise LookupRefused('bundle', p.stderr.decode().strip().removeprefix('REJECT: ') or 'REJECT')
    if p.returncode != 0: raise LookupRefused('verifier', p.stderr.decode().strip() or f'{exe} exited {p.returncode}')
    return json.loads(p.stdout)


def lookup(bundle, now=None):
    """{did, key, key_b64, chain, recovery} of the bundle's current identity, or LookupRefused."""
    if not isinstance(bundle, dict) or bundle.get('typ') != 'bundle': raise LookupRefused('shape', 'not a sigelo bundle')
    r = verify(bundle, int(time.time()) if now is None else now)
    nodes = [bundle['genesis']] + [x['next_genesis'] for x in bundle['rotations']]
    key = next((g['key'] for g in nodes if did_of(g) == r['did']), None)  # from the bundle, never a claimed field
    try: raw = unb58(key)
    except ValueError: raw = b''
    if len(raw) != 34 or raw[:2] != b'\xed\x01': raise LookupRefused('key', f'no Ed25519 key for {r["did"]}')
    return {'did': r['did'], 'key': key, 'key_b64': base64.b64encode(raw[2:]).decode(), 'chain': r['chain'], 'recovery': r['recovery']}


def merge(pinned, served):
    """The pinned bundle plus what `served` adds; exact duplicates (same JCS) dropped, nothing pinned dropped.
    Run lookup() on the result: a fork in the union refuses there (SPEC §7.3)."""
    for b in (pinned, served):
        if not isinstance(b, dict) or b.get('typ') != 'bundle' or not all(isinstance(b.get(k), list) for k in LISTS):
            raise LookupRefused('shape', 'not a sigelo bundle')
    try: same = did_of(pinned['genesis']) == did_of(served['genesis'])
    except (ValueError, TypeError): same = False
    if not same: raise LookupRefused('genesis', 'the served bundle names another identity (its first DID differs)')
    out = dict(pinned)
    for k in LISTS:
        items, seen = list(pinned[k]), set()
        for x in items:
            try: seen.add(jcs(x))
            except ValueError: pass
        for x in served[k]:
            try: c = jcs(x)
            except ValueError: c = None  # not canonical: kept, and the verifier judges it
            if c is None or c not in seen: items.append(x); seen.add(c)
        out[k] = items
    return out


def card_body(card, ext):
    """What the identity key signs (verify.mjs cardBody): the card minus `signatures` and this `params.sig`."""
    params = {k: v for k, v in ext['params'].items() if k != 'sig'}
    exts = [dict(e, params=params) if e is ext else e for e in card['capabilities']['extensions']]
    unsigned = dict({k: v for k, v in card.items() if k != 'signatures'}, capabilities=dict(card['capabilities'], extensions=exts))
    return {'v': 'sigelo/0', 'typ': 'a2a-card', 'did': params.get('did'), 'card': 'sha256:' + hashlib.sha256(jcs(unsigned)).hexdigest()}


def card_lookup(card, now=None):
    """lookup() of the bundle in a sigelo-signed A2A card, after the card signature checks under the current key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    caps = card.get('capabilities') if isinstance(card, dict) else None
    exts = [e for e in (caps or {}).get('extensions') or [] if isinstance(e, dict) and e.get('uri') == URI]
    if len(exts) != 1 or not isinstance(exts[0].get('params'), dict): raise LookupRefused('extension', 'not exactly one sigelo extension')
    p = exts[0]['params']
    r = lookup(p.get('bundle'), now)
    if p.get('did') != r['did']: raise LookupRefused('did', "params.did is not the bundle's current DID")
    try: Ed25519PublicKey.from_public_bytes(base64.b64decode(r['key_b64'])).verify(unb58(p.get('sig')), b'sigelo\n' + jcs(card_body(card, exts[0])))
    except Exception as e: raise LookupRefused('sig', 'the card signature does not verify under the current key') from e
    return r


def _load(path):
    def strict(pairs):
        if len({k for k, _ in pairs}) != len(pairs): raise ValueError('duplicate key')
        return dict(pairs)
    with open(path, encoding='utf-8') as f: return json.load(f, object_pairs_hook=strict)


if __name__ == '__main__':
    a = sys.argv[1:]
    now = int(a[a.index('--now') + 1]) if '--now' in a else None
    try:
        out = card_lookup(_load(a[a.index('--card') + 1]), now) if '--card' in a else lookup(_load(a[0]), now)
    except LookupRefused as e: sys.exit(f'REFUSED {e}')
    except (IndexError, ValueError, OSError) as e: sys.exit(f'usage: sigelo_lookup.py bundle.json | --card card.json [--now N] ({e})')
    print(json.dumps(out, indent=2))
