#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# DID -> current key for a sigelo peer, for an A2A delegation hook (Tenuo's pinned public_key_b64).
# SPEC §9 runs in the sigelo-verify binary (verifier=, else $SIGELO_VERIFY, else on PATH); the rest is stdlib.
# card_lookup's signature check needs `cryptography`.
#   python3 sigelo_lookup.py bundle.json | --card card.json [--now N]
import base64, hashlib, json, os, subprocess, sys, time

URI = 'https://github.com/csigelo/sigelo/tree/main/integrations/a2a'  # as verify.mjs
LISTS = ('rotations', 'bindings', 'attestations', 'issuers')
MAX_DEPTH = 512  # SPEC §3
MAX_BYTES = 4 << 20  # the most JSON handed to the verifier
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


class LookupRefused(Exception):
    def __init__(self, check, message):
        super().__init__(f'{check}: {message}')
        self.check, self.message = check, message


def jcs(o):
    """RFC 8785 bytes, as SPEC §3 asks: UTF-16 key order, integers only (±2^53-1), 512 levels at most.
    A work list, not recursion (as ts/src/jcs.ts): a deep value is a ValueError, never a RecursionError."""
    out, todo, level = [], [o], 0
    while todo:
        x = todo.pop()
        if isinstance(x, _Lit):
            if x in (']', '}'): level -= 1
            out.append(x)
        elif isinstance(x, (list, dict)):
            level += 1
            if level > MAX_DEPTH: raise ValueError(f'nested deeper than {MAX_DEPTH}')
            if isinstance(x, list):
                out.append('['); todo.append(_Lit(']'))
                for n in range(len(x) - 1, -1, -1):
                    todo.append(x[n])
                    if n: todo.append(_Lit(','))
            else:
                out.append('{'); todo.append(_Lit('}'))
                if not all(isinstance(k, str) for k in x): raise ValueError('object key not a string')
                ks = sorted(x, key=lambda k: k.encode('utf-16-be', 'surrogatepass'))
                for n in range(len(ks) - 1, -1, -1):
                    todo += [x[ks[n]], _Lit((',' if n else '') + json.dumps(ks[n], ensure_ascii=False) + ':')]
        else: out.append(_scalar(x))
    return ''.join(out).encode('utf-8')


class _Lit(str): pass  # output queued between a container's values


def _scalar(o):
    if o is None or isinstance(o, bool): return {None: 'null', True: 'true', False: 'false'}[o]
    if isinstance(o, int):
        if abs(o) > 2 ** 53 - 1: raise ValueError('integer out of range')
        return str(o)
    if isinstance(o, str): return json.dumps(o, ensure_ascii=False)
    raise ValueError(f'not signable: {type(o).__name__}')  # floats included (SPEC §3)


def depth(o):
    """Levels of nesting of arrays and objects, combined (SPEC §3: the outermost is level 1), without recursion."""
    deepest, todo = 0, [(o, 1)]
    while todo:
        x, d = todo.pop()
        if isinstance(x, (list, tuple, dict)):
            deepest = max(deepest, d)
            if deepest > MAX_DEPTH: break
            todo += [(v, d + 1) for v in (x.values() if isinstance(x, dict) else x)]
    return deepest


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


def _did(genesis):
    try: return did_of(genesis)
    except ValueError: return None


def verify(bundle, now, verifier=None):
    """SPEC §9 by the sigelo-verify binary -> the §9.1 result, or LookupRefused('bundle', <its REJECT>).
    The binary: `verifier`, else $SIGELO_VERIFY, else sigelo-verify on PATH."""
    exe = verifier or os.environ.get('SIGELO_VERIFY') or 'sigelo-verify'
    if depth(bundle) > MAX_DEPTH: raise LookupRefused('bundle', f'nested deeper than {MAX_DEPTH} (SPEC §3)')
    try: text = json.dumps(bundle, separators=(',', ':')).encode('ascii')  # \u escapes: a lone surrogate stays one item's fault (SPEC §3.1)
    except (TypeError, ValueError, RecursionError) as e: raise LookupRefused('shape', f'not JSON: {e}') from e
    if len(text) > MAX_BYTES: raise LookupRefused('size', f'bundle is {len(text)} bytes, over {MAX_BYTES}')
    try: p = subprocess.run([exe, '-', '--now', str(int(now))], input=text, capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired, TypeError, ValueError, OverflowError) as e:
        raise LookupRefused('verifier', f'cannot run {exe}: {e}') from e
    err = p.stderr.decode('utf-8', 'replace').strip()
    if p.returncode == 1: raise LookupRefused('bundle', err.removeprefix('REJECT: ') or 'REJECT')
    if p.returncode != 0: raise LookupRefused('verifier', err or f'{exe} exited {p.returncode}')
    try: r = json.loads(p.stdout)
    except (ValueError, RecursionError) as e: raise LookupRefused('verifier', f'{exe} printed no JSON result') from e
    ok = isinstance(r, dict) and isinstance(r.get('did'), str) and isinstance(r.get('chain'), list) and r['chain'][-1:] == [r['did']] \
        and all(isinstance(d, str) for d in r['chain']) and (r.get('recovery') is None or isinstance(r['recovery'], str))
    if not ok: raise LookupRefused('verifier', f'{exe} printed no SPEC §9.1 result')
    return r


def lookup(bundle, now=None, verifier=None):
    """{did, key, key_b64, chain, recovery} of the bundle's current identity, or LookupRefused."""
    if not isinstance(bundle, dict) or bundle.get('typ') != 'bundle': raise LookupRefused('shape', 'not a sigelo bundle')
    r = verify(bundle, int(time.time()) if now is None else now, verifier)
    nodes = [bundle.get('genesis')] + [x.get('next_genesis') for x in bundle.get('rotations') or [] if isinstance(x, dict)]
    key = next((g.get('key') for g in nodes if isinstance(g, dict) and _did(g) == r['did']), None)  # from the bundle, never a claimed field
    try: raw = unb58(key)
    except ValueError: raw = b''
    if len(raw) != 34 or raw[:2] != b'\xed\x01': raise LookupRefused('key', f'no Ed25519 key for {r["did"]}')
    return {'did': r['did'], 'key': key, 'key_b64': base64.b64encode(raw[2:]).decode(), 'chain': r['chain'], 'recovery': r['recovery']}


def merge(pinned, served):
    """The pinned bundle plus what `served` adds; exact duplicates (same JCS) dropped, nothing pinned dropped.
    Run lookup() on the result: a fork in the union refuses there (SPEC §7.3)."""
    for b in (pinned, served):
        if not isinstance(b, dict) or b.get('typ') != 'bundle' or not isinstance(b.get('genesis'), dict) \
                or not all(isinstance(b.get(k), list) for k in LISTS):
            raise LookupRefused('shape', 'not a sigelo bundle (SPEC §8: a genesis and four lists)')
    try: same = did_of(pinned.get('genesis')) == did_of(served.get('genesis'))
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


def card_lookup(card, now=None, verifier=None):
    """lookup() of the bundle in a sigelo-signed A2A card, after the card signature checks under the current key."""
    try: from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as e: raise LookupRefused('cryptography', 'card_lookup needs the cryptography package') from e
    caps = card.get('capabilities') if isinstance(card, dict) else None
    if not isinstance(caps, dict) or not isinstance(caps.get('extensions'), list):
        raise LookupRefused('extension', 'no capabilities.extensions list')
    exts = [e for e in caps['extensions'] if isinstance(e, dict) and e.get('uri') == URI]
    if len(exts) != 1 or not isinstance(exts[0].get('params'), dict): raise LookupRefused('extension', 'not exactly one sigelo extension')
    p = exts[0]['params']
    r = lookup(p.get('bundle'), now, verifier)
    if p.get('did') != r['did']: raise LookupRefused('did', "params.did is not the bundle's current DID")
    try: Ed25519PublicKey.from_public_bytes(base64.b64decode(r['key_b64'])).verify(unb58(p.get('sig')), b'sigelo\n' + jcs(card_body(card, exts[0])))
    except Exception as e: raise LookupRefused('sig', 'the card signature does not verify under the current key') from e
    return r


def parse(text):
    """JSON text (str, or UTF-8 bytes) -> objects for lookup/card_lookup, or LookupRefused('parse', ...).
    SPEC §3: a duplicate key or `__proto__` anywhere, invalid UTF-8, a BOM, NaN, or nesting past 512
    refuses the whole text; parsed objects cannot show the first two to the verifier."""
    def strict(pairs):
        keys = [k for k, _ in pairs]
        if len(set(keys)) != len(keys): raise ValueError('duplicate key')
        if '__proto__' in keys: raise ValueError('forbidden key "__proto__"')
        return dict(pairs)
    def no_constant(c): raise ValueError(f'{c} is not JSON')
    try:
        if isinstance(text, (bytes, bytearray)): text = bytes(text).decode('utf-8')
        if not isinstance(text, str): raise ValueError('not text')
        if text.startswith('\ufeff'): raise ValueError('byte-order mark')
        o = json.loads(text, object_pairs_hook=strict, parse_constant=no_constant)
    except (ValueError, RecursionError) as e: raise LookupRefused('parse', str(e)) from None
    if depth(o) > MAX_DEPTH: raise LookupRefused('parse', f'nested deeper than {MAX_DEPTH}')
    return o


def _load(path):
    with open(path, 'rb') as f: return parse(f.read())


if __name__ == '__main__':
    a = sys.argv[1:]
    now = int(a[a.index('--now') + 1]) if '--now' in a else None
    try:
        out = card_lookup(_load(a[a.index('--card') + 1]), now) if '--card' in a else lookup(_load(a[0]), now)
    except LookupRefused as e: sys.exit(f'REFUSED {e}')
    except (IndexError, ValueError, OSError) as e: sys.exit(f'usage: sigelo_lookup.py bundle.json | --card card.json [--now N] ({e})')
    print(json.dumps(out, indent=2))
