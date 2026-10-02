#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""ROADMAP T12: sigelo's primitives against third-party code and test suites.

sigelo (ts/ and go/) is the thing under test; every expected answer comes from code or
vectors sigelo's authors did not write:

  JCS      cyberphone/json-canonicalization (the RFC 8785 author's reference): its testdata
           pairs, and its Python, Go and Node canonicalizers / ES6 number formatters as three
           independent oracles on random documents and numbers.
  Monero   monero-python (PyPI `monero`): base58, address parsing, 25-word seeds, wallet keys,
           subaddresses (its point arithmetic is libsodium via PyNaCl). Tie-breaks on curve
           points use the Python code published in RFC 8032 §6, exec'd from the RFC text.
  Ed25519  RFC 8032 §7.1 vectors (parsed from the RFC text), Wycheproof ed25519_test.json,
           ed25519-speccheck cases.json; end to end, libsodium (PyNaCl) signing
           "sigelo\\n" || JCS(body) with JCS from the Python reference; `base58` (PyPI) for
           sigelo's base58btc multibase.

Run through run.sh (it builds the drivers and the venv). Writes results/latest/*.json (git-ignored;
the committed results/*.json are a recorded run, copied there by hand); exit status 0 iff there is
no unexplained divergence.
"""
import json
import os
import random
import re
import subprocess
import sys
import time
from binascii import hexlify, unhexlify

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, '.work')
RES = os.path.join(HERE, 'results', 'latest')
sys.path.insert(0, os.path.join(WORK, 'jcs-ref', 'python3', 'src'))

from org.webpki.json.Canonicalize import canonicalize as ref_py_canon  # noqa: E402
from org.webpki.json.NumberToJson import convert2Es6Format as ref_py_num  # noqa: E402
import monero  # noqa: E402
import monero.address  # noqa: E402
import monero.base58  # noqa: E402
import monero.seed  # noqa: E402
from monero.backends.offline import OfflineWallet  # noqa: E402
from monero.keccak import keccak_256  # noqa: E402
from monero.wallet import Wallet  # noqa: E402
from monero.wordlists import get_wordlist  # noqa: E402
import nacl.bindings  # noqa: E402
import nacl.signing  # noqa: E402
import base58 as b58btc  # noqa: E402

SEED = int(os.environ.get('CROSSCHECK_SEED', '20260929'))
SCALE = float(os.environ.get('CROSSCHECK_SCALE', '1'))  # 0.1 for a quick run
R = random.Random(SEED)
SELF_TEST = os.environ.get('CROSSCHECK_SELF_TEST') == '1'
L = 2**252 + 27742317777372353535851937790883648493


def n(x):
    return max(1, int(x * SCALE))


# ------------------------------------------------------------------ drivers

DRIVERS = {
    'ts': ['node', os.path.join(HERE, 'driver-ts.mjs')],
    'go': [os.path.join(WORK, 'sigelo-go-driver')],
    'ref-go': [os.path.join(WORK, 'ref-go-driver')],
    'ref-node': ['node', os.path.join(HERE, 'ref-node.cjs')],
}


def batch(name, reqs):
    """Send every request to one driver process; answers come back in order."""
    if not reqs:
        return []
    data = '\n'.join(json.dumps(r, ensure_ascii=True) for r in reqs) + '\n'
    p = subprocess.run(DRIVERS[name], input=data.encode(), stdout=subprocess.PIPE, check=True)
    out = [json.loads(line) for line in p.stdout.decode().splitlines()]
    if len(out) != len(reqs):
        raise SystemExit(f'driver {name}: {len(reqs)} requests, {len(out)} answers')
    if SELF_TEST and name in ('ts', 'go'):
        # harness self-test: damage every 7th sigelo answer; every section must then report
        # divergences, which shows the comparisons can fail
        for a in out[::7]:
            if 'out' in a and isinstance(a.get('out'), str) and a.get('out'):
                a['out'] = a['out'][:-1] + ('0' if a['out'][-1] != '0' else '1')
            else:
                a['ok'] = not a['ok']
                a.setdefault('err', 'self-test')
    return out


def both(reqs):
    return batch('ts', reqs), batch('go', reqs)


RESULTS = {}      # section -> dict of counts
DIVERGENCES = []  # sigelo disagreeing with an oracle with no documented reason
EXPLAINED = []    # disagreements traced to an oracle defect or a documented sigelo restriction
ORACLE_SPLITS = []  # third-party oracles disagreeing with each other


def diverge(section, detail):
    DIVERGENCES.append({'section': section, **detail})


def explained(section, why, detail):
    EXPLAINED.append({'section': section, 'why': why, **detail})


# ------------------------------------------------------------------ 1. JCS

TD = os.path.join(WORK, 'jcs-ref', 'testdata')
NUM_RE = re.compile(r'-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?')


def has_non_integer(text):
    """True if the JSON text has a number literal SPEC §3 forbids (fraction, exponent, > 2^53-1)."""
    # Strings can hold digits; strip them first (the testdata has no \" inside numbers).
    stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)
    for m in NUM_RE.finditer(stripped):
        lit = m.group(0)
        if re.search(r'[.eE]', lit) or abs(int(lit)) > 2**53 - 1:
            return True
    return False


def jcs_testdata():
    rows, sec = [], 'jcs-testdata'
    files = sorted(os.listdir(os.path.join(TD, 'input')))
    cases = []
    for f in files:
        text = open(os.path.join(TD, 'input', f), encoding='utf-8').read()
        exp = open(os.path.join(TD, 'output', f), 'rb').read()
        cases.append((f, text, exp.hex()))
    # Float-free variants of the two files that carry floats, so their string and key parts
    # are byte-compared too. structures.json: 56.0 -> 56 leaves the reference output unchanged.
    # values.json: the numbers array replaced by integers; expected output = the three
    # reference implementations, which must agree.
    s = open(os.path.join(TD, 'input', 'structures.json'), encoding='utf-8').read().replace('56.0', '56')
    cases.append(('structures.json[56.0->56]', s, open(os.path.join(TD, 'output', 'structures.json'), 'rb').read().hex()))
    v = open(os.path.join(TD, 'input', 'values.json'), encoding='utf-8').read()
    v = re.sub(r'"numbers": \[[^\]]*\]', '"numbers": [333333333, -0, 4, 2, 9007199254740991, -9007199254740991]', v)
    refs = [ref_py_canon(json.loads(v)).hex()] + [a.get('out') for a in (batch('ref-go', [{'op': 'jcs', 'text': v}])[0], batch('ref-node', [{'op': 'jcs', 'text': v}])[0])]
    if len(set(refs)) != 1:
        ORACLE_SPLITS.append({'section': sec, 'case': 'values.json[ints]', 'refs': refs})
    cases.append(('values.json[ints]', v, refs[0]))

    reqs = [{'op': 'jcs', 'text': t} for _, t, _ in cases]
    ts, go = both(reqs)
    rgo, rnode = batch('ref-go', reqs), batch('ref-node', reqs)
    counts = {'cases': len(cases), 'byte_equal': 0, 'rejected_by_design': 0, 'fail': 0}
    for (name, text, exp), a, b, c, d in zip(cases, ts, go, rgo, rnode):
        refpy = ref_py_canon(json.loads(text)).hex()
        oracle_ok = [refpy == exp, c.get('out') == exp, d.get('out') == exp]
        row = {'case': name, 'ts': 'match' if a.get('out') == exp else a.get('err', 'MISMATCH'),
               'go': 'match' if b.get('out') == exp else b.get('err', 'MISMATCH'),
               'refs_reproduce_expected': oracle_ok}
        if not all(oracle_ok):
            ORACLE_SPLITS.append({'section': sec, 'case': name, 'refs': oracle_ok})
        if a.get('out') == exp and b.get('out') == exp:
            row['verdict'] = 'byte-equal'
            counts['byte_equal'] += 1
        elif has_non_integer(text) and not a['ok'] and not b['ok'] and 'non-integer' in (a.get('err') or '') and 'non-integer' in (b.get('err') or ''):
            row['verdict'] = 'rejected by design (SPEC §3: no floats)'
            counts['rejected_by_design'] += 1
        else:
            row['verdict'] = 'FAIL'
            counts['fail'] += 1
            diverge(sec, {'case': name, 'ts': a, 'go': b, 'expected_hex': exp})
        rows.append(row)
    RESULTS[sec] = counts
    return rows


# Random documents -------------------------------------------------------------

def is_nonchar(cp):
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


def rand_cp():
    x = R.random()
    if x < 0.40:
        return R.randint(0x20, 0x7E)
    if x < 0.50:
        return R.randint(0, 0x1F)
    if x < 0.55:
        return R.randint(0x7F, 0x9F)
    if x < 0.58:
        return R.choice([0x2028, 0x2029])
    if x < 0.83:
        while True:
            c = R.randint(0xA0, 0xFFFF)
            if not (0xD800 <= c <= 0xDFFF) and not is_nonchar(c):
                return c
    if x < 0.95:
        while True:
            c = R.randint(0x10000, 0x10FFFF)
            if not is_nonchar(c):
                return c
    return R.choice([0xFF5E, 0x1D11E, 0xE000, 0xFFFD, 0xFEFF, 0x10000, 0x10FFFD, 0xD7FF])


def rand_str(maxlen):
    return ''.join(chr(rand_cp()) for _ in range(R.randint(0, maxlen)))


SHORT = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'}


def u_esc(cu):
    h = '%04x' % cu
    return '\\u' + (h.upper() if R.random() < 0.5 else h)


def enc_str(s):
    """A JSON string literal for s with randomly chosen, all-legal escape spellings."""
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch in SHORT and (ch in '"\\' or R.random() < 0.7):
            out.append(SHORT[ch] if R.random() < 0.8 or ch in '"\\' else u_esc(cp))
        elif cp < 0x20:
            out.append(u_esc(cp))
        elif ch == '/' and R.random() < 0.3:
            out.append('\\/')
        elif R.random() < 0.15:
            if cp > 0xFFFF:
                v = cp - 0x10000
                out.append(u_esc(0xD800 + (v >> 10)) + u_esc(0xDC00 + (v & 0x3FF)))
            else:
                out.append(u_esc(cp))
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def rand_int():
    x = R.random()
    if x < 0.3:
        return R.randint(-1000, 1000)
    if x < 0.6:
        return R.choice([1, -1]) * R.randint(0, 10 ** R.randint(1, 15))
    if x < 0.8:
        return R.randint(-(2**53 - 1), 2**53 - 1)
    k = R.randint(0, 52)
    return R.choice([1, -1]) * min(2**53 - 1, max(0, 2**k + R.randint(-2, 2)))


def ws():
    return ''.join(R.choice(' \t\n\r') for _ in range(R.choice([0, 0, 0, 1, 2])))


def rand_value(depth):
    x = R.random()
    if depth < 4 and x < 0.35:
        if R.random() < 0.5:
            return ('arr', [rand_value(depth + 1) for _ in range(R.randint(0, 5))])
        keys, want = [], R.randint(0, 6)  # a list, not a set: set order varies with PYTHONHASHSEED
        while len(keys) < want:
            k = rand_str(6) if R.random() < 0.8 else R.choice(['a', 'b', 'A', '1', '10', '', 'é', '\U0001d11e', '～'])
            if k != '__proto__' and k not in keys:
                keys.append(k)
        return ('obj', [(k, rand_value(depth + 1)) for k in keys])
    if x < 0.55:
        return ('str', rand_str(12))
    if x < 0.85:
        i = rand_int()
        return ('num', '-0' if i == 0 and R.random() < 0.3 else str(i))
    return ('lit', R.choice(['true', 'false', 'null']))


def render(v):
    t, x = v
    if t == 'arr':
        return '[' + ws() + (',' + ws()).join(render(e) + ws() for e in x) + ']'
    if t == 'obj':
        return '{' + ws() + ','.join(ws() + enc_str(k) + ws() + ':' + ws() + render(e) + ws() for k, e in x) + '}'
    if t == 'str':
        return enc_str(x)
    return x


def rand_doc():
    v = rand_value(0) if R.random() < 0.1 else ('obj' if R.random() < 0.7 else 'arr', None)
    if v[1] is None:
        while True:
            v = rand_value(0)
            if v[0] in ('obj', 'arr'):
                break
    return ws() + render(v) + ws()


def jcs_random():
    sec = 'jcs-random'
    docs = [rand_doc() for _ in range(n(20000))]
    reqs = [{'op': 'jcs', 'text': d} for d in docs]
    ts, go = both(reqs)
    rgo, rnode = batch('ref-go', reqs), batch('ref-node', reqs)
    c = {'documents': len(docs), 'oracles_agree': 0, 'ts_equal': 0, 'go_equal': 0, 'oracle_splits': 0, 'divergences': 0}
    for d, a, b, g, nd in zip(docs, ts, go, rgo, rnode):
        py = ref_py_canon(json.loads(d)).hex()
        # the Go reference accepts only an object or array at the top level; for a top-level
        # scalar the Python and Node references decide
        go_ok = g.get('out') == py or (not g['ok'] and g.get('err').startswith("Expected '{'") and not isinstance(json.loads(d), (dict, list)))
        c['top_level_scalar_go_ref_skipped'] = c.get('top_level_scalar_go_ref_skipped', 0) + (g.get('out') != py and go_ok)
        if not (py == nd.get('out') and go_ok):
            c['oracle_splits'] += 1
            ORACLE_SPLITS.append({'section': sec, 'doc': d, 'py': py, 'go': g, 'node': nd})
            continue
        c['oracles_agree'] += 1
        c['ts_equal'] += a.get('out') == py
        c['go_equal'] += b.get('out') == py
        if a.get('out') != py or b.get('out') != py:
            c['divergences'] += 1
            diverge(sec, {'doc': d, 'expected_hex': py, 'ts': a, 'go': b})
    RESULTS[sec] = c


def jcs_restricted():
    """SPEC §3/§3.1 restrictions: documents RFC 8785 canonicalizes but sigelo must refuse."""
    sec = 'jcs-restricted'
    cats = {
        'float': lambda: R.choice(['1.5', '1.0', '1e2', '-0.0', '2E-3', '333333333.33333329', '9007199254740992', '-9007199254740992', '100000000000000000000']),
        'nonchar': lambda: R.choice(['"\\ufdd0"', '"a﷯b"', '"\\uFFFE"', '"￿"', '"\\ud83f\\udffe"', '"\U0010ffff"']),
        'lone-surrogate': lambda: R.choice(['"\\ud800"', '"x\\udc00y"', '"\\ud834"', '"\\udfff\\ud800"']),
        'duplicate-key': lambda: '{"k":1,"k":2}',
        '__proto__': lambda: '{"__proto__":1}',
        'depth-513': lambda: '[' * 513 + ']' * 513,
    }
    per = n(300)
    reqs, meta = [], []
    for cat, gen in cats.items():
        for _ in range(per):
            bad = gen()
            host = {'k': 0, 'a': [1, 2]}
            text = json.dumps(host)
            # put the bad value at a random spot: a member value or an array element
            if R.random() < 0.5:
                text = text[:-1] + ', "x": ' + bad + '}'
            else:
                text = text.replace('[1, 2]', '[1, ' + bad + ', 2]')
            if cat == 'duplicate-key' and R.random() < 0.5:
                text = '{"k":1,"k":2}'
            reqs.append({'op': 'jcs', 'text': text})
            meta.append(cat)
    ts, go = both(reqs)
    c = {k: {'cases': per, 'ts_rejects': 0, 'go_rejects': 0, 'same_stage': 0} for k in cats}
    for cat, r, a, b in zip(meta, reqs, ts, go):
        c[cat]['ts_rejects'] += not a['ok']
        c[cat]['go_rejects'] += not b['ok']
        c[cat]['same_stage'] += a.get('stage') == b.get('stage')
        if a['ok'] or b['ok']:
            diverge(sec, {'category': cat, 'text': r['text'], 'ts': a, 'go': b})
    RESULTS[sec] = c


def f64bits(x):
    import struct
    return struct.pack('>d', x).hex()


def jcs_numbers():
    sec = 'jcs-numbers'
    ints = [rand_int() for _ in range(n(100000))] + [0, 1, -1, 2**53 - 1, -(2**53 - 1), 2**31, 2**32, 10**15]
    # just outside the range: ES6 re-spells 10^16-1 as 10000000000000000 (float64 rounding) —
    # the reason SPEC §3 bounds integers — so sigelo must refuse these, not re-spell them
    over = [2**53, -(2**53), 2**53 + 1, 10**16 - 1, 2**63, 10**21]
    ro = both([{'op': 'jcs', 'text': str(i)} for i in over])
    ci_over = {'out_of_range': len(over), 'ts_rejects': sum(not a['ok'] for a in ro[0]), 'go_rejects': sum(not a['ok'] for a in ro[1])}
    for i, a, b in zip(over, *ro):
        if a['ok'] or b['ok']:
            diverge(sec, {'int': i, 'ts': a, 'go': b})
    reqs = [{'op': 'jcs', 'text': str(i)} for i in ints]
    ts, go = both(reqs)
    nreq = [{'op': 'num', 'bits': f64bits(float(i))} for i in ints]
    rgo, rnode = batch('ref-go', nreq), batch('ref-node', nreq)
    ci = {'integers': len(ints), 'oracles_agree': 0, 'ts_equal': 0, 'go_equal': 0}
    for i, a, b, g, nd in zip(ints, ts, go, rgo, rnode):
        es6 = ref_py_num(float(i))
        if not (es6 == g.get('out') == nd.get('out')):
            ORACLE_SPLITS.append({'section': sec, 'int': i, 'py': es6, 'go': g, 'node': nd})
            continue
        ci['oracles_agree'] += 1
        want = es6.encode().hex()
        ci['ts_equal'] += a.get('out') == want
        ci['go_equal'] += b.get('out') == want
        if a.get('out') != want or b.get('out') != want:
            diverge(sec, {'int': i, 'es6': es6, 'ts': a, 'go': b})
    # Reverse direction: random doubles, spelled by the ES6 reference. sigelo must accept
    # exactly the spellings that are plain integers in ±2^53-1, echo them byte for byte, and
    # reject every other spelling (never re-spell a number).
    import struct
    dbl = []
    while len(dbl) < n(100000):
        x = R.random()
        if x < 0.5:
            d = struct.unpack('>d', R.getrandbits(64).to_bytes(8, 'big'))[0]
        elif x < 0.75:
            d = R.randint(-10**9, 10**9) / 10 ** R.randint(0, 12)
        elif x < 0.9:
            d = float(R.choice([1, -1]) * R.randint(2**53 - 50, 2**60))
        else:
            d = float(R.choice([1, -1]) * R.randint(0, 2**53 - 1))
        if d == d and d not in (float('inf'), float('-inf')):
            dbl.append(d)
    spell = [ref_py_num(d) for d in dbl]
    nreq = [{'op': 'num', 'bits': f64bits(d)} for d in dbl]
    rgo, rnode = batch('ref-go', nreq), batch('ref-node', nreq)
    reqs = [{'op': 'jcs', 'text': s} for s in spell]
    ts, go = both(reqs)
    cd = {'doubles': len(dbl), 'oracles_agree': 0, 'accepted_integers': 0, 'rejected_non_integers': 0, 'divergences': 0}
    for d, s, g, nd, a, b in zip(dbl, spell, rgo, rnode, ts, go):
        if not (s == g.get('out') == nd.get('out')):
            ORACLE_SPLITS.append({'section': sec, 'double': repr(d), 'py': s, 'go': g, 'node': nd})
            continue
        cd['oracles_agree'] += 1
        allowed = re.fullmatch(r'-?\d+', s) is not None and abs(int(s)) <= 2**53 - 1
        want = s.encode().hex()
        if allowed:
            ok = a.get('out') == want and b.get('out') == want
            cd['accepted_integers'] += ok
        else:
            ok = not a['ok'] and not b['ok']
            cd['rejected_non_integers'] += ok
        if not ok:
            cd['divergences'] += 1
            diverge(sec, {'double': repr(d), 'es6': s, 'allowed': allowed, 'ts': a, 'go': b})
    RESULTS[sec] = {'integers': ci, 'out_of_range_integers': ci_over, 'doubles': cd}


# ------------------------------------------------------------------ 2. Monero

def py_b58dec(s):
    try:
        return monero.base58.decode(s)
    except Exception as e:  # noqa: BLE001 — the oracle's own exception types vary
        return e


def mon_base58():
    sec = 'monero-base58'
    datas = []
    for _ in range(n(10000)):
        ln = R.choice([R.randint(0, 100), 69, 77, 64, 8, 16, 1, 7, 9])
        b = bytes(R.getrandbits(8) for _ in range(ln))
        if R.random() < 0.1:
            b = b'\0' * R.randint(1, 9) + b
        if R.random() < 0.05:
            b = b'\xff' * ln
        datas.append(b)
    reqs = [{'op': 'b58enc', 'hex': b.hex()} for b in datas]
    ts, go = both(reqs)
    ce = {'encode': len(datas), 'ts_equal': 0, 'go_equal': 0}
    encoded = []
    for b, a, g in zip(datas, ts, go):
        want = monero.base58.encode(b.hex())
        encoded.append(want)
        ce['ts_equal'] += a.get('out') == want
        ce['go_equal'] += g.get('out') == want
        if a.get('out') != want or g.get('out') != want:
            diverge(sec, {'op': 'encode', 'hex': b.hex(), 'want': want, 'ts': a, 'go': g})
    # decode: the valid encodings, then fuzzed strings
    alph = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    fuzz = list(encoded)
    for _ in range(n(10000)):
        s = R.choice(encoded) or '11'
        x = R.random()
        if x < 0.3:  # substitute a char, sometimes outside the alphabet
            i = R.randrange(len(s))
            s = s[:i] + R.choice(alph + '0OIl+/ ') + s[i + 1:]
        elif x < 0.5:  # truncate / extend to any length, invalid block lengths included
            s = s[:R.randrange(len(s) + 1)] + ''.join(R.choice(alph) for _ in range(R.randint(0, 3)))
        elif x < 0.8:  # blocks of high digits: overflow candidates
            k = R.choice([11, 2, 3, 5, 6, 7, 9, 10])
            s = ''.join(R.choice('stuvwxyz') for _ in range(k)) if R.random() < 0.5 else 'z' * k
            if R.random() < 0.5:
                s = R.choice(encoded)[:11 * R.randint(0, 3)] + s
        else:  # a full block holding exactly 2^64 + small, or 2^(8k) for a partial block
            k = R.choice([8, 1, 2, 3, 4, 5, 6, 7])
            v = 2 ** (8 * k) + R.randint(-1, 2)
            size = [0, 2, 3, 5, 6, 7, 9, 10, 11][k]
            digs = ''
            while v:
                digs = alph[v % 58] + digs
                v //= 58
            s = digs.rjust(size, '1')[-size:] if len(digs) <= size else digs
        fuzz.append(s)
    reqs = [{'op': 'b58dec', 's': s} for s in fuzz]
    ts, go = both(reqs)
    cd = {'decode': len(fuzz), 'oracle_accepts': 0, 'oracle_rejects': 0, 'agree': 0, 'explained': 0, 'divergences': 0}
    for s, a, g in zip(fuzz, ts, go):
        want = py_b58dec(s)
        ok_o = not isinstance(want, Exception)
        cd['oracle_accepts' if ok_o else 'oracle_rejects'] += 1
        same = (a['ok'] == g['ok'] == ok_o) and (not ok_o or a.get('out') == g.get('out') == want)
        if same:
            cd['agree'] += 1
            continue
        why = b58_explain(s, want, a, g)
        if why:
            cd['explained'] += 1
            explained(sec, why, {'s': s, 'oracle': repr(want), 'ts': a, 'go': g})
        else:
            cd['divergences'] += 1
            diverge(sec, {'op': 'decode', 's': s, 'oracle': repr(want), 'ts': a, 'go': g})
    RESULTS[sec] = {'encode': ce, 'decode': cd}


def b58_explain(s, oracle, a, g):
    """A decode disagreement where the oracle is the one that departs from Monero's C++."""
    if a['ok'] or g['ok'] or a.get('err') != g.get('err') or isinstance(oracle, Exception):
        return None
    # monero-python decode_block tests `product > 2**64`; Monero's base58.cpp decode_block
    # fails on any carry out of 64 bits (mul128 hi != 0 or `tmp < res_num`), so a full block
    # worth exactly 2^64 is refused by Monero and read as 8 zero bytes by monero-python.
    alph = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    for i in range(0, len(s), 11):
        blk = s[i:i + 11]
        if len(blk) == 11:
            v = 0
            for ch in blk:
                v = v * 58 + alph.index(ch)
            if v == 2**64 and 'overflows' in (a.get('err') or ''):
                return 'oracle-bug: monero-python accepts a full base58 block equal to 2^64 (checks > 2^64, Monero base58.cpp refuses any 64-bit carry); sigelo refuses it'
    return None


# RFC 8032 §6 reference code, exec'd from the RFC text: the tie-breaker for "is this 32-byte
# string a canonical curve point", which is Monero's check_key (ge_frombytes_vartime).
def load_rfc8032():
    lines = open(os.path.join(WORK, 'rfc8032.txt'), encoding='ascii').read().split('\n')
    start = next(i for i, x in enumerate(lines) if x.startswith('6.  Ed25519 Python Illustration'))
    end = next(i for i, x in enumerate(lines) if x.startswith('7.  Test Vectors'))
    code = [x for x in lines[start:end] if not re.match(r'^(Josefsson|RFC 8032|\f)', x) and x.strip() != '\f']
    body = '\n'.join(code)
    body = body[body.index('import hashlib'):]
    ns = {}
    exec(compile(body, 'rfc8032-section6', 'exec'), ns)  # noqa: S102 — the RFC's published code
    return ns


RFC = None


def rfc_point_ok(b):
    return RFC['point_decompress'](b) is not None


def mon_addresses():
    sec = 'monero-address'
    nets = {'main': 'mainnet', 'stage': 'stagenet', 'test': 'testnet'}
    valid = []  # (address string, net, kind, spend hex, view hex, pid hex)
    wallets = []
    for i in range(n(5000)):
        net = R.choice(list(nets))
        raw = bytes(R.getrandbits(8) for _ in range(32))
        sd = monero.seed.Seed(raw.hex())
        a = sd.public_address(net)
        wallets.append((raw.hex(), net, sd.secret_spend_key(), sd.secret_view_key(), str(a)))
        valid.append((str(a), nets[net], 'standard', a.spend_key(), a.view_key(), ''))
        if i % 2 == 0:
            pid = R.getrandbits(64)
            ia = a.with_payment_id(pid)
            valid.append((str(ia), nets[net], 'integrated', a.spend_key(), a.view_key(), '%016x' % pid))
        if i % 2 == 1:
            major, minor = R.choice([(0, R.randint(1, 50)), (R.randint(1, 5), R.randint(0, 50)), (R.getrandbits(32), R.getrandbits(32))])
            w = Wallet(OfflineWallet(str(a), view_key=sd.secret_view_key()))
            sa = w.get_address(major, minor)
            valid.append((str(sa), nets[net], 'subaddress', sa.spend_key(), sa.view_key(), ''))
            wallets.append(('sub', net, sd.secret_view_key(), a.spend_key(), (major, minor, str(sa))))
    # sigelo derives: wallet (keys + standard address) and subaddress, vs monero-python
    dreq, dmeta = [], []
    for w in wallets:
        if w[0] == 'sub':
            _, net, svk, psk, (major, minor, want) = w
            dreq.append({'op': 'subaddr', 'a': svk, 'B': psk, 'major': major, 'minor': minor, 'net': nets[net]})
            dmeta.append(('subaddress', want, None))
        else:
            raw, net, ssk, svk, want = w
            dreq.append({'op': 'wallet', 'hex': raw, 'net': nets[net]})
            dmeta.append(('wallet', want, (ssk, svk)))
    ts, go = both(dreq)
    cderive = {'wallets_from_seed': 0, 'subaddresses': 0, 'ts_equal': 0, 'go_equal': 0}
    for (kind, want, keys), a, g in zip(dmeta, ts, go):
        cderive['wallets_from_seed' if kind == 'wallet' else 'subaddresses'] += 1
        ok_a = a.get('out') == want and (keys is None or (a.get('b'), a.get('a')) == keys)
        ok_g = g.get('out') == want and (keys is None or (g.get('b'), g.get('a')) == keys)
        cderive['ts_equal'] += ok_a
        cderive['go_equal'] += ok_g
        if not (ok_a and ok_g):
            diverge(sec, {'op': kind, 'want': want, 'keys': keys, 'ts': a, 'go': g})
    # parse the valid addresses
    reqs = [{'op': 'addr', 's': v[0]} for v in valid]
    ts, go = both(reqs)
    cv = {'valid': len(valid), 'standard': 0, 'integrated': 0, 'subaddress': 0, 'ts_equal': 0, 'go_equal': 0}
    for v, a, g in zip(valid, ts, go):
        cv[v[2]] += 1
        want = {'ok': True, 'net': v[1], 'kind': v[2], 'spend': v[3], 'view': v[4], 'pid': v[5]}
        cv['ts_equal'] += a == want
        cv['go_equal'] += g == want
        if a != want or g != want:
            diverge(sec, {'op': 'parse-valid', 'addr': v[0], 'want': want, 'ts': a, 'go': g})
    # invalid / adversarial: correct checksums over bodies the oracle may or may not accept
    known = [18, 19, 42, 24, 25, 36, 53, 54, 63]
    base = [v for v in valid if v[2] != 'integrated']
    adv = []
    for _ in range(n(10000)):
        x = R.random()
        v = R.choice(base)
        spend, view = unhexlify(v[3]), unhexlify(v[4])
        prefix = R.choice(known)
        if x < 0.15:  # one char changed: checksum breaks
            s = v[0]
            i = R.randrange(len(s))
            s = s[:i] + R.choice([c for c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' if c != s[i]]) + s[i + 1:]
            adv.append(('checksum', s))
            continue
        if x < 0.45:  # random 32 bytes as one or both keys
            if R.random() < 0.5:
                spend = bytes(R.getrandbits(8) for _ in range(32))
            else:
                view = bytes(R.getrandbits(8) for _ in range(32))
            cat = 'random-key'
        elif x < 0.6:  # special encodings: identity, small order, y >= p, x = 0 with sign
            sp = R.choice([bytes(32), (1).to_bytes(32, 'little'), ((2**255 - 19) + R.randint(0, 18)).to_bytes(32, 'little'),
                           (1 | 1 << 255).to_bytes(32, 'little'), (2**255 - 20).to_bytes(32, 'little'),
                           unhexlify('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'),
                           unhexlify('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')])
            if R.random() < 0.5:
                spend = sp
            else:
                view = sp
            cat = 'special-point'
        elif x < 0.75:  # unknown prefix
            prefix = R.choice([0, 1, 17, 20, 23, 26, 35, 37, 41, 43, 52, 55, 62, 64, 127])
            cat = 'unknown-prefix'
        elif x < 0.85:  # wrong length body (still 95 chars? not necessarily)
            body = bytes([prefix]) + spend + view + bytes(R.getrandbits(8) for _ in range(R.choice([1, 2, 7, 9])))
            s = monero.base58.encode((body + keccak_256(body).digest()[:4]).hex())
            adv.append(('bad-length', s))
            continue
        else:  # integrated prefix on a standard-length body, or standard prefix on integrated length
            if R.random() < 0.5:
                prefix = R.choice([19, 25, 54])
                body = bytes([prefix]) + spend + view
            else:
                prefix = R.choice([18, 24, 53, 42, 36, 63])
                body = bytes([prefix]) + spend + view + bytes(8)
            s = monero.base58.encode((body + keccak_256(body).digest()[:4]).hex())
            adv.append(('kind-length-mismatch', s))
            continue
        body = bytes([prefix]) + spend + view + (bytes(R.getrandbits(8) for _ in range(8)) if prefix in (19, 25, 54) else b'')
        adv.append((cat, monero.base58.encode((body + keccak_256(body).digest()[:4]).hex())))
    reqs = [{'op': 'addr', 's': s} for _, s in adv]
    ts, go = both(reqs)
    ca = {'adversarial': len(adv), 'agree': 0, 'explained': 0, 'divergences': 0, 'by_category': {}}
    for (cat, s), a, g in zip(adv, ts, go):
        bc = ca['by_category'].setdefault(cat, {'cases': 0, 'agree': 0, 'explained': 0})
        bc['cases'] += 1
        try:
            o = monero.address.address(s)
            oracle = {'ok': True, 'net': {'main': 'mainnet', 'stage': 'stagenet', 'test': 'testnet'}[o.net],
                      'spend': o.spend_key(), 'view': o.view_key()}
        except Exception as e:  # noqa: BLE001
            oracle = {'ok': False, 'err': str(e)}
        if a['ok'] != g['ok'] or (a['ok'] and a != g):
            ca['divergences'] += 1
            diverge(sec, {'op': 'ts-vs-go', 'cat': cat, 'addr': s, 'ts': a, 'go': g})
            continue
        if a['ok'] and not (rfc_point_ok(unhexlify(a.get('spend') or '00' * 32)) and rfc_point_ok(unhexlify(a.get('view') or '00' * 32))):
            ca['divergences'] += 1  # sigelo accepted a key the RFC 8032 decoder refuses
            diverge(sec, {'op': 'accepted-non-point', 'cat': cat, 'addr': s, 'ts': a, 'go': g})
            continue
        if a['ok'] == oracle['ok'] and (not a['ok'] or (a.get('net'), a.get('spend'), a.get('view')) == (oracle['net'], oracle['spend'], oracle['view'])):
            ca['agree'] += 1
            bc['agree'] += 1
            continue
        why = addr_explain(s, oracle, a)
        if why:
            ca['explained'] += 1
            bc['explained'] += 1
            explained(sec, why, {'cat': cat, 'addr': s, 'oracle': oracle, 'sigelo': a})
        else:
            ca['divergences'] += 1
            diverge(sec, {'op': 'parse-adversarial', 'cat': cat, 'addr': s, 'oracle': oracle, 'ts': a, 'go': g})
    RESULTS[sec] = {'derive': cderive, 'parse_valid': cv, 'parse_adversarial': ca}


def addr_explain(s, oracle, sg):
    """Why sigelo and monero-python may legitimately disagree on an address."""
    if not oracle['ok'] or sg['ok']:
        return None
    raw = unhexlify(monero.base58.decode(s))
    spend, view = raw[1:33], raw[33:65]
    bad = [name for name, k in (('spend', spend), ('view', view)) if not rfc_point_ok(k)]
    if bad and 'point' in (sg.get('err') or ''):
        return ('sigelo-stricter (Monero check_key): monero-python does not decode the keys; the %s key is not a '
                'canonical curve point per the RFC 8032 §6 reference decoder, and Monero\'s '
                'get_account_address_from_str runs check_key on both keys' % '+'.join(bad))
    return None


def mon_seeds():
    sec = 'monero-seed'
    wl = get_wordlist('English')
    scal = [R.randrange(1, L).to_bytes(32, 'little') for _ in range(n(3000))]
    anyb = [bytes(R.getrandbits(8) for _ in range(32)) for _ in range(n(1000))]  # non-canonical too
    keys = scal + anyb + [bytes(32), b'\xff' * 32, (L - 1).to_bytes(32, 'little'), L.to_bytes(32, 'little')]
    reqs = [{'op': 'wenc', 'hex': k.hex()} for k in keys]
    ts, go = both(reqs)
    ce = {'keys': len(keys), 'canonical_scalars': len(scal), 'ts_equal': 0, 'go_equal': 0}
    phrases = []
    for k, a, g in zip(keys, ts, go):
        want = monero.seed.Seed(k.hex()).phrase
        phrases.append(want)
        ce['ts_equal'] += a.get('out') == want
        ce['go_equal'] += g.get('out') == want
        if a.get('out') != want or g.get('out') != want:
            diverge(sec, {'op': 'encode', 'hex': k.hex(), 'want': want, 'ts': a, 'go': g})
    # words -> key: the oracle's phrases, random 24-word phrases with the oracle's checksum,
    # and phrases with a wrong 25th word
    tests = [(p, k.hex()) for p, k in zip(phrases, keys)]
    for _ in range(n(3000)):
        ws24 = [R.choice(wl.word_list) for _ in range(24)]
        p = ' '.join(ws24)
        tests.append((p + ' ' + wl.get_checksum(p), None))
    for _ in range(n(1000)):
        p = R.choice(phrases).split(' ')
        p[-1] = R.choice([w for w in wl.word_list if w != p[-1]])
        tests.append((' '.join(p), None))
    reqs = [{'op': 'wdec', 's': p} for p, _ in tests]
    ts, go = both(reqs)
    cd = {'phrases': len(tests), 'agree': 0, 'explained': 0, 'divergences': 0}
    for (p, k), a, g in zip(tests, ts, go):
        try:
            want = monero.seed.Seed(p).hex
            ok_o = True
        except Exception as e:  # noqa: BLE001
            want, ok_o = str(e), False
        if k is not None and ok_o and want != k:
            ORACLE_SPLITS.append({'section': sec, 'phrase': p, 'roundtrip': want, 'key': k})
        if a['ok'] == g['ok'] == ok_o and (not ok_o or a.get('out') == g.get('out') == want):
            cd['agree'] += 1
            continue
        if ok_o and not a['ok'] and not g['ok'] and seed_overflow(p, wl) and 'electrum-words.cpp:326' in (a.get('err') or '') and a.get('err') == g.get('err'):
            cd['explained'] += 1
            explained(sec, 'oracle-bug: monero-python formats a word triple worth >= 2^32 as 9 hex digits and endian_swap '
                           'keeps 8, returning a wrong key silently; Monero electrum-words.cpp:326 refuses the phrase '
                           '((x mod 2^32) mod 1626 != w1 whenever x >= 2^32, as 1626 does not divide 2^32) and so does sigelo',
                      {'phrase': p, 'oracle_hex': want, 'ts': a, 'go': g})
            continue
        cd['divergences'] += 1
        diverge(sec, {'op': 'decode', 'phrase': p, 'oracle': want, 'ts': a, 'go': g})
    RESULTS[sec] = {'encode': ce, 'decode': cd}


def seed_overflow(phrase, wl):
    """True if a triple of the phrase is worth >= 2^32 under monero-python's own formula."""
    w = [wl.word_list.index(x) for x in phrase.split(' ')[:24]]
    N = wl.n
    return any(w[i] + N * ((w[i + 1] - w[i]) % N) + N * N * ((w[i + 2] - w[i + 1]) % N) >= 2**32 for i in range(0, 24, 3))


# ------------------------------------------------------------------ 3. Ed25519

def rfc8032_vectors():
    """The five §7.1 vectors, parsed from the RFC text (fields span page breaks)."""
    t = open(os.path.join(WORK, 'rfc8032.txt'), encoding='ascii').read()
    sec = t[t.rindex('7.1.  Test Vectors for Ed25519'):t.rindex('7.2.  Test Vectors for Ed25519ctx')]
    out, cur, field = [], None, None
    for line in sec.split('\n'):
        x = line.strip().strip('\f')
        if re.match(r'^(Josefsson|RFC 8032)', x) or not x:
            continue
        m = re.match(r'^-----TEST (.+)$', x)
        if m or x == '-----':
            if cur:
                out.append(cur)
            cur, field = ({'name': m.group(1), 'sk': '', 'pk': '', 'msg': '', 'sig': '', 'len': None} if m else None), None
            continue
        if cur is None:
            continue
        m = re.match(r'^(ALGORITHM|SECRET KEY|PUBLIC KEY|MESSAGE|SIGNATURE)(?: \(length (\d+) bytes?\))?:$', x)
        if m:
            field = {'SECRET KEY': 'sk', 'PUBLIC KEY': 'pk', 'MESSAGE': 'msg', 'SIGNATURE': 'sig'}.get(m.group(1))
            if m.group(2):
                cur['len'] = int(m.group(2))
            continue
        if field and re.fullmatch(r'[0-9a-f]+', x):
            cur[field] += x
    for v in out:
        if v['len'] is None or len(v['msg']) != 2 * v['len'] or len(v['sk']) != 64 or len(v['pk']) != 64 or len(v['sig']) != 128:
            raise SystemExit('rfc8032.txt: could not parse TEST ' + v['name'])
    if len(out) != 5:
        raise SystemExit('rfc8032.txt: expected 5 vectors in §7.1, got %d' % len(out))
    return out


def ed25519():
    sec = 'ed25519'
    res = {}
    # RFC 8032 §7.1
    vec = rfc8032_vectors()
    reqs = [{'op': 'edraw', 'pub': v['pk'], 'msg': v['msg'], 'sig': v['sig']} for v in vec]
    ts, go = both(reqs)
    preq = [{'op': 'edpub', 'hex': v['sk']} for v in vec]
    tsp, gop = both(preq)
    c = {'vectors': len(vec), 'names': [v['name'] for v in vec], 'verify_ts': 0, 'verify_go': 0, 'pubkey_ts': 0, 'pubkey_go': 0}
    for v, a, g, pa, pg in zip(vec, ts, go, tsp, gop):
        want_key = 'z' + b58btc.b58encode(b'\xed\x01' + unhexlify(v['pk'])).decode()
        c['verify_ts'] += a['ok'] is True
        c['verify_go'] += g['ok'] is True
        c['pubkey_ts'] += pa.get('out') == want_key
        c['pubkey_go'] += pg.get('out') == want_key
        if not (a['ok'] and g['ok'] and pa.get('out') == want_key == pg.get('out')):
            diverge(sec, {'rfc8032': v['name'], 'ts': a, 'go': g, 'pub_ts': pa, 'pub_go': pg})
    res['rfc8032_7.1'] = c
    # Wycheproof
    wy = json.load(open(os.path.join(WORK, 'wycheproof', 'testvectors_v1', 'ed25519_test.json')))
    cases = [(g['publicKey']['pk'], t) for g in wy['testGroups'] for t in g['tests']]
    reqs = [{'op': 'edraw', 'pub': pk, 'msg': t['msg'], 'sig': t['sig']} for pk, t in cases]
    ts, go = both(reqs)
    c = {'vectors': len(cases), 'valid': 0, 'invalid': 0, 'acceptable': 0, 'ts_match': 0, 'go_match': 0}
    for (pk, t), a, g in zip(cases, ts, go):
        c[t['result']] += 1
        if t['result'] == 'acceptable':
            continue
        want = t['result'] == 'valid'
        c['ts_match'] += a['ok'] == want
        c['go_match'] += g['ok'] == want
        if a['ok'] != want or g['ok'] != want:
            diverge(sec, {'wycheproof': t['tcId'], 'comment': t['comment'], 'flags': t['flags'], 'want': want, 'ts': a, 'go': g})
    res['wycheproof'] = c
    # ed25519-speccheck: 12 edge cases. Expected column = sigelo's documented rule (SPEC §2,
    # go/primitives.go ed25519Strict: canonical A and R, A not small order, S < L, cofactored
    # equation) applied to the case table in the speccheck README; the table is third-party,
    # the policy column is sigelo's own and is stated as such.
    sc = json.load(open(os.path.join(WORK, 'speccheck', 'cases.json')))
    policy = [False, False, True, True, True, True, False, False, False, False, False, False]
    reqs = [{'op': 'edraw', 'pub': x['pub_key'], 'msg': x['message'], 'sig': x['signature']} for x in sc]
    ts, go = both(reqs)
    row = {'cases': len(sc), 'ts': ''.join('V' if a['ok'] else 'X' for a in ts), 'go': ''.join('V' if a['ok'] else 'X' for a in go),
           'policy': ''.join('V' if p else 'X' for p in policy),
           'libsodium_published': 'XXXVXXXXXXXX', 'go_crypto_ed25519_published': 'VVVVXXXXXXXV'}
    for i, (p, a, g) in enumerate(zip(policy, ts, go)):
        if a['ok'] != p or g['ok'] != p:
            diverge(sec, {'speccheck': i, 'policy': p, 'ts': a, 'go': g})
    res['speccheck'] = row
    # End to end through the wrappers: libsodium signs "sigelo\n" || refJCS(body)
    e2e = {'bodies': 0, 'signing_input_ts': 0, 'signing_input_go': 0, 'pubkey_ts': 0, 'pubkey_go': 0,
           'sign_ts_equals_libsodium': 0, 'verify_ts': 0, 'verify_go': 0,
           'malleated_rejected_ts': 0, 'malleated_rejected_go': 0, 'malleated_rejected_libsodium': 0, 'malleated': 0}
    items = []
    for _ in range(n(500)):
        while True:
            text = rand_doc()
            if json.loads(text) is not None and isinstance(json.loads(text), dict):
                break
        seed = bytes(R.getrandbits(8) for _ in range(32))
        sk = nacl.signing.SigningKey(seed)
        msg = b'sigelo\n' + ref_py_canon(json.loads(text))
        sig = sk.sign(msg).signature
        pk = bytes(sk.verify_key)
        items.append((text, seed, msg, sig, pk))
    reqs = []
    for text, seed, msg, sig, pk in items:
        key = 'z' + b58btc.b58encode(b'\xed\x01' + pk).decode()
        mb = 'z' + b58btc.b58encode(sig).decode()
        reqs += [{'op': 'siginput', 'text': text}, {'op': 'edpub', 'hex': seed.hex()},
                 {'op': 'edverify', 'key': key, 'text': text, 'sig': mb}]
    ts, go = both(reqs)
    tsg = batch('ts', [{'op': 'edsign', 'hex': s.hex(), 'text': t} for t, s, _, _, _ in items])
    for i, (text, seed, msg, sig, pk) in enumerate(items):
        key = 'z' + b58btc.b58encode(b'\xed\x01' + pk).decode()
        e2e['bodies'] += 1
        e2e['signing_input_ts'] += ts[3 * i].get('out') == msg.hex()
        e2e['signing_input_go'] += go[3 * i].get('out') == msg.hex()
        e2e['pubkey_ts'] += ts[3 * i + 1].get('out') == key
        e2e['pubkey_go'] += go[3 * i + 1].get('out') == key
        e2e['verify_ts'] += ts[3 * i + 2]['ok'] is True
        e2e['verify_go'] += go[3 * i + 2]['ok'] is True
        e2e['sign_ts_equals_libsodium'] += tsg[i].get('out') == 'z' + b58btc.b58encode(sig).decode()
        if not (ts[3 * i].get('out') == go[3 * i].get('out') == msg.hex() and ts[3 * i + 1].get('out') == go[3 * i + 1].get('out') == key
                and ts[3 * i + 2]['ok'] and go[3 * i + 2]['ok'] and tsg[i].get('out') == 'z' + b58btc.b58encode(sig).decode()):
            diverge(sec, {'e2e': text, 'seed': seed.hex(), 'ts': ts[3 * i:3 * i + 3], 'go': go[3 * i:3 * i + 3], 'sign': tsg[i]})
    # malleations: S + L (non-canonical S), a flipped bit in R, a flipped bit in the message's body
    # value (other body), and the identity key with (R = identity, S = 0)
    mreq, lib = [], []
    for text, seed, msg, sig, pk in items[:n(200)]:
        key = 'z' + b58btc.b58encode(b'\xed\x01' + pk).decode()
        S = int.from_bytes(sig[32:], 'little')
        variants = []
        if S + L < 2**256:
            variants.append((key, text, sig[:32] + (S + L).to_bytes(32, 'little'), pk, msg))
        r = bytearray(sig)
        r[R.randrange(32)] ^= 1 << R.randrange(8)
        variants.append((key, text, bytes(r), pk, msg))
        other = json.dumps({'x': R.randint(0, 2**40), 'orig': 1})
        variants.append((key, other, sig, pk, b'sigelo\n' + ref_py_canon(json.loads(other))))
        ident = (1).to_bytes(32, 'little')
        variants.append(('z' + b58btc.b58encode(b'\xed\x01' + ident).decode(), text, ident + bytes(32), ident, msg))
        for k, t, s, p, m in variants:
            mreq.append({'op': 'edverify', 'key': k, 'text': t, 'sig': 'z' + b58btc.b58encode(s).decode()})
            try:
                nacl.signing.VerifyKey(p).verify(m, s)
                lib.append(True)
            except Exception:  # noqa: BLE001
                lib.append(False)
    ts, go = both(mreq)
    for r_, a, g, l_ in zip(mreq, ts, go, lib):
        e2e['malleated'] += 1
        e2e['malleated_rejected_ts'] += a['ok'] is False
        e2e['malleated_rejected_go'] += g['ok'] is False
        e2e['malleated_rejected_libsodium'] += l_ is False
        if a['ok'] or g['ok']:
            diverge(sec, {'malleation': r_, 'ts': a, 'go': g, 'libsodium_accepts': l_})
    res['end_to_end_libsodium'] = e2e
    RESULTS[sec] = res


def multibase():
    sec = 'base58btc-multibase'
    datas = []
    for _ in range(n(10000)):
        b = bytes(R.getrandbits(8) for _ in range(R.choice([R.randint(0, 80), 34, 64, 32])))
        if R.random() < 0.15:
            b = b'\0' * R.randint(1, 5) + b
        datas.append(b)
    reqs = [{'op': 'mbenc', 'hex': b.hex()} for b in datas]
    ts, go = both(reqs)
    dreq = [{'op': 'mbdec', 's': 'z' + b58btc.b58encode(b).decode(), 'max': 1000} for b in datas]
    god = batch('go', dreq)
    keys = [b'\xed\x01' + bytes(R.getrandbits(8) for _ in range(32)) for _ in range(n(2000))]
    kts = batch('ts', [{'op': 'keydec', 's': 'z' + b58btc.b58encode(k).decode()} for k in keys])
    c = {'encode': len(datas), 'ts_equal': 0, 'go_equal': 0, 'decode_go_equal': 0, 'key_decode_ts': len(keys), 'key_decode_ts_equal': 0}
    for b, a, g, d in zip(datas, ts, go, god):
        want = 'z' + b58btc.b58encode(b).decode()
        c['ts_equal'] += a.get('out') == want
        c['go_equal'] += g.get('out') == want
        c['decode_go_equal'] += d.get('out') == b.hex()
        if not (a.get('out') == g.get('out') == want and d.get('out') == b.hex()):
            diverge(sec, {'hex': b.hex(), 'want': want, 'ts': a, 'go': g, 'go_dec': d})
    for k, a in zip(keys, kts):
        c['key_decode_ts_equal'] += a.get('out') == k[2:].hex()
        if a.get('out') != k[2:].hex():
            diverge(sec, {'key': k.hex(), 'ts': a})
    RESULTS[sec] = c


# ------------------------------------------------------------------ main

def main():
    global RFC
    os.makedirs(RES, exist_ok=True)
    t0 = time.time()
    RFC = load_rfc8032()
    steps = [('jcs testdata', jcs_testdata), ('jcs random', jcs_random), ('jcs restricted', jcs_restricted),
             ('jcs numbers', jcs_numbers), ('monero base58', mon_base58), ('monero addresses', mon_addresses),
             ('monero seeds', mon_seeds), ('ed25519', ed25519), ('base58btc multibase', multibase)]
    rows, per_step = None, []
    for name, f in steps:
        t = time.time()
        out = f()
        if name == 'jcs testdata':
            rows = out
        print(f'  {name}: {time.time() - t:.0f}s, divergences so far {len(DIVERGENCES)}', flush=True)
        if SELF_TEST:
            per_step.append((name, len(DIVERGENCES)))
    if SELF_TEST:
        prev, dead = 0, []
        for name, k in per_step:
            if k == prev:
                dead.append(name)
            prev = k
        print('SELF-TEST:', 'every section caught the damage' if not dead else 'NO divergence caught in: ' + ', '.join(dead))
        return 1 if dead else 0
    summary = {
        'date': time.strftime('%Y-%m-%d'), 'seed': SEED, 'scale': SCALE, 'seconds': round(time.time() - t0),
        'oracles': versions(), 'results': RESULTS, 'jcs_testdata_rows': rows,
        'divergences': len(DIVERGENCES), 'explained': len(EXPLAINED), 'oracle_splits': len(ORACLE_SPLITS),
    }
    json.dump(summary, open(os.path.join(RES, 'summary.json'), 'w'), indent=1, ensure_ascii=False)
    json.dump(DIVERGENCES, open(os.path.join(RES, 'divergences.json'), 'w'), indent=1, ensure_ascii=False)
    # explained: keep every distinct reason with a count and three examples, not thousands of rows
    by = {}
    for e in EXPLAINED:
        b = by.setdefault((e['section'], e['why']), {'section': e['section'], 'why': e['why'], 'count': 0, 'examples': []})
        b['count'] += 1
        if len(b['examples']) < 3:
            b['examples'].append(e)
    json.dump(list(by.values()), open(os.path.join(RES, 'explained.json'), 'w'), indent=1, ensure_ascii=False)
    json.dump(ORACLE_SPLITS[:200], open(os.path.join(RES, 'oracle-splits.json'), 'w'), indent=1, ensure_ascii=False)
    print(json.dumps({'divergences': len(DIVERGENCES), 'explained': {f'{k[0]}: {k[1][:60]}': v['count'] for k, v in by.items()},
                      'oracle_splits': len(ORACLE_SPLITS)}, indent=1, ensure_ascii=False))
    return 1 if DIVERGENCES else 0


def versions():
    def git(d):
        try:
            return subprocess.run(['git', '-C', os.path.join(WORK, d), 'rev-parse', 'HEAD'], stdout=subprocess.PIPE, check=True).stdout.decode().strip()
        except Exception:  # noqa: BLE001
            return None
    import importlib.metadata as md
    return {
        'sigelo_under_test': subprocess.run(['git', '-C', os.path.dirname(HERE), 'rev-parse', 'HEAD'], stdout=subprocess.PIPE).stdout.decode().strip(),
        'json-canonicalization': git('jcs-ref'), 'wycheproof': git('wycheproof'), 'ed25519-speccheck': git('speccheck'),
        'monero-python': md.version('monero'), 'PyNaCl': md.version('PyNaCl'), 'base58': md.version('base58'),
        'libsodium': nacl.bindings.sodium_version_string() if hasattr(nacl.bindings, 'sodium_version_string') else 'bundled with PyNaCl',
        'rfc8032.txt_bytes': os.path.getsize(os.path.join(WORK, 'rfc8032.txt')),
        'python': sys.version.split()[0], 'node': subprocess.run(['node', '--version'], stdout=subprocess.PIPE).stdout.decode().strip(),
        'go': subprocess.run(['go', 'version'], stdout=subprocess.PIPE).stdout.decode().strip(),
    }


if __name__ == '__main__':
    sys.exit(main())
