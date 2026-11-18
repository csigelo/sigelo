# SPDX-License-Identifier: MIT
# python3 -m unittest test_lookup (from this folder). Fixtures: gen.mjs. Needs `cryptography` and a
# sigelo-verify binary: $SIGELO_VERIFY, else one on PATH, else it is built from go/ into a temporary directory.
import base64, copy, json, os, shutil, subprocess, sys, tempfile, unittest
from unittest import mock
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from sigelo_lookup import LookupRefused, b58, card_lookup, jcs, lookup, merge, parse, unb58, verify, URI

FX = json.load(open(os.path.join(HERE, 'fixtures', 'lookup-v0.json'), encoding='utf-8'))
NOW, D, K, B = FX['now'], FX['dids'], FX['keys'], FX['bundles']


def setUpModule():
    if os.environ.get('SIGELO_VERIFY') or shutil.which('sigelo-verify'): return
    global TMP; TMP = tempfile.mkdtemp(prefix='sigelo-lookup-')
    go = os.path.join(HERE, '..', '..', '..', '..', 'go')
    subprocess.run(['go', 'build', '-o', os.path.join(TMP, 'sigelo-verify'), './cmd/sigelo-verify'], cwd=go, check=True)
    os.environ['SIGELO_VERIFY'] = os.path.join(TMP, 'sigelo-verify')


def tearDownModule():
    if 'TMP' in globals(): shutil.rmtree(TMP, ignore_errors=True)


class Lookup(unittest.TestCase):
    def refused(self, check, f, *a):
        with self.assertRaises(LookupRefused) as c: f(*a)
        self.assertEqual(c.exception.check, check, c.exception)
        return c.exception

    def test_genesis_only(self):
        r = lookup(B['genesis'], NOW)
        self.assertEqual((r['did'], r['key'], r['chain']), (D['A0'], K['A0'], [D['A0']]))
        self.assertEqual(len(r['key_b64']), 44)
        raw = base64.b64decode(r['key_b64'], validate=True)
        self.assertEqual((len(raw), raw), (32, unb58(K['A0'])[2:]))
        self.assertTrue(r['recovery'].startswith('sha256:'))

    def test_voluntary_rotation(self):
        r = lookup(B['rotated'], NOW)
        self.assertEqual((r['did'], r['key'], r['chain']), (D['A1'], K['A1'], [D['A0'], D['A1']]))

    def test_recovery_after_the_thief(self):
        r = lookup(B['recovered_at_thief'], NOW)
        self.assertEqual((r['did'], r['key']), (D['A3'], K['A3']))
        self.assertEqual(r['chain'], [D['A0'], D['A1'], D['T'], D['A3']])  # the thief's DID is in the chain, not current

    def test_recovery_beats_the_thief(self):
        r = lookup(B['recovered'], NOW)
        self.assertEqual((r['did'], r['key'], r['chain']), (D['A2'], K['A2'], [D['A0'], D['A1'], D['A2']]))
        self.assertNotEqual(r['recovery'], lookup(B['thief'], NOW)['recovery'])

    def test_merge_same(self):
        m = merge(B['recovered'], copy.deepcopy(B['recovered']))
        self.assertEqual(m, B['recovered'])
        self.assertEqual(lookup(m, NOW), lookup(B['recovered'], NOW))

    def test_merge_rollback_keeps_recovery(self):
        for pinned, cur in (('recovered', 'A2'), ('recovered_at_thief', 'A3')):
            self.assertEqual(lookup(merge(B[pinned], B['thief']), NOW)['did'], D[cur], pinned)

    def test_merge_sees_new_rotation(self):
        self.assertEqual(lookup(merge(B['genesis'], B['rotated']), NOW)['key'], K['A1'])
        self.assertEqual(lookup(merge(B['rotated'], B['thief']), NOW)['did'], D['T'])

    def test_merge_never_drops_pinned(self):
        self.assertEqual(merge(B['thief'], B['rotated'])['rotations'], B['thief']['rotations'])

    def test_fork_refused(self):
        e = self.refused('bundle', lookup, merge(B['thief'], B['fork_other']), NOW)
        self.assertIn('fork', e.message)

    def test_duplicate_dropped(self):
        self.assertIn('fork', self.refused('bundle', lookup, B['duplicate'], NOW).message)  # §7.3: no dedupe in the verifier
        m = merge(B['genesis'], B['duplicate'])
        self.assertEqual(len(m['rotations']), 1)
        self.assertEqual(lookup(m, NOW)['did'], D['A1'])

    def test_hostile_fork_at_an_older_node_refused(self):
        # A0's leaked key rotates again at A0: with the pinned A0 -> A1, a fork (SPEC §7.3); the pin itself still answers
        for pinned, cur in (('rotated', 'A1'), ('recovered', 'A2')):
            with self.subTest(pinned=pinned):
                self.assertIn('fork', self.refused('bundle', lookup, merge(B[pinned], B['fork_at_genesis']), NOW).message)
                self.assertEqual(lookup(B[pinned], NOW)['did'], D[cur])

    def test_served_duplicates_of_pinned_rotations_dropped(self):
        self.assertEqual(merge(B['recovered'], B['thief'])['rotations'], B['recovered']['rotations'])
        self.assertEqual(merge(B['rotated'], B['duplicate'])['rotations'], B['rotated']['rotations'])
        self.assertEqual(lookup(merge(B['rotated'], B['duplicate']), NOW)['did'], D['A1'])

    def test_merge_idempotent(self):
        for p, s in (('genesis', 'rotated'), ('rotated', 'thief'), ('thief', 'recovered'), ('recovered', 'recovered_at_thief')):
            with self.subTest(pinned=p, served=s):
                m = merge(B[p], B[s])
                self.assertEqual(merge(m, B[s]), m)
                self.assertEqual(merge(m, B[p]), m)
                self.assertEqual(merge(m, m), m)

    def test_key_b64_round_trip(self):
        for name in ('genesis', 'rotated', 'recovered', 'recovered_at_thief', 'thief'):
            with self.subTest(bundle=name):
                r = lookup(B[name], NOW)
                self.assertEqual('z' + b58(b'\xed\x01' + base64.b64decode(r['key_b64'], validate=True)), r['key'])

    def test_rotation_at_the_current_wire_needs_sig_next(self):
        self.assertTrue(all('sig_next' in x for x in B['rotated']['rotations']))
        self.assertEqual(lookup(B['rotated'], NOW)['key'], K['A1'])
        b = copy.deepcopy(B['rotated']); del b['rotations'][0]['sig_next']
        self.refused('bundle', lookup, b, NOW)

    def test_other_genesis_refused(self):
        self.refused('genesis', merge, B['rotated'], B['other_genesis'])

    def test_not_a_bundle(self):
        self.refused('shape', lookup, {'typ': 'genesis'}, NOW)
        self.refused('shape', merge, B['genesis'], {'typ': 'bundle'})

    def test_verifier_missing(self):
        old = os.environ.get('SIGELO_VERIFY'); os.environ['SIGELO_VERIFY'] = os.path.join(HERE, 'no-such-binary')
        try: self.refused('verifier', lookup, B['genesis'], NOW)
        finally:
            if old is None: del os.environ['SIGELO_VERIFY']
            else: os.environ['SIGELO_VERIFY'] = old

    def test_lone_surrogate_attestation_discarded_not_fatal(self):
        # SPEC §3.1/§9 step 2: a lone surrogate sinks only its item; the lookup still answers (2026-11-18)
        b = copy.deepcopy(B['rotated'])
        b['attestations'].append({'body': {'v': 'sigelo/0', 'typ': 'attestation', 'iss': D['B0'], 'sub': D['A1'],
                                           'ctx': 'x', 'claims': {'name': '\ud800'}, 'iat': NOW - 10, 'exp': NOW + 10}, 'sig': 'z1'})
        self.assertEqual(verify(b, NOW)['rejected']['attestations'], 1)
        self.assertEqual(lookup(b, NOW)['did'], D['A1'])

    def test_now_out_of_range_refused(self):
        for now in (float('inf'), float('nan'), 'soon', None.__class__):
            with self.subTest(now=now): self.refused('verifier', lookup, B['genesis'], now)

    def test_verifier_garbage_output_refused(self):
        tmp = tempfile.mkdtemp(prefix='sigelo-fake-verify-'); self.addCleanup(shutil.rmtree, tmp, True)
        for n, out in enumerate(('not json', '[]', '{"did": 5}', '{"did": "did:sigelo:zX", "chain": []}')):
            exe = os.path.join(tmp, f'v{n}')
            with open(exe, 'w') as f: f.write(f"#!/bin/sh\ncat >/dev/null\nprintf '%s' '{out}'\n")
            os.chmod(exe, 0o755)
            with self.subTest(out=out), mock.patch.dict(os.environ, {'SIGELO_VERIFY': exe}):
                self.refused('verifier', lookup, B['genesis'], NOW)

    def test_over_4_mib_refused_before_the_verifier(self):
        b = copy.deepcopy(B['genesis']); b['attestations'].append({'body': {'claims': 'x' * (4 << 20)}, 'sig': 'z1'})
        self.refused('size', lookup, b, NOW, os.path.join(HERE, 'no-such-binary'))  # refused before any run

    def test_explicit_verifier_wins(self):
        exe, missing = os.environ.get('SIGELO_VERIFY') or shutil.which('sigelo-verify'), os.path.join(HERE, 'no-such-binary')
        with mock.patch.dict(os.environ, {'SIGELO_VERIFY': missing}):
            self.assertEqual(lookup(B['rotated'], NOW, exe)['did'], D['A1'])
            self.assertEqual(card_lookup(FX['card'], NOW, verifier=exe)['did'], D['A0'])
            self.refused('verifier', lookup, B['rotated'], NOW)
        self.refused('verifier', lookup, B['rotated'], NOW, missing)

    def test_jcs_utf16_order(self):
        self.assertEqual(jcs({'～': 1, '\U0001d11e': 2}), '{"\U0001d11e":2,"～":1}'.encode())
        self.assertRaises(ValueError, jcs, {'x': 1.5})


class CardLookup(unittest.TestCase):
    ext = staticmethod(lambda c: next(e for e in c['capabilities']['extensions'] if e.get('uri') == URI))

    def refused(self, check, card):
        with self.assertRaises(LookupRefused) as c: card_lookup(card, NOW)
        self.assertEqual(c.exception.check, check, c.exception)

    def test_signed_by_sign_mjs(self):
        self.assertEqual(card_lookup(FX['card'], NOW)['key'], K['A0'])

    def test_rotated_card(self):
        r = card_lookup(FX['card_rotated'], NOW)
        self.assertEqual((r['did'], r['key']), (D['A1'], K['A1']))

    def test_a2a_signatures_added_later(self):
        c = copy.deepcopy(FX['card']); c['signatures'] = [{'protected': 'e30', 'signature': 'x'}]
        self.assertEqual(card_lookup(c, NOW)['did'], D['A0'])

    def test_tampered_signature_refused(self):
        c = copy.deepcopy(FX['card']); p = self.ext(c)['params']
        p['sig'] = p['sig'][:-2] + ('2' if p['sig'][-2] != '2' else '3') + p['sig'][-1]
        self.refused('sig', c)

    def test_extension_with_another_uri_refused(self):
        c = copy.deepcopy(FX['card']); self.ext(c)['uri'] = URI + '/v2'
        self.refused('extension', c)

    def test_two_sigelo_extensions_refused(self):
        c = copy.deepcopy(FX['card']); c['capabilities']['extensions'].append(self.ext(copy.deepcopy(FX['card_rotated'])))
        self.refused('extension', c)

    def test_tampered(self):
        c = copy.deepcopy(FX['card']); c['supportedInterfaces'][0]['url'] = 'https://evil.example/a2a'
        self.refused('sig', c)

    def test_params_did_an_earlier_chain_did_refused(self):
        c = copy.deepcopy(FX['card_rotated']); self.ext(c)['params']['did'] = D['A0']  # an earlier DID of the same chain
        self.refused('did', c)

    def test_old_key_after_rotation(self):
        c = copy.deepcopy(FX['card']); self.ext(c)['params']['bundle'] = B['rotated']  # A0's signature, A1 current
        self.refused('did', c)
        self.ext(c)['params']['did'] = D['A1']
        self.refused('sig', c)

    def test_same_sigelo_extension_twice_refused(self):
        c = copy.deepcopy(FX['card']); c['capabilities']['extensions'].append(self.ext(c))
        self.refused('extension', c)


class Parse(unittest.TestCase):
    """SPEC §3: card text with a duplicate key or __proto__ has no single reading: refused whole (2026-11-18)."""
    text = json.dumps(FX['card'])

    def refused(self, text):
        with self.assertRaises(LookupRefused) as c: parse(text)
        self.assertEqual(c.exception.check, 'parse', c.exception)

    def test_card_text_parses_and_verifies(self):
        for t in (self.text, self.text.encode()):
            self.assertEqual(card_lookup(parse(t), NOW)['did'], D['A0'])

    def test_duplicate_key_refused(self):
        self.refused(self.text.replace('"name": "Alice"', '"name": "Alice", "name": "Mallory"', 1))
        self.refused(self.text.replace('"typ": "genesis"', '"typ": "genesis", "typ": "genesis"', 1))  # deep inside the bundle

    def test_proto_key_refused(self):
        self.refused(self.text.replace('"name": "Alice"', '"name": "Alice", "__proto__": {}', 1))
        self.refused(self.text.replace('"streaming": true', '"streaming": true, "__proto__": null', 1))

    def test_not_json_text_refused(self):
        for t in (b'\xff{}', b'\xef\xbb\xbf{}', '{"a": NaN}', '{"a": Infinity}', '{', '[' * 513 + ']' * 513, '[' * 3000 + ']' * 3000, 5, None):
            with self.subTest(text=repr(t)[:40]): self.refused(t)
        self.assertEqual(parse('[' * 512 + ']' * 512), nested(512))


def nested(n):
    """n arrays, each inside the next: n levels of nesting (SPEC §3 counts the outermost as level 1)."""
    x = []
    for _ in range(n - 1): x = [x]
    return x


class Depth(unittest.TestCase):
    """SPEC §3: 512 levels at most; deeper refuses, and never as RecursionError (2026-11-18)."""
    def deep_attestation(self, claims_depth):  # bundle, attestations, envelope, body, claims: 5 levels above
        b = copy.deepcopy(B['rotated'])
        b['attestations'].append({'body': {'v': 'sigelo/0', 'typ': 'attestation', 'iss': D['B0'], 'sub': D['A1'], 'ctx': 'x',
                                           'claims': {'deep': nested(claims_depth)}, 'iat': NOW - 10, 'exp': NOW + 10}, 'sig': 'z1'})
        return b

    def test_jcs_bound_at_512(self):
        self.assertEqual(jcs(nested(512)), b'[' * 512 + b']' * 512)
        self.assertRaises(ValueError, jcs, nested(513))
        self.assertRaises(ValueError, jcs, {'a': nested(3000)})

    def test_depth_512_bundle_answers(self):
        self.assertEqual(lookup(self.deep_attestation(507), NOW)['did'], D['A1'])

    def test_3000_deep_served_item_refuses(self):
        b = self.deep_attestation(3000)
        m = merge(B['rotated'], b)
        self.assertEqual(len(m['attestations']), 1)  # kept: the verifier judges it
        for f, a in ((lookup, (b, NOW)), (lookup, (m, NOW)), (merge, (b, B['rotated']))):
            try: f(*a)
            except LookupRefused as e: self.assertEqual(e.check, 'bundle', e)

    def test_3000_deep_card_refuses(self):
        c = copy.deepcopy(FX['card']); c['skills'] = nested(3000)
        with self.assertRaises(LookupRefused) as e: card_lookup(c, NOW)
        self.assertEqual(e.exception.check, 'sig')


def with_ext(**ext):
    """A copy of the fixture card whose sigelo extension is replaced by `ext`."""
    c = copy.deepcopy(FX['card']); e = CardLookup.ext(c); e.clear(); e.update(ext)
    return c


class MalformedInputOnlyLookupRefused(unittest.TestCase):
    """Every malformed input ends in LookupRefused, the one exception a hook catches (2026-11-18)."""
    def only_refused(self, f, *a):
        try: f(*a)
        except LookupRefused: return
        self.fail(f'{f.__name__}{a!r:.120} returned instead of refusing')

    def test_card_shapes(self):
        p = lambda **kw: dict(CardLookup.ext(FX['card'])['params'], **kw)
        cards = [None, 5, [], 'x', {}, {'capabilities': None}, {'capabilities': 'x'}, {'capabilities': [1]},
                 {'capabilities': {'extensions': 5}}, {'capabilities': {'extensions': 'abc'}},
                 {'capabilities': {'extensions': [None, 1, 'x', [URI]]}},
                 with_ext(uri=URI), with_ext(uri=URI, params=None), with_ext(uri=URI, params=[1]),
                 with_ext(uri=URI, params='x'), with_ext(uri=URI, params=p(bundle=None)), with_ext(uri=URI, params=p(bundle=5)),
                 with_ext(uri=URI, params=p(bundle={'typ': 'bundle'})), with_ext(uri=URI, params=p(sig=5)), with_ext(uri=URI, params=p(sig=None)),
                 with_ext(uri=URI, params=p(did=5)), dict(FX['card'], version=1.5), dict(FX['card'], capabilities=dict(FX['card']['capabilities'], x={1, 2}))]
        for c in cards:
            with self.subTest(card=repr(c)[:80]): self.only_refused(card_lookup, c, NOW)

    def test_bundle_shapes(self):
        g = B['rotated']
        bundles = [None, 5, [], 'x', {}, {'typ': 'bundle'}, dict(g, genesis=None), dict(g, genesis='x'),
                   dict(g, rotations=5), dict(g, rotations=[None]), dict(g, rotations=[{'next_genesis': 5}]),
                   dict(g, issuers={1}), dict(g, bindings=[b'x']), dict(g, genesis=dict(g['genesis'], key=None))]
        for b in bundles:
            with self.subTest(bundle=repr(b)[:80]): self.only_refused(lookup, b, NOW)

    def test_merge_shapes(self):
        g = B['rotated']; no_genesis = {k: v for k, v in g.items() if k != 'genesis'}
        served = [None, 5, [], {}, no_genesis, dict(g, genesis=None), dict(g, genesis='x'), dict(g, genesis=[1]),
                  dict(g, rotations=None), dict(g, genesis=dict(g['genesis'], key=1.5))]
        for b in served:
            with self.subTest(served=repr(b)[:80]):
                self.only_refused(merge, g, b)
                self.only_refused(merge, b, g)

    def test_merge_served_without_genesis_refused(self):
        with self.assertRaises(LookupRefused) as c: merge(B['rotated'], {k: v for k, v in B['rotated'].items() if k != 'genesis'})
        self.assertEqual(c.exception.check, 'shape')

    def test_missing_cryptography_refuses_card_lookup(self):
        with mock.patch.dict(sys.modules, {'cryptography.hazmat.primitives.asymmetric.ed25519': None}):
            with self.assertRaises(LookupRefused) as c: card_lookup(FX['card'], NOW)
        self.assertEqual(c.exception.check, 'cryptography')


if __name__ == '__main__': unittest.main()
