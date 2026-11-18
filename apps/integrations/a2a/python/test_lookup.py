# SPDX-License-Identifier: MIT
# python3 -m unittest test_lookup (from this folder). Fixtures: gen.mjs. Needs `cryptography` and a
# sigelo-verify binary: $SIGELO_VERIFY, else one on PATH, else it is built from go/ into a temporary directory.
import base64, copy, json, os, shutil, subprocess, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from sigelo_lookup import LookupRefused, card_lookup, jcs, lookup, merge, unb58, URI

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

    def test_tampered(self):
        c = copy.deepcopy(FX['card']); c['supportedInterfaces'][0]['url'] = 'https://evil.example/a2a'
        self.refused('sig', c)

    def test_did_swapped(self):
        c = copy.deepcopy(FX['card_rotated']); self.ext(c)['params']['did'] = D['A0']  # an earlier DID of the same chain
        self.refused('did', c)

    def test_old_key_after_rotation(self):
        c = copy.deepcopy(FX['card']); self.ext(c)['params']['bundle'] = B['rotated']  # A0's signature, A1 current
        self.refused('did', c)
        self.ext(c)['params']['did'] = D['A1']
        self.refused('sig', c)

    def test_extension_count(self):
        c = copy.deepcopy(FX['card']); c['capabilities']['extensions'].append(self.ext(c))
        self.refused('extension', c)


if __name__ == '__main__': unittest.main()
