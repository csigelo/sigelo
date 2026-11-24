#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Unit tests for the sigelo Hermes peer authenticator, no Hermes needed, stdlib unittest only.
# Real identities and signatures (sigelo_fixture.py), a local sigelo-verify, and sockets disabled in
# this process so the plugin cannot reach the network.  python3 apps/integrations/hermes/peer-auth/test_peer_auth.py
import importlib.util, os, socket, sys, types, unittest
from pathlib import Path
sys.dont_write_bytecode = True  # no __pycache__ in the checkout
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import sigelo_fixture as fx

def load():  # import the plugin dir as a package, as Hermes does (spec_from_file_location + search path)
    spec = importlib.util.spec_from_file_location('sigelo_peer_auth', os.path.join(HERE, '__init__.py'), submodule_search_locations=[HERE])
    mod = importlib.util.module_from_spec(spec); sys.modules['sigelo_peer_auth'] = mod; spec.loader.exec_module(mod); return mod

def no_network(*a, **k): raise AssertionError('network use during verification')
X, Y = {'slug': 'x'}, {'slug': 'y'}

class PeerAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (why := fx.missing()): raise unittest.SkipTest(why)
        os.environ['SIGELO_VERIFY'] = fx.verifier()
        for k in ('SIGELO_PEER_TOKEN_TTL', 'SIGELO_REQUIRED_ATTESTATIONS', 'SIGELO_PEER_CTX', 'A2A_PUBLIC_URL'): os.environ.pop(k, None)
        cls.ids, cls.m = fx.make(), load()
        cls.saved, socket.socket.connect = socket.socket.connect, no_network

    @classmethod
    def tearDownClass(cls): socket.socket.connect = cls.saved

    def peers(self, **env):
        env = {'SIGELO_PEER_CTX': 'a2a.test', **env}
        for k, v in env.items(): os.environ[k] = v
        try: return self.m.SigeloPeers()
        finally: [os.environ.pop(k) for k in env]

    def login(self, p, who='A', agent=X):
        return p.accept(fx.answer(self.ids[who], p.challenge(self.ids[who]['did'], agent)), agent)

    def test_full_flow(self):
        p, A = self.peers(), self.ids['A']
        c = p.challenge(A['did'], X)
        self.assertEqual((sorted(c), c['ctx'], c['did']), (['ctx', 'did', 'nonce', 'typ', 'v'], 'a2a.test/x', A['did']))
        r = p.accept(fx.answer(A, c), X)
        self.assertEqual((r['identity'], r['expires_in']), (A['did'], 3600))
        self.assertTrue(r['token'].startswith('sgl1_') and len(r['token']) > 45)
        self.assertEqual(p.authenticate('Bearer ' + r['token'], '1.2.3.4', X), A['did'])
        self.assertEqual(p.authenticate('bearer  ' + r['token'] + ' ', '', {'slug': 'x', 'path': '/x'}), A['did'])
        self.assertNotIn(r['token'], repr(p.tokens))  # only hashes are kept
        self.assertEqual(self.login(p, agent={'slug': ''})['identity'], A['did'])  # root agent -> audience "default"

    def test_challenge_single_use(self):
        p, A = self.peers(), self.ids['A']
        body = fx.answer(A, p.challenge(A['did'], X)); p.accept(body, X)
        with self.assertRaises(self.m.PeerAuthError): p.accept(body, X)
        with self.assertRaises(self.m.PeerAuthError): p.accept(dict(body, challenge=body['challenge']['nonce']), X)

    def test_expiry(self):
        p = self.peers(SIGELO_PEER_TOKEN_TTL='60'); tok = self.login(p)['token']
        self.assertEqual(self.login(p)['expires_in'], 60)
        real = self.m.time
        try:
            self.m.time = types.SimpleNamespace(time=lambda: real.time() + 61)
            with self.assertRaises(self.m.PeerAuthError): p.authenticate('Bearer ' + tok, '', X)
            self.assertEqual(p.tokens, {})  # pruned
        finally: self.m.time = real

    def test_audience_mismatch(self):
        p = self.peers(); tok = self.login(p, agent=X)['token']
        with self.assertRaises(self.m.PeerAuthError): p.authenticate('Bearer ' + tok, '', Y)
        with self.assertRaises(self.m.PeerAuthError): p.authenticate('Bearer ' + tok, '', {'slug': ''})
        A = self.ids['A']; c = p.challenge(A['did'], X)  # a challenge issued on x answered on y's route
        with self.assertRaises(self.m.PeerAuthError): p.accept(fx.answer(A, c), Y)
        with self.assertRaises(self.m.PeerAuthError): p.accept(fx.answer(A, c), X)  # and it is spent

    def test_defer_and_reject(self):
        p = self.peers()
        for h in (None, '', 'Bearer', 'Basic dXNlcjpwYXNz', 'Bearer static-peer-token', 'Bearer eyJhbGciOi.x.y', 'Bearer \udcff garbage'):
            self.assertIsNone(p.authenticate(h, '1.2.3.4', X), h)  # not ours: defer
        for h in ('Bearer sgl1_' + 'A' * 43, 'Bearer sgl1_', 'Bearer sgl1_\udcff'):
            with self.assertRaises(self.m.PeerAuthError): p.authenticate(h, '', X)  # ours by prefix, unknown

    def test_refusals(self):
        p, A, B = self.peers(), self.ids['A'], self.ids['B']
        c = p.challenge(A['did'], X); body = fx.answer(A, c)
        sig = body['sig']; body['sig'] = sig[:-2] + ('1' if sig[-2] != '1' else '2') + sig[-1]
        with self.assertRaises(self.m.PeerAuthError): p.accept(body, X)  # tampered sig
        c = p.challenge(A['did'], X)
        with self.assertRaises(self.m.PeerAuthError): p.accept(fx.answer(A, c, B['bundle']), X)  # someone else's bundle
        c = p.challenge(A['did'], X)
        with self.assertRaises(self.m.PeerAuthError): p.accept(dict(fx.answer(B, dict(c, did=B['did'])), challenge=c), X)
        for bad in (None, 'did:web:example.com', 'did:sigelo:', 42):
            with self.assertRaises(ValueError): p.challenge(bad, X)
        for bad in (None, [], {}, {'challenge': 'n'}, {'challenge': {'nonce': ['x']}, 'bundle': {}}):
            with self.assertRaises(ValueError): p.accept(bad, X)
        self.assertEqual(self.login(p, 'B')['identity'], B['did'])  # B itself is fine
        self.assertEqual(p.accept(fx.answer(A, p.challenge(A['did'], X), A['genesis']), X)['identity'], A['did'])  # bare genesis

    def test_required_attestations(self):
        W = self.ids['world']['did']
        p = self.peers(SIGELO_REQUIRED_ATTESTATIONS=f' {W} , did:sigelo:zOther')
        self.assertEqual(self.login(p, 'A')['identity'], self.ids['A']['did'])
        with self.assertRaises(self.m.PeerAuthError): self.login(p, 'B')
        A = self.ids['A']  # a bare genesis carries no attestations
        with self.assertRaises(self.m.PeerAuthError): p.accept(fx.answer(A, p.challenge(A['did'], X), A['genesis']), X)
        with self.assertRaises(self.m.PeerAuthError): self.login(self.peers(SIGELO_REQUIRED_ATTESTATIONS='did:sigelo:zOther'), 'A')

    def test_ctx_host(self):
        p = self.peers(SIGELO_PEER_CTX='a2a.example.com/')
        self.assertEqual(p.challenge(self.ids['A']['did'], {'slug': ''})['ctx'], 'a2a.example.com/default')
        self.assertEqual(self.login(p)['identity'], self.ids['A']['did'])
        p = self.peers(SIGELO_PEER_CTX='', A2A_PUBLIC_URL='https://hermes.example.org/a2a/')
        self.assertEqual(p.challenge(self.ids['A']['did'], {'slug': 'x'})['ctx'], 'hermes.example.org/a2a/x')
        with self.assertLogs(level='WARNING'): p = self.peers(SIGELO_PEER_CTX='')  # no public name: refuse,
        with self.assertRaises(self.m.PeerAuthError): p.challenge(self.ids['A']['did'], X)  # never a bare slug

    def test_pending_is_safe_under_request_threads(self):
        pending = self.m.sigelo_accept.PENDING
        self.assertIsInstance(pending, self.m._Pending)
        pending['n1'], pending['n2'] = ({}, 0), ({}, 0)
        for n, _ in pending.items(): pending.pop('n2', None); pending['n3'] = ({}, 0)  # no RuntimeError
        del pending['n1'], pending['n1']  # a nonce another thread removed first: no KeyError
        for n in ('n2', 'n3'): pending.pop(n, None)

    def test_register_and_vendored_copy(self):
        got = []
        self.m.register(types.SimpleNamespace(register_a2a_peer_authenticator=got.append))
        self.assertEqual((len(got), got[0].name), (1, 'sigelo'))
        for k in ('challenge', 'accept', 'authenticate'): self.assertTrue(callable(getattr(got[0], k)))
        src = os.path.join(fx.REPO, 'accept', 'python', 'sigelo_accept.py')
        self.assertEqual(Path(HERE, 'sigelo_accept.py').read_bytes(), Path(src).read_bytes(),
                         'vendored sigelo_accept.py drifted: cp accept/python/sigelo_accept.py apps/integrations/hermes/peer-auth/')

if __name__ == '__main__': unittest.main(verbosity=2)
