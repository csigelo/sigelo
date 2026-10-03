# SPDX-License-Identifier: MIT
# Pair two agents by sigelo DID, not by Agent Card name or bearer token (SPEC §5.2, §7, §9).
# The card carries {did, bundle} in an A2A extension; everything is verified offline.
#   store = Contacts('contacts.json')
#   c = store.issue(did, ctx, now, 'alice')   -> send c; name None refreshes a known contact
#   pair(card, {'body': ..., 'sig': ...}, store, now) -> {did, current_did, current_key, attestations, rejected}, or raises
# Contract and fixtures: adapters/hermes/pairing/. Reuses sigelo_accept.py (cryptography + sigelo-verify).
import json, os, secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sigelo_accept import B58, did_of, jcs, unmb, verify_bundle

V, EXT, TTL = 'sigelo-a2a-pairing/0', 'urn:sigelo:a2a-pairing:0', 300

class PairingError(ValueError):
    def __init__(self, check, why): super().__init__(f'{check}: {why}'); self.check = check

def fail(check, why): raise PairingError(check, why)

def attempt(check, f):
    try: return f()
    except PairingError: raise
    except Exception as e: fail(check, str(e))

def sig_ok(key, body, sig):
    try:
        pub = unmb(key, 64)
        Ed25519PublicKey.from_public_bytes(pub[2:] if pub[:2] == b'\xed\x01' else b'').verify(unmb(sig), b'sigelo\n' + jcs(body)); return True
    except Exception: return False

class Contacts:  # the JSON-file store: {v, pending: {nonce: {challenge, exp, name}}, contacts: {original DID: contact}}
    def __init__(self, path):
        self.path = path
        self.s = json.load(open(path)) if os.path.exists(path) else {'v': V, 'pending': {}, 'contacts': {}}
    def save(self):
        with open(self.path + '.tmp', 'w') as f: json.dump(self.s, f, indent=2, ensure_ascii=False)
        os.replace(self.path + '.tmp', self.path)
    def issue(self, did, ctx, now, name=None, nonce=None):  # name: the owner pairs a new contact; None: only a known contact may answer
        nonce = nonce or 'z' + ''.join(secrets.choice(B58) for _ in range(22))
        c = {'v': 'sigelo/0', 'typ': 'challenge', 'did': did, 'ctx': ctx, 'nonce': nonce}
        self.s['pending'][nonce] = {'challenge': c, 'exp': now + TTL, 'name': name}; self.save(); return c
    def lookup(self, did): return next((c for c in self.s['contacts'].values() if did in c['chain']), None)
    def revoke(self, did):  # local and final for this store; pending challenges to the contact die with it
        c = self.lookup(did) or fail('not_contact', f'{did} is not a contact')
        c['revoked'] = True
        self.s['pending'] = {n: p for n, p in self.s['pending'].items() if p['challenge']['did'] not in c['chain']}
        self.save(); return c

def pair(card, answer, store, now):
    exts = ((card or {}).get('capabilities') or {}).get('extensions')
    ext = next((x for x in exts if isinstance(x, dict) and x.get('uri') == EXT), None) if isinstance(exts, list) else None
    params = (ext or {}).get('params') or {}
    claimed, bundle = params.get('did'), params.get('bundle')
    if not isinstance(claimed, str) or not isinstance(bundle, dict) or bundle.get('typ') != 'bundle': fail('card', f'no {EXT} extension with params {{did, bundle}}')
    nonce = ((answer or {}).get('body') or {}).get('nonce')
    p = store.s['pending'].pop(nonce, None) if isinstance(nonce, str) else None
    store.save()  # single use, whatever happens next
    if p is None: fail('challenge_unknown', 'not issued here, or already answered')
    if now >= p['exp']: fail('challenge_expired', f"expired at {p['exp']}")
    r = attempt('bundle', lambda: verify_bundle(bundle, now))  # §9, offline; a fork or bad chain raises
    if r['did'] != claimed: fail('card_did', f"the bundle resolves to {r['did']}, the card claims {claimed}")
    if p['challenge']['did'] != r['did']: fail('challenge_did', f"issued to {p['challenge']['did']}, answered by {r['did']}: a card name is not an identity")
    if jcs(answer['body']) != jcs(p['challenge']): fail('challenge_body', 'differs from the challenge issued')
    key_of = lambda rots, d: next(g['key'] for g in [bundle['genesis']] + [x['next_genesis'] for x in rots] if did_of(g) == d)
    if not sig_ok(key_of(bundle['rotations'], r['did']), p['challenge'], answer.get('sig')): fail('sig', 'does not verify under the current key')
    old = store.s['contacts'].get(r['chain'][0])  # keyed by the ORIGINAL DID: rotation keeps the pairing
    if old and old['revoked']: fail('revoked', f"{r['chain'][0]} was revoked by this owner")
    if not old and p['name'] is None: fail('not_contact', f"{r['chain'][0]} is not a contact; pairing needs the owner")
    rotations = bundle['rotations']
    if old:  # a peer cannot hide a rotation this store has seen: merge, and §7.3 decides (recovery beats voluntary)
        seen = {jcs(x) for x in rotations}
        rotations = rotations + [x for x in old['rotations'] if jcs(x) not in seen]
        r = attempt('bundle', lambda: verify_bundle(dict(bundle, rotations=rotations), now))
        if r['did'] != claimed: fail('stale_chain', f"the rotations already seen resolve to {r['did']}, not {claimed}")
    c = {'name': old['name'] if old else p['name'], 'did': r['chain'][0], 'current_did': r['did'], 'current_key': key_of(rotations, r['did']),
         'revoked': False, 'chain': r['chain'], 'rotations': rotations}
    store.s['contacts'][c['did']] = c; store.save()
    return {k: c[k] for k in ('did', 'current_did', 'current_key')} | {'attestations': r['attestations'], 'rejected': r['rejected']}
