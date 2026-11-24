# SPDX-License-Identifier: MIT
# sigelo peer authenticator for the Hermes Agent A2A adapter (the provider protocol of
# ctx.register_a2a_peer_authenticator). A remote agent proves its sigelo DID once, by a §5.2 challenge
# plus its §8 bundle verified offline (sigelo_accept.py, vendored byte for byte from accept/python/),
# and gets an opaque Bearer token; on every later request authenticate() maps that token back to the
# DID, which Hermes then treats like any peer name (a2a.trusted_peers, rate limit, framing, audit).
#   GET  <agent>/peer-auth/challenge?did=   -> challenge(did, agent)   -> the challenge body
#   POST <agent>/peer-auth {challenge, did, sig, bundle} -> accept()   -> {identity, token, expires_in}
#   Authorization: Bearer sgl1_...          -> authenticate()          -> DID | None (not ours) | PeerAuthError
# Audience = the served agent's slug, "default" for the root agent: a token works only on the agent
# that minted it. Challenge ctx = "<this Hermes's public name>/<slug>", the name from SIGELO_PEER_CTX
# else A2A_PUBLIC_URL; with neither the challenge route refuses: a ctx naming no host lets a hostile
# Hermes relay our challenge to a peer logging into it (the peer checks ctx before it signs).
# State is in memory, one process: a restart forgets every token (peers just log in again).
# ValueError = bad input (400); PeerAuthError = refused (401, never a fall-through to static tokens).
import hashlib, hmac, logging, os, secrets, threading, time, urllib.parse
from . import sigelo_accept

class _Pending(dict):  # sigelo_accept prunes PENDING by iterating it; request threads insert and pop concurrently
    def items(self): return list(dict.items(self))  # a snapshot (one C call under the GIL)
    def __delitem__(self, key): self.pop(key, None)  # another thread may have pruned or answered it first
sigelo_accept.PENDING = _Pending(sigelo_accept.PENDING)

try:  # the hook's own error class when Hermes has it; else a stand-in of the same name (Hermes
    from plugins.platforms.a2a.security import PeerAuthError  # turns any provider exception into a 401)
except ImportError:
    class PeerAuthError(Exception): pass

PREFIX, MAX_TOKENS, MAX_PENDING = 'sgl1_', 10000, 10000

def _env(name, default=''): return (os.environ.get(name) or default).strip()
def _aud(agent): return str((agent or {}).get('slug') or 'default')
def _key(token): return hashlib.sha256(token.encode('utf-8', 'surrogatepass')).digest()  # store never holds a token

class SigeloPeers:
    name = 'sigelo'

    def __init__(self):  # settings captured once, at plugin load (request threads see no profile scope)
        self.ttl = int(_env('SIGELO_PEER_TOKEN_TTL', '3600'))
        self.required = frozenset(d.strip() for d in _env('SIGELO_REQUIRED_ATTESTATIONS').split(',') if d.strip())
        public = urllib.parse.urlsplit(_env('A2A_PUBLIC_URL'))
        self.ctx_host = (_env('SIGELO_PEER_CTX') or public.netloc + public.path).rstrip('/')
        if not self.ctx_host:
            logging.getLogger(__name__).warning('sigelo peer auth: set SIGELO_PEER_CTX (or A2A_PUBLIC_URL) to this '
                                                "Hermes's public host; until then the challenge route refuses")
        self.tokens, self.lock = {}, threading.Lock()  # sha256(token) -> (did, audience, expiry)

    def ctx(self, agent): return f'{self.ctx_host}/{_aud(agent)}'

    def challenge(self, did, agent):
        if not self.ctx_host: raise PeerAuthError('this agent has no public name for the challenge ctx (SIGELO_PEER_CTX)')
        now, pending = time.time(), sigelo_accept.PENDING
        for n in [n for n, (_, exp) in list(pending.items()) if exp <= now]: pending.pop(n, None)
        if len(pending) >= MAX_PENDING: raise PeerAuthError('too many outstanding challenges, retry later')
        return sigelo_accept.challenge(did, self.ctx(agent))  # ValueError on a malformed DID

    def accept(self, body, agent):
        if not isinstance(body, dict) or not isinstance(body.get('bundle'), dict) or not isinstance(body.get('challenge'), (dict, str)):
            raise ValueError('want {challenge, did, sig, bundle}')
        chal = body['challenge']
        if not isinstance(nonce := chal if isinstance(chal, str) else chal.get('nonce'), str): raise ValueError('challenge.nonce: want a string')
        issued = sigelo_accept.PENDING.get(nonce, ({},))[0]
        if issued.get('ctx', self.ctx(agent)) != self.ctx(agent):  # a challenge from another agent's route
            sigelo_accept.PENDING.pop(nonce, None); raise PeerAuthError('challenge was issued for another agent')
        try: r = sigelo_accept.accept(chal, body, body['bundle'])  # single use; offline unless SIGELO_VERIFY=https://
        except Exception as e: raise PeerAuthError(str(e) or 'refused') from e
        if self.required and not self.required & set(r.get('attestations') or {}):
            raise PeerAuthError('no attestation from an issuer this agent requires')
        token, exp = PREFIX + secrets.token_urlsafe(32), time.time() + self.ttl
        with self.lock:
            self._prune()
            if len(self.tokens) >= MAX_TOKENS: raise PeerAuthError('too many live peer tokens, retry later')
            self.tokens[_key(token)] = (r['did'], _aud(agent), exp)
        return {'identity': r['did'], 'token': token, 'expires_in': self.ttl}

    def authenticate(self, authorization, client_ip, agent):
        parts = (authorization or '').split(None, 1)
        if len(parts) != 2 or parts[0].lower() != 'bearer' or not parts[1].strip().startswith(PREFIX):
            return None  # not ours: a static token or another provider's credential may match
        key = _key(parts[1].strip())
        with self.lock:
            self._prune()
            hit = self.tokens.get(key)  # keyed by SHA-256: lookup timing reveals nothing about a live token
        if hit is None:
            raise PeerAuthError('sigelo token unknown or expired: log in again')  # ours by prefix, so no fall-through
        did, aud, _ = hit
        if not hmac.compare_digest(aud.encode(), _aud(agent).encode()):
            raise PeerAuthError('sigelo token was minted for another agent')
        return did

    def _prune(self):  # caller holds the lock
        now = time.time()
        for k in [k for k, (_, _, exp) in self.tokens.items() if exp <= now]: del self.tokens[k]

def register(ctx):
    ctx.register_a2a_peer_authenticator(SigeloPeers())
