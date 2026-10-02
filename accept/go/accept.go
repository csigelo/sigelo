// SPDX-License-Identifier: MIT
// Package accept accepts a sigelo identity (SPEC §5.2 + §9) in any Go web stack, on the
// repository's reference verifier. Pending challenges live in memory, in one process:
// replace the map with your session store.
package accept

import (
	"crypto/rand"
	"errors"
	"maps"
	"sync"
	"time"

	"github.com/csigelo/sigelo/go"
)

// TTL is a challenge's lifetime. pending maps each issued challenge (its JCS bytes) to its expiry.
var TTL, mu, pending = 5 * time.Minute, sync.Mutex{}, map[string]time.Time{}

// Challenge issues a single-use §5.2 challenge for did (the agent's current DID) in ctx (your
// domain), as the JSON to send.
func Challenge(did, ctx string) []byte {
	c, _ := sigelo.Canonicalize(sigelo.Object{}.With("v", "sigelo/0").With("typ", "challenge").With("did", did).With("ctx", ctx).With("nonce", rand.Text()))
	mu.Lock()
	defer mu.Unlock()
	maps.DeleteFunc(pending, func(_ string, exp time.Time) bool { return time.Now().After(exp) })
	pending[string(c)] = time.Now().Add(TTL)
	return c
}

// Accept checks the answer {did, sig} to challenge (sent back as issued) against the agent's bundle
// (or current genesis): the bundle verifies (§9), its current DID is did, sig is the current key's
// over the challenge. It returns the §9.1 result: r.DID is who they are.
func Accept(challenge []byte, did, sig string, bundle []byte) (*sigelo.Result, error) {
	v, _ := sigelo.Parse(challenge)
	c, _ := v.(sigelo.Object)
	cj, _ := sigelo.Canonicalize(c)
	mu.Lock()
	exp, ok := pending[string(cj)]
	delete(pending, string(cj)) // single use, whatever happens next
	mu.Unlock()
	if cd, _ := c.Get("did"); !ok || time.Now().After(exp) || cd != did {
		return nil, errors.New("challenge unknown, expired, already answered, or issued to another DID")
	}
	v, _ = sigelo.Parse(bundle)
	b, _ := v.(sigelo.Object)
	if typ, _ := b.Get("typ"); typ == "genesis" { // a bare genesis: the bundle that holds nothing else
		b = sigelo.Object{}.With("v", "sigelo/0").With("typ", "bundle").With("genesis", v).With("rotations", []any{}).With("bindings", []any{}).With("attestations", []any{}).With("issuers", []any{})
	}
	r, err := sigelo.Verify(b, time.Now().Unix(), nil)
	if err != nil || r.DID != did {
		return nil, errors.Join(err, errors.New("not a valid bundle whose current DID is did"))
	}
	g0, _ := b.Get("genesis")
	rs, _ := b.Get("rotations")
	for _, g := range append([]any{g0}, rs.([]any)...) {
		if next, ok := g.(sigelo.Object).Get("next_genesis"); ok {
			g = next
		}
		if d, _ := sigelo.DID(g); d == did {
			key, _ := g.(sigelo.Object).Get("key")
			if sigelo.VerifySig(key, c, sig) {
				return r, nil
			}
		}
	}
	return nil, errors.New("sig does not verify under the current key")
}
