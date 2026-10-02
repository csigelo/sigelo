// SPDX-License-Identifier: MIT

// Package sigelo is the SPEC §9 verifier for sigelo v0.1 (wire `sigelo/0`): portable agent
// identity.
//
// Verify follows SPEC §9 step by step, in order, with the same names as
// ts/src/sigelo.ts. Nothing in the verification path reads a clock or the network: `now` is a
// parameter and everything a verifier needs is inside the bundle (SPEC §1.1).
//
// Values are what Parse returns: nil, bool, string, int64, []any and Object (an ordered map).
package sigelo

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
)

// Version is the wire version every signed body carries in `v`.
const Version = "sigelo/0"

var (
	prefix         = []byte("sigelo\n") // domain separation (SPEC §3, THREAT-MODEL §2.5c)
	admission      = []string{"open", "captcha", "invite", "payment", "human", "stake"}
	atomicUnit     = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	commitmentForm = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`) // a recovery commitment (§4)
	nonceForm      = regexp.MustCompile(`^z[1-9A-HJ-NP-Za-km-z]{1,63}$`)
	required       = map[string][]string{
		"genesis":     {"v", "typ", "key", "recovery", "created", "nonce"},
		"rotation":    {"v", "typ", "id", "next", "iat", "reason"},
		"binding":     {"v", "typ", "id", "method", "addr", "iat", "exp", "nonce"},
		"attestation": {"v", "typ", "iss", "sub", "iat", "exp", "ctx", "admission", "claims"},
		"challenge":   {"v", "typ", "did", "ctx", "nonce"},                          // §5.2; never in a bundle
		"invoice":     {"v", "typ", "did", "method", "addr", "iat", "exp", "nonce"}, // §6.3; never in a bundle
		"bundle":      {"v", "typ", "genesis", "rotations", "bindings", "attestations", "issuers"},
	}
	// §3.1: the only keys beyond `required` a body may carry. Everything else is malformed.
	optional = map[string][]string{
		"rotation": {"recovery_key"}, "attestation": {"admission_by", "admission_cost"}, "invoice": {"amount", "memo"}}
	// §3.1 field types: iat/exp are integer Unix seconds, everything else a string except these.
	notString = []string{"iat", "exp", "recovery", "claims", "amount", "genesis", "rotations", "bindings", "attestations", "issuers"}
	// §3.1: an envelope is exactly these members. Nothing outside `body` is signed.
	envelopeKeys = map[string][]string{"rotation": {"body", "sig", "next_genesis"}, "binding": {"body", "sig_id", "sig_addr"}, "attestation": {"body", "sig"}}
)

// SigeloError is every fatal failure. The message names the check that failed.
type SigeloError string

func (e SigeloError) Error() string { return string(e) }

func fail(format string, a ...any) error { return SigeloError(fmt.Sprintf(format, a...)) }

// ---------------------------------------------------------------- primitives

// SigningInput is "sigelo\n" || JCS(body), the bytes every sigelo signature covers (SPEC §3).
func SigningInput(body any) ([]byte, error) {
	j, err := Canonicalize(body)
	return append(slices.Clone(prefix), j...), err
}

// DID is "did:sigelo:" + multibase SHA-256 of the canonical genesis (SPEC §4).
func DID(genesis any) (string, error) {
	j, err := Canonicalize(genesis)
	h := sha256.Sum256(j)
	return "did:sigelo:z" + b58encode(h[:]), err
}

// did is DID for a genesis Structure has already accepted, which always canonicalizes.
func did(g any) string { d, _ := DID(g); return d }

func commitmentOf(key any) string {
	raw, _ := decodeKey(key)
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

// VerifySig verifies a detached signature by a multibase public key. Never fails; malformed
// input is false.
func VerifySig(key, body, sig any) bool {
	pub, err1 := decodeKey(key)
	s, err2 := unmb(sig, maxSigChars)
	msg, err3 := SigningInput(body)
	return err1 == nil && err2 == nil && err3 == nil && ed25519Strict(pub, msg, s)
}

// ---------------------------------------------------------------- §9 step 2: structure

// Structure is SPEC §9 step 2 for one body presented in `slot` (genesis, rotation, binding,
// attestation, challenge, invoice or bundle). Canonicalizing is itself the float / range /
// lone-surrogate / "__proto__" check, so it is done first and reported under the slot.
func Structure(body any, slot string) error {
	b, ok := body.(Object)
	if !ok || b == nil {
		return fail("%s: body is not an object", slot)
	}
	whole := b
	if slot == "bundle" { // its attestations and bindings are canonicalized one by one in
		whole = b.With("attestations", []any{}).With("bindings", []any{}) // Verify (invariant 7)
	}
	if _, err := Canonicalize(whole); err != nil {
		return fail("%s: %v", slot, err)
	}
	for _, f := range required[slot] {
		if _, ok := b.Get(f); !ok {
			return fail("%s: missing %s", slot, f)
		}
	}
	// §3.1: no other top-level keys. An unknown field is data nobody agreed to sign over, and
	// the next implementation may treat it as meaningful; there is no safe way to ignore it.
	for _, m := range b {
		if !slices.Contains(required[slot], m.Key) && !slices.Contains(optional[slot], m.Key) {
			return fail("%s: unknown field %s", slot, stringify(m.Key))
		}
	}
	get := func(k string) any { v, _ := b.Get(k); return v }
	if get("v") != Version {
		return fail("%s: unknown v %s", slot, stringify(get("v")))
	}
	if get("typ") != slot {
		return fail("%s: typ is %s", slot, stringify(get("typ")))
	}
	for _, m := range b {
		if n, isInt := m.Value.(int64); (m.Key == "iat" || m.Key == "exp") && !(isInt && n >= 0) {
			return fail("%s: %s is not a non-negative integer", slot, m.Key)
		}
		if _, isStr := m.Value.(string); !slices.Contains(notString, m.Key) && !isStr {
			return fail("%s: %s is not a string", slot, m.Key)
		}
	}
	if exp, ok := b.Get("exp"); ok && !(exp.(int64) > get("iat").(int64)) {
		return fail("%s: exp is not after iat", slot)
	}
	// §2: a nonce is z + base58btc, at most 64 characters — except §5.2's, the world's to choose.
	if n, ok := b.Get("nonce"); ok && slot != "challenge" && !nonceForm.MatchString(n.(string)) {
		return fail("%s: nonce is not z + base58btc (at most 64 characters)", slot)
	}
	switch slot {
	case "genesis":
		if err := publicKey(get("key")); err != nil {
			return err // fail closed on a key that is not multicodec ed25519-pub, or no usable point
		}
		// §4: exactly sha256: + 64 lowercase hex. A prefix check let "sha256:", "sha256:xyz" and
		// UPPERCASE hex through — a commitment nothing hashes to, which silently disables recovery.
		if rec, isStr := get("recovery").(string); get("recovery") != nil && !(isStr && commitmentForm.MatchString(rec)) {
			return fail("genesis: recovery is neither null nor sha256: + 64 lowercase hex")
		}
		if !isRFC3339UTC(get("created").(string)) { // §4; a type failure was reported above
			return fail("genesis: created is not RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)")
		}
	case "rotation":
		if get("reason") != "voluntary" && get("reason") != "recovery" {
			return fail("rotation: unknown reason")
		}
		rk, hasKey := b.Get("recovery_key")
		if (get("reason") == "recovery") != hasKey {
			return fail("rotation: recovery_key present iff reason is recovery")
		}
		if err := publicKey(rk); hasKey && err != nil {
			return err
		}
		if get("next") == get("id") {
			return fail("rotation: next == id")
		}
	case "binding":
		if get("method") == "ed25519-test" { // §6.1a: addr is a public key
			if err := publicKey(get("addr")); err != nil {
				return err
			}
		}
	case "attestation":
		if a, _ := get("admission").(string); !slices.Contains(admission, a) {
			return fail("attestation: unknown admission %s", stringify(get("admission")))
		}
	case "invoice":
		// §3.1 / §6.3: `amount` is a STRING of atomic units. A JSON number would be a float in
		// some language's parser; "0.15" and "-1" are not atomic units at all. The canonicalizer
		// cannot catch either, because both are legal JSON strings.
		if amt, ok := b.Get("amount"); ok {
			if s, isStr := amt.(string); !isStr || !atomicUnit.MatchString(s) {
				return fail("invoice: amount is not a decimal string of atomic units %s", stringify(amt))
			}
		}
	case "bundle":
		for _, a := range []string{"rotations", "bindings", "attestations", "issuers"} {
			if _, isArr := get(a).([]any); !isArr {
				return fail("bundle: %s is not an array", a)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- §7.3 chain

type rotation struct {
	body        Object
	sig         string
	nextGenesis Object
}

func (r rotation) str(k string) string { s, _ := r.body.Get(k); return s.(string) }
func (r rotation) iat() int64          { n, _ := r.body.Get("iat"); return n.(int64) }

// resolveChain walks the chain from the original genesis (SPEC §7.3). It returns the ordered
// DIDs and the governing recovery commitment (§7.2: the one in the most recent
// recovery-signed genesis). Rotations must already have passed Structure.
func resolveChain(g0 Object, rotations []rotation) ([]string, any, error) {
	cur := did(g0)
	chain := []string{cur}
	genesisOf := map[string]Object{cur: g0}
	for _, r := range rotations {
		genesisOf[did(r.nextGenesis)] = r.nextGenesis
	}
	commitment, _ := g0.Get("recovery")
	for {
		var recovery, voluntary []rotation
		for _, r := range rotations {
			if r.str("id") != cur { // 1
				continue
			}
			ngRecovery, _ := r.nextGenesis.Get("recovery")
			hashOK := did(r.nextGenesis) == r.str("next")
			if r.str("reason") == "recovery" && commitment != nil && hashOK && // 2
				commitmentOf(r.str("recovery_key")) == commitment && VerifySig(r.str("recovery_key"), r.body, r.sig) {
				recovery = append(recovery, r)
			}
			// §7: a voluntary rotation MUST carry the commitment forward unchanged. That is
			// what stops a thief with the hot key from installing a recovery key of their own.
			gkey, _ := genesisOf[cur].Get("key")
			if r.str("reason") == "voluntary" && hashOK && ngRecovery == commitment && VerifySig(gkey, r.body, r.sig) { // 3
				voluntary = append(voluntary, r)
			}
		}
		var chosen rotation
		switch {
		case len(recovery) > 0:
			// §7.1 precedence. This looks wrong — it ignores `iat`, and the voluntary rotation
			// may be newer and perfectly valid — which is exactly the point: a thief can produce
			// a valid voluntary rotation, and only the operator's offline key can produce this
			// one. Ordering by timestamp would hand the identity to whoever signed last.
			top := slices.MaxFunc(recovery, func(a, b rotation) int { return int(a.iat() - b.iat()) }).iat()
			ties := slices.DeleteFunc(slices.Clone(recovery), func(r rotation) bool { return r.iat() != top })
			if len(ties) > 1 { // operator error: the operator controls both, no rule picks one
				return nil, nil, fail("chain: recovery tie at %s (two valid recovery rotations share iat %d)", cur, top)
			}
			chosen = ties[0]
			commitment, _ = chosen.nextGenesis.Get("recovery") // §7.2: only a recovery may change it
		case len(voluntary) == 1:
			chosen = voluntary[0]
		case len(voluntary) > 1: // a fork under one key is a compromise signal; do not pick a side
			return nil, nil, fail("chain: fork at %s (%d valid voluntary rotations)", cur, len(voluntary))
		default:
			return chain, commitment, nil // 4
		}
		// 5: a `next` already in the chain is a cycle. Only a key holder can produce one, it has
		// no legitimate meaning, and following it would hang the verifier — reject, never loop.
		if slices.Contains(chain, chosen.str("next")) {
			return nil, nil, fail("chain: cycle back to %s", chosen.str("next"))
		}
		cur = chosen.str("next")
		chain = append(chain, cur)
	}
}

// ---------------------------------------------------------------- §9 verify

// Result is the §9.1 result. Its JSON form (Value, MarshalJSON) uses the §9.1 field names.
type Result struct {
	DID          string              `json:"did"`
	Chain        []string            `json:"chain"`
	Recovery     *string             `json:"recovery"`     // the governing commitment; nil if none
	Attestations map[string][]Object `json:"attestations"` // accepted bodies, by iss, bundle order
	Bindings     []BindingResult     `json:"bindings"`     // accepted bodies, bundle order
	Rejected     Rejected            `json:"rejected"`
}

// BindingResult is one accepted binding: its body and its §6.1 proof status.
type BindingResult struct {
	Body  Object `json:"body"`
	Proof string `json:"proof"` // "proven", "unproven" or "unsupported"
}

// Rejected counts what §9 steps 2, 5 and 6 discarded.
type Rejected struct {
	Attestations int `json:"attestations"`
	Bindings     int `json:"bindings"`
}

// malformed returns the indices whose envelope, body or signature slot is malformed:
// per-item, never fatal (§9 step 2, invariant 7).
func malformed(items []any, slot, sigField string) map[int]bool {
	bad := map[int]bool{}
	for i, it := range items {
		env, _ := it.(Object) // the envelope may be junk
		body, _ := env.Get("body")
		_, err := Canonicalize(it) // the whole envelope: a float or lone surrogate anywhere
		if err == nil {
			err = Structure(body, slot)
		}
		if err == nil {
			err = envelope(env, slot)
		}
		if s, _ := env.Get(sigField); err != nil || !isString(s) {
			bad[i] = true
		}
	}
	return bad
}

func isString(v any) bool { _, ok := v.(string); return ok }

// envelope is §3.1's rule for the members around a body: exactly the defined ones.
func envelope(env Object, slot string) error {
	for _, m := range env {
		if !slices.Contains(envelopeKeys[slot], m.Key) {
			return fail("%s: unknown envelope field %s", slot, stringify(m.Key))
		}
	}
	return nil
}

// Verify is SPEC §9. It returns the §9.1 result, or a SigeloError on a structural failure in
// what defines the identity, a fork, a tie or a cycle — those are fatal to the whole bundle.
// Anything wrong with an individual attestation or binding is counted in Rejected instead.
// knownIssuers maps DIDs to locally pinned issuer genesis documents; it may be nil.
func Verify(bundle any, now int64, knownIssuers map[string]Object) (*Result, error) {
	b, _ := bundle.(Object)
	field := func(o Object, k string) any { v, _ := o.Get(k); return v }
	// 1. Genesis
	if err := Structure(field(b, "genesis"), "genesis"); err != nil {
		return nil, err
	}
	g0 := field(b, "genesis").(Object)
	d0 := did(g0)
	// 2. Structure
	if err := Structure(bundle, "bundle"); err != nil {
		return nil, err
	}
	var rotations []rotation
	for _, r := range field(b, "rotations").([]any) {
		env, _ := r.(Object)
		if err := Structure(field(env, "body"), "rotation"); err != nil {
			return nil, err
		}
		// §3.1: the envelope is part of the same rule, and a rotation defines the identity, so
		// a missing half is fatal rather than per-item.
		ng, ok := env.Get("next_genesis")
		if !ok {
			return nil, fail("rotation: missing next_genesis")
		}
		if err := Structure(ng, "genesis"); err != nil {
			return nil, err
		}
		sig, ok := field(env, "sig").(string)
		if !ok {
			return nil, fail("rotation: missing sig")
		}
		if err := envelope(env, "rotation"); err != nil {
			return nil, err
		}
		rotations = append(rotations, rotation{field(env, "body").(Object), sig, ng.(Object)})
	}
	for _, g := range field(b, "issuers").([]any) {
		if err := Structure(g, "genesis"); err != nil {
			return nil, err
		}
	}
	// Everything above defines the identity, so malformation there is fatal. An attestation or
	// binding is written by an issuer or a counterparty, not by the identity: a malformed one is
	// discarded and counted, exactly as a bad signature would be. One world's bug must not sink
	// its members' bundles (§9 step 2).
	attestations, bindings := field(b, "attestations").([]any), field(b, "bindings").([]any)
	badAttestations := malformed(attestations, "attestation", "sig")
	badBindings := malformed(bindings, "binding", "sig_id")
	// 3. Chain
	chain, recovery, err := resolveChain(g0, rotations)
	if err != nil {
		return nil, err
	}
	genesisOf := map[string]Object{d0: g0}
	for _, r := range rotations {
		genesisOf[did(r.nextGenesis)] = r.nextGenesis
	}
	// 4. Issuers — derived by hashing, so no key/value pair can disagree (SPEC §8). A locally
	// known genesis wins over the presented copy; honest copies are identical anyway.
	issuers := map[string]Object{}
	for k, g := range knownIssuers {
		issuers[k] = g
	}
	for _, g := range field(b, "issuers").([]any) {
		if _, known := issuers[did(g)]; !known {
			issuers[did(g)] = g.(Object)
		}
	}
	res := &Result{Chain: chain, DID: chain[len(chain)-1], Attestations: map[string][]Object{}, Bindings: []BindingResult{}}
	if s, ok := recovery.(string); ok {
		res.Recovery = &s
	}
	inWindow := func(body Object) bool {
		return field(body, "iat").(int64) <= now && now < field(body, "exp").(int64)
	}
	// 5. Attestations — discarded individually; one bad attestation does not sink a bundle.
	for i, a := range attestations {
		if badAttestations[i] {
			res.Rejected.Attestations++
			continue
		}
		body := field(a.(Object), "body").(Object)
		iss, known := issuers[field(body, "iss").(string)]
		if !known || !VerifySig(field(iss, "key"), body, field(a.(Object), "sig")) ||
			!inWindow(body) || !slices.Contains(chain, field(body, "sub").(string)) {
			res.Rejected.Attestations++
			continue
		}
		issDID := field(body, "iss").(string) // grouped by iss, in bundle order (§9.1)
		res.Attestations[issDID] = append(res.Attestations[issDID], body)
	}
	// 6. Bindings
	for i, x := range bindings {
		if badBindings[i] {
			res.Rejected.Bindings++
			continue
		}
		env := x.(Object)
		body := field(env, "body").(Object)
		id := field(body, "id").(string)
		g, known := genesisOf[id]
		if !known || !slices.Contains(chain, id) || !VerifySig(field(g, "key"), body, field(env, "sig_id")) || !inWindow(body) {
			res.Rejected.Bindings++
			continue
		}
		sigAddr, present := env.Get("sig_addr")
		proof, ok := "proven", true
		switch method := field(body, "method"); {
		case !present:
			proof = "unproven" // a claim only — MUST NOT be paid
		case method == "ed25519-test":
			ok = VerifySig(field(body, "addr"), body, sigAddr)
		case method == "monero":
			// §6.2: a Monero wallet signature (SigV2) over the same §3 signing input, checked
			// with Monero's routine against the binding's own `addr`, not with Ed25519.
			ok = VerifySigeloMoneroSigAddr(body, field(body, "addr").(string), sigAddr).Good
		default:
			proof = "unsupported" // sig_addr present, no routine for this method (§6.1)
		}
		if !ok {
			res.Rejected.Bindings++ // §6.1: a bad proof is not the same thing as no proof
			continue
		}
		res.Bindings = append(res.Bindings, BindingResult{body, proof})
	}
	// 7. Return. No scores, no ranking — weighting is the caller's job.
	return res, nil
}

// Value is the §9.1 result as a JSON value, for Canonicalize or comparison.
func (r *Result) Value() Object {
	var rec any
	if r.Recovery != nil {
		rec = *r.Recovery
	}
	atts := Object{}
	for iss, bodies := range r.Attestations {
		list := []any{}
		for _, a := range bodies {
			list = append(list, a)
		}
		atts = append(atts, Member{iss, list})
	}
	binds := []any{}
	for _, x := range r.Bindings {
		binds = append(binds, Object{{"body", x.Body}, {"proof", x.Proof}})
	}
	chain := []any{}
	for _, d := range r.Chain {
		chain = append(chain, d)
	}
	return Object{{"did", r.DID}, {"chain", chain}, {"recovery", rec}, {"attestations", atts}, {"bindings", binds},
		{"rejected", Object{{"attestations", r.Rejected.Attestations}, {"bindings", r.Rejected.Bindings}}}}
}

// MarshalJSON writes the §9.1 result in JCS form.
func (r *Result) MarshalJSON() ([]byte, error) { return Canonicalize(r.Value()) }
