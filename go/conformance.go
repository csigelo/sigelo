package sigelo

// The conformance run over test-vectors.json (and, when given, ts/test/monero-vectors.json):
// every vector checked the way the reference verifier checks it, one "PASS <name>" or
// "FAIL <name>" line each. `go test` (TestVectors) and `sigelo-verify --conformance` both call
// Conformance, so the lines an implementer sees from the binary are the lines CI sees. Its
// PASS-line names are those of the former Python reference, so a port can diff its output
// against this one line by line.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"filippo.io/edwards25519"
)

// ConformanceReport counts the lines Conformance printed. Fatal is set when the run could not
// continue (an unreadable vectors file, a vector the checks depend on that does not verify);
// it is also printed as a FAIL line and counted in Failed.
type ConformanceReport struct {
	Passed, Failed int
	Fatal          error
}

// OK is true when every check passed and nothing was fatal.
func (r ConformanceReport) OK() bool { return r.Failed == 0 && r.Fatal == nil && r.Passed > 0 }

type conformance struct {
	w      io.Writer
	monero any // parsed ts/test/monero-vectors.json, or nil to skip that section
	rep    ConformanceReport
}

type conformanceFatal struct{ err error }

// Conformance runs every vector in `vectors` (the text of test-vectors.json) and, if
// moneroVectors is non-nil, the §6.2 section over ts/test/monero-vectors.json. It writes one
// PASS/FAIL line per check to w and never reads a clock: the `now` in the file is used.
func Conformance(w io.Writer, vectors, moneroVectors []byte) (rep ConformanceReport) {
	cr := &conformance{w: w}
	defer func() {
		if x := recover(); x != nil {
			f, isFatal := x.(conformanceFatal)
			if !isFatal {
				f = conformanceFatal{fmt.Errorf("panic: %v", x)} // a malformed vectors file must not crash the CLI
			}
			cr.check("fatal: "+f.err.Error(), false)
			cr.rep.Fatal = f.err
		}
		rep = cr.rep
	}()
	// Lenient: the vectors file is data ABOUT bodies, not a body, and must be able to carry the
	// "__proto__" negative cases (floats parse either way). Parse is exercised on the `raw` cases.
	d, err := parse(vectors, false)
	if err != nil {
		cr.fatal(fmt.Errorf("vectors file: %v", err))
	}
	if moneroVectors != nil {
		if cr.monero, err = parse(moneroVectors, false); err != nil {
			cr.fatal(fmt.Errorf("monero vectors file: %v", err))
		}
	}
	cr.vectors(d)
	return
}

func (cr *conformance) check(name string, c bool) {
	if c {
		fmt.Fprintln(cr.w, "PASS "+name)
		cr.rep.Passed++
	} else {
		fmt.Fprintln(cr.w, "FAIL "+name)
		cr.rep.Failed++
	}
}

// rejects is py's rejects(): the call must fail, and its error must carry `want`.
func (cr *conformance) rejects(name string, err error, want string) {
	if err == nil {
		cr.check(name, false)
		return
	}
	cr.check(fmt.Sprintf("%s (%v)", name, err), strings.Contains(err.Error(), want))
}

func (cr *conformance) fatal(err error) { panic(conformanceFatal{err}) }

func (cr *conformance) mustVerify(bundle any, now int64) *Result {
	r, err := Verify(bundle, now, nil)
	if err != nil {
		cr.fatal(fmt.Errorf("verify: %v", err))
	}
	return r
}

// at walks Objects by key.
func at(v any, path ...string) any {
	for _, k := range path {
		o, _ := v.(Object)
		v, _ = o.Get(k)
	}
	return v
}
func obj(v any, path ...string) Object  { o, _ := at(v, path...).(Object); return o }
func str_(v any, path ...string) string { s, _ := at(v, path...).(string); return s }

func canon(v any) string { b, _ := Canonicalize(v); return string(b) }

func sign(seedHex string, body any) string {
	seed, _ := hex.DecodeString(seedHex)
	in, _ := SigningInput(body)
	return "z" + b58encode(ed25519.Sign(ed25519.NewKeyFromSeed(seed), in))
}

func rot(v Object) rotation {
	s, _ := v.Get("sig")
	return rotation{obj(v, "body"), s.(string), obj(v, "next_genesis")}
}

func chainOf(g0 Object, rs []rotation) ([]string, error) {
	c, _, err := resolveChain(g0, rs)
	return c, err
}

func sameChain(got []string, want any) bool { return canon(toAny(got)) == canon(want) }

func toAny(ss []string) []any {
	out := []any{}
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}

func proofs(r *Result) []string {
	var out []string
	for _, b := range r.Bindings {
		out = append(out, b.Proof)
	}
	return out
}

func (cr *conformance) vectors(d any) {
	P, N, NOW := obj(d, "vectors"), obj(d, "negative"), at(d, "now").(int64)

	// genesis
	G := map[string]Object{}
	for _, g := range []string{"genesis", "world_genesis", "member_genesis"} {
		cr.check(g+" did", did(obj(P, g, "doc")) == str_(P, g, "expect_did"))
		G[str_(P, g, "expect_did")] = obj(P, g, "doc")
	}
	ROT := []string{"rotation_voluntary", "rotation_hostile", "rotation_hostile_carried", "rotation_recovery", "rotation_recovery_second"}
	for _, r := range ROT {
		G[did(obj(P, r, "next_genesis"))] = obj(P, r, "next_genesis")
	}
	keyof := func(D string) string { return str_(G[D], "key") }

	// attestation / binding
	a := obj(P, "attestation")
	cr.check("attestation sig", VerifySig(keyof(str_(a, "body", "iss")), at(a, "body"), at(a, "sig")))
	u := obj(P, "attestation_unicode")
	cr.check("attestation_unicode canonical bytes", canon(at(u, "body")) == str_(u, "canonical"))
	in, _ := SigningInput(at(u, "body"))
	h := sha256.Sum256(in)
	cr.check("attestation_unicode signing-input hash", hex.EncodeToString(h[:]) == str_(u, "signing_input_sha256"))
	cr.check("attestation_unicode sig", VerifySig(keyof(str_(u, "body", "iss")), at(u, "body"), at(u, "sig")))
	iv := obj(P, "invoice")
	if err := Structure(at(iv, "body"), "invoice"); err != nil {
		cr.fatal(err)
	}
	cr.check("invoice sig", VerifySig(keyof(str_(iv, "body", "did")), at(iv, "body"), at(iv, "sig")))
	cr.rejects("invoice body is not a binding", Structure(at(iv, "body"), "binding"), "binding:")
	ch := obj(P, "challenge")
	if err := Structure(at(ch, "body"), "challenge"); err != nil {
		cr.fatal(err)
	}
	cr.check("challenge sig", VerifySig(keyof(str_(ch, "body", "did")), at(ch, "body"), at(ch, "sig")))
	typ := str_(ch, "body", "typ")
	cr.check("challenge typ never a bundle slot", typ != "genesis" && typ != "rotation" && typ != "binding" && typ != "attestation")
	b := obj(P, "binding")
	cr.check("binding sig_id", VerifySig(keyof(str_(b, "body", "id")), at(b, "body"), at(b, "sig_id")))
	cr.check("binding sig_addr", VerifySig(str_(b, "body", "addr"), at(b, "body"), at(b, "sig_addr")))
	un := obj(P, "binding_unproven")
	_, hasAddr := un.Get("sig_addr")
	cr.check("unproven binding sig_id", VerifySig(keyof(str_(un, "body", "id")), at(un, "body"), at(un, "sig_id")) && !hasAddr)
	// §6.2 from the vectors file. One Verify call so the proof STATUS is pinned, not just the
	// signature: a verifier that reported this `unproven` would still pass a raw sig check.
	bm := obj(P, "binding_monero")
	xb1 := func(e Object) Object { // the envelope only: §3.1 discards one carrying the vector's annotations
		env := Object{{"body", at(e, "body")}, {"sig_id", at(e, "sig_id")}, {"sig_addr", at(e, "sig_addr")}}
		return Object{{"v", Version}, {"typ", "bundle"}, {"genesis", obj(P, "genesis", "doc")}, {"rotations", []any{}},
			{"bindings", []any{env}}, {"attestations", []any{}}, {"issuers", []any{}}}
	}
	rbm := cr.mustVerify(xb1(bm), NOW)
	cr.check("binding_monero verifies as proven, view mode",
		fmt.Sprint(proofs(rbm)) == fmt.Sprint([]string{str_(bm, "expect_proof")}) && rbm.Rejected.Bindings == 0 &&
			VerifySigeloMoneroSigAddr(at(bm, "body"), str_(bm, "body", "addr"), at(bm, "sig_addr")).Mode == str_(bm, "expect_mode"))
	// §6.2 subaddress (0,1) of the same wallet, one binding per mode, each signed over the
	// subaddress's own (D, C). The keys are inside the hash, so neither verifies under the base.
	for _, n := range []string{"binding_monero_subaddress_spend", "binding_monero_subaddress_view"} {
		e := obj(P, n)
		r := cr.mustVerify(xb1(e), NOW)
		da, err := DecodeAddress(str_(e, "body", "addr"))
		cr.check(n+" verifies as proven, "+str_(e, "expect_mode")+" mode",
			err == nil && da.Kind == "subaddress" && fmt.Sprint(proofs(r)) == fmt.Sprint([]string{str_(e, "expect_proof")}) &&
				r.Rejected.Bindings == 0 && VerifySigeloMoneroSigAddr(at(e, "body"), str_(e, "body", "addr"), at(e, "sig_addr")).Mode == str_(e, "expect_mode"))
		cr.check(n+" sig_addr does not verify under the base address",
			!VerifySigeloMoneroSigAddr(at(e, "body"), str_(bm, "body", "addr"), at(e, "sig_addr")).Good)
	}

	// chain
	R := func(n string) rotation { return rot(obj(P, n)) }
	var all []rotation
	for _, n := range ROT {
		all = append(all, R(n))
	}
	g0 := obj(P, "genesis", "doc")
	c, _ := chainOf(g0, all)
	cr.check("chain resolves to expected", sameChain(c, at(P, "expected_chain")))
	for _, hn := range []string{"rotation_hostile", "rotation_hostile_carried"} {
		cr.check(hn+" sig is valid (must lose on rules, not crypto)", VerifySig(keyof(str_(P, hn, "body", "id")), at(P, hn, "body"), at(P, hn, "sig")))
		cr.check("recovery iat < "+hn+" iat", at(P, "rotation_recovery", "body", "iat").(int64) < at(P, hn, "body", "iat").(int64))
	}
	cp := obj(P, "chain_precedence_only")
	var cps []rotation
	for _, n := range at(cp, "rotations").([]any) {
		cps = append(cps, R(n.(string)))
	}
	c, _ = chainOf(g0, cps)
	cr.check("chain_precedence_only", sameChain(c, at(cp, "expected_chain")))

	// every vector carrying a bundle + expect
	for _, m := range P {
		if bv, isObj := m.Value.(Object); isObj {
			if _, has := bv.Get("bundle"); has {
				r, err := Verify(at(bv, "bundle"), at(bv, "now").(int64), nil)
				cr.check(m.Key+" verify == expect", err == nil && canon(r.Value()) == canon(at(bv, "expect")))
			}
		}
	}

	// negatives
	w := keyof(str_(a, "body", "iss"))
	neg := func(n string) Object { return obj(N, n) }
	cr.check("neg tampered_claims", !VerifySig(w, at(neg("tampered_claims"), "body"), at(neg("tampered_claims"), "sig")))
	cr.check("neg wrong_signer", !VerifySig(w, at(neg("wrong_signer"), "body"), at(neg("wrong_signer"), "sig")))
	cr.check("neg missing_prefix", !VerifySig(w, at(neg("missing_prefix"), "body"), at(neg("missing_prefix"), "sig")))
	cr.check("neg genesis_tampered", did(obj(N, "genesis_tampered", "doc")) != str_(N, "genesis_tampered", "claimed_did"))
	cr.rejects("neg float_in_claims", Structure(at(N, "float_in_claims", "body"), "attestation"), "non-integer")
	cr.rejects("neg int_out_of_range", Structure(at(N, "int_out_of_range", "body"), "attestation"), "2^53")
	_, err := Parse([]byte(str_(N, "duplicate_key", "raw")))
	if err == nil {
		cr.check("neg duplicate_key", false)
	} else {
		cr.check(fmt.Sprintf("neg duplicate_key (%v)", err), strings.Contains(err.Error(), "duplicate"))
	}
	tm := neg("typ_mismatch")
	cr.check("neg typ_mismatch", VerifySig(w, at(tm, "body"), at(tm, "sig")) && str_(tm, "body", "typ") != "attestation")
	NR := func(n string) rotation { return rot(neg(n)) }
	// "not a candidate" rotations: each states the chain that results (§7.4)
	for _, n := range []string{"recovery_key_mismatch", "stale_recovery_key", "voluntary_changes_recovery", "rotation_bad_sig"} {
		if err := Structure(at(neg(n), "body"), "rotation"); err != nil {
			cr.fatal(err)
		}
		var rs []rotation
		for _, x := range at(neg(n), "chain_with").([]any) {
			rs = append(rs, R(x.(string)))
		}
		c, _ := chainOf(g0, append(rs, NR(n)))
		cr.check(fmt.Sprintf("neg %s -> chain %d", n, len(at(neg(n), "expected_chain").([]any))), sameChain(c, at(neg(n), "expected_chain")))
	}
	cr.rejects("neg unknown_field_attestation", Structure(at(N, "unknown_field_attestation", "body"), "attestation"), "unknown field")
	cr.rejects("neg unknown_field_genesis", Structure(at(N, "unknown_field_genesis", "doc"), "genesis"), "unknown field")
	_, err = chainOf(g0, []rotation{R("rotation_voluntary"), NR("fork")})
	cr.rejects("neg fork", err, "fork")
	_, err = chainOf(g0, []rotation{R("rotation_voluntary"), NR("cycle")})
	cr.rejects("neg cycle", err, "cycle")
	cr.rejects("neg self_rotation", Structure(at(N, "self_rotation", "body"), "rotation"), "next == id")
	ex := neg("expired_attestation")
	cr.check("neg expired", !(at(ex, "body", "iat").(int64) <= NOW && NOW < at(ex, "body", "exp").(int64)))
	// §3.1/§6.3: amount is a string of atomic units. Each body's signature is VALID; only the
	// structural check stands between a float-shaped amount and two languages disagreeing on it.
	for _, n := range []string{"invoice_amount_number", "invoice_amount_float_string", "invoice_amount_negative", "invoice_amount_empty"} {
		cr.check("neg "+n+" sig is valid (must lose on structure, not crypto)", VerifySig(keyof(str_(N, n, "body", "did")), at(N, n, "body"), at(N, n, "sig")))
		cr.rejects("neg "+n, Structure(at(N, n, "body"), "invoice"), "atomic units")
	}
	envelope := func(e Object, keys ...string) Object {
		var out Object
		for _, k := range keys {
			if v, has := e.Get(k); has {
				out = append(out, Member{k, v})
			}
		}
		return out
	}
	// §6.2: Monero signatures that must not make a binding `proven`. Discarded per-item
	// (§6.1: a bad proof is not no proof), never downgraded.
	for _, n := range []string{"binding_monero_subaddress_base_sig", "binding_monero_integrated_addr", "binding_monero_sigv1",
		"binding_monero_view_key_y_ge_p", "binding_monero_spend_key_x0_signbit"} {
		r := cr.mustVerify(xb1(envelope(neg(n), "body", "sig_id", "sig_addr")), NOW)
		cr.check("neg "+n+" discarded, not downgraded", len(r.Bindings) == 0 && r.Rejected.Bindings == 1)
	}
	// The same sig_addr under wallet2's own rules still verifies: the rule is sigelo's, not Monero's.
	ni := neg("binding_monero_integrated_addr")
	iin, _ := SigningInput(at(ni, "body"))
	cr.check("neg binding_monero_integrated_addr is a signature monero itself accepts", VerifyMessage(iin, str_(ni, "body", "addr"), str_(ni, "sig_addr")).Good)
	// The base-keyed sig_addr is genuine — it verifies under the base address — and wallet2 itself
	// refuses it under the subaddress: the wrong keys, not a sigelo-only rule.
	sb := neg("binding_monero_subaddress_base_sig")
	sbin, _ := SigningInput(at(sb, "body"))
	cr.check("neg binding_monero_subaddress_base_sig is genuine under the base address, refused by monero under the subaddress",
		VerifyMessage(sbin, str_(bm, "body", "addr"), str_(sb, "sig_addr")).Good && !VerifyMessage(sbin, str_(sb, "body", "addr"), str_(sb, "sig_addr")).Good)
	s1 := neg("binding_monero_sigv1")
	s1in, _ := SigningInput(at(s1, "body"))
	cr.check("neg binding_monero_sigv1 is a signature monero itself accepts",
		VerifyMessage(s1in, str_(s1, "body", "addr"), str_(s1, "sig_addr")) == MsgResult{Good: true, Mode: "spend", Version: 1})
	// ge_frombytes_vartime (src/crypto/crypto-ops.c), via check_key on both address keys, refuses
	// y >= p and x = 0 with the sign bit set. Each sig_addr is genuine by the mode's own (valid)
	// key, which a decoder permissive about the other key accepts: SetBytes is that decoder.
	permissive := func(e Object, mode string) bool {
		raw, _ := MoneroBase58Decode(str_(e, "body", "addr"))
		B, A := raw[1:33], raw[33:65] // 1-byte prefix 18
		sg, _ := MoneroBase58Decode(str_(e, "sig_addr")[5:])
		pub := map[string][]byte{"spend": B, "view": A}[mode]
		P, err := new(edwards25519.Point).SetBytes(pub)
		c, err1 := edwards25519.NewScalar().SetCanonicalBytes(sg[:32])
		r, err2 := edwards25519.NewScalar().SetCanonicalBytes(sg[32:])
		in, _ := SigningInput(at(e, "body"))
		R := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(c, P, r)
		return err == nil && err1 == nil && err2 == nil && bytes.Equal(HashToScalar(MessageHash(B, A, mode, in), pub, R.Bytes()), sg[:32])
	}
	for _, x := range []struct{ n, mode, key string }{
		{"binding_monero_view_key_y_ge_p", "spend", "ed" + strings.Repeat("ff", 30) + "7f"},
		{"binding_monero_spend_key_x0_signbit", "view", "01" + strings.Repeat("00", 30) + "80"},
	} {
		e := neg(x.n)
		raw, _ := MoneroBase58Decode(str_(e, "body", "addr"))
		refused := raw[1:33]
		if x.mode == "spend" {
			refused = raw[33:65]
		}
		cr.check("neg "+x.n+" sig_addr is genuine under a decoder permissive about the refused key (must lose on the key, not crypto)",
			VerifySig(keyof(str_(e, "body", "id")), at(e, "body"), at(e, "sig_id")) && permissive(e, x.mode) && hex.EncodeToString(refused) == x.key)
		_, err := DecodeAddress(str_(e, "body", "addr"))
		cr.rejects("neg "+x.n+": decodeAddress refuses the key, as check_key does", err, "not a canonical curve point")
		in, _ := SigningInput(at(e, "body"))
		cr.check("neg "+x.n+": verifyMessage (wallet2) refuses it too", !VerifyMessage(in, str_(e, "body", "addr"), str_(e, "sig_addr")).Good)
	}
	// §3.1 field types. Each binding has a VALID sig_id and a genuine SigV2 sig_addr from the
	// vectors' wallet: it must lose on structure (the varint spelling: at §6.2), never on crypto.
	for _, m := range N {
		e, _ := m.Value.(Object)
		reject, hasReject := e.Get("reject")
		if _, hasSigID := e.Get("sig_id"); !hasReject || !hasSigID {
			continue
		}
		ein, _ := SigningInput(at(e, "body"))
		cr.check("neg "+m.Key+" sig_id valid and sig_addr a genuine wallet signature (must lose on rules, not crypto)",
			VerifySig(keyof(str_(e, "body", "id")), at(e, "body"), at(e, "sig_id")) &&
				VerifyMessage(ein, str_(P, "binding_monero", "body", "addr"), str_(e, "sig_addr")).Good)
		if reject != nil {
			cr.rejects("neg "+m.Key, Structure(at(e, "body"), "binding"), reject.(string))
		}
		r := cr.mustVerify(xb1(envelope(e, "body", "sig_id", "sig_addr")), NOW)
		cr.check("neg "+m.Key+" discarded by verify", len(r.Bindings) == 0 && r.Rejected.Bindings == 1)
	}
	if _, err := DecodeAddress(str_(N, "binding_monero_noncanonical_varint_addr", "body", "addr")); err == nil {
		cr.check("neg noncanonical varint decoded", false)
	} else {
		cr.check(fmt.Sprintf("neg binding_monero_noncanonical_varint_addr: decode_address refuses it, as wallet2 does (%v)", err),
			strings.Contains(err.Error(), "non-canonical"))
	}
	e := neg("invoice_memo_lone_surrogate")
	lv, err := Parse([]byte(str_(e, "raw")))
	if err != nil {
		cr.fatal(err)
	}
	lone := lv.(Object)
	cr.check("neg invoice_memo_lone_surrogate sig is valid over the U+FFFD twin (the old collision)",
		VerifySig(keyof(str_(lone, "did")), lone.With("memo", "�"), at(e, "sig")) && !VerifySig(keyof(str_(lone, "did")), lone, at(e, "sig")))
	cr.rejects("neg invoice_memo_lone_surrogate", Structure(lone, "invoice"), str_(e, "reject"))
	e = neg("invoice_memo_not_string")
	cr.check("neg invoice_memo_not_string sig is valid", VerifySig(keyof(str_(e, "body", "did")), at(e, "body"), at(e, "sig")))
	cr.rejects("neg invoice_memo_not_string", Structure(at(e, "body"), "invoice"), str_(e, "reject"))
	if _, err := Parse([]byte(str_(N, "proto_key", "raw"))); err == nil {
		cr.check("neg proto_key", false)
	} else {
		cr.check(fmt.Sprintf("neg proto_key (%v)", err), strings.Contains(err.Error(), "__proto__"))
	}
	// Parity: the same malformed bundles through Verify here and in ts/.
	pnow := at(N, "parity", "now").(int64)
	for _, m := range obj(N, "parity", "cases") {
		c := m.Value.(Object)
		bundle, err := at(c, "bundle"), error(nil)
		var r *Result
		if raw, isRaw := c.Get("raw"); isRaw { // bundle TEXT: a parse failure (duplicate key) is fatal
			bundle, err = Parse([]byte(raw.(string)))
		}
		if err == nil {
			r, err = Verify(bundle, pnow, nil)
		}
		if err != nil {
			want, _ := at(c, "expect", "reject").(string)
			cr.check(fmt.Sprintf("parity %s (%v)", m.Key, err), want != "" && strings.Contains(err.Error(), want))
			continue
		}
		n := 0
		for _, bodies := range r.Attestations {
			n += len(bodies)
		}
		got := Object{{"proofs", toAny(proofs(r))}, {"rejected", Object{{"attestations", r.Rejected.Attestations}, {"bindings", r.Rejected.Bindings}}},
			{"attestations", n}}
		cr.check("parity "+m.Key, canon(got) == canon(at(c, "expect")))
	}
	cr.rejects("neg genesis_bad_key", Structure(at(N, "genesis_bad_key", "doc"), "genesis"), "ed25519-pub")
	_, err = Verify(at(N, "bundle_rotations_not_array", "bundle"), NOW, nil)
	cr.rejects("neg bundle_rotations_not_array", err, "not an array")

	if cr.monero == nil {
		fmt.Fprintln(cr.w, "SKIP monero section: no monero-vectors.json given")
		return
	}
	cr.moneroSection(d, P, NOW)
}

// testMonero is py's "monero (SPEC §6.2)" section. ts/test/monero-vectors.json comes from
// monero-ts 0.11.15 — Monero's own C++ core compiled to WASM — restored from the documented
// private spend key. Signatures use a random nonce, so the target is that this verifier
// accepts what monero itself produced and rejects what monero rejects.
func (cr *conformance) moneroSection(d any, P Object, NOW int64) {
	X := cr.monero
	seed, _ := hex.DecodeString(str_(X, "private_spend_key"))
	mk, _ := KeysFromSpend(seed)
	hexs := func(b []byte) string { return hex.EncodeToString(b) }
	cr.check("monero keccak256(\"\") is Keccak, not SHA3-256",
		hexs(Keccak256(nil)) == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
	rt, _ := MoneroBase58Decode(MoneroBase58Encode([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa}))
	cr.check("monero base58 round-trips an 8+3 byte split", hexs(rt) == "00112233445566778899aa")
	for _, m := range obj(X, "networks") {
		net, v := m.Key, m.Value.(Object)
		cr.check("monero "+net+" keys_from_spend: a = H_s(b), B = bG, A = aG",
			hexs(mk.View) == str_(v, "private_view_key") && hexs(mk.SpendPub) == str_(v, "public_spend_key") && hexs(mk.ViewPub) == str_(v, "public_view_key"))
		primary, _ := EncodeAddress(net, "standard", mk.SpendPub, mk.ViewPub, nil)
		cr.check("monero "+net+" primary address", primary == str_(v, "primary_address"))
		dec, err := DecodeAddress(primary)
		cr.check("monero "+net+" decode_address round-trips and reports kind/net", err == nil && dec.Net == net && dec.Kind == "standard" &&
			dec.PaymentID == nil && hexs(dec.Spend) == str_(v, "public_spend_key") && hexs(dec.View) == str_(v, "public_view_key"))
		// An integrated address is the same two keys plus an 8-byte payment id, prefix + 1.
		pid, _ := hex.DecodeString("0123456789abcdef")
		ia, _ := EncodeAddress(net, "integrated", mk.SpendPub, mk.ViewPub, pid)
		di, err := DecodeAddress(ia)
		cr.check("monero "+net+" integrated address round-trips its payment id", err == nil && di.Kind == "integrated" && hexs(di.PaymentID) == "0123456789abcdef")
		subs := obj(v, "subaddresses")
		good := 0
		for _, s := range subs {
			var major, minor uint32
			fmt.Sscanf(s.Key, "%d/%d", &major, &minor)
			got, _ := Subaddress(mk.View, mk.SpendPub, major, minor, net)
			if da, err := DecodeAddress(s.Value.(string)); got == s.Value && err == nil && da.Kind == "subaddress" {
				good++
			}
		}
		cr.check(fmt.Sprintf("monero %s %d subaddresses", net, len(subs)), good == len(subs))
		// (0,0) is the account's own address, never derived (src/device/device_default.cpp).
		s00addr, _ := Subaddress(mk.View, mk.SpendPub, 0, 0, net)
		cr.check("monero "+net+" subaddress (0,0) is the primary address", s00addr == str_(v, "primary_address"))
		sigs := at(v, "signatures").([]any)
		good = 0
		var s00 Object
		for _, g := range sigs {
			g := g.(Object)
			if at(g, "oracle_verify") == true && at(g, "oracle_version") == int64(2) &&
				VerifyMessage([]byte(str_(g, "message")), str_(g, "address"), str_(g, "signature")) == (MsgResult{true, str_(g, "mode"), 2}) {
				good++
			}
			if s00 == nil && at(g, "account") == int64(0) && at(g, "index") == int64(0) {
				s00 = g
			}
		}
		cr.check(fmt.Sprintf("monero %s all %d oracle SigV2 signatures verify with the right mode", net, len(sigs)), good == len(sigs) && good == 18)
		negs := at(v, "negative").([]any)
		msg, sig := str_(s00, "message"), str_(s00, "signature")
		cr.check("monero "+net+" neg: "+str_(negs[0], "what"), !VerifyMessage([]byte(msg), str_(subs, "0/1"), sig).Good)
		cr.check("monero "+net+" neg: "+str_(negs[1], "what"), !VerifyMessage([]byte(msg+"!"), str_(s00, "address"), sig).Good)
		mut := sig[:len(sig)-1] + "A"
		if strings.HasSuffix(sig, "A") {
			mut = sig[:len(sig)-1] + "B"
		}
		cr.check("monero "+net+" tampered signature fails", !VerifyMessage([]byte(msg), str_(s00, "address"), mut).Good)
	}
	// Surprising and load-bearing for §6.2: the hash covers the address's two public keys, not
	// its prefix, so one wallet's mainnet, stagenet and testnet spellings are interchangeable
	// for verification. A verifier that cares which network must check DecodeAddress(addr).Net.
	mp := str_(X, "networks", "mainnet", "primary_address")
	ms := obj(at(X, "networks", "mainnet", "signatures").([]any)[0].(Object))
	cr.check("monero a signature verifies under every network spelling of the same keys",
		VerifyMessage([]byte(str_(ms, "message")), str_(X, "networks", "stagenet", "primary_address"), str_(ms, "signature")).Good)
	// §6.2 accepts every oracle signature above, subaddresses included (each message is a §3 input).
	msgBody := func(msg string) any { v, _ := Parse([]byte(strings.TrimPrefix(msg, "sigelo\n"))); return v }
	sg, total := 0, 0
	for _, net := range []string{"mainnet", "stagenet", "testnet"} {
		for _, g := range at(X, "networks", net, "signatures").([]any) {
			total++
			r := VerifySigeloMoneroSigAddr(msgBody(str_(g, "message")), str_(g, "address"), str_(g, "signature"))
			if strings.HasPrefix(str_(g, "message"), "sigelo\n") && r.Good && r.Mode == str_(g, "mode") {
				sg++
			}
		}
	}
	cr.check(fmt.Sprintf("monero verifySigeloMoneroSigAddr accepts all %d oracle signatures, subaddresses included", total), sg == total && total == 54)
	// A live monero-wallet-rpc (stagenet) as a second oracle: its stateless `verify` on the §6.2
	// vectors, and its own `sign` for a standard and a subaddress in both modes (wallet2::sign's
	// subaddress branch). Integrated is where sigelo parts from wallet2 on purpose.
	wr := at(X, "wallet_rpc_oracle", "entries").([]any)
	wsub := 0
	for _, e := range wr {
		msg, addr, sig := str_(e, "message"), str_(e, "address"), str_(e, "signature")
		w := VerifyMessage([]byte(msg), addr, sig)
		g := VerifySigeloMoneroSigAddr(msgBody(msg), addr, sig)
		da, err := DecodeAddress(addr)
		rg, acc := at(e, "rpc_verify", "good") == true, at(e, "sigelo_accepts") == true
		verdict := map[bool]string{true: "accepts", false: "refuses"}[acc]
		cr.check(fmt.Sprintf("monero wallet-rpc oracle: %s (rpc good=%v, sigelo %s)", str_(e, "what"), rg, verdict),
			err == nil && da.Kind == str_(e, "kind") && w.Good == rg && (!w.Good || w.Mode == str_(e, "rpc_verify", "signature_type")) && g.Good == acc)
		if str_(e, "kind") == "subaddress" && at(e, "index") == int64(1) && rg {
			wsub++
		}
	}
	cr.check("monero wallet-rpc oracle covers subaddress spend+view signatures from the wallet itself", wsub == 2 && len(wr) == 9)
	// The encoders, unlike the verifiers, do fail — MoneroError, naming the failing check.
	rejectsXMR := func(name string, err error, want string) {
		if err == nil {
			cr.check(name+" (accepted!)", false)
			return
		}
		cr.check(fmt.Sprintf("%s (%v)", name, err), strings.Contains(err.Error(), want))
	}
	_, err := DecodeAddress(mp[:len(mp)-1] + "x")
	rejectsXMR("monero address with a corrupted digit", err, "checksum")
	body := append([]byte{99}, make([]byte, 64)...)
	_, err = DecodeAddress(MoneroBase58Encode(append(body, Keccak256(body)[:4]...)))
	rejectsXMR("monero address with an unknown prefix", err, "unknown prefix")
	// Round-trip through our own signer. The nonce is random, so this is the only way to test it.
	xm := []byte("sigelo\n{\"typ\":\"binding\",\"v\":\"sigelo/0\"}")
	sv, _ := SignMessage(xm, "view", mk.View, mk.SpendPub, mk.ViewPub, nil)
	cr.check("monero sign_message(view) verifies, reported as mode view", strings.HasPrefix(sv, "SigV2") &&
		VerifyMessage(xm, mp, sv) == MsgResult{true, "view", 2})
	ss, _ := SignMessage(xm, "spend", mk.Spend, mk.SpendPub, mk.ViewPub, nil)
	cr.check("monero sign_message(spend) verifies, reported as mode spend", VerifyMessage(xm, mp, ss) == MsgResult{true, "spend", 2})
	cr.check("monero our own signature does not verify under another message", !VerifyMessage(append(xm, ' '), mp, ss).Good)

	// A real §6.2 binding end to end: the identity key signs sig_id, the wallet signs sig_addr
	// over the identical §3 signing input, and Verify reports `proven`.
	xb := Object{{"v", Version}, {"typ", "binding"}, {"id", str_(P, "genesis", "expect_did")}, {"method", "monero"},
		{"addr", mp}, {"iat", NOW - 60}, {"exp", NOW + 86400}, {"nonce", "z2Nuar5"}}
	xsig := sign(str_(d, "seeds", "agent"), xb)
	xbundle := func(sa *string) Object {
		env := Object{{"body", xb}, {"sig_id", xsig}}
		if sa != nil {
			env = append(env, Member{"sig_addr", *sa})
		}
		return Object{{"v", Version}, {"typ", "bundle"}, {"genesis", obj(P, "genesis", "doc")}, {"rotations", []any{}},
			{"bindings", []any{env}}, {"attestations", []any{}}, {"issuers", []any{}}}
	}
	for _, mode := range []struct {
		name   string
		secret []byte
	}{{"view", mk.View}, {"spend", mk.Spend}} {
		s, _ := SigeloMoneroSigAddr(xb, mode.name, mode.secret, mk.SpendPub, mk.ViewPub, nil)
		r := cr.mustVerify(xbundle(&s), NOW)
		cr.check("monero binding with a "+mode.name+"-mode sig_addr verifies as proven",
			len(r.Bindings) == 1 && r.Bindings[0].Proof == "proven" && r.Rejected.Bindings == 0)
	}
	// §6.1: a bad proof is not the same thing as no proof — the binding is discarded, not
	// downgraded to `unproven`. A verifier that downgraded would let a thief publish a binding
	// to an address they do not control and still have it shown.
	g_, _ := SigeloMoneroSigAddr(xb, "view", mk.View, mk.SpendPub, mk.ViewPub, nil)
	tampered := g_[:len(g_)-1] + "A"
	if strings.HasSuffix(g_, "A") {
		tampered = g_[:len(g_)-1] + "B"
	}
	rt2 := cr.mustVerify(xbundle(&tampered), NOW)
	cr.check("monero binding with a tampered sig_addr is discarded, not downgraded", len(rt2.Bindings) == 0 && rt2.Rejected.Bindings == 1)
	cr.check("monero binding without sig_addr is unproven", cr.mustVerify(xbundle(nil), NOW).Bindings[0].Proof == "unproven")
	// The verifiers never fail; only the encoders do.
	cr.check("monero verifiers return false on junk rather than raising",
		!VerifyMessage([]byte("x"), "not-an-address", "SigV2nope").Good && !VerifySigeloMoneroSigAddr(Object{}, "nope", 42).Good)
}
