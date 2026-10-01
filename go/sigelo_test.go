package sigelo

// A run over test-vectors.json and ts/test/monero-vectors.json: the reference verifier's
// conformance run, which lives in conformance.go so `sigelo-verify --conformance` prints the same
// lines (TestVectors calls it). Go-only checks follow in their own tests, named "go ...".
// TestMain prints ALL PASS.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"
)

var ok = true

func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 && ok {
		fmt.Println("\nALL PASS")
	} else {
		fmt.Println("\nFAILURES")
		code = 1
	}
	os.Exit(code)
}

func check(name string, c bool) {
	if c {
		fmt.Println("PASS " + name)
	} else {
		fmt.Println("FAIL " + name)
		ok = false
	}
}

// rejects is py's rejects(): the call must fail, and its error must carry `want`.
func rejects(name string, err error, want string) {
	if err == nil {
		check(name, false)
		return
	}
	check(fmt.Sprintf("%s (%v)", name, err), strings.Contains(err.Error(), want))
}

func load(t *testing.T, path string) any {
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Lenient: the vectors file is data ABOUT bodies, not a body, and must be able to carry the
	// "__proto__" negative cases (floats parse either way). Parse is exercised on the `raw` cases.
	v, err := parse(text, false)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustVerify(t *testing.T, bundle any, now int64) *Result {
	r, err := Verify(bundle, now, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return r
}

// TestVectors is the conformance run (conformance.go), the same one `sigelo-verify --conformance`
// prints: every vector in ../test-vectors.json and the §6.2 section over ../ts/test/monero-vectors.json.
func TestVectors(t *testing.T) {
	vectors, err := os.ReadFile("../test-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	monero, err := os.ReadFile("../ts/test/monero-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if rep := Conformance(os.Stdout, vectors, monero); !rep.OK() {
		ok = false
		if rep.Fatal != nil {
			t.Fatal(rep.Fatal)
		}
	}
}

// ---------------------------------------------------------------- Go-only checks

// TestJCS is the JCS known-answer self-test (from the former Python canonicalizer), plus
// what the Go parser has to get right on its own.
func TestJCS(t *testing.T) {
	must := func(v any) string { b, err := Canonicalize(v); check2(err == nil, err); return string(b) }
	check("go jcs: 𝄞 sorts before ～ (UTF-16 order, not code point)", must(Object{{"\U0001d11e", 1}, {"～", 2}}) == "{\"\U0001d11e\":1,\"～\":2}" &&
		must(Object{{"～", 2}, {"\U0001d11e", 1}}) == "{\"\U0001d11e\":1,\"～\":2}")
	check("go jcs: ES6 escape set, lowercase \\u00xx, raw U+007F and U+2028",
		must("\x01\b\t\n\f\r\"\\\x7f ") == "\"\\u0001\\b\\t\\n\\f\\r\\\"\\\\\x7f \"")
	check("go jcs: null, booleans and integers at both ends", must([]any{nil, true, false, 0, -1, int64(MaxInt)}) == "[null,true,false,0,-1,9007199254740991]")
	for _, bad := range []any{Object{{"x", Number("0.5")}}, Object{{"x", int64(MaxInt + 1)}}, Object{{"x", 1.5}}} {
		_, err := Canonicalize(bad)
		check(fmt.Sprintf("go jcs: canonicalize refuses %s (%v)", stringify(bad), err), err != nil)
	}
	for _, c := range []struct{ text, want string }{
		{`{"a":1,"a":2}`, "duplicate key"}, {`[{"a":{"b":1,"b":1}}]`, "duplicate key"}, {`{"a":1.}`, "expected digit"},
		{`{"a":1e}`, "expected digit"}, {`{"a":{"__proto__":{}}}`, "__proto__"},
		{"{\"a\":\"\xff\"}", "invalid UTF-8"}, {"{\"a\":\"\xed\xa0\x80\"}", "invalid UTF-8"}, {`{"a":1} x`, "trailing content"},
		{`{"a":"\x"}`, "bad escape"}, {"{\"a\":\"\x01\"}", "unescaped control"},
	} {
		_, err := Parse([]byte(c.text))
		check(fmt.Sprintf("go jcs: Parse refuses %q (%v)", c.text, err), err != nil && strings.Contains(err.Error(), c.want))
	}
	// Invariant 7: a forbidden NUMBER is not parse ambiguity. It parses (as a Number) and is
	// refused at canonicalization, so only the item holding it is malformed; "1.0" included.
	fv, err := Parse([]byte(`{"a":1.0,"b":1e2,"c":9007199254740992}`))
	check("go jcs: Parse keeps a forbidden number as a Number, not a parse error",
		err == nil && at(fv, "a") == Number("1.0") && at(fv, "b") == Number("1e2") && at(fv, "c") == Number("9007199254740992"))
	for _, c := range []struct{ k, want string }{{"a", "non-integer number 1.0"}, {"b", "non-integer number 1e2"}, {"c", "integer outside +-2^53-1: 9007199254740992"}} {
		_, err := Canonicalize(Object{{c.k, at(fv, c.k)}})
		check(fmt.Sprintf("go jcs: Canonicalize refuses a parsed %s (%v)", c.k, err), err != nil && strings.Contains(err.Error(), c.want))
	}
	v, err := Parse([]byte(`{"a":"\ud800","b":"𝄞","c":-0}`))
	_, cerr := Canonicalize(at(v, "a"))
	check(fmt.Sprintf("go jcs: a \\ud800 escape parses and is refused at canonicalization, not before (%v)", cerr),
		err == nil && cerr != nil && strings.Contains(cerr.Error(), `lone surrogate in string "\ud800"`))
	check("go jcs: an escaped surrogate PAIR is one character; -0 is 0", at(v, "b") == "\U0001d11e" && at(v, "c") == int64(0) && must(at(v, "b")) == "\"\U0001d11e\"")

	// SPEC §3 nesting depth: 512 levels, arrays and objects combined. Parse used to recurse
	// until Go's stack limit, a fatal error recover() cannot catch, near 750 000 levels.
	nest := func(n int, inner string) string { return strings.Repeat("[", n) + inner + strings.Repeat("]", n) }
	dv, err := Parse([]byte(nest(512, "")))
	check("go jcs: depth 512 parses and round-trips", err == nil && must(dv) == nest(512, ""))
	dv, err = Parse([]byte(nest(511, `{"a":1}`)))
	check("go jcs: depth 512 mixing objects and arrays parses", err == nil && must(dv) == nest(511, `{"a":1}`))
	for _, c := range []struct{ text, want string }{
		{nest(513, ""), "nesting deeper than 512 at offset 512"},
		{nest(512, "{}"), "nesting deeper than 512 at offset 512"},
		{`{"é😀":` + nest(512, "") + "}", "nesting deeper than 512 at offset 518"}, // UTF-16 units, as ts
		{nest(800_000, ""), "nesting deeper than 512 at offset 512"},
		{strings.Repeat("[", 1_000_000), "nesting deeper than 512 at offset 512"},
	} {
		_, err := Parse([]byte(c.text))
		check(fmt.Sprintf("go jcs: Parse refuses depth %d (%v)", strings.Count(c.text, "[")+strings.Count(c.text, "{"), err),
			err != nil && err.Error() == c.want)
	}
	// Differential M1: the same offset table as ts/src/test.ts — AT the offending character.
	for _, c := range []struct{ text, want string }{
		{`{"a":"\u12G4"}`, `bad \u escape at offset 7`}, {`{"a":"\u12"}`, `bad \u escape at offset 7`},
		{`{"a" 1}`, `expected ":" at offset 5`}, {`{"a":1 "b":2}`, `expected "," or "}" at offset 7`},
		{`[1 2]`, `expected "," or "]" at offset 3`}, {`["😀" 1]`, `expected "," or "]" at offset 6`},
		{`{"a":"\x"}`, `bad escape \x at offset 7`}, {`{"a":1,}`, `expected string at offset 7`}, {`[1,`, `unexpected end of input at offset 3`},
	} {
		_, err := Parse([]byte(c.text))
		check(fmt.Sprintf("go jcs: Parse %q: %s (%v)", c.text, c.want, err), err != nil && err.Error() == c.want)
	}
	// Differential S5: the same noncharacter table as ts/src/test.ts.
	for _, c := range []struct {
		cp  rune
		bad bool
	}{
		{0xfdcf, false}, {0xfdd0, true}, {0xfdef, true}, {0xfdf0, false}, {0xfffd, false}, {0xfffe, true}, {0xffff, true},
		{0x1fffe, true}, {0x1ffff, true}, {0x10000, false}, {0x10fffd, false}, {0x10fffe, true}, {0x10ffff, true}, {0xeffff, true},
	} {
		u := fmt.Sprintf("U+%04X", c.cp)
		esc := ""
		for _, x := range utf16.Encode([]rune{c.cp}) {
			esc += fmt.Sprintf(`\u%04x`, x)
		}
		for _, h := range []struct{ how, text, off string }{
			{"raw", `{"a":["x","` + string(c.cp) + `"]}`, "10"}, {"escaped", `{"a":["x","` + esc + `"]}`, "10"}, {"key", `{"a":{"` + esc + `":1}}`, "6"},
		} {
			_, err := Parse([]byte(h.text))
			if !c.bad {
				check(fmt.Sprintf("go jcs: %s %s parses (%v)", u, h.how, err), err == nil)
			} else {
				check(fmt.Sprintf("go jcs: %s %s is a parse error (%v)", u, h.how, err), err != nil && err.Error() == "noncharacter "+u+" in string at offset "+h.off)
			}
		}
		if c.bad {
			_, err := Canonicalize(Object{{string(c.cp), int64(1)}})
			check(fmt.Sprintf("go jcs: Canonicalize refuses %s built in memory (%v)", u, err), err != nil && err.Error() == "noncharacter "+u+" in string")
		}
	}
	var deep any = []any{}
	for range 100_000 {
		deep = []any{deep}
	}
	_, err = Canonicalize(deep)
	check(fmt.Sprintf("go jcs: Canonicalize refuses a built value deeper than 512 (%v)", err), err != nil && err.Error() == "nesting deeper than 512")
	var ok512 any = []any{}
	for range 511 {
		ok512 = []any{ok512}
	}
	check("go jcs: Canonicalize accepts exactly 512", must(ok512) == nest(512, ""))

	// Differential P1: base58 decoding is quadratic and ran before any length check. SPEC §2
	// bounds (64 characters for a key, 100 for a signature) come first now.
	long := "z" + strings.Repeat("2", 300_000)
	_, kerr := decodeKey(long)
	_, serr := unmb(long, maxSigChars)
	check(fmt.Sprintf("go: a 300 000-character key / signature is refused on its length (%v / %v)", kerr, serr),
		kerr != nil && kerr.Error() == "multibase: longer than 64 characters" && serr != nil && serr.Error() == "multibase: longer than 100 characters")
	// Differential S1: the same `created` table as ts/src/test.ts.
	g0 := at(load(t, "../test-vectors.json"), "vectors", "genesis", "doc").(Object)
	for _, c := range []struct {
		s    string
		good bool
	}{
		{"2026-09-07T00:00:00Z", true}, {"2000-02-29T00:00:00Z", true}, {"0000-01-01T00:00:00Z", true}, {"9999-12-31T23:59:59Z", true},
		{"2026-06-30T23:59:60Z", false}, {"2026-01-01T00:00:00+00:00", false}, {"2026-01-01T00:00:00+05:30", false},
		{"2026-01-01T00:00:00.123Z", false}, {"10000-01-01T00:00:00Z", false}, {"2026-01-01 00:00:00Z", false},
		{"2026-01-01t00:00:00z", false}, {"2026-01-01T00:00:00", false}, {"2026-13-45T25:61:61Z", false}, {"", false},
		{"yesterday", false}, {"1900-02-29T00:00:00Z", false}, {"2026-04-31T00:00:00Z", false}, {"2026-00-10T00:00:00Z", false},
		{"2026-01-00T00:00:00Z", false}, {"2026-1-01T00:00:00Z", false}, {"２０２６-01-01T00:00:00Z", false},
	} {
		err := Structure(g0.With("created", c.s), "genesis")
		if c.good {
			check(fmt.Sprintf("go: created %q is RFC 3339 UTC (%v)", c.s, err), err == nil)
		} else {
			rejects(fmt.Sprintf("go: created %q is refused", c.s), err, "genesis: created is not RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)")
		}
	}
	// Differential S2: the same key table as ts/src/test.ts.
	V := load(t, "../test-vectors.json")
	const point = "key: not a valid Ed25519 point (non-canonical, off the curve or of small order)"
	realKey, _ := decodeKey(at(V, "vectors", "genesis", "doc", "key"))
	for _, c := range []struct {
		name, hex string
		good      bool
	}{
		{"a real key", hex.EncodeToString(realKey), true},
		{"y = 3 (a point with a torsion part, not small order)", "03" + strings.Repeat("00", 31), true},
		{"all zero (order 4)", strings.Repeat("00", 32), false},
		{"the identity", "01" + strings.Repeat("00", 31), false},
		{"an order-8 point", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", false},
		{"y = p (non-canonical)", "ed" + strings.Repeat("ff", 30) + "7f", false},
		{"x = 0 with the sign bit", "01" + strings.Repeat("00", 30) + "80", false},
		{"y = 2 (off the curve)", "02" + strings.Repeat("00", 31), false},
	} {
		raw, _ := hex.DecodeString(c.hex)
		k := "z" + b58encode(append([]byte{0xed, 0x01}, raw...))
		for _, s := range []struct {
			slot string
			err  error
		}{
			{"genesis key", Structure(at(V, "vectors", "genesis", "doc").(Object).With("key", k), "genesis")},
			{"recovery_key", Structure(at(V, "vectors", "rotation_recovery", "body").(Object).With("recovery_key", k), "rotation")},
			{"ed25519-test addr", Structure(at(V, "vectors", "binding", "body").(Object).With("addr", k), "binding")},
		} {
			if c.good {
				check(fmt.Sprintf("go: %s: %s is a usable key (%v)", s.slot, c.name, s.err), s.err == nil)
			} else {
				rejects(fmt.Sprintf("go: %s: %s is refused", s.slot, c.name), s.err, point)
			}
		}
	}
	// Differential S3: the same commitment table as ts/src/test.ts.
	for _, rec := range []string{"sha256:", "sha256:xyz", "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("a", 65), "SHA256:" + strings.Repeat("a", 64), " sha256:" + strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("a", 64) + "\n", "sha512:" + strings.Repeat("a", 128)} {
		rejects(fmt.Sprintf("go: recovery %q is refused", rec), Structure(at(V, "vectors", "genesis", "doc").(Object).With("recovery", rec), "genesis"),
			"genesis: recovery is neither null nor sha256: + 64 lowercase hex")
	}
	// Differential S4: the same nonce table as ts/src/test.ts.
	for _, c := range []struct {
		n    string
		good bool
	}{
		{"z2", true}, {"z" + strings.Repeat("2", 63), true}, {at(V, "vectors", "genesis", "doc", "nonce").(string), true},
		{"", false}, {"z", false}, {"z0", false}, {"zO", false}, {"zI", false}, {"zl", false}, {"Z2", false}, {"2", false},
		{"z" + strings.Repeat("2", 64), false}, {"\u0000", false}, {"z2/", false}, {"z2\u2028", false}, {"z😀", false}, {"z\u00e9", false},
	} {
		for _, slot := range []string{"genesis", "binding", "invoice"} {
			body := at(V, "vectors", slot, "doc")
			if body == nil {
				body = at(V, "vectors", slot, "body")
			}
			err := Structure(body.(Object).With("nonce", c.n), slot)
			if c.good {
				check(fmt.Sprintf("go: %s nonce %q is z + base58btc (%v)", slot, c.n, err), err == nil)
			} else {
				rejects(fmt.Sprintf("go: %s nonce %q is refused", slot, c.n), err, slot+": nonce is not z + base58btc (at most 64 characters)")
			}
		}
	}
	check("go: the §5.2 challenge nonce is exempt", Structure(at(V, "vectors", "challenge", "body").(Object).With("nonce", "any opaque thing, 0OIl"), "challenge") == nil)
	_, aerr := decodeKey("z" + strings.Repeat("0", 100))
	check(fmt.Sprintf("go: the alphabet is checked before the length (%v)", aerr), aerr != nil && aerr.Error() == `multibase: "0" is not a base58btc digit`)
}

func check2(c bool, err error) {
	if !c {
		check(fmt.Sprintf("go unexpected error %v", err), false)
	}
}

// TestJSONv2 pins why jcs.go does not use encoding/json/v2: what it does with a lone surrogate.
func TestJSONv2(t *testing.T) {
	var v any
	err := jsonv2.Unmarshal([]byte(`{"a":"\ud800"}`), &v)
	check(fmt.Sprintf("go json/v2 fails the WHOLE document on \\ud800 (%v) — per-item discard would be impossible", err), err != nil)
	err = jsonv2.Unmarshal([]byte(`{"a":"\ud800"}`), &v, jsontext.AllowInvalidUTF8(true))
	check("go json/v2 with AllowInvalidUTF8 maps \\ud800 to U+FFFD — the collision SPEC §3.1 forbids", err == nil && at(toObject(v), "a") == "�")
	err = jsonv2.Unmarshal([]byte("{\"a\":\"\xff\"}"), &v)
	check(fmt.Sprintf("go json/v2 refuses raw invalid UTF-8 (%v); so does Parse", err), err != nil)
	err = jsonv2.Unmarshal([]byte(`{"a":1,"a":2}`), &v)
	check(fmt.Sprintf("go json/v2 refuses duplicate keys by default (%v)", err), err != nil)
}

func toObject(v any) Object {
	m, _ := v.(map[string]any)
	var o Object
	for k, x := range m {
		o = append(o, Member{k, x})
	}
	return o
}

// TestEd25519Strict: the Go verifier accepts exactly what ts/'s @noble/ed25519 (zip215:false)
// accepts on the vectors, and refuses the small-order-key forgery crypto/ed25519 would accept.
func TestEd25519Strict(t *testing.T) {
	d := load(t, "../test-vectors.json")
	P := obj(d, "vectors")
	G := map[string]string{}
	for _, m := range P {
		for _, k := range []string{"doc", "next_genesis"} {
			if g := obj(m.Value, k); g != nil {
				G[did(g)] = str_(g, "key")
			}
		}
	}
	agree, n := true, 0
	for _, m := range P {
		body, sig := obj(m.Value, "body"), at(m.Value, "sig")
		signer := G[str_(body, "iss")] + G[str_(body, "did")] + G[str_(body, "id")]
		if str_(body, "recovery_key") != "" {
			signer = str_(body, "recovery_key")
		}
		if body == nil || sig == nil || signer == "" {
			continue
		}
		pub, _ := decodeKey(signer)
		raw, _ := unmb(sig, maxSigChars)
		in, _ := SigningInput(body)
		if !ed25519Strict(pub, in, raw) || !ed25519.Verify(pub, in, raw) {
			agree = false
		}
		n++
	}
	check(fmt.Sprintf("go ed25519: strict verify and crypto/ed25519 both accept all %d signed vectors", n), agree)
	identity := append([]byte{1}, make([]byte, 31)...)
	forged := append(bytes.Clone(identity), make([]byte, 32)...)
	check("go ed25519: (R = identity, S = 0) under the identity key — crypto/ed25519 accepts, strict refuses",
		ed25519.Verify(identity, []byte("anything"), forged) && !ed25519Strict(identity, []byte("anything"), forged))
	nonCanon := append([]byte{0xee}, bytes.Repeat([]byte{0xff}, 30)...) // y = 2^255 - 18 ≡ 1 (mod p): the identity, spelled long
	nonCanon = append(nonCanon, 0x7f)
	check("go ed25519: a non-canonical key encoding is refused", !ed25519Strict(nonCanon, []byte("x"), forged))
}

// Test1f916 is the cross-implementation check on the 1f916 adapter (it replaces the old
// adapters/1f916/check.py): the bundle the adapter's own test emitted,
// adapters/1f916/sample-bundle.json, is ACCEPTED, and the same bundle with one signature
// character flipped is not.
func Test1f916(t *testing.T) {
	sample := load(t, "../adapters/1f916/sample-bundle.json")
	bundle, now := at(sample, "bundle"), at(sample, "now").(int64)
	r := mustVerify(t, bundle, now)
	att := obj(at(bundle, "attestations").([]any)[0], "body")
	world := obj(at(bundle, "issuers").([]any)[0])
	member := obj(bundle, "genesis")
	accepted := r.Attestations[did(world)]
	check("go 1f916: subject DID is the genesis the bundle was built from", r.DID == did(member))
	check("go 1f916: nothing discarded", r.Rejected == Rejected{0, 0})
	check("go 1f916: the attestation is accepted, byte for byte, under the world DID", len(accepted) == 1 && canon(accepted[0]) == canon(att))
	check("go 1f916: iss hash-matches issuers[0], sub is the subject",
		str_(att, "iss") == did(world) && str_(att, "sub") == did(member) && str_(att, "admission") == "open" && str_(att, "ctx") == "1f916.ai")
	check("go 1f916: 30-day lifetime", at(att, "exp").(int64)-at(att, "iat").(int64) == 30*86400)
	claims := obj(att, "claims")
	names := []string{}
	for _, m := range claims {
		names = append(names, m.Key)
	}
	sort.Strings(names)
	_, isPosts := at(claims, "posts").(int64)
	_, isComments := at(claims, "comments").(int64)
	check("go 1f916: claims are exactly handle/joined/posts/comments, counts integers (SPEC §3)",
		strings.Join(names, ",") == "comments,handle,joined,posts" && isPosts && isComments)
	// Negative control: a verifier that accepts anything proves nothing.
	env := obj(at(bundle, "attestations").([]any)[0])
	sig := str_(env, "sig")
	flip := sig[:len(sig)-1] + "2"
	if strings.HasSuffix(sig, "2") {
		flip = sig[:len(sig)-1] + "3"
	}
	tampered := obj(bundle).With("attestations", []any{env.With("sig", flip)})
	c := mustVerify(t, tampered, now)
	check("go 1f916: ACCEPTED, and rejected when one signature character is flipped", len(c.Attestations) == 0 && c.Rejected.Attestations == 1)
}
