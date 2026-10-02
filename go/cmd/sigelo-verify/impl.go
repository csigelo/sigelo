// SPDX-License-Identifier: MIT

package main

// `--conformance --impl '<command>'`: the vectors run against a CANDIDATE verifier, not this
// one. The protocol is docs-test/grade-verifier.mjs's, adopted verbatim (docs-test/TASK-verifier.md
// "Interface (exact)"), so the binary and the node grader score a candidate identically:
//
//	<command> <case.json> --now <N>      (or, with --impl-stdin: <command> - --now <N>, bytes on stdin)
//
// exit 0 with the §9.1 result as JSON on stdout = accepted; exit 1 = rejected (fatal, §9);
// anything else (another exit code, a signal, a timeout) is a failure of the candidate. The
// cases are built from test-vectors.json exactly as grade-verifier.mjs builds them — same
// names, same groups, same comparisons — except that every sub-document is spliced into the
// case as the BYTES the vectors file holds (never re-serialized), so no number spelling, escape
// or key can change on the way to the candidate.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- raw JSON, order and bytes kept

// robj is a JSON object read without re-encoding: keys in document order, values as raw bytes.
// A repeated key keeps its first position and its last value, as JSON.parse does.
type robj struct {
	keys []string
	vals map[string]json.RawMessage
}

func decodeObj(raw json.RawMessage) (*robj, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, fmt.Errorf("not a JSON object: %.40s", raw)
	}
	o := &robj{vals: map[string]json.RawMessage{}}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k := t.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if _, dup := o.vals[k]; !dup {
			o.keys = append(o.keys, k)
		}
		o.vals[k] = v
	}
	return o, nil
}

// vecs navigates the vectors file; a missing path is a fatal error of the file, reported once.
type vecs struct{ err error }

func (vs *vecs) obj(raw json.RawMessage, path ...string) *robj {
	for _, k := range path {
		o := vs.obj(raw)
		if o == nil {
			return nil
		}
		v, ok := o.vals[k]
		if !ok {
			vs.fail(fmt.Errorf("vectors file: no %q", k))
			return nil
		}
		raw = v
	}
	o, err := decodeObj(raw)
	if err != nil {
		vs.fail(err)
	}
	return o
}

func (vs *vecs) at(raw json.RawMessage, path ...string) json.RawMessage {
	if len(path) == 0 {
		return raw
	}
	o := vs.obj(raw, path[:len(path)-1]...)
	if o == nil {
		return json.RawMessage("null")
	}
	v, ok := o.vals[path[len(path)-1]]
	if !ok {
		vs.fail(fmt.Errorf("vectors file: no %q", path[len(path)-1]))
		return json.RawMessage("null")
	}
	return v
}

func (vs *vecs) str(raw json.RawMessage, path ...string) string {
	var s string
	if err := json.Unmarshal(vs.at(raw, path...), &s); err != nil {
		vs.fail(fmt.Errorf("vectors file: %s is not a string", strings.Join(path, ".")))
	}
	return s
}

func (vs *vecs) strs(raw json.RawMessage, path ...string) []string {
	var s []string
	if err := json.Unmarshal(vs.at(raw, path...), &s); err != nil {
		vs.fail(fmt.Errorf("vectors file: %s is not a string array", strings.Join(path, ".")))
	}
	return s
}

func (vs *vecs) int(raw json.RawMessage, path ...string) int64 {
	var n int64
	if err := json.Unmarshal(vs.at(raw, path...), &n); err != nil {
		vs.fail(fmt.Errorf("vectors file: %s is not an integer", strings.Join(path, ".")))
	}
	return n
}

func (vs *vecs) fail(err error) {
	if vs.err == nil {
		vs.err = err
	}
}

type kv struct {
	k string
	v json.RawMessage
}

func quote(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimRight(b.Bytes(), "\n")
}

// object writes {"k":v,...} from raw pieces, byte for byte.
func object(pairs ...kv) json.RawMessage {
	b := []byte{'{'}
	for i, p := range pairs {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(append(append(b, quote(p.k)...), ':'), p.v...)
	}
	return append(b, '}')
}

func array(items ...json.RawMessage) json.RawMessage {
	b := []byte{'['}
	for i, it := range items {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, it...)
	}
	return append(b, ']')
}

// pick is grade-verifier's env(): the listed keys of o that are present, in the listed order.
func pick(o *robj, keys ...string) json.RawMessage {
	var ps []kv
	if o != nil {
		for _, k := range keys {
			if v, ok := o.vals[k]; ok {
				ps = append(ps, kv{k, v})
			}
		}
	}
	return object(ps...)
}

// with is {...o, k: v}: o's keys in order, k replaced in place or appended.
func with(o *robj, k string, v json.RawMessage) json.RawMessage {
	var ps []kv
	seen := false
	if o != nil {
		for _, key := range o.keys {
			if key == k {
				ps, seen = append(ps, kv{k, v}), true
			} else {
				ps = append(ps, kv{key, o.vals[key]})
			}
		}
	}
	if !seen {
		ps = append(ps, kv{k, v})
	}
	return object(ps...)
}

// hasProto: a "__proto__" key anywhere in the value.
func hasProto(raw json.RawMessage) bool {
	s := bytes.TrimSpace(raw)
	switch {
	case len(s) > 0 && s[0] == '{':
		o, err := decodeObj(s)
		if err != nil {
			return false
		}
		for _, k := range o.keys {
			if k == "__proto__" || hasProto(o.vals[k]) {
				return true
			}
		}
	case len(s) > 0 && s[0] == '[':
		var a []json.RawMessage
		_ = json.Unmarshal(s, &a)
		for _, x := range a {
			if hasProto(x) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------- cases

type implCase struct {
	group, name string
	text        []byte
	now         int64
	kind        string // "result" | "check" | "reject"
	expect      any    // kind "result": the normalized §9.1 surface
	fn          func(r map[string]any) string
}

// buildCases is grade-verifier.mjs's case list, in its order and with its names.
func buildCases(text []byte) (cases []implCase, inexpressible []string, err error) {
	vs := &vecs{}
	root := json.RawMessage(text)
	if !json.Valid(text) {
		return nil, nil, errors.New("vectors file is not JSON")
	}
	NOW := vs.int(root, "now")
	P := vs.obj(root, "vectors")
	N := vs.obj(root, "negative")
	if vs.err != nil {
		return nil, nil, vs.err
	}
	pv := func(n string) json.RawMessage { return vs.at(P.vals[n]) }
	nv := func(n string) json.RawMessage { return vs.at(N.vals[n]) }
	G0 := vs.at(pv("genesis"), "doc")
	W := vs.at(pv("world_genesis"), "doc")
	bundle := func(over ...kv) json.RawMessage {
		ps := []kv{{"v", json.RawMessage(`"sigelo/0"`)}, {"typ", json.RawMessage(`"bundle"`)}, {"genesis", G0},
			{"rotations", json.RawMessage("[]")}, {"bindings", json.RawMessage("[]")}, {"attestations", json.RawMessage("[]")}, {"issuers", json.RawMessage("[]")}}
		for _, o := range over {
			for i := range ps {
				if ps[i].k == o.k {
					ps[i].v = o.v
				}
			}
		}
		return object(ps...)
	}
	rot := func(raw json.RawMessage) json.RawMessage { return pick(vs.obj(raw), "body", "sig", "next_genesis") }
	bnd := func(raw json.RawMessage) json.RawMessage { return pick(vs.obj(raw), "body", "sig_id", "sig_addr") }
	val := func(raw json.RawMessage) any { v, _ := decodeVal(raw); return v }
	add := func(c implCase) {
		if c.now == 0 {
			c.now = NOW
		}
		cases = append(cases, c)
	}
	ROT := []string{"rotation_voluntary", "rotation_hostile", "rotation_hostile_carried", "rotation_recovery", "rotation_recovery_second"}
	rots := func(names []string) []json.RawMessage {
		var out []json.RawMessage
		for _, n := range names {
			out = append(out, rot(pv(n)))
		}
		return out
	}

	// ---- positive: the two bundles with a full §9.1 expectation
	for _, n := range []string{"bundle", "bundle_minimal"} {
		add(implCase{group: "positive", name: n + " == expect", text: vs.at(pv(n), "bundle"), now: vs.int(pv(n), "now"),
			kind: "result", expect: surface(val(vs.at(pv(n), "expect")))})
	}
	// ---- positive: genesis → DID (§4)
	for _, n := range []string{"genesis", "world_genesis", "member_genesis"} {
		d := vs.str(pv(n), "expect_did")
		add(implCase{group: "positive", name: n + " did", text: bundle(kv{"genesis", vs.at(pv(n), "doc")}), kind: "check",
			fn: func(r map[string]any) string {
				return want(r["did"] == d && eq(r["chain"], []any{d}), "did/chain ≠ "+d)
			}})
	}
	// ---- positive: attestations (§5, §3 JCS via the unicode claims)
	for _, n := range []string{"attestation", "attestation_unicode"} {
		body := val(vs.at(pv(n), "body"))
		iss := vs.str(pv(n), "body", "iss")
		add(implCase{group: "positive", name: n + " accepted",
			text: bundle(kv{"attestations", array(pick(vs.obj(pv(n)), "body", "sig"))}, kv{"issuers", array(W)}), kind: "check",
			fn: func(r map[string]any) string {
				return want(eq(r["attestations"], map[string]any{iss: []any{body}}) && eq(r["rejected"], rej(0, 0)), "not accepted verbatim under its iss")
			}})
	}
	// ---- positive: typ binding (§3). A challenge and an invoice fit no bundle slot.
	add(implCase{group: "positive", name: "challenge presented as an attestation is discarded",
		text: bundle(kv{"attestations", array(pick(vs.obj(pv("challenge")), "body", "sig"))}, kv{"issuers", array(W)}), kind: "check",
		fn: func(r map[string]any) string {
			return want(nAtt(r) == 0 && field(r["rejected"], "attestations") == int64(1), "challenge accepted in the attestation slot")
		}})
	add(implCase{group: "positive", name: "invoice presented as a binding is discarded",
		text: bundle(kv{"bindings", array(object(kv{"body", vs.at(pv("invoice"), "body")}, kv{"sig_id", vs.at(pv("invoice"), "sig")}))}), kind: "check",
		fn: func(r map[string]any) string {
			return want(len(proofs(r)) == 0 && field(r["rejected"], "bindings") == int64(1), "invoice accepted in the binding slot")
		}})
	// ---- positive: bindings and their proof status (§6.1, §6.1a, §6.2)
	for _, np := range [][2]string{{"binding", "proven"}, {"binding_unproven", "unproven"}, {"binding_monero", "proven"},
		{"binding_monero_subaddress_spend", "proven"}, {"binding_monero_subaddress_view", "proven"}} {
		n, p := np[0], np[1]
		body := val(vs.at(pv(n), "body"))
		add(implCase{group: groupOf(n, "positive"), name: n + " → " + p, text: bundle(kv{"bindings", array(bnd(pv(n)))}), kind: "check",
			fn: func(r map[string]any) string {
				return want(eq(r["bindings"], []any{map[string]any{"body": body, "proof": p}}) && field(r["rejected"], "bindings") == int64(0),
					fmt.Sprintf("bindings %s, want [%q]", js(proofs(r)), p))
			}})
	}
	// ---- positive: chains (§7)
	expChain := val(pv("expected_chain"))
	add(implCase{group: "positive", name: "expected_chain (all five rotations)", text: bundle(kv{"rotations", array(rots(ROT)...)}), kind: "check",
		fn: func(r map[string]any) string {
			ec, _ := expChain.([]any)
			return want(eq(r["chain"], expChain) && len(ec) > 0 && r["did"] == ec[len(ec)-1], "chain ≠ expected_chain")
		}})
	rev := rots(ROT)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	add(implCase{group: "positive", name: "expected_chain (rotations in reverse array order)", text: bundle(kv{"rotations", array(rev...)}), kind: "check",
		fn: func(r map[string]any) string { return want(eq(r["chain"], expChain), "chain depends on array order") }})
	cpo := pv("chain_precedence_only")
	cpoChain := val(vs.at(cpo, "expected_chain"))
	add(implCase{group: "positive", name: "chain_precedence_only", text: bundle(kv{"rotations", array(rots(vs.strs(cpo, "rotations"))...)}), kind: "check",
		fn: func(r map[string]any) string {
			return want(eq(r["chain"], cpoChain), "chain ≠ expected (precedence §7.1)")
		}})

	// ---- negatives: attestations discarded individually (§9 steps 2, 5)
	A := vs.obj(pv("attestation"))
	for _, n := range []string{"tampered_claims", "wrong_signer", "missing_prefix", "typ_mismatch", "unknown_field_attestation", "expired_attestation", "float_in_claims", "int_out_of_range"} {
		x := vs.obj(nv(n))
		if x == nil {
			break
		}
		body, sig := x.vals["body"], x.vals["sig"]
		if !truthy(sig) { // carries only v/typ/claims: grafted onto the positive attestation, as schema/check.mjs does
			body = with(vs.obj(A.vals["body"]), "claims", vs.at(body, "claims"))
			sig = A.vals["sig"]
		}
		add(implCase{group: "negative", name: "neg " + n + " discarded",
			text: bundle(kv{"attestations", array(object(kv{"body", body}, kv{"sig", sig}))}, kv{"issuers", array(W)}), kind: "check",
			fn: func(r map[string]any) string {
				return want(nAtt(r) == 0 && field(r["rejected"], "attestations") == int64(1), "attestation accepted")
			}})
	}
	// duplicate key / __proto__ anywhere in the bundle TEXT is fatal (§3)
	for _, n := range []string{"duplicate_key", "proto_key"} {
		raw := vs.str(nv(n), "raw")
		add(implCase{group: "negative", name: "neg " + n + " in bundle text rejects",
			text: bundle(kv{"attestations", array(object(kv{"body", json.RawMessage(raw)}, kv{"sig", A.vals["sig"]}))}, kv{"issuers", array(W)}), kind: "reject"})
	}
	claimed := vs.str(nv("genesis_tampered"), "claimed_did")
	add(implCase{group: "negative", name: "neg genesis_tampered: result DID ≠ claimed DID", text: bundle(kv{"genesis", vs.at(nv("genesis_tampered"), "doc")}), kind: "check",
		fn: func(r map[string]any) string {
			d, ok := r["did"].(string)
			return want(ok && d != claimed, "result DID equals the claimed DID")
		}})
	for _, n := range []string{"unknown_field_genesis", "genesis_bad_key"} {
		add(implCase{group: "negative", name: "neg " + n + " rejects", text: bundle(kv{"genesis", vs.at(nv(n), "doc")}), kind: "reject"})
	}
	// "not a candidate" rotations: each states the chain that results (§7.4)
	for _, n := range []string{"recovery_key_mismatch", "stale_recovery_key", "voluntary_changes_recovery", "rotation_bad_sig"} {
		ec := val(vs.at(nv(n), "expected_chain"))
		ecl, _ := ec.([]any)
		add(implCase{group: "negative", name: fmt.Sprintf("neg %s → chain of %d", n, len(ecl)),
			text: bundle(kv{"rotations", array(append(rots(vs.strs(nv(n), "chain_with")), rot(nv(n)))...)}), kind: "check",
			fn: func(r map[string]any) string { return want(eq(r["chain"], ec), "chain "+js(r["chain"])) }})
	}
	for _, n := range []string{"fork", "cycle", "self_rotation"} {
		add(implCase{group: "negative", name: "neg " + n + " rejects", text: bundle(kv{"rotations", array(rot(pv("rotation_voluntary")), rot(nv(n)))}), kind: "reject"})
	}
	add(implCase{group: "negative", name: "neg bundle_rotations_not_array rejects", text: vs.at(nv("bundle_rotations_not_array"), "bundle"), kind: "reject"})
	// bindings discarded, never downgraded (§6.1, §6.2, §3.1 types)
	for _, n := range N.keys {
		x, err := decodeObj(N.vals[n])
		if err != nil {
			continue
		}
		if _, ok := x.vals["sig_id"]; !ok {
			continue
		}
		add(implCase{group: groupOf(n, "negative"), name: "neg " + n + " discarded", text: bundle(kv{"bindings", array(bnd(N.vals[n]))}), kind: "check",
			fn: func(r map[string]any) string {
				return want(len(proofs(r)) == 0 && field(r["rejected"], "bindings") == int64(1),
					fmt.Sprintf("bindings %s, rejected %s", js(proofs(r)), js(field(r["rejected"], "bindings"))))
			}})
	}
	for _, n := range N.keys {
		if strings.HasPrefix(n, "invoice_") {
			inexpressible = append(inexpressible, n)
		}
	}

	// ---- parity: malformed bundles both reference verifiers treat identically. A case given as
	// an OBJECT holding a "__proto__" key is an in-memory bundle to verify(), which discards the
	// item carrying it; written to a file it is bundle TEXT, and §3 makes that fatal.
	par := nv("parity")
	pnow := vs.int(par, "now")
	pc := vs.obj(par, "cases")
	if pc != nil {
		for _, n := range pc.keys {
			c := vs.obj(pc.vals[n])
			if c == nil {
				break
			}
			raw, isRaw := c.vals["raw"]
			var t json.RawMessage
			if isRaw {
				t = json.RawMessage(vs.str(raw))
			} else {
				t = c.vals["bundle"]
			}
			asText := !isRaw && hasProto(t)
			name := "parity " + n
			if asText {
				name += " (as text: __proto__ is fatal, §3)"
			}
			e := vs.obj(c.vals["expect"])
			if e == nil {
				break
			}
			base := implCase{group: "parity", name: name, now: pnow, text: t}
			if _, rj := e.vals["reject"]; rj || asText {
				base.kind = "reject"
			} else {
				ep, ea, er := val(e.vals["proofs"]), val(e.vals["attestations"]), val(e.vals["rejected"])
				ex := js(val(c.vals["expect"]))
				base.kind, base.fn = "check", func(r map[string]any) string {
					return want(eq(proofs(r), ep) && eq(int64(nAtt(r)), ea) && eq(r["rejected"], er),
						fmt.Sprintf("got proofs %s attestations %d rejected %s, want %s", js(proofs(r)), nAtt(r), js(r["rejected"]), ex))
				}
			}
			add(base)
		}
	}
	if vs.err != nil {
		return nil, nil, vs.err
	}
	return cases, inexpressible, nil
}

func groupOf(n, dflt string) string {
	if strings.Contains(n, "monero") {
		return "monero"
	}
	return dflt
}

func truthy(raw json.RawMessage) bool {
	s := string(bytes.TrimSpace(raw))
	return s != "" && s != "null" && s != `""` && s != "false" && s != "0"
}

// ---------------------------------------------------------------- comparing results

// missing stands for an absent member, so that {"recovery": null} and {} are not equal.
type missing struct{}

// decodeVal decodes JSON with every number normalized: an integer to int64 (or its decimal
// string when larger), anything else to its exact rational, so 1000 and 1e3 compare equal.
func decodeVal(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing content")
	}
	return norm(v), nil
}

func norm(v any) any {
	switch v := v.(type) {
	case json.Number:
		r, ok := new(big.Rat).SetString(string(v))
		if !ok {
			return string(v)
		}
		if r.IsInt() && r.Num().IsInt64() {
			return r.Num().Int64()
		}
		return "num:" + r.RatString()
	case []any:
		for i := range v {
			v[i] = norm(v[i])
		}
	case map[string]any:
		for k := range v {
			v[k] = norm(v[k])
		}
	}
	return v
}

func eq(a, b any) bool { return reflect.DeepEqual(a, b) }

func member(m map[string]any, k string) any {
	if v, ok := m[k]; ok {
		return v
	}
	return missing{}
}

func field(v any, k string) any {
	if m, ok := v.(map[string]any); ok {
		return member(m, k)
	}
	return missing{}
}

func rej(a, b int64) map[string]any { return map[string]any{"attestations": a, "bindings": b} }

// surface is §9.1's conformance surface: the six fields, of a binding entry body and proof,
// of rejected its two counts. Anything else a verifier attaches is ignored (§9.1, §6.2).
func surface(v any) any {
	r, ok := v.(map[string]any)
	if !ok {
		return v
	}
	s := map[string]any{"did": member(r, "did"), "chain": member(r, "chain"), "recovery": member(r, "recovery"), "attestations": member(r, "attestations")}
	if bs, ok := r["bindings"].([]any); ok {
		out := make([]any, len(bs))
		for i, b := range bs {
			out[i] = map[string]any{"body": field(b, "body"), "proof": field(b, "proof")}
		}
		s["bindings"] = out
	} else {
		s["bindings"] = member(r, "bindings")
	}
	if rj, ok := r["rejected"].(map[string]any); ok {
		s["rejected"] = map[string]any{"attestations": member(rj, "attestations"), "bindings": member(rj, "bindings")}
	} else {
		s["rejected"] = member(r, "rejected")
	}
	return s
}

func nAtt(r map[string]any) int {
	n := 0
	if m, ok := r["attestations"].(map[string]any); ok {
		for _, xs := range m {
			if a, ok := xs.([]any); ok {
				n += len(a)
			}
		}
	}
	return n
}

// proofs lists the proof of each binding entry; bindings that are not an array cannot pass a
// "none accepted" check, so they list a marker instead of nothing.
func proofs(r map[string]any) []any {
	switch bs := r["bindings"].(type) {
	case []any:
		out := []any{}
		for _, b := range bs {
			out = append(out, field(b, "proof"))
		}
		return out
	case missing, nil:
		return []any{}
	default:
		return []any{"<bindings is not an array>"}
	}
}

func want(ok bool, why string) string {
	if ok {
		return ""
	}
	return why
}

func js(v any) string {
	if _, ok := v.(missing); ok {
		return "undefined"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// judge applies grade-verifier.mjs's verdict rules to one run of the candidate.
func judge(c implCase, exit int, stdout, stderr []byte, runErr string) (bool, string) {
	switch {
	case runErr != "":
		return false, runErr
	case c.kind == "reject":
		return exit == 1, want(exit == 1, fmt.Sprintf("exit %d, want 1 (reject)", exit))
	case exit != 0:
		line, _, _ := strings.Cut(strings.TrimSpace(string(stderr)), "\n")
		if len(line) > 120 {
			line = line[:120]
		}
		return false, fmt.Sprintf("exit %d, want 0: %s", exit, line)
	}
	v, err := decodeVal(stdout)
	if err != nil {
		return false, "stdout is not JSON"
	}
	s := surface(v)
	if c.kind == "result" {
		out := strings.TrimSpace(string(stdout))
		if len(out) > 160 {
			out = out[:160]
		}
		return eq(s, c.expect), want(eq(s, c.expect), "result ≠ expect: "+out)
	}
	r, ok := s.(map[string]any)
	if !ok {
		return false, "stdout is not a JSON object"
	}
	why := c.fn(r)
	return why == "", why
}

// ---------------------------------------------------------------- running the candidate

// splitWords splits a command line like a POSIX shell's quoting does — '…' literal, "…" with
// \" and \\, a backslash outside quotes escaping the next character — with no expansion and
// no shell: the first word is the program, run directly.
func splitWords(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	in, quote := false, byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case quote == '"':
			if c == '"' {
				quote = 0
			} else if c == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
				i++
				cur.WriteByte(s[i])
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote, in = c, true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			in = true
		case c == ' ' || c == '\t' || c == '\n':
			if in {
				out, in = append(out, cur.String()), false
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
			in = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if in {
		out = append(out, cur.String())
	}
	if len(out) == 0 {
		return nil, errors.New("empty command")
	}
	return out, nil
}

type implOpts struct {
	cmd     []string
	stdin   bool
	timeout time.Duration
}

// runCase runs the candidate once on one case and returns its verdict line material.
func runCase(o implOpts, dir string, i int, c implCase) (bool, string) {
	args := append([]string{}, o.cmd[1:]...)
	var stdin io.Reader
	if o.stdin {
		args = append(args, "-")
		stdin = bytes.NewReader(c.text)
	} else {
		f := filepath.Join(dir, fmt.Sprintf("case-%03d.json", i))
		if err := os.WriteFile(f, c.text, 0o600); err != nil {
			return false, "could not write the case: " + err.Error()
		}
		args = append(args, f)
	}
	args = append(args, "--now", strconv.FormatInt(c.now, 10))
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, o.cmd[0], args...)
	cmd.Stdin = stdin
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.WaitDelay = 2 * time.Second // a child that keeps the pipes open must not hang the run
	err := cmd.Run()
	exit, runErr := 0, ""
	var ee *exec.ExitError
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		runErr = fmt.Sprintf("timed out after %s", o.timeout)
	case errors.As(err, &ee):
		exit = ee.ExitCode()
		if exit < 0 {
			runErr = "killed: " + ee.String()
		}
	case err != nil:
		runErr = "could not run: " + err.Error()
	}
	return judge(c, exit, out.Bytes(), errb.Bytes(), runErr)
}

// runImpl is `--conformance --impl`: one PASS/FAIL line per case, the per-group counts, and
// ALL PASS (exit 0) or FAILURES (exit 1); 2 if the vectors file is unusable.
func runImpl(w io.Writer, vectorsPath string, o implOpts) int {
	text, err := os.ReadFile(vectorsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sigelo-verify:", err)
		return 2
	}
	cases, inexpressible, err := buildCases(text)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sigelo-verify:", err)
		return 2
	}
	dir, err := os.MkdirTemp("", "sigelo-impl-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "sigelo-verify:", err)
		return 2
	}
	defer os.RemoveAll(dir)
	type count struct{ pass, total int }
	groups, order := map[string]*count{}, []string{}
	pass := 0
	for i, c := range cases {
		ok, why := runCase(o, dir, i, c)
		if groups[c.group] == nil {
			groups[c.group], order = &count{}, append(order, c.group)
		}
		groups[c.group].total++
		if ok {
			pass++
			groups[c.group].pass++
			fmt.Fprintln(w, "PASS "+c.name)
		} else {
			fmt.Fprintln(w, "FAIL "+c.name+" — "+why)
		}
	}
	fmt.Fprintln(w)
	for _, g := range order {
		fmt.Fprintf(w, "%-9s %d/%d\n", g, groups[g].pass, groups[g].total)
	}
	fmt.Fprintln(w, "not expressible through the bundle interface (not scored): "+strings.Join(inexpressible, ", "))
	fmt.Fprintf(w, "\n%d passed, %d failed\n", pass, len(cases)-pass)
	if pass == len(cases) && pass > 0 {
		fmt.Fprintln(w, "ALL PASS")
		return 0
	}
	fmt.Fprintln(w, "FAILURES")
	return 1
}
