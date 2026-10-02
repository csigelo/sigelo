// SPDX-License-Identifier: MIT

// Batch driver for sigelo's Go package: one JSON request per stdin line, one JSON answer per
// stdout line, in order. The requests come from crosscheck.py, which compares the answers with
// third-party oracles. It calls only sigelo's own entry points (plus the three unexported
// primitives export.go.txt overlays in); it computes nothing itself.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/csigelo/sigelo/go"
)

type req struct {
	Op    string `json:"op"`
	Text  string `json:"text"`
	Hex   string `json:"hex"`
	S     string `json:"s"`
	Net   string `json:"net"`
	Kind  string `json:"kind"`
	Pub   string `json:"pub"`
	Msg   string `json:"msg"`
	Sig   string `json:"sig"`
	Key   string `json:"key"`
	A     string `json:"a"`
	B     string `json:"B"`
	Major uint32 `json:"major"`
	Minor uint32 `json:"minor"`
	Max   int    `json:"max"`
}

func unhex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func do(r req) map[string]any {
	errOut := func(err error) map[string]any { return map[string]any{"ok": false, "err": err.Error()} }
	switch r.Op {
	case "jcs":
		v, err := sigelo.Parse([]byte(r.Text))
		if err != nil {
			return map[string]any{"ok": false, "err": err.Error(), "stage": "parse"}
		}
		out, err := sigelo.Canonicalize(v)
		if err != nil {
			return map[string]any{"ok": false, "err": err.Error(), "stage": "canonicalize"}
		}
		return map[string]any{"ok": true, "out": hex.EncodeToString(out)}
	case "b58enc":
		return map[string]any{"ok": true, "out": sigelo.MoneroBase58Encode(unhex(r.Hex))}
	case "b58dec":
		b, err := sigelo.MoneroBase58Decode(r.S)
		if err != nil {
			return errOut(err)
		}
		return map[string]any{"ok": true, "out": hex.EncodeToString(b)}
	case "addr":
		a, err := sigelo.DecodeAddress(r.S)
		if err != nil {
			return errOut(err)
		}
		return map[string]any{"ok": true, "net": a.Net, "kind": a.Kind, "spend": hex.EncodeToString(a.Spend), "view": hex.EncodeToString(a.View), "pid": hex.EncodeToString(a.PaymentID)}
	case "addrenc":
		var pid []byte
		if r.Kind == "integrated" {
			pid = unhex(r.Hex)
		}
		s, err := sigelo.EncodeAddress(r.Net, r.Kind, unhex(r.A), unhex(r.B), pid)
		if err != nil {
			return errOut(err)
		}
		return map[string]any{"ok": true, "out": s}
	case "wenc":
		w, err := sigelo.EncodeMoneroWords(unhex(r.Hex))
		if err != nil {
			return errOut(err)
		}
		return map[string]any{"ok": true, "out": w}
	case "wdec":
		b, err := sigelo.DecodeMoneroWords(r.S)
		if err != nil {
			return errOut(err)
		}
		return map[string]any{"ok": true, "out": hex.EncodeToString(b[:])}
	case "wallet": // standard address of a spend seed: KeysFromSpend + EncodeAddress
		k, err := sigelo.KeysFromSpend(unhex(r.Hex))
		if err != nil {
			return errOut(err)
		}
		s, err := sigelo.EncodeAddress(r.Net, "standard", k.SpendPub, k.ViewPub, nil)
		if err != nil {
			return errOut(err)
		}
		return map[string]any{"ok": true, "b": hex.EncodeToString(k.Spend), "a": hex.EncodeToString(k.View), "out": s}
	case "subaddr":
		s, err := sigelo.Subaddress(unhex(r.A), unhex(r.B), r.Major, r.Minor, r.Net)
		if err != nil {
			return errOut(err)
		}
		return map[string]any{"ok": true, "out": s}
	case "edraw":
		return map[string]any{"ok": sigelo.CrosscheckEd25519Strict(unhex(r.Pub), unhex(r.Msg), unhex(r.Sig))}
	case "edpub":
		var seed [32]byte
		copy(seed[:], unhex(r.Hex))
		return map[string]any{"ok": true, "out": sigelo.PublicKey(seed)}
	case "edverify": // the wrapper: multibase key, JSON body text, multibase sig
		body, err := sigelo.Parse([]byte(r.Text))
		if err != nil {
			return errOut(err)
		}
		return map[string]any{"ok": sigelo.VerifySig(r.Key, body, r.Sig)}
	case "siginput":
		body, err := sigelo.Parse([]byte(r.Text))
		if err != nil {
			return errOut(err)
		}
		b, err := sigelo.SigningInput(body)
		if err != nil {
			return errOut(err)
		}
		return map[string]any{"ok": true, "out": hex.EncodeToString(b)}
	case "mbenc":
		return map[string]any{"ok": true, "out": "z" + sigelo.CrosscheckB58Encode(unhex(r.Hex))}
	case "mbdec":
		b, err := sigelo.CrosscheckUnmb(r.S, r.Max)
		if err != nil {
			return errOut(err)
		}
		return map[string]any{"ok": true, "out": hex.EncodeToString(b)}
	}
	return map[string]any{"ok": false, "err": "unknown op " + r.Op}
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	for in.Scan() {
		var r req
		if err := json.Unmarshal(in.Bytes(), &r); err != nil {
			enc.Encode(map[string]any{"ok": false, "err": "driver: " + err.Error()})
			continue
		}
		enc.Encode(do(r))
	}
}
