// SPDX-License-Identifier: MIT

// Batch driver for the THIRD-PARTY oracle: cyberphone/json-canonicalization's Go reference
// (webpki.org/jsoncanonicalizer, by the RFC 8785 author). Same line protocol as the sigelo
// drivers. "jcs" canonicalizes JSON text; "num" formats a float64 (given as 16 hex digits of its
// IEEE-754 bits) with the reference ES6 Number::toString.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"strconv"

	"webpki.org/jsoncanonicalizer"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	for in.Scan() {
		var r struct{ Op, Text, Bits string }
		if err := json.Unmarshal(in.Bytes(), &r); err != nil {
			enc.Encode(map[string]any{"ok": false, "err": err.Error()})
			continue
		}
		switch r.Op {
		case "jcs":
			b, err := jsoncanonicalizer.Transform([]byte(r.Text))
			if err != nil {
				enc.Encode(map[string]any{"ok": false, "err": err.Error()})
			} else {
				enc.Encode(map[string]any{"ok": true, "out": hex.EncodeToString(b)})
			}
		case "num":
			u, _ := strconv.ParseUint(r.Bits, 16, 64)
			s, err := jsoncanonicalizer.NumberToJSON(math.Float64frombits(u))
			if err != nil {
				enc.Encode(map[string]any{"ok": false, "err": err.Error()})
			} else {
				enc.Encode(map[string]any{"ok": true, "out": s})
			}
		default:
			enc.Encode(map[string]any{"ok": false, "err": "unknown op"})
		}
	}
}
