// SPDX-License-Identifier: MIT

// Primitives TypeScript takes from @noble: base58btc multibase and Ed25519 verification. Kept out of
// sigelo.go so the §9 verifier there reads on its own.
package sigelo

import (
	"bytes"
	"crypto/sha512"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"filippo.io/edwards25519"
)

// ---------------------------------------------------------------- base58btc / multibase

func b58encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++ // leading zero bytes become '1's
	}
	var digits []byte // base 58, least significant first
	for _, c := range b[zeros:] {
		carry := int(c)
		for j := range digits {
			x := int(digits[j])*256 + carry
			digits[j], carry = byte(x%58), x/58
		}
		for ; carry > 0; carry /= 58 {
			digits = append(digits, byte(carry%58))
		}
	}
	out := strings.Repeat("1", zeros)
	for i := len(digits) - 1; i >= 0; i-- {
		out += string(b58Alphabet[digits[i]])
	}
	return out
}

// SPEC §2 length bounds on a multibase value, `z` included, checked BEFORE decoding: base58
// decoding is quadratic in the length, and a 300 000-character signature took over a minute
// here (three in ts). 34 bytes spell at most 47 base58 digits and 64 bytes at most 88; the
// bounds leave a margin and are the same in ts/src/sigelo.ts.
const (
	maxKeyChars = 64  // multicodec ed25519-pub: 34 bytes
	maxSigChars = 100 // Ed25519 signature: 64 bytes
)

// unmb decodes multibase base58btc of at most max characters. The alphabet is checked first
// (a linear scan, so the length below counts ASCII characters in both implementations).
func unmb(s any, max int) ([]byte, error) {
	str, ok := s.(string)
	if !ok || !strings.HasPrefix(str, "z") {
		return nil, fail(`multibase: not base58btc (expected a leading "z")`)
	}
	for _, ch := range str[1:] {
		if !strings.ContainsRune(b58Alphabet, ch) {
			return nil, fail("multibase: %s is not a base58btc digit", stringify(string(ch)))
		}
	}
	if len(str) > max {
		return nil, fail("multibase: longer than %d characters", max)
	}
	zeros := len(str[1:]) - len(strings.TrimLeft(str[1:], "1"))
	var le []byte // base 256, least significant first
	for _, ch := range str[1+zeros:] {
		carry := strings.IndexRune(b58Alphabet, ch)
		for j := range le {
			x := int(le[j])*58 + carry
			le[j], carry = byte(x), x>>8
		}
		for ; carry > 0; carry >>= 8 {
			le = append(le, byte(carry))
		}
	}
	slices.Reverse(le)
	return append(make([]byte, zeros), le...), nil
}

// decodeKey is the inverse of multicodec 0xed01 + 32 raw bytes, multibase `z` (SPEC §2).
func decodeKey(key any) ([]byte, error) {
	b, err := unmb(key, maxKeyChars)
	if err != nil {
		return nil, err
	}
	if len(b) != 34 || b[0] != 0xed || b[1] != 0x01 {
		return nil, fail("key: not multicodec ed25519-pub")
	}
	return b[2:], nil
}

// publicKey is decodeKey plus SPEC §2's point rule, for the slots that hold a public key
// (§3.1: genesis `key`, rotation `recovery_key`, an `ed25519-test` binding's `addr`): the 32
// bytes must be the canonical encoding of a curve point that is not of small order — the keys
// ed25519Strict (and @noble with zip215:false) could ever verify a signature under. All-zero,
// the identity, y ≥ p and x = 0 with the sign bit all fail here, by the same rule as ts.
func publicKey(key any) error {
	raw, err := decodeKey(key)
	if err != nil {
		return err
	}
	P, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil || !bytes.Equal(P.Bytes(), raw) || new(edwards25519.Point).MultByCofactor(P).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return fail("key: not a valid Ed25519 point (non-canonical, off the curve or of small order)")
	}
	return nil
}

// ---------------------------------------------------------------- §4 field formats

var rfc3339 = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$`)

// isRFC3339UTC is SPEC §4's `created`: exactly YYYY-MM-DDTHH:MM:SSZ, a real Gregorian date,
// seconds 00–59 (no leap second: no clock can check one), no fraction, no offset, uppercase T
// and Z. The same check as ts/src/sigelo.ts `isRFC3339UTC`.
func isRFC3339UTC(s string) bool {
	m := rfc3339.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	n := func(i int) int { v, _ := strconv.Atoi(m[i]); return v }
	y, mo, d := n(1), n(2), n(3)
	if mo < 1 || mo > 12 || d < 1 || n(4) > 23 || n(5) > 59 || n(6) > 59 {
		return false
	}
	days := [...]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[mo-1]
	if mo == 2 && y%4 == 0 && (y%100 != 0 || y%400 == 0) {
		days = 29
	}
	return d <= days
}

// ---------------------------------------------------------------- Ed25519

// ed25519Strict is RFC 8032 verification with the same strictness as ts/'s @noble/ed25519 with
// zip215:false, so the two verifiers accept exactly the same signatures: A and R must be
// canonical encodings, A must not be of small order, S < l, and the cofactored equation
// [8](R + kA − SB) = 0 must hold. crypto/ed25519 differs on all three edge cases (it would
// accept every signature (R = identity, S = 0) under the identity key, for any message).
func ed25519Strict(pub, msg, sig []byte) bool {
	if len(pub) != 32 || len(sig) != 64 {
		return false
	}
	A, errA := new(edwards25519.Point).SetBytes(pub)
	R, errR := new(edwards25519.Point).SetBytes(sig[:32])
	S, errS := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if errA != nil || errR != nil || errS != nil || !bytes.Equal(A.Bytes(), pub) || !bytes.Equal(R.Bytes(), sig[:32]) {
		return false
	}
	id := edwards25519.NewIdentityPoint()
	if new(edwards25519.Point).MultByCofactor(A).Equal(id) == 1 {
		return false
	}
	h := sha512.Sum512(slices.Concat(sig[:32], pub, msg))
	k, _ := edwards25519.NewScalar().SetUniformBytes(h[:])
	sB := new(edwards25519.Point).ScalarBaseMult(S)
	v := new(edwards25519.Point).Add(R, new(edwards25519.Point).ScalarMult(k, A))
	return new(edwards25519.Point).MultByCofactor(v.Subtract(v, sB)).Equal(id) == 1
}
