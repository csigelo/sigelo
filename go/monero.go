// SPDX-License-Identifier: MIT

// Monero primitives for `method: "monero"` bindings (SPEC §6.2).
//
// A port of ts/src/monero.ts (and the former py/monero.py), which were checked line by line
// against monero master 9e3a3103; every routine names the monero file it mirrors. Monero signs on edwards25519
// — the curve of Ed25519 — with a different construction (Schnorr over Keccak-256, not RFC 8032),
// so crypto/ed25519 is no help and the group operations come from filippo.io/edwards25519, the
// importable copy of the standard library's own. Two traps that silently produce garbage:
//   - Keccak-256 is the ORIGINAL Keccak (pad 0x01), not SHA3-256 (pad 0x06); golang.org/x/crypto
//     would call it NewLegacyKeccak256. It is ported below instead, to keep one dependency.
//   - The domain strings are hashed WITH their trailing NUL (`sizeof` on a C literal, not
//     `strlen`): "SubAddr\x00" is 8 bytes, "MoneroMessageSignature\x00" is 23.
package sigelo

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/bits"
	"slices"
	"strings"

	"filippo.io/edwards25519"
)

// MoneroError is returned by the decoders and encoders. The verifiers never fail: malformed
// input is a MsgResult with Good false.
type MoneroError string

func (e MoneroError) Error() string { return string(e) }

// ---------------------------------------------------------------- Keccak-256 (src/crypto/keccak.c)

var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008}

// keccakRot is the rho rotation of lane x + 5y.
var keccakRot = [25]int{0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14}

// keccakF is Keccak-f[1600] over 25 lanes indexed x + 5y.
func keccakF(a *[25]uint64) {
	for _, rc := range keccakRC {
		var c, d [5]uint64
		for x := range 5 {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := range 5 {
			d[x] = c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
		}
		var b [25]uint64
		for i := range 25 { // theta, then rho and pi: lane (x, y) moves to (y, 2x + 3y)
			x, y := i%5, i/5
			b[y+5*((2*x+3*y)%5)] = bits.RotateLeft64(a[i]^d[x], keccakRot[i])
		}
		for i := range 25 { // chi
			row := i / 5 * 5
			a[i] = b[i] ^ (^b[row+(i+1)%5] & b[row+(i+2)%5])
		}
		a[0] ^= rc // iota
	}
}

// Keccak256 is Keccak-256 with ORIGINAL padding 0x01 (src/crypto/keccak.c:119) over the
// concatenation of its arguments.
func Keccak256(parts ...[]byte) []byte {
	const rate = 136 // 1600/8 - 2*32
	data := bytes.Join(parts, nil)
	pad := append(data, 0x01)
	pad = append(pad, make([]byte, (rate-len(pad)%rate)%rate)...)
	pad[len(pad)-1] ^= 0x80
	var a [25]uint64
	for off := 0; off < len(pad); off += rate {
		for i := range rate / 8 {
			a[i] ^= binary.LittleEndian.Uint64(pad[off+8*i:])
		}
		keccakF(&a)
	}
	out := make([]byte, 32)
	for i := range 4 {
		binary.LittleEndian.PutUint64(out[8*i:], a[i])
	}
	return out
}

// ---------------------------------------------------------------- scalars and points (src/crypto/crypto-ops.c)

// ScReduce32 is 32 bytes little-endian reduced mod l (sc_reduce32).
func ScReduce32(b []byte) ([]byte, error) {
	if len(b) != 32 {
		return nil, MoneroError(fmt.Sprintf("sc_reduce32: expected 32 bytes, got %d", len(b)))
	}
	return scalar(b).Bytes(), nil
}

// scalar reduces up to 64 little-endian bytes mod l.
func scalar(b []byte) *edwards25519.Scalar {
	wide := make([]byte, 64)
	copy(wide, b)
	s, _ := edwards25519.NewScalar().SetUniformBytes(wide)
	return s
}

// HashToScalar is H_s(x) = sc_reduce32(Keccak256(x)) (src/crypto/crypto.cpp hash_to_scalar).
func HashToScalar(parts ...[]byte) []byte { return scalar(Keccak256(parts...)).Bytes() }

// point is ge_frombytes_vartime (src/crypto/crypto-ops.c): fe_frombytes_vartime refuses
// y >= p, and "If x = 0, the sign must be positive". edwards25519's SetBytes accepts both, and
// those are exactly the encodings that do not survive a round trip, so re-encoding and
// comparing is Monero's rule (and noble's zip215:false, which ts/ uses).
func point(b []byte) (*edwards25519.Point, error) {
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil || !bytes.Equal(p.Bytes(), b) {
		return nil, MoneroError("point: not a canonical curve point (ge_frombytes_vartime)")
	}
	return p, nil
}

func baseMul(s []byte) []byte { return new(edwards25519.Point).ScalarBaseMult(scalar(s)).Bytes() }

// ---------------------------------------------------------------- base58 (src/common/base58.cpp)

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" // Bitcoin's

// encSize[n] is the number of characters an n-byte block encodes to; 8 bytes -> 11.
var encSize = []int{0, 2, 3, 5, 6, 7, 9, 10, 11}

// MoneroBase58Encode encodes independent 8-byte blocks, big-endian within a block. No checksum.
func MoneroBase58Encode(data []byte) string {
	var out strings.Builder
	for i := 0; i < len(data); i += 8 {
		block := data[i:min(i+8, len(data))]
		n, s := new(big.Int).SetBytes(block), ""
		for r := new(big.Int); n.Sign() > 0; {
			n.DivMod(n, big.NewInt(58), r)
			s = string(b58Alphabet[r.Int64()]) + s
		}
		out.WriteString(strings.Repeat("1", encSize[len(block)]-len(s)) + s) // leading zero bytes are '1's
	}
	return out.String()
}

// MoneroBase58Decode is the inverse of MoneroBase58Encode.
func MoneroBase58Decode(s string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(s); i += 11 {
		chunk := s[i:min(i+11, len(s))]
		size := -1
		for k, n := range encSize {
			if n == len(chunk) {
				size = k
			}
		}
		if size < 1 {
			return nil, MoneroError(fmt.Sprintf("base58: %d is not a valid block length", len(chunk)))
		}
		n := new(big.Int)
		for _, ch := range chunk {
			d := strings.IndexRune(b58Alphabet, ch)
			if d < 0 {
				return nil, MoneroError(fmt.Sprintf("base58: %q is not a base58 digit", ch))
			}
			n.Mul(n, big.NewInt(58)).Add(n, big.NewInt(int64(d)))
		}
		if n.BitLen() > 8*size {
			return nil, MoneroError("base58: block overflows its byte length")
		}
		out = append(out, n.FillBytes(make([]byte, size))...)
	}
	return out, nil
}

// ---------------------------------------------------------------- addresses

// Address is a decoded Monero address.
type Address struct {
	Net, Kind   string // mainnet|testnet|stagenet, standard|integrated|subaddress
	Spend, View []byte
	PaymentID   []byte // 8 bytes iff Kind is integrated
}

var (
	netNames  = []string{"mainnet", "testnet", "stagenet"}
	kindNames = []string{"standard", "integrated", "subaddress"}
	prefixes  = map[string][3]uint64{ // src/cryptonote_config.h, in kindNames order
		"mainnet": {18, 19, 42}, "testnet": {53, 54, 63}, "stagenet": {24, 25, 36}}
)

// varint is Monero's LEB128 unsigned varint (src/common/varint.h write_varint).
func varint(n uint64) []byte { return binary.AppendUvarint(nil, n) }

func readVarint(b []byte) (uint64, int, error) {
	var n uint64
	for i, shift := 0, 0; ; i, shift = i+1, shift+7 {
		if i >= len(b) || shift > 28 {
			return 0, 0, MoneroError("varint: truncated or too long")
		}
		// read_varint's EVARINT_REPRESENT: a zero byte after the first is a non-minimal
		// encoding (`98 00` for 24). wallet2's decode_addr refuses it, so one wallet cannot
		// have two spellings of which only one is Monero's.
		if b[i] == 0 && shift > 0 {
			return 0, 0, MoneroError("varint: non-canonical (zero continuation byte)")
		}
		n |= uint64(b[i]&0x7f) << shift
		if b[i]&0x80 == 0 {
			return n, i + 1, nil
		}
	}
}

// EncodeAddress is base58(varint(prefix) || spend || view || [payment_id] || Keccak256(that)[0:4]).
func EncodeAddress(net, kind string, spend, view, paymentID []byte) (string, error) {
	if len(spend) != 32 || len(view) != 32 {
		return "", MoneroError("address: keys must be 32 bytes")
	}
	if (kind == "integrated") != (paymentID != nil) || (paymentID != nil && len(paymentID) != 8) {
		return "", MoneroError("address: payment_id must be 8 bytes and present iff kind is integrated")
	}
	pre, ok := prefixes[net]
	ki := slices.Index(kindNames, kind)
	if !ok || ki < 0 {
		return "", MoneroError(fmt.Sprintf("address: no prefix for %s %s", net, kind))
	}
	body := bytes.Join([][]byte{varint(pre[ki]), spend, view, paymentID}, nil)
	return MoneroBase58Encode(append(body, Keccak256(body)[:4]...)), nil
}

// DecodeAddress is the inverse of EncodeAddress. It fails on a bad digit, a bad checksum, a
// non-minimal prefix varint or an unknown prefix.
func DecodeAddress(s string) (*Address, error) {
	raw, err := MoneroBase58Decode(s)
	if err != nil {
		return nil, err
	}
	if len(raw) < 69 {
		return nil, MoneroError(fmt.Sprintf("address: %d bytes is too short", len(raw)))
	}
	body := raw[:len(raw)-4]
	if !bytes.Equal(Keccak256(body)[:4], raw[len(raw)-4:]) {
		return nil, MoneroError("address: checksum mismatch")
	}
	prefix, off, err := readVarint(body)
	if err != nil {
		return nil, err
	}
	for _, net := range netNames {
		for ki, val := range prefixes[net] {
			if val != prefix {
				continue
			}
			kind, want := kindNames[ki], off+64
			if kind == "integrated" {
				want += 8
			}
			if len(body) != want {
				return nil, MoneroError(fmt.Sprintf("address: %s body is %d bytes, expected %d", kind, len(body), want))
			}
			// get_account_address_from_str (src/cryptonote_basic/cryptonote_basic_impl.cpp) runs
			// check_key on both keys. In spend mode the view key is only hashed, never decoded, so
			// without this an address with a key Monero refuses could still carry a proven binding.
			for _, k := range [][]byte{body[off : off+32], body[off+32 : off+64]} {
				if _, err := point(k); err != nil {
					return nil, err
				}
			}
			a := &Address{Net: net, Kind: kind, Spend: body[off : off+32], View: body[off+32 : off+64]}
			if kind == "integrated" {
				a.PaymentID = body[off+64 : off+72]
			}
			return a, nil
		}
	}
	return nil, MoneroError(fmt.Sprintf("address: unknown prefix %d", prefix))
}

// ---------------------------------------------------------------- keys

// MoneroKeys are a wallet's private spend key b, private view key a, B = bG and A = aG.
type MoneroKeys struct{ Spend, View, SpendPub, ViewPub []byte }

// KeysFromSpend is b = sc_reduce32(seed), a = H_s(b), B = bG, A = aG (src/crypto/crypto.cpp:212).
func KeysFromSpend(seed []byte) (*MoneroKeys, error) {
	b, err := ScReduce32(seed)
	if err != nil {
		return nil, err
	}
	a := HashToScalar(b)
	return &MoneroKeys{Spend: b, View: a, SpendPub: baseMul(b), ViewPub: baseMul(a)}, nil
}

// SubaddressKeys is m = H_s("SubAddr\0" || a || le32(major) || le32(minor)), D = B + mG, C = aD
// (src/device/device_default.cpp:211). (0,0) is the account's own address, never derived:
// deriving it would give a different, unfunded address that no wallet watches.
func SubaddressKeys(a, spendPub []byte, major, minor uint32) (c, d []byte, err error) {
	if major == 0 && minor == 0 {
		return baseMul(a), bytes.Clone(spendPub), nil
	}
	idx := binary.LittleEndian.AppendUint32(binary.LittleEndian.AppendUint32(nil, major), minor)
	m := HashToScalar([]byte("SubAddr\x00"), a, idx)
	B, err := point(spendPub)
	if err != nil {
		return nil, nil, err
	}
	D := new(edwards25519.Point).Add(B, new(edwards25519.Point).ScalarBaseMult(scalar(m)))
	return new(edwards25519.Point).ScalarMult(scalar(a), D).Bytes(), D.Bytes(), nil
}

// Subaddress is the address string for one subaddress index; (0,0) is the primary address.
func Subaddress(a, spendPub []byte, major, minor uint32, net string) (string, error) {
	c, d, err := SubaddressKeys(a, spendPub, major, minor)
	if err != nil {
		return "", err
	}
	kind := "subaddress"
	if major == 0 && minor == 0 {
		kind = "standard"
	}
	return EncodeAddress(net, kind, d, c, nil)
}

// ---------------------------------------------------------------- message signatures

// msgDomain is config::HASH_KEY_MESSAGE_SIGNING, 23 bytes: `sizeof` keeps the NUL.
var msgDomain = []byte("MoneroMessageSignature\x00")

// MessageHash is wallet2::get_message_hash (src/wallet/wallet2.cpp ~13037). Mode byte: 0 spend, 1 view.
func MessageHash(spendPub, viewPub []byte, mode string, data []byte) []byte {
	m := byte(1)
	if mode == "spend" {
		m = 0
	}
	return Keccak256(msgDomain, spendPub, viewPub, []byte{m}, varint(uint64(len(data))), data)
}

// checkSignature is crypto::check_signature (src/crypto/crypto.cpp ~364). Never fails.
func checkSignature(h, pub, sig []byte) bool {
	c, err1 := edwards25519.NewScalar().SetCanonicalBytes(sig[:32]) // sc_check on both,
	r, err2 := edwards25519.NewScalar().SetCanonicalBytes(sig[32:]) // sc_isnonzero on c
	P, err3 := point(pub)
	if err1 != nil || err2 != nil || err3 != nil || c.Equal(edwards25519.NewScalar()) == 1 {
		return false
	}
	R := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(c, P, r) // c·P + r·G
	if R.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false // Monero memcmps the identity's encoding out
	}
	return bytes.Equal(HashToScalar(h, pub, R.Bytes()), sig[:32])
}

// SignMessage is "SigV2" + base58(c || r) (wallet2::sign ~13057, crypto::generate_signature
// ~335). secret is the scalar the mode selects: spend mode signs with b (or b + m for a
// subaddress), view mode with a (or a(b + m)). nonce is for deterministic tests; nil is random.
func SignMessage(message []byte, mode string, secret, spendPub, viewPub, nonce []byte) (string, error) {
	pub := viewPub
	if mode == "spend" {
		pub = spendPub
	}
	h := MessageHash(spendPub, viewPub, mode, message)
	if nonce == nil {
		nonce = make([]byte, 32)
		rand.Read(nonce)
	}
	k := scalar(nonce)
	for k.Equal(edwards25519.NewScalar()) == 1 {
		rand.Read(nonce)
		k = scalar(nonce)
	}
	kG := new(edwards25519.Point).ScalarBaseMult(k).Bytes()
	c := scalar(HashToScalar(h, pub, kG))
	r := edwards25519.NewScalar().Subtract(k, edwards25519.NewScalar().Multiply(c, scalar(secret))) // sc_mulsub
	return "SigV2" + MoneroBase58Encode(append(c.Bytes(), r.Bytes()...)), nil
}

// MsgResult reports a message verification: which mode matched and which signature version.
type MsgResult struct {
	Good    bool
	Mode    string // "spend" or "view" when Good
	Version int    // 1 or 2
}

// VerifyMessage is wallet2::verify: try mode 0 against the address's spend key, then mode 1
// against its view key, and report which matched. SigV1 hashes only Keccak256(data); sigelo
// never emits it, old wallets did, so wallet2 (and this) accepts it. Never fails.
func VerifyMessage(message []byte, address, signature string) MsgResult {
	version := 1
	if strings.HasPrefix(signature, "SigV2") {
		version = 2
	}
	if !strings.HasPrefix(signature, "SigV1") && version != 2 {
		return MsgResult{Version: version}
	}
	sig, err := MoneroBase58Decode(signature[5:])
	if err != nil || len(sig) != 64 {
		return MsgResult{Version: version}
	}
	addr, err := DecodeAddress(address)
	if err != nil {
		return MsgResult{Version: version} // a malformed address is a failed verification
	}
	for _, mode := range []string{"spend", "view"} {
		h, pub := Keccak256(message), addr.Spend
		if version == 2 {
			h = MessageHash(addr.Spend, addr.View, mode, message)
		}
		if mode == "view" {
			pub = addr.View
		}
		if checkSignature(h, pub, sig) {
			return MsgResult{Good: true, Mode: mode, Version: version}
		}
	}
	return MsgResult{Version: version}
}

// ---------------------------------------------------------------- sigelo glue (SPEC §6.2)

// SigeloMoneroSigAddr produces `sig_addr` for a binding body with a Monero wallet key.
func SigeloMoneroSigAddr(body any, mode string, secret, spendPub, viewPub, nonce []byte) (string, error) {
	in, err := SigningInput(body)
	if err != nil {
		return "", err
	}
	return SignMessage(in, mode, secret, spendPub, viewPub, nonce)
}

// VerifySigeloMoneroSigAddr verifies a binding's sig_addr against its own `addr` (§6.1, §6.2).
// Two §6.2 rules live here rather than in VerifyMessage, which stays a faithful wallet2: the
// address must be STANDARD or SUBADDRESS (never integrated), and SigV1 is not accepted. A
// subaddress is checked against its own (D, C), which wallet2::sign's subaddress branch signs
// with (b + m spend, a(b + m) view): either mode needs the spend key there. Never fails.
func VerifySigeloMoneroSigAddr(body any, addr string, sigAddr any) MsgResult {
	s, _ := sigAddr.(string)
	bad := MsgResult{Version: 1}
	if strings.HasPrefix(s, "SigV2") {
		bad.Version = 2
	}
	// §6.2: "Integrated forms are not accepted as `addr`." The message hash covers (B, A), not
	// the prefix, so the integrated spelling of a wallet reuses the base address's signature
	// verbatim — accepting it would let a payment id nobody signed for ride along on a proven
	// binding. A subaddress carries its own keys, so its signature is its own.
	if a, err := DecodeAddress(addr); err != nil || a.Kind == "integrated" {
		return bad
	}
	// §6.2: "Legacy SigV1 is not accepted." Its hash is Keccak256(data) alone: neither the mode
	// byte nor the address's keys are inside it, so it cannot tell view from spend.
	in, err := SigningInput(body)
	if bad.Version != 2 || err != nil {
		return bad
	}
	return VerifyMessage(in, addr, s)
}
