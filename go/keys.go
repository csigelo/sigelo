// SPDX-License-Identifier: MIT

// Root-seed derivation (MONERO.md §2), the same functions as ts/src/keys.ts, so a Go keeper or
// verifier derives byte-for-byte the keys the ts offline box derives. Kept out of sigelo.go:
// a world that only verifies bundles never reads this file.
//
//	vault      = the Monero wallet whose 25-word seed is S: b = sc_reduce32(S), a = H_s(b)
//	k(R, path) = HKDF-SHA256(ikm = R, salt = "", info = path)   -> 32 bytes   R = S or a keeper root K
//	identity   = Ed25519 seed  k(S, "sigelo/v1/identity/ed25519/<n>")
//	recovery   = Ed25519 seed  k(S, "sigelo/v1/recovery/ed25519")
//	wallet     = b = sc_reduce32(k(S, "sigelo/v1/monero/<w>"))   a = H_s(b), B = bG, A = aG
//	keeper     = K_j = k(S, "sigelo/v1/keeper/<j>")
//	agent      = Ed25519 seed  k(K, "sigelo/v1/identity/<i>/ed25519/<n>")
//
// The path is the HKDF info verbatim: the strings below are literals and must never be
// "tidied". Indices are decimal without leading zeros, capped at 2^53−1 as in ts (a JS safe
// integer), so the two implementations accept exactly the same paths.
//
// S travels as Monero's 25 English words (electrum-words.cpp), decoded and encoded here as in
// ts; S must be canonical, 0 < S < l, so the vault's spend key is S itself and a stock wallet
// shows back the words it was given. The vault is the Owner's and is never loaded by a keeper.
package sigelo

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"regexp"
	"slices"
	"strings"
)

// K is k(root, info) = HKDF-SHA256(ikm = root, salt = "", info), 32 bytes. An empty salt is
// RFC 5869's HashLen zeros in both crypto/hkdf and @noble/hashes. The root must be 32 bytes.
func K(root []byte, info string) ([32]byte, error) {
	var out [32]byte
	if len(root) != 32 {
		return out, fail("root: seed must be 32 bytes, got %d", len(root))
	}
	b, err := hkdf.Key(sha256.New, root, nil, info, 32)
	copy(out[:], b)
	return out, err
}

// index is keys.ts's index(): a non-negative safe integer, so "%d" is plain decimal.
func index(what string, v uint64) error {
	if v > MaxInt {
		return fail("%s: index must be a non-negative integer, got %d", what, v)
	}
	return nil
}

// IdentitySeed is the Ed25519 seed for identity rotation n. Raw: the Ed25519 branch never reduces.
func IdentitySeed(S []byte, n uint64) ([32]byte, error) {
	if n > MaxInt {
		return [32]byte{}, fail("identity: rotation counter must be a non-negative integer, got %d", n)
	}
	return K(S, fmt.Sprintf("sigelo/v1/identity/ed25519/%d", n))
}

// KeeperRoot is K_j, the subtree of S one keeper holds to mint agent identities after the
// ceremony has forgotten S. A root in its own right: every function here takes it where it takes S.
func KeeperRoot(S []byte, j uint64) ([32]byte, error) {
	if err := index("keeper", j); err != nil {
		return [32]byte{}, err
	}
	return K(S, fmt.Sprintf("sigelo/v1/keeper/%d", j))
}

// AgentIdentitySeed is the Ed25519 seed for agent i (its account index), rotation n, under
// keeper root K. The account segment sits before "ed25519", so no agent path equals the
// keeper's own identity/ed25519/<n>.
func AgentIdentitySeed(keeper []byte, i, n uint64) ([32]byte, error) {
	if err := index("agent", i); err != nil {
		return [32]byte{}, err
	}
	if err := index("agent rotation", n); err != nil {
		return [32]byte{}, err
	}
	return K(keeper, fmt.Sprintf("sigelo/v1/identity/%d/ed25519/%d", i, n))
}

// RecoverySeed is the Ed25519 seed for the recovery key: one per root, it outlives every rotation.
func RecoverySeed(S []byte) ([32]byte, error) { return K(S, "sigelo/v1/recovery/ed25519") }

// PublicKey is the multibase (multicodec ed25519-pub, base58btc) public key of an Ed25519 seed.
func PublicKey(seed [32]byte) string {
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	return "z" + b58encode(slices.Concat([]byte{0xed, 0x01}, pub))
}

// RecoveryPublicKey is the recovery public key, multibase: the only half that leaves the offline box.
func RecoveryPublicKey(S []byte) (string, error) {
	seed, err := RecoverySeed(S)
	return PublicKey(seed), err
}

// RecoveryCommitment is "sha256:<hex>" of the recovery public key, what a genesis carries (SPEC §4).
func RecoveryCommitment(S []byte) (string, error) {
	key, err := RecoveryPublicKey(S)
	return commitmentOf(key), err
}

// Wallet is one Monero wallet from a root. ViewOnly is what MONERO.md §2 hands a runtime.
type Wallet struct {
	MoneroKeys
	Address string
}

// ViewOnly drops the spend key: sees every receipt, can spend nothing.
func (w *Wallet) ViewOnly() Wallet {
	return Wallet{MoneroKeys{View: w.View, SpendPub: w.SpendPub, ViewPub: w.ViewPub}, w.Address}
}

// WalletFromRoot is b = sc_reduce32(k(S, "sigelo/v1/monero/<name>")), a = H_s(b), with the
// standard address on net. name (treasury, allowance, counterparty/<id>) goes in verbatim.
func WalletFromRoot(S []byte, name, net string) (*Wallet, error) {
	if name == "" {
		return nil, fail("wallet: name must not be empty")
	}
	seed, err := K(S, "sigelo/v1/monero/"+name)
	if err != nil {
		return nil, err
	}
	return walletOf(seed[:], net)
}

// VaultFromRoot is the wallet a stock Monero wallet restores from S's 25 words: b = sc_reduce32(S),
// a = H_s(b) (account_base::generate, src/cryptonote_basic/account.cpp). The Owner's, cold: a
// keeper never loads it, because its spend key is S.
func VaultFromRoot(S []byte, net string) (*Wallet, error) {
	if len(S) != 32 {
		return nil, fail("root: seed must be 32 bytes, got %d", len(S))
	}
	return walletOf(S, net)
}

func walletOf(seed []byte, net string) (*Wallet, error) {
	keys, _ := KeysFromSpend(seed) // 32 bytes: KeysFromSpend reduces and cannot fail
	addr, err := EncodeAddress(net, "standard", keys.SpendPub, keys.ViewPub, nil)
	if err != nil {
		return nil, err
	}
	return &Wallet{*keys, addr}, nil
}

// ---------------------------------------------------------------- Monero 25 words for S

// Monero's Electrum-style mnemonic, English only (src/mnemonics/electrum-words.cpp, monero
// d02c7c57), exactly as ts/src/keys.ts: each 4-byte little-endian chunk x gives w1 = x % n,
// w2 = (x/n + w1) % n, w3 = (x/n/n + w2) % n (bytes_to_words, :471-473); the 25th word repeats
// word crc32(3-letter prefixes of the 24) % 24 (create_checksum_index, :192-209; IEEE CRC-32).
// Decoding: x = w1 + n((n-w1+w2)%n) + n²((n-w2+w3)%n) (:323-324), which wallet2 computes in
// uint32 and refuses unless x % n == w1 (:326) — exactly "x < 2^32", since 2^32 % 1626 = 490.
const wordPrefix = 3

var wordByPrefix = func() map[string]int {
	m := make(map[string]int, len(moneroWords))
	for i, w := range moneroWords {
		m[w[:wordPrefix]] = i
	}
	return m
}()

func checksumIndex(idx []int) int {
	var p strings.Builder
	for _, i := range idx {
		p.WriteString(moneroWords[i][:wordPrefix])
	}
	return int(crc32.ChecksumIEEE([]byte(p.String())) % uint32(len(idx)))
}

// EncodeMoneroWords is Monero's bytes_to_words for 32 bytes. No canonicality check: see MnemonicFromRoot.
func EncodeMoneroWords(b []byte) (string, error) {
	if len(b) != 32 {
		return "", fail("mnemonic: seed must be 32 bytes, got %d", len(b))
	}
	n := uint32(len(moneroWords))
	idx := make([]int, 0, 25)
	for i := 0; i < 32; i += 4 {
		x := uint32(b[i]) | uint32(b[i+1])<<8 | uint32(b[i+2])<<16 | uint32(b[i+3])<<24
		w1 := x % n
		w2 := (x/n + w1) % n
		idx = append(idx, int(w1), int(w2), int((x/n/n+w2)%n))
	}
	idx = append(idx, idx[checksumIndex(idx)])
	words := make([]string, len(idx))
	for i, j := range idx {
		words[i] = moneroWords[j]
	}
	return strings.Join(words, " "), nil
}

// DecodeMoneroWords is Monero's words_to_bytes for 25 English words, checksum enforced. A word
// is accepted whole or as exactly its 3-letter prefix, case-insensitively.
func DecodeMoneroWords(text string) ([32]byte, error) {
	var out [32]byte
	words := strings.Fields(strings.ToLower(text))
	if len(words) != 25 {
		return out, fail("mnemonic: expected 25 words, got %d", len(words))
	}
	idx := make([]int, 25)
	for k, w := range words {
		i, ok := -1, false
		if len(w) >= wordPrefix {
			i, ok = wordByPrefix[w[:wordPrefix]]
		}
		if !ok || (w != moneroWords[i] && w != moneroWords[i][:wordPrefix]) {
			return out, fail("mnemonic: %q is not in the Monero English wordlist", w)
		}
		idx[k] = i
	}
	if idx[checksumIndex(idx[:24])] != idx[24] {
		return out, fail("mnemonic: checksum mismatch (the 25th word)")
	}
	n := uint64(len(moneroWords))
	for t := range 8 {
		w1, w2, w3 := uint64(idx[3*t]), uint64(idx[3*t+1]), uint64(idx[3*t+2])
		x := w1 + n*((n-w1+w2)%n) + n*n*((n-w2+w3)%n)
		if x >= 1<<32 {
			return out, fail("mnemonic: words %d-%d are not a Monero seed encoding (electrum-words.cpp:326)", 3*t+1, 3*t+3)
		}
		for j := range 4 {
			out[4*t+j] = byte(x >> (8 * j))
		}
	}
	return out, nil
}

// checkCanonical: 0 < S < l. Past l a restored wallet shows sc_reduce32(S)'s words, another root.
func checkCanonical(S []byte, what string) error {
	r, err := ScReduce32(S)
	if err != nil {
		return err
	}
	if string(r) != string(S) || !slices.ContainsFunc(S, func(b byte) bool { return b != 0 }) {
		return fail("%s: not a canonical root (need 0 < S < l) — a Monero wallet restored from it would show different words, and sigelo would derive a different root from those", what)
	}
	return nil
}

// MnemonicFromRoot is S's 25 words; a non-canonical S is refused.
func MnemonicFromRoot(S []byte) (string, error) {
	if err := checkCanonical(S, "mnemonic"); err != nil {
		return "", err
	}
	return EncodeMoneroWords(S)
}

// RootFromMnemonic is S from its 25 words: checksum enforced, canonical scalar required.
func RootFromMnemonic(words string) ([32]byte, error) {
	S, err := DecodeMoneroWords(words)
	if err == nil {
		err = checkCanonical(S[:], "mnemonic")
	}
	if err != nil {
		return [32]byte{}, err
	}
	return S, nil
}

// Identity is a derived sigelo identity: keygen's result in ts.
type Identity struct {
	DID     string
	Genesis Object
	Secret  [32]byte
	Key     string
}

var commitmentRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// DeriveIdentity is ts's deriveIdentity(S, n, recovery, {created, nonce}): the genesis for
// rotation n, reproducible byte for byte. recovery "" means the root's own recovery key;
// otherwise it is a multibase recovery public key or a "sha256:<hex>" commitment, used
// verbatim. created and nonce (raw bytes, multibase-encoded here) are required: Go reads no clock and draws no randomness.
func DeriveIdentity(S []byte, n uint64, recovery, created string, nonce []byte) (*Identity, error) {
	seed, err := IdentitySeed(S, n)
	if err != nil {
		return nil, err
	}
	if recovery == "" {
		recovery, _ = RecoveryPublicKey(S)
	}
	if !commitmentRe.MatchString(recovery) {
		raw, err := decodeKey(recovery)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(raw)
		recovery = "sha256:" + hex.EncodeToString(h[:])
	}
	g := Object{{"v", Version}, {"typ", "genesis"}, {"key", PublicKey(seed)},
		{"recovery", recovery}, {"created", created}, {"nonce", "z" + b58encode(nonce)}}
	if err := Structure(g, "genesis"); err != nil {
		return nil, err
	}
	return &Identity{did(g), g, seed, PublicKey(seed)}, nil
}
