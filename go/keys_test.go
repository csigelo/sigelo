package sigelo

// MONERO.md §2 key derivation against ts/src/keys.ts. The keeper/agent seeds are ts/src/test.ts
// section g's fixed vectors; the identity, recovery and wallet values were printed by ts's
// own keys.js (deriveIdentity, recoveryPublicKey, walletFromRoot) over the same root, so a
// mismatch here is a Go/ts disagreement, not a changed vector.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func hx(b [32]byte) string { return hex.EncodeToString(b[:]) }

// must drops the error of a derivation the test has no reason to expect to fail; a failure
// still shows, as an all-zero key that matches no vector.
func must(b [32]byte, _ error) [32]byte { return b }

func TestKeys(t *testing.T) {
	// "sigelo root seed, test vector #1" / "#2" as ASCII, as in ts/src/test.ts. Never for funds.
	S1, _ := hex.DecodeString("736967656c6f20726f6f7420736565642c207465737420766563746f72202331")
	S2, _ := hex.DecodeString("736967656c6f20726f6f7420736565642c207465737420766563746f72202332")

	K0 := must(KeeperRoot(S1, 0))
	K1 := must(KeeperRoot(S1, 1))
	check("go keys keeperRoot fixed vectors: K_0 and K_1 of S1",
		hx(K0) == "683fbd16792613e6a361b2061fb2cbfb56118276954179c63a98ac6b7d19bdf2" &&
			hx(K1) == "532211c88fe219df3270cb8640c89f89f525845624b54f0352b696c97960b801" &&
			K0 == must(K(S1, "sigelo/v1/keeper/0")))
	check("go keys agentIdentitySeed fixed vector: (K_0, i=0, n=0)",
		hx(must(AgentIdentitySeed(K0[:], 0, 0))) == "918b0cb138791dc35a1e843585e9433a029dd6e6f3b3d7a764ccb89c1a8448c3")
	check("go keys agentIdentitySeed fixed vector: (K_0, i=1, n=0)",
		hx(must(AgentIdentitySeed(K0[:], 1, 0))) == "36ca4e02c29c9131344139b99be1d894c30d43fab762a1dd4e37720e08c5e2df" &&
			must(AgentIdentitySeed(K0[:], 1, 0)) == must(K(K0[:], "sigelo/v1/identity/1/ed25519/0")))
	check("go keys agentIdentitySeed fixed vector: (K_0, i=0, n=1)",
		hx(must(AgentIdentitySeed(K0[:], 0, 1))) == "400d40c3663541b8f2dd7341ac491e921bb05b91f3308b1ca8c4770884935037")

	// Root identity and recovery, as ts derives them from S1.
	check("go keys identitySeed(S1, 0) matches ts",
		hx(must(IdentitySeed(S1, 0))) == "d701590b1694a79577d39fa47868069d1d594444eabfa6e09adcc19d2f1a7509")
	check("go keys recoverySeed and recovery public key match ts",
		hx(must(RecoverySeed(S1))) == "ad3697ed02859525647f96d6007040acd30f5ad99dc4e42be821c42f36012895" &&
			PublicKey(must(RecoverySeed(S1))) == "z6MkrqZ2EqXr8HxquJpujTZYB1abAMNeEmHNE8tYiMwyeSWg")
	rc, _ := RecoveryCommitment(S1)
	check("go keys recovery commitment matches ts",
		rc == "sha256:cdd6b57b4d3d703430a97987e19f82ccf63d4742eabe247644fc86dcb64bb07d")
	nonce, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	id0, err := DeriveIdentity(S1, 0, "", "2026-01-01T00:00:00Z", nonce)
	check("go keys deriveIdentity(S1, 0) reproduces ts's key, genesis and DID",
		err == nil && id0.Key == "z6Mknxzocw2qpktdYKW6BZc5r7YfkYNEaCsxz89YJXnXuTT7" &&
			canon(id0.Genesis) == `{"created":"2026-01-01T00:00:00Z","key":"z6Mknxzocw2qpktdYKW6BZc5r7YfkYNEaCsxz89YJXnXuTT7","nonce":"z1UoWww8DGaVGLtea7zU7p","recovery":"sha256:cdd6b57b4d3d703430a97987e19f82ccf63d4742eabe247644fc86dcb64bb07d","typ":"genesis","v":"sigelo/0"}` &&
			id0.DID == "did:sigelo:z2ufU9s5PTTFVxFbFeejk7ZUmNpkjtQ6wnucWYdZyUH6m")
	id1, err1 := DeriveIdentity(S1, 1, "", "2026-01-01T00:00:00Z", nonce)
	check("go keys deriveIdentity(S1, 1) matches ts's DID",
		err1 == nil && id1.DID == "did:sigelo:z9UT4e39JzPR9K4AgqdMgZBrtsK5tW6Lp1tuzmVrf38N4")
	pk, _ := RecoveryPublicKey(S1)
	idc, errc := DeriveIdentity(S1, 0, rc, "2026-01-01T00:00:00Z", nonce)
	idk, errk := DeriveIdentity(S1, 0, pk, "2026-01-01T00:00:00Z", nonce)
	check("go keys deriveIdentity takes the recovery as key or as commitment, same DID",
		errc == nil && errk == nil && idc.DID == id0.DID && idk.DID == id0.DID)
	msg, _ := SigningInput(Object{{"v", Version}, {"typ", "challenge"}, {"did", id0.DID}, {"ctx", "keys-test"}, {"nonce", "z1UoWww8DGaVGLtea7zU7p"}})
	sig := "z" + b58encode(ed25519.Sign(ed25519.NewKeyFromSeed(id0.Secret[:]), msg))
	check("go keys a derived identity signs and verifies", VerifySig(id0.Key, Object{{"v", Version}, {"typ", "challenge"}, {"did", id0.DID}, {"ctx", "keys-test"}, {"nonce", "z1UoWww8DGaVGLtea7zU7p"}}, sig))

	// Wallets: the values ts's walletFromRoot printed, which ts's interop test hands to a stock
	// monero-wallet-rpc (generate_from_keys) and checks it reproduces.
	for _, w := range []struct{ name, net, b, a, B, A, addr string }{
		{"treasury", "stagenet", "a5d93a3d39b38ce47998ee64c8768308c12fd23026551259d82a87216949ca05",
			"c002a05afdd3f118676c0e90164c3ee11422a0b2dc489b399fc7e50a19d43304",
			"8d46ec4f064d1181154d6cc27a1463b08037528ed753035cc9bb8edd1d320318",
			"a848a3d9473d4d9b4df55f648d3a773b9cf1d58869e26aada264f71c76407062",
			"57BfQWnMGhNNbGbScmfomcWXHCWKKB1L6GXAHGK7D4Uz58D2EbvyWUCSyecM4ecNiJAyKeD8K74TjW3UJXkmQEnsC7SRR6s"},
		{"allowance", "stagenet", "50c2ab67245a3489803c15e160cad0aaa57c33db6f4a4862b02cc2c0d19b270f",
			"450a184938f841c386d93f85f6e32bf9b1d6fceaa42cb80195f29afd6c69f50c",
			"df9853546fe80ac88576b2f87536b21e56ea5e018b02cae3a01a8a82433ed6fe",
			"64348c7d0e5c9fd3097832900d882fd78b2471c3164c9ef819376a97728df296",
			"5AJbLyL9AW5aYJsoWCdazu65LDT8dDrbsf5FbG4WdyNdjYv6koJk9jtcJKk7jowqXLd43Sw8QxhMFiVsF4W87MboHz7he7T"},
	} {
		wl, err := WalletFromRoot(S1, w.name, w.net)
		check("go keys walletFromRoot(S1, "+w.name+", "+w.net+"): b, a, B, A and address match ts",
			err == nil && hex.EncodeToString(wl.Spend) == w.b && hex.EncodeToString(wl.View) == w.a &&
				hex.EncodeToString(wl.SpendPub) == w.B && hex.EncodeToString(wl.ViewPub) == w.A && wl.Address == w.addr)
	}
	tw, _ := WalletFromRoot(S1, "treasury", "stagenet")
	tm, _ := WalletFromRoot(S1, "treasury", "mainnet")
	check("go keys the network changes the address, not the keys",
		tm.Address == "46ydKfsPd6GNbGbScmfomcWXHCWKKB1L6GXAHGK7D4Uz58D2EbvyWUCSyecM4ecNiJAyKeD8K74TjW3UJXkmQEnsC9Pn2vM" &&
			hex.EncodeToString(tm.Spend) == hex.EncodeToString(tw.Spend))
	kw, _ := WalletFromRoot(K0[:], "counterparty/acme", "stagenet")
	check("go keys a keeper root is a root: walletFromRoot(K_0, counterparty/acme) matches ts",
		kw.Address == "53kC5Aj3CwZN2Ud366M7XGUZ55Q8RzB7aW36sp6sNyaSbCos5y9vxskHhSvgCkEVpYYMoReFjvj4p658gamWFtbpShHvxND")
	vo := tw.ViewOnly()
	check("go keys ViewOnly() drops the spend key", vo.Spend == nil && vo.Address == tw.Address && string(vo.View) == string(tw.View))
	t2, _ := WalletFromRoot(S1, "treasury2", "stagenet")
	check("go keys a wallet name is part of the path", t2.Address != tw.Address)

	// Domain separation, as ts: the path string is the key.
	seps := [][32]byte{K0, K1, must(IdentitySeed(S1, 0)), must(IdentitySeed(S1, 1)), must(IdentitySeed(K0[:], 0)),
		must(RecoverySeed(S1)), must(K(S1, "sigelo/v1/monero/treasury")), must(K(S1, "sigelo/v1/monero/allowance")),
		must(AgentIdentitySeed(K0[:], 0, 0)), must(AgentIdentitySeed(K0[:], 1, 0)), must(AgentIdentitySeed(K0[:], 0, 1)),
		must(AgentIdentitySeed(K1[:], 0, 0))}
	seen := map[[32]byte]bool{}
	for _, s := range seps {
		seen[s] = true
	}
	check("go keys keeper, identity, recovery, wallet and agent paths are domain-separated", len(seen) == len(seps) && !seen[[32]byte{}])
	check("go keys a root differing in one byte derives a different keeper root and identity",
		must(KeeperRoot(S2, 0)) != K0 && must(IdentitySeed(S2, 0)) != must(IdentitySeed(S1, 0)))

	// Rejections, with ts's messages. uint64 cannot be negative; the huge index is 2^53, the
	// first one ts's Number.isSafeInteger refuses, and every uint64 above it is refused too.
	_, err = AgentIdentitySeed(K0[:], MaxInt+1, 0)
	rejects("go keys an agent index past 2^53-1 is rejected", err, "agent: index must be a non-negative integer, got 9007199254740992")
	_, err = AgentIdentitySeed(K0[:], 0, ^uint64(0))
	rejects("go keys an agent rotation of 2^64-1 (a negative int cast to uint64) is rejected", err, "agent rotation: index must be a non-negative integer")
	_, err = KeeperRoot(S1, MaxInt+1)
	rejects("go keys a keeper index past 2^53-1 is rejected", err, "keeper: index must be a non-negative integer")
	_, err = IdentitySeed(S1, MaxInt+1)
	rejects("go keys an identity rotation counter past 2^53-1 is rejected", err, "identity: rotation counter must be a non-negative integer")
	check("go keys the largest safe index 2^53-1 is accepted", must(AgentIdentitySeed(K0[:], MaxInt, MaxInt)) != [32]byte{})
	_, err = K(S1[:31], "sigelo/v1/keeper/0")
	rejects("go keys a 31-byte root is rejected", err, "root: seed must be 32 bytes, got 31")
	_, err = WalletFromRoot(S1, "", "stagenet")
	rejects("go keys an empty wallet name is rejected", err, "wallet: name must not be empty")
}

// TestMoneroWords pins the root's 25-word encoding to ts/src/test.ts's words section: the same
// wordlist hash, the same three vectors (each confirmed there against monero-wallet-rpc
// 0.18.5's restore_deterministic_wallet) and the same 64-root sweep digest, so ts and Go
// produce identical words and vault keys for every pinned seed. Never use a vector for funds.
func TestMoneroWords(t *testing.T) {
	list := sha256.Sum256([]byte(strings.Join(moneroWords, "\n") + "\n"))
	prefixes := map[string]bool{}
	for _, w := range moneroWords {
		prefixes[w[:3]] = true
	}
	check("go words the Monero English wordlist: 1626 words, 1626 distinct 3-letter prefixes, hash pinned",
		len(moneroWords) == 1626 && len(prefixes) == 1626 &&
			hex.EncodeToString(list[:]) == "eaa6bce7dd92f4d6dd74f224264e0ef4ad21095d68ec77616b26ceb599baf4f7")

	vectors := []struct{ seed, words, a, stagenet, mainnet string }{
		{"7788b79c3a481c90542e7106471ee0079f09c65b12836d74d72206e3fe49ec02",
			"loyal yacht obliged afoot lofty army frown demonstrate drinks rowboat rejoices rumble different nearby uttered jittery epoxy repent woken odds lesson suture hedgehog hire lesson",
			"c5df810e80b045d656dbf366622896ecc9367d8cd907fab47986beea05233d06",
			"59XmNWmDNk6RprQAMPpqfKb36WXut2KqoBCXABdgcd9rfxS5rgbmTBpYzurnpXtRaEWqgCoRZBdSEfGNbVZi2YcF2cXZMSq",
			"49KjHfrFj8zRprQAMPpqfKb36WXut2KqoBCXABdgcd9rfxS5rgbmTBpYzurnpXtRaEWqgCoRZBdSEfGNbVZi2YcF2fkiK1T"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f",
			"foamy solved soggy foamy solved soggy foamy solved soggy foamy solved soggy foamy solved soggy foamy solved soggy foamy solved soggy jury yawning ankle soggy",
			"4560c4b2bdacb15cc4f9a4a8938bb849c26c9011272c308f6d9b70445f53db05",
			"5ArT6ercKKQGbrAdSKCbVL73ME4FGv2cpczjV2peqqkxagm5D4gBqAHJta6NpbtxyuRe3ywaTj6QCHD59savvPW69vakaa1",
			"4AeR1owefiJGbrAdSKCbVL73ME4FGv2cpczjV2peqqkxagm5D4gBqAHJta6NpbtxyuRe3ywaTj6QCHD59savvPW69wfW9my"},
		{"ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
			"laptop height rowboat beware woozy gather slackens vain nanny tumbling gained identity abbey abbey abbey abbey abbey abbey abbey abbey abbey justice yearbook annoyed annoyed",
			"8f368706106c9b6bc7d8e3def8aa18840f2e605e3ca5495fb99f7fc64260b503",
			"55BScWfUCysJ8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmfXUvkY7NQhchNuYKoXRoGSJCjenATXkEoZobEXSTnwtF3XdByMR",
			"44yQXfkWZNmJ8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmfXUvkY7NQhchNuYKoXRoGSJCjenATXkEoZobEXSTnwtF3ZiFSbR"},
	}
	for i, v := range vectors {
		S, _ := hex.DecodeString(v.seed)
		words, errW := MnemonicFromRoot(S)
		back, errB := RootFromMnemonic(v.words)
		st, errS := VaultFromRoot(S, "stagenet")
		mn, errM := VaultFromRoot(S, "mainnet")
		check(fmt.Sprintf("go words fixed vector V%d: seed -> 25 words -> seed, vault b = S, a, stagenet and mainnet addresses match ts", i+1),
			errW == nil && errB == nil && errS == nil && errM == nil && words == v.words && hx(back) == v.seed &&
				hex.EncodeToString(st.Spend) == v.seed && hex.EncodeToString(st.View) == v.a &&
				st.Address == v.stagenet && mn.Address == v.mainnet)
	}

	var sweep strings.Builder
	for i := range 64 {
		s := sha256.Sum256([]byte(fmt.Sprintf("sigelo words sweep %d", i)))
		s[31] &= 0x0f
		w, err := MnemonicFromRoot(s[:])
		back, err2 := RootFromMnemonic(w)
		if err != nil || err2 != nil || back != s {
			sweep.WriteString("ROUND TRIP FAILED")
		}
		sweep.WriteString(w + "\n")
	}
	sd := sha256.Sum256([]byte(sweep.String()))
	check("go words 64-root sweep round-trips, digest pinned with ts", hex.EncodeToString(sd[:]) == "1a7aff8d3f1432532425934dae8ecb56e6490105e5452d5419cf6ba766fd2733")

	w1 := vectors[0].words
	parts := strings.Fields(w1)
	short := make([]string, len(parts))
	for i, p := range parts {
		short[i] = p[:3]
	}
	up, _ := RootFromMnemonic("  " + strings.ReplaceAll(strings.ToUpper(w1), " ", "\n\t ") + " ")
	pre, _ := RootFromMnemonic(strings.Join(short, " "))
	check("go words case, extra whitespace and 3-letter prefixes are accepted, as wallet2 does", hx(up) == vectors[0].seed && hx(pre) == vectors[0].seed)

	// withChecksum: 24 data words plus the 25th that makes the checksum hold.
	withChecksum := func(w24 []string) string {
		for _, c := range w24 {
			s := strings.Join(append(slices.Clone(w24), c), " ")
			if _, err := DecodeMoneroWords(s); err == nil || !strings.Contains(err.Error(), "checksum") {
				return s
			}
		}
		return ""
	}
	wrong := strings.Join(append(slices.Clone(parts[:24]), "abbey"), " ")
	_, err := RootFromMnemonic(wrong)
	rejects("go words a wrong checksum word is rejected", err, "checksum mismatch")
	sw := slices.Clone(parts)
	sw[0], sw[1] = sw[1], sw[0]
	_, err = RootFromMnemonic(strings.Join(sw, " "))
	rejects("go words two swapped words are rejected", err, "checksum mismatch")
	_, err = RootFromMnemonic("sigelo " + strings.Join(parts[1:], " "))
	rejects("go words a word outside the wordlist is rejected", err, "not in the Monero English wordlist")
	_, err = RootFromMnemonic("loyalty " + strings.Join(parts[1:], " "))
	rejects("go words a word matching only on its prefix is rejected", err, "not in the Monero English wordlist")
	_, err = RootFromMnemonic(strings.Join(parts[:24], " "))
	rejects("go words 24 words are rejected", err, "expected 25 words, got 24")
	_, err = RootFromMnemonic(withChecksum(append([]string{"zoom", "zones", "zombie"}, parts[3:24]...)))
	rejects("go words a triple past 2^32 is rejected (electrum-words.cpp:326)", err, "words 1-3 are not a Monero seed encoding")

	S1, _ := hex.DecodeString("736967656c6f20726f6f7420736565642c207465737420766563746f72202331")
	w, _ := EncodeMoneroWords(S1)
	_, err = RootFromMnemonic(w)
	rejects("go words a non-canonical root (S >= l) is refused as words", err, "not a canonical root")
	_, err = MnemonicFromRoot(S1)
	rejects("go words MnemonicFromRoot refuses a non-canonical root", err, "not a canonical root")
	l, _ := hex.DecodeString("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
	_, err = MnemonicFromRoot(l)
	rejects("go words l itself is refused", err, "not a canonical root")
	_, err = MnemonicFromRoot(make([]byte, 32))
	rejects("go words the zero root is refused", err, "not a canonical root")

	// The vault and HKDF over the same S are separate: no derived key is the vault's b or a.
	VS, _ := hex.DecodeString(vectors[0].seed)
	v, _ := VaultFromRoot(VS, "stagenet")
	K0 := must(KeeperRoot(VS, 0))
	tr, _ := WalletFromRoot(VS, "treasury", "stagenet")
	al, _ := WalletFromRoot(VS, "allowance", "stagenet")
	derived := [][]byte{tr.Spend, tr.View, al.Spend, al.View}
	for _, s := range [][32]byte{must(IdentitySeed(VS, 0)), must(RecoverySeed(VS)), K0, must(KeeperRoot(VS, 1)), must(AgentIdentitySeed(K0[:], 0, 0))} {
		derived = append(derived, slices.Clone(s[:]))
	}
	clash := false
	for _, d := range derived {
		clash = clash || string(d) == string(v.Spend) || string(d) == string(v.View)
	}
	check("go keys no derived key equals the vault spend key b (= S) or view key a", !clash && tr.Address != v.Address)
}
