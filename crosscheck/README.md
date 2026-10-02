# crosscheck — sigelo against third-party code

`ts/` and `go/` checked against answers from code and vectors sigelo's authors did not write
(RFC 8785 references, Wycheproof, speccheck, libsodium, monero-python, RFC 8032). Nothing in `ts/`
or `go/` is modified; the Go driver reaches three unexported primitives through `go build -overlay`.

```sh
crosscheck/run.sh              # full run, ~2 min
crosscheck/run.sh --quick      # 10 % of the random cases
crosscheck/run.sh --self-test  # damages every 7th sigelo answer; passes only if every section notices
```

Exit 0 iff no unexplained divergence. Fetches and builds go to `.work/` (git-ignored) and are
reused; network is needed only to fill it (pinned checkouts, a pinned PyPI venv, `rfc8032.txt`
checked by SHA-256). Random cases come from `CROSSCHECK_SEED` (default 20260929). Output:
`results/latest/{summary,divergences,explained,oracle-splits}.json`; `results/` holds the recorded
run the tables cite (update by copying after a full run, with the README).

## Oracles

| Oracle | Version | Used for |
|---|---|---|
| cyberphone/json-canonicalization (RFC 8785 author's reference): testdata, Python `Canonicalize.py` + `NumberToJson.py`, Go `jsoncanonicalizer`, Node `node-es6/canonicalize.js` | commit `19d51d7` | JCS: the six testdata pairs; three independent canonicalizers and ES6 number formatters on random input |
| monero-python (PyPI `monero`) | 1.1.1 | Monero base58, address parsing, integrated addresses, subaddresses (`Wallet.get_address`), wallet keys from a seed, 25-word `Seed` |
| libsodium via PyNaCl | PyNaCl 1.6.2 | Ed25519 signing/verification end to end; also monero-python's point arithmetic |
| RFC 8032 text (rfc-editor.org) | SHA-256 `ed63657f…` | §7.1 vectors (parsed from the text); §6 Python code exec'd from the text as the canonical-point decoder that tie-breaks address disagreements |
| C2SP/wycheproof `ed25519_test.json` | commit `3fa63dd` | 151 Ed25519 verification vectors |
| novifinancial/ed25519-speccheck `cases.json` | commit `6551933` | 12 edge cases (small order, non-canonical A/R, S ≥ L, cofactored vs cofactorless) |
| `base58` (PyPI) | 2.1.1 | sigelo's base58btc multibase (keys, signatures) |

Where monero-python and sigelo disagree, Monero's C++ source decides (below). SigV2 is not
covered here (monero-python has no message signatures); `ts/`'s `wallet_rpc_oracle` checks it
against `monero-wallet-rpc`.

## Recorded run (`results/summary.json`): 0 divergences

| Target | Cases | ts | go | Notes |
|---|---|---|---|---|
| JCS testdata pairs (+2 float-free variants) | 8 | 6 byte-equal, 2 rejected | same | the 2 rejections are `structures.json` (`56.0`) and `values.json` (floats): SPEC §3 forbids non-integers; their float-free variants are byte-equal |
| JCS random documents (random escapes, whitespace, astral keys, U+2028, C0/C1, ints) | 20 000 | 20 000 = | 20 000 = | Python, Go and Node references agree on all; the Go reference takes only an object/array at top level, so for 1 252 top-level scalars Python+Node decide |
| JCS integers ±2^53−1 vs ES6 Number::toString | 100 008 | all = | all = | three reference formatters agree on all |
| JCS integers just outside the range (2^53, 10^16−1, 10^21 …) | 6 | 6 rejected | 6 rejected | ES6 re-spells 10^16−1 as `10000000000000000`; sigelo refuses rather than re-spell |
| JCS random doubles spelled by the ES6 reference | 100 000 | 12 243 accepted byte-for-byte, 87 757 rejected | same | every accepted spelling is a plain integer ≤ 2^53−1; nothing re-spelled |
| JCS SPEC §3/§3.1 restrictions RFC 8785 would accept (float, noncharacter, lone surrogate, duplicate key, `__proto__`, depth 513) | 6 × 300 | all rejected | all rejected | ts and go reject at the same stage (parse vs canonicalize) in every case |
| Monero base58 encode | 10 000 | = | = | |
| Monero base58 decode (valid + fuzzed: bad digits, block lengths, overflow blocks) | 20 000 | 19 935 agree, 65 explained | same | explained = oracle bug B1 |
| Wallet keys + address from a 32-byte seed (b, a, address) | 5 000 | = | = | mainnet / stagenet / testnet |
| Subaddress derivation (random major/minor, up to 2^32−1) | 2 500 | = | = | |
| Parse valid addresses (standard / integrated / subaddress) | 10 000 | = | = | net, kind, keys, payment id |
| Parse adversarial addresses (valid checksum over bad bodies, broken checksums, unknown prefixes, wrong lengths, special points) | 10 000 | 8 066 agree, 1 934 explained | same | explained = O1; every address sigelo accepts has both keys decodable by the RFC 8032 decoder |
| 25-word seed, key → words (3 000 canonical scalars, 1 000 arbitrary, 4 edges) | 4 004 | = | = | Go has the codec too (`go/keys.go`), so it is tested |
| 25-word seed, words → key (round trips, random 24 words + oracle checksum, wrong checksum) | 8 004 | 7 978 agree, 26 explained | same | explained = oracle bug B2 |
| Ed25519 RFC 8032 §7.1 (TEST 1, 2, 3, 1024, SHA(abc)) | 5 | verify + public key = | same | |
| Ed25519 Wycheproof | 151 (88 valid, 63 invalid) | 151 | 151 | incl. S+nL, non-canonical R/A, small-order, truncated, garbage |
| Ed25519 speccheck 0–11 | 12 | `XXVVVVXXXXXX` | `XXVVVVXXXXXX` | = sigelo's documented rule (canonical A and R, A not small order, S < L, cofactored equation); libsodium publishes `XXXVXXXXXXXX`, Go crypto/ed25519 `VVVVXXXXXXXV` |
| End to end: libsodium signs `"sigelo\n" ‖ JCS_ref(body)` | 500 | signing input, public key, `sign()` output, `verifySig` all = | signing input, public key, `VerifySig` all = | |
| … malleated (S+L, flipped R bit, other body, identity key with R=identity, S=0) | 800 | 800 rejected | 800 rejected | libsodium rejects the same 800 |
| base58btc multibase encode / decode | 10 000 / 10 000 + 2 000 keys | = | = | |

The speccheck "policy" column is the one expectation here that is sigelo's own (its stated rule
applied to speccheck's third-party case table); everything else is an oracle's answer.

## Explained disagreements (sigelo right, per Monero's C++)

- **B1 — monero-python base58 accepts a full block worth exactly 2^64.** Its `decode_block`
  checks `product > 2**64`; Monero's `decode_block` fails on any carry out of 64 bits (`mul128`
  high word or `tmp < res_num`). `jpXCZedGfVR` decodes to `0000000000000000` in monero-python
  and is refused by Monero and by sigelo ts and go ("block overflows its byte length").
- **B2 — monero-python decodes an invalid 25-word phrase to a wrong key, silently.** A word triple
  worth x ≥ 2^32 is formatted as 9 hex digits and `endian_swap` keeps 8. Monero's
  `words_to_bytes` refuses the phrase (`electrum-words.cpp:326`: with uint32 arithmetic,
  `(x mod 2^32) mod 1626 ≠ w1` exactly when x ≥ 2^32, since 1626 = 2·3·271 does not divide
  2^32); sigelo refuses it with that reference in the message.
- **O1 — monero-python does not decode address keys.** It checks length, checksum and netbyte
  only. Monero's `get_account_address_from_str` runs `check_key` on the spend and view keys;
  sigelo does too, and refuses addresses whose key is not a canonical curve point. Every one of
  these was confirmed not decodable by the RFC 8032 §6 reference decoder. Small-order and
  identity points are *accepted* by both sides, as by Monero's `check_key`.
