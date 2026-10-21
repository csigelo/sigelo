// SPDX-License-Identifier: MIT
// Regenerates fixtures/short-code-v0.json, byte for byte: contract sigelo-park/0 (short.mjs header).
//   node contact/gen-short.mjs           write the file
//   node contact/gen-short.mjs --check   exit 1 if the committed file differs
// Independent of short.mjs on purpose: base32, normalisation, hashes and words are worked out here
// with node:crypto and string handling of their own, so the fixture checks short.mjs (test-short.mjs)
// instead of echoing it. The word list is read from bip39-english.mjs (data only; its hash is
// checked here). Random inputs: rng(label) = SHA-256("sigelo-park/0 " + label), first 5 bytes.
// Output: JSON.stringify(out, null, 2) + "\n".
import { createHash, hkdfSync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { BIP39_SHA256, WORDS } from './bip39-english.mjs';

const V = 'sigelo-park/0', LABEL = 'sigelo-fingerprint/0';
const OUT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'short-code-v0.json');
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const sha = (b) => createHash('sha256').update(b).digest();
if (sha(WORDS.join('\n') + '\n').toString('hex') !== BIP39_SHA256 || WORDS.length !== 2048) throw new Error('bip39-english.mjs is not the BIP-39 English list');

// 40 bits → 8 digits, as a binary string cut in fives.
const encode = (bytes) => [...bytes].map((b) => b.toString(2).padStart(8, '0')).join('').match(/.{5}/g).map((s) => CROCKFORD[parseInt(s, 2)]).join('');
const rng = (label) => sha(`${V} ${label}`).subarray(0, 5);
const hashOf = (norm) => sha(Buffer.concat([Buffer.from(V, 'utf8'), Buffer.from(norm, 'utf8')])).toString('hex');

const made = ['a', 'b', 'c', 'd'].map((l) => {
  const bytes = rng(l), code = encode(bytes);
  return { label: l, rng: bytes.toString('hex'), code: `${code.slice(0, 4)}-${code.slice(4)}`, normalised: code, code_hash: hashOf(code) };
});
// The edges of the alphabet: all zero bits, all one bits.
made.push({ label: 'zeros', rng: '0000000000', code: '0000-0000', normalised: '00000000', code_hash: hashOf('00000000') });
made.push({ label: 'ones', rng: 'ffffffffff', code: 'ZZZZ-ZZZZ', normalised: 'ZZZZZZZZ', code_hash: hashOf('ZZZZZZZZ') });

// Relay tags: the first 20 bits of SHA-256("sigelo-relay-tag/0" ‖ relay), 4 digits; a code made on
// such a relay is its 8 digits, then the tag.
const TAG = 'sigelo-relay-tag/0';
const tagOf = (relay) => sha(Buffer.from(TAG + relay, 'utf8')).toString('hex').slice(0, 5).split('').map((h) => parseInt(h, 16).toString(2).padStart(4, '0')).join('').match(/.{5}/g).map((b) => CROCKFORD[parseInt(b, 2)]).join('');
const relay_tags = ['corp.example.com', 'relay.sigelo.ai', 'relay.test', '127.0.0.1:8443', 'xn--bcher-kva.example'].map((relay) => ({ relay, sha256_20: sha(Buffer.from(TAG + relay, 'utf8')).toString('hex').slice(0, 5), tag: tagOf(relay) }));
const tagged = ['e', 'f'].map((l, i) => {
  const bytes = rng(l), code = encode(bytes) + relay_tags[i].tag;
  return { label: l, rng: bytes.toString('hex'), relay: relay_tags[i].relay, code: code.match(/.{4}/g).join('-'), normalised: code, code_hash: hashOf(code) };
});

const K = made[0].normalised, k = K.toLowerCase();
const normalise = [
  { case: 'as shown', input: `${K.slice(0, 4)}-${K.slice(4)}`, normalised: K },
  { case: 'without the dash', input: K, normalised: K },
  { case: 'lowercase', input: `${k.slice(0, 4)}-${k.slice(4)}`, normalised: K },
  { case: 'spoken in groups', input: ` ${k.slice(0, 2)} ${k.slice(2, 4)} ${k.slice(4, 6)} ${k.slice(6)} `, normalised: K },
  { case: 'an en dash from a phone', input: `${K.slice(0, 4)}–${K.slice(4)}`, normalised: K },
  { case: 'I, i, L and l read as 1', input: 'IiLl-2345', normalised: '11112345' },
  { case: 'O and o read as 0', input: 'Oo00-ABCD', normalised: '0000ABCD' },
  { case: 'U is no digit', input: 'U000-0000', error: 'short_code' },
  { case: 'seven characters', input: `${K.slice(0, 4)}-${K.slice(4, 7)}`, error: 'short_code' },
  { case: 'nine characters', input: `${K}0`, error: 'short_code' },
  { case: 'twelve characters: a relay tag', input: `${k.slice(0, 4)} ${k.slice(4)} 4wxn`, normalised: `${K}4WXN` },
  { case: 'ten characters', input: `${K}4W`, error: 'short_code' },
  { case: 'thirteen characters', input: `${K}4WXN0`, error: 'short_code' },
  { case: 'a symbol', input: 'K7F3_Q9ZP', error: 'short_code' },
  { case: 'a long code', input: 'sgl1' + '2'.repeat(122), error: 'short_code' },
];

// The words: HKDF-SHA256(pair, salt LABEL, empty info, 6 bytes), first 44 bits, 11 at a time.
function words(pairHex) {
  const okm = Buffer.from(hkdfSync('sha256', Buffer.from(pairHex, 'hex'), Buffer.from(LABEL, 'utf8'), Buffer.alloc(0), 6));
  const bits = [...okm].map((b) => b.toString(2).padStart(8, '0')).join('').slice(0, 44);
  const indices = bits.match(/.{11}/g).map((s) => parseInt(s, 2));
  return { okm: okm.toString('hex'), indices, words: indices.map((i) => WORDS[i]).join(' ') };
}
const carrier = JSON.parse(readFileSync(join(dirname(OUT), 'carrier-v0.json'), 'utf8')).derived.pair.hex;
const fingerprints = [
  { case: 'carrier-v0.json derived.pair', pair: carrier, ...words(carrier) },
  { case: 'zero pair', pair: '0'.repeat(32), ...words('0'.repeat(32)) },
  { case: 'ones pair', pair: 'f'.repeat(32), ...words('f'.repeat(32)) },
  { case: 'pair of rng("pair")', pair: sha(`${V} pair`).subarray(0, 16).toString('hex'), ...words(sha(`${V} pair`).subarray(0, 16).toString('hex')) },
];

export function build() {
  const out = {
    contract: V,
    alphabet: CROCKFORD,
    rules: {
      code: '8 characters of the alphabet from 5 random bytes, 5 bits each, most significant first; shown as XXXX-XXXX; lives 600 s, one fetch',
      normalise: 'drop whitespace and dashes (U+002D, U+2010 to U+2015, U+2212); uppercase; I and L → 1, O → 0; then exactly 8 (or 12, with a relay tag) characters of the alphabet, else short_code',
      relay_tag: 'the first 20 bits of SHA-256(UTF-8 "sigelo-relay-tag/0" ‖ UTF-8 relay host[:port]), 5 bits a character; a code made on a relay other than relay.sigelo.ai is its 8 characters then the tag, shown XXXX-XXXX-TTTT, hashed whole',
      code_hash: 'hex(SHA-256(UTF-8 "sigelo-park/0" ‖ UTF-8 normalised code))',
      fingerprint: 'HKDF-SHA256(16 bytes of the pair id, salt "sigelo-fingerprint/0", empty info, 6 bytes); the first 44 bits, 11 at a time, index the BIP-39 English list (sha256 of the list one word a line: ' + BIP39_SHA256 + ')',
      rng: 'rng(label) = first 5 bytes of SHA-256(UTF-8 "sigelo-park/0 " + label)',
    },
    codes: made,
    relay_tags,
    tagged,
    normalise,
    fingerprints,
  };
  return JSON.stringify(out, null, 2) + '\n';
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const text = build();
  if (process.argv.includes('--check')) {
    let cur = '';
    try { cur = readFileSync(OUT, 'utf8'); } catch {}
    if (cur !== text) { console.error('short-code-v0.json differs from the seeds: run node contact/gen-short.mjs'); process.exit(1); }
    console.log('short-code-v0.json reproduces byte for byte');
  } else { writeFileSync(OUT, text); console.log(`wrote ${OUT.split('/').slice(-2).join('/')} (${text.length} bytes)`); }
}
