// SPDX-License-Identifier: MIT
// Personal Agent side of the PAP profile draft (README.md): the identification fields of a token
// request, from the agent's bundle and a §5.2 answer to the Company's nonce.
//   node present.mjs <auth.issuer> <nonce> <user_id> [client_name] > params.json
// The key never passes through here: `sigelo-agent sign-challenge` signs (any key provider), and
// `sigelo-agent bundle` gives the bundle. SIGELO_AGENT overrides the command; nothing goes online.
//   node present.mjs --pairwise <auth.issuer> <nonce> <user_id> [--operator <file>] [--keeper <file>]
// One DID per business (README): derived from the keeper root K of `sigelo-agent keeper --from-words`
// (--keeper, default: the identity file's .keeper.json), so this mode reads K, as enrol does.
// --operator: a JSON file {attestations, issuers} for the per-business DID; without it, none.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { canonicalize, decodeKey, keygen, parse, rotate, sign, verify } from 'sigelo';
import { k } from 'sigelo/dist/keys.js';
import { URI, verifyPresentation } from './verify.mjs';

/** `signer`: { did, sign(body) → "z…" }, the K1 shape (adapters/moadim/sigelo-agent-keys.ts). */
export function present({ signer, bundle, issuer, nonce, user_id, client_name, now = Math.floor(Date.now() / 1000) }) {
  const r = verify(bundle, now);
  if (signer.did !== r.did) throw new Error(`pap: the signer is ${signer.did}, not the bundle's current DID ${r.did}`);
  const body = { v: 'sigelo/0', typ: 'challenge', did: r.did, ctx: issuer, nonce };
  const params = { client_id: r.chain[0], client_assertion_type: URI,
    client_assertion: canonicalize({ bundle, proof: { body, sig: signer.sign(body) } }), user_id, ...(client_name && { client_name }) };
  verifyPresentation(params, { issuer, nonce, now, requireOperator: false });    // what the Company will check
  return params;
}

/**
 * The per-business identity: seed m = keys.ts k(K, `${PAP_PATH}/<m>/<issuer>`), the same HKDF as
 * agentIdentitySeed. Issuer verbatim and last, rotation m before it: no two (issuer, m) share a
 * path, and none equals an agent's `sigelo/v1/identity/<i>/ed25519/<n>`. No table: the issuer is
 * the index. Genesis pinned as contact/enrol.mjs pins workers (created fixed, nonce = SHA-256(key)
 * [0:16]), rotations 0 → n voluntary at iat 0, so the 25 words give the same DIDs back.
 */
export const PAP_PATH = 'sigelo/v1/pap/ed25519', PINNED_CREATED = '1970-01-01T00:00:00Z';
export function pairwise(K, recovery, issuer, n = 0) {
  if (!/^https:\/\/\S+$/.test(issuer)) throw new Error(`pap: --pairwise needs the business's auth.issuer, an HTTPS URL, not ${JSON.stringify(issuer)}`);
  const g = Array.from({ length: n + 1 }, (_, m) => {
    const seed = k(K, `${PAP_PATH}/${m}/${issuer}`), key = keygen({ seed, recovery, created: PINNED_CREATED, nonce: new Uint8Array(16) }).key;
    return { seed, ...keygen({ seed, recovery, created: PINNED_CREATED, nonce: createHash('sha256').update(decodeKey(key)).digest().subarray(0, 16) }) };
  });
  const rotations = g.slice(1).map((x, m) => rotate({ genesis: g[m].genesis, next_genesis: x.genesis, iat: 0, reason: 'voluntary', secret: g[m].seed }));
  const bundle = { v: 'sigelo/0', typ: 'bundle', genesis: g[0].genesis, rotations, bindings: [], attestations: [], issuers: [] };
  return { bundle, signer: { did: g[n].did, sign: (body) => sign(g[n].seed, body) } };
}

if (process.argv[1] && realpathSync(process.argv[1]) === import.meta.filename) {
  const args = process.argv.slice(2), opt = (f) => { const i = args.indexOf(f); return i < 0 ? undefined : args.splice(i, 2)[1]; };
  const pw = opt('--pairwise'), opFile = opt('--operator'), keeper = opt('--keeper');
  if (pw) {
    const [nonce, user_id, client_name] = args, id = process.env.SIGELO_IDENTITY ?? `${homedir()}/.config/moadim/sigelo.local.json`;
    const kp = parse(readFileSync(keeper ?? id.replace(/\.json$/, '') + '.keeper.json', 'utf8'));
    const { bundle, signer } = pairwise(Uint8Array.from(Buffer.from(kp.root_hex, 'hex')), kp.recovery, pw);
    if (opFile) { const o = parse(readFileSync(opFile, 'utf8')); bundle.attestations = o.attestations ?? []; bundle.issuers = o.issuers ?? []; }
    console.log(JSON.stringify(present({ signer, bundle, issuer: pw, nonce, user_id, client_name }), null, 2));
    process.exit(0);
  }
  const [issuer, nonce, user_id, client_name] = args;
  const run = (...a) => parse(execFileSync(process.env.SIGELO_AGENT ?? 'sigelo-agent', a, { encoding: 'utf8' }));
  const bundle = run('bundle'), did = verify(bundle, Math.floor(Date.now() / 1000)).did;
  const signer = { did, sign: (body) => run('sign-challenge', JSON.stringify(body)).sig };
  console.log(JSON.stringify(present({ signer, bundle, issuer, nonce, user_id, client_name }), null, 2));
}
