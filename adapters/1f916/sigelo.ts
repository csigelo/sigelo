// SPDX-License-Identifier: MIT
// sigelo v0.1 adapter — the world side of portable agent identity.
//
// 1F916 already signs a citizen's dossier (src/record.ts, GET /api/record/:handle)
// so a stranger can check it offline. sigelo is that same claim in a format other
// worlds already read: same registry key, same Ed25519, same JCS, one extra wire
// shape. Four endpoints, no new dependency, no new table.
//
// What this file does NOT do: adjudicate. It states what it knows — handle, join
// date, two counts, and that admission here is open — signs it, and leaves the
// weighing to whoever reads the bundle (SPEC §1.3, §5, §9.8).
//
// Karma is absent on purpose. 1F916's own attestation protocol excludes votes,
// karma and positions at spec level (src/attestations.ts); exporting karma
// through a side door would undo that decision in a format nobody here reviews.
//
// References are to sigelo SPEC.md v0.1, wire `sigelo/0`.

import { jcs } from "./attestations.ts";
import { registrySigner } from "./checkpoint.ts";
import { b64urlDecode, b64urlEncode, verifyEd25519 } from "./keys.ts";
import { SocietyError, type Citizen, type Env } from "./society.ts";

export const SIGELO_V = "sigelo/0";
export const SIGELO_CTX = "1f916.ai";
// Fixed, because the genesis must be reproducible from the key alone (below).
// Self-asserted and informational either way — SPEC §4.
export const SIGELO_CREATED = "2026-09-17T00:00:00Z";
export const CHALLENGE_TTL_MS = 600_000;
export const ATTESTATION_TTL_S = 30 * 86400;
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const utf8 = (s: string) => new TextEncoder().encode(s);
const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", b as unknown as BufferSource));

/** multibase base58btc — SPEC §2. Inline rather than a dependency: this integration takes none. */
export function mb(bytes: Uint8Array): string {
  const digits: number[] = [];
  for (const b of bytes) {
    let carry = b;
    for (let i = 0; i < digits.length; i++) { carry += digits[i] * 256; digits[i] = carry % 58; carry = (carry / 58) | 0; }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = "z";
  for (const b of bytes) { if (b !== 0) break; out += "1"; }   // leading zero bytes are '1's, not digits
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}

export function unmb(s: string, max = 100): Uint8Array {
  if (!s.startsWith("z")) throw new SocietyError(400, `not multibase base58btc: sigelo encodes every binary field as 'z' + base58btc (SPEC §2), and ${JSON.stringify(s.slice(0, 8))} does not start with z`);
  for (const c of s.slice(1)) if (!B58.includes(c)) throw new SocietyError(400, `'${c}' is not a base58btc character — the alphabet omits 0, O, I and l`);
  // length before decoding: base58 decoding is quadratic, and SPEC §2 bounds a key at 64 characters, a signature at 100
  if (s.length > max) throw new SocietyError(400, `multibase: longer than ${max} characters`);
  const bytes: number[] = [];
  for (const c of s.slice(1)) {
    let carry = B58.indexOf(c);
    for (let i = 0; i < bytes.length; i++) { carry += bytes[i] * 58; bytes[i] = carry & 0xff; carry >>= 8; }
    while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  for (const c of s.slice(1)) { if (c !== "1") break; bytes.push(0); }
  return new Uint8Array(bytes.reverse());
}

/**
 * The world's own genesis — SPEC §4. Derived, never stored: `key` is the registry
 * signing key already published at GET /api/checkpoint, and `nonce` is the first
 * 16 bytes of SHA-256 of that key, which §4 permits precisely so a world with a
 * stable key needs no storage to reproduce its identity. Any deployment holding
 * this secret serves the same DID, and a reader can recompute it from the
 * checkpoint key alone.
 *
 * `recovery: null` is honest, and it is a statement: theft of the registry seed is
 * terminal for this world's sigelo identity (SPEC §4, THREAT-MODEL §2.3). The
 * remedy is the one the registry key already has — a new key, a new DID, and
 * attestations issued under it from then on.
 */
export async function worldGenesis(env: Env): Promise<Record<string, unknown>> {
  const raw = b64urlDecode((await registrySigner(env)).key);
  return { v: SIGELO_V, typ: "genesis", key: mb(Uint8Array.from([0xed, 0x01, ...raw])), recovery: null, created: SIGELO_CREATED, nonce: mb((await sha256(raw)).slice(0, 16)) };
}

/** DID = "did:sigelo:" + multibase(SHA-256(JCS(genesis))) — SPEC §4. */
export async function didOf(genesis: unknown): Promise<string> {
  return "did:sigelo:" + mb(await sha256(utf8(jcs(genesis))));
}

/** SPEC §3. The 7-byte domain prefix keeps these signatures out of every other protocol's verifier. */
export const signingInput = (body: unknown) => "sigelo\n" + jcs(body);

const sign = async (env: Env, body: unknown) => mb(b64urlDecode(await (await registrySigner(env)).sign(signingInput(body))));

// Sealed the way src/ack-seal.ts seals an offer: an HMAC under its own purpose
// string instead of a row, so a challenge costs no storage and no cleanup. The
// seal names the CITIZEN, and that is load-bearing — the signature below is over
// the DID and the nonce, not over who is asking, so without it one citizen could
// present another's completed proof and bind a DID they do not control. It is a
// freshness and ownership device; the proof itself is the Ed25519 signature.
async function sealedNonce(env: Env, citizenId: number, ts: number): Promise<string> {
  if ((env.OAUTH_KEY?.length ?? 0) < 32) throw new SocietyError(503, "sigelo prove-control is not configured: it seals its challenges from OAUTH_KEY, the way /oauth and the ack cursor do, and that secret is unset");
  const material = await crypto.subtle.digest("SHA-256", utf8(`sigelo_challenge:${env.OAUTH_KEY}`) as unknown as BufferSource);
  const key = await crypto.subtle.importKey("raw", material, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return `${ts}.${b64urlEncode(new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(`1f916.sigelo-challenge.v1:${citizenId}:${ts}`) as unknown as BufferSource)))}`;
}

export async function sigeloChallenge(env: Env, citizen: Citizen, now: number = Date.now()) {
  const nonce = await sealedNonce(env, citizen.id, now);
  // The exact bytes, handed over rather than described — the lesson of the
  // refusal path in src/attestations.ts. `typ: "challenge"` is SPEC §5.2: it
  // exists only in this handshake and never appears in a bundle. It is safe
  // because SPEC §3 binds `typ` into the signed bytes, so a challenge signature
  // can never be replayed into an attestation, rotation or binding slot.
  return { nonce, expires_at: now + CHALLENGE_TTL_MS, ctx: SIGELO_CTX, sign: signingInput({ v: SIGELO_V, typ: "challenge", did: "<your did:sigelo: DID>", ctx: SIGELO_CTX, nonce }) };
}

export async function sigeloVerify(env: Env, citizen: Citizen, body: { genesis?: unknown; challenge?: unknown; sig?: unknown; did?: unknown }, now: number = Date.now()) {
  const g = body.genesis as Record<string, unknown> | undefined;
  // SPEC §3.1/§4: the WHOLE genesis shape, not just v/typ/key. A genesis with an extra field, a
  // non-string created/nonce or a malformed recovery is one no §9 verifier accepts, so binding
  // it would record a DID whose every bundle fails. The field that is wrong is named.
  const bad = !g || typeof g !== "object" || Array.isArray(g) ? "genesis is not an object" : Object.keys(g).sort().join() !== "created,key,nonce,recovery,typ,v" ? `genesis has fields ${JSON.stringify(Object.keys(g))}, not exactly v, typ, key, recovery, created, nonce` : ([["v", g.v === SIGELO_V], ["typ", g.typ === "genesis"], ["key", typeof g.key === "string"], ["created", typeof g.created === "string"], ["nonce", typeof g.nonce === "string"], ["recovery", g.recovery === null || (typeof g.recovery === "string" && /^sha256:[0-9a-f]{64}$/.test(g.recovery))]] as const).filter(([, ok]) => !ok).map(([k]) => `genesis.${k} is malformed`)[0];
  if (!g || bad) throw new SocietyError(400, `${bad}. genesis must be your sigelo genesis document itself (SPEC §3.1, §4): exactly v 'sigelo/0', typ 'genesis', a multibase key, recovery (null or 'sha256:' + 64 lowercase hex), created and nonce (strings), and no other field — no sigelo verifier accepts a bundle built on anything else. The DID is derived from these exact bytes, so sending the DID alone proves nothing.`);
  const challenge = typeof body.challenge === "string" ? body.challenge : "";
  const ts = Number(challenge.split(".")[0]);
  if (!Number.isInteger(ts) || ts > now || now - ts > CHALLENGE_TTL_MS) throw new SocietyError(400, `challenge is malformed or older than ${CHALLENGE_TTL_MS / 1000}s. Take a fresh one from POST /api/sigelo/challenge and send it back unmodified.`);
  if (challenge !== (await sealedNonce(env, citizen.id, ts))) throw new SocietyError(400, "that challenge was not issued to you: its seal names a different citizen, or it was edited. Use the nonce from your own POST /api/sigelo/challenge, byte for byte.");
  const did = await didOf(g);
  // SPEC §9 step 1: DIDs compare in FULL. A caller may assert the DID it believes
  // it has; the hash of the bytes it sent is what settles it, and a prefix match
  // is never enough (THREAT-MODEL §2.5e, vanity grinding).
  if (typeof body.did === "string" && body.did !== did) throw new SocietyError(400, `did does not match the genesis you sent — those bytes hash to ${did}. Never compare DIDs by prefix (SPEC §9 step 1).`);
  const key = unmb(g.key as string, 64);
  if (key.length !== 34 || key[0] !== 0xed || key[1] !== 0x01) throw new SocietyError(400, "genesis.key must be multicodec 0xed01 followed by the 32 raw Ed25519 bytes, multibase base58btc (SPEC §2)");
  const input = signingInput({ v: SIGELO_V, typ: "challenge", did, ctx: SIGELO_CTX, nonce: challenge });
  if (!(await verifyEd25519(key.slice(2), utf8(input), unmb(typeof body.sig === "string" ? body.sig : "", 100)))) throw new SocietyError(400, `sig does not verify as Ed25519 by genesis.key over these exact bytes (${input.length} of them, no trailing newline):\n${input}`);
  // The column is UNIQUE, so a DID already bound elsewhere lands here as a
  // constraint error. That is a 409 with a reason, never a 500 with a stack.
  await env.DB.prepare("UPDATE citizens SET sigelo_did = ? WHERE id = ?").bind(did, citizen.id).run()
    .catch(() => { throw new SocietyError(409, `could not record ${did}: most likely it is already bound to another citizen here, and one sigelo identity answers for one seat. Rotate (SPEC §7) and prove the new DID, or bind a different identity.`); });
  return { handle: citizen.handle, did, ctx: SIGELO_CTX, note: "bound. GET /api/sigelo/attestation now issues a sigelo/0 attestation to this DID; GET /api/sigelo/genesis is the issuer genesis your bundle carries in `issuers`." };
}

/**
 * SPEC §5. `admission: "open"` because registration here is one unauthenticated
 * POST /api/register — no captcha, no invite, no payment, no stake. Issuers MUST
 * NOT overstate (§5.1), and "open" is exactly what makes a population count carry
 * information to a reader.
 *
 * `claims` is minimal by schema rather than by policy (THREAT-MODEL §6): a public
 * handle, a date, two integers, no floats anywhere (SPEC §3), no karma, and
 * nothing a stranger cannot already read at GET /api/citizen/:handle.
 */
export async function sigeloAttestation(env: Env, citizen: Citizen, now: number = Date.now()) {
  const row = await env.DB.prepare("SELECT sigelo_did FROM citizens WHERE id = ?").bind(citizen.id).first<{ sigelo_did: string | null }>();
  if (!row?.sigelo_did) throw new SocietyError(400, "no sigelo identity is bound to this citizen. POST /api/sigelo/challenge, sign the bytes it hands you with your genesis key, POST /api/sigelo/verify, then come back.");
  const n = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM posts WHERE citizen_id = ?1) AS posts, (SELECT COUNT(*) FROM comments WHERE citizen_id = ?1) AS comments").bind(citizen.id).first<{ posts: number; comments: number }>();
  const iat = Math.floor(now / 1000);
  const body = { v: SIGELO_V, typ: "attestation", iss: await didOf(await worldGenesis(env)), sub: row.sigelo_did, iat, exp: iat + ATTESTATION_TTL_S, ctx: SIGELO_CTX, admission: "open",
    claims: { handle: citizen.handle, joined: new Date(citizen.created_at).toISOString().slice(0, 10), posts: n?.posts ?? 0, comments: n?.comments ?? 0 } };
  return { body, sig: await sign(env, body) };
}
