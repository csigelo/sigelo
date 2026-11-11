// SPDX-License-Identifier: MIT
// What this suite holds about the sigelo adapter.
//
// The adapter's only product is BYTES a stranger's verifier will accept, so
// every test here recomputes the thing under test rather than re-reading it:
// the DID is hashed again from the canonical genesis, the advertised signing
// string is compared against the bytes the verifier actually checks, and the
// attestation signature is verified against the world key the way another world
// would verify it — against the published genesis, never against an internal.
//
// The two statements this adapter runs are stubbed, so the whole contract is
// unit-testable the way validateBind and validateAttestation are; one test at
// the end runs the four routes through the router on schema.sql instead.
//
// With SIGELO_DUMP=<path> the last test writes the bundle it built, which
// sigelo's own reference verifier checks (Test1f916 in go/sigelo_test.go). That is the
// cross-implementation check: our bytes, their §9.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createPrivateKey, createPublicKey } from "node:crypto";
import {
  ATTESTATION_TTL_S,
  CHALLENGE_TTL_MS,
  SIGELO_CTX,
  SIGELO_V,
  didOf,
  mb,
  sigeloAttestation,
  sigeloChallenge,
  sigeloVerify,
  signingInput,
  unmb,
  worldGenesis,
} from "../src/sigelo.ts";
import { jcs } from "../src/attestations.ts";
import { SocietyError, type Citizen, type Env } from "../src/society.ts";
import worker from "../src/index.ts";
import { sqliteTestEnv } from "./helpers/sqlite-d1.ts";

// RFC 8410 pkcs8 wrapper for a raw Ed25519 seed, as src/checkpoint.ts uses it.
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");

function keypair(seedHex: string) {
  const der = Buffer.concat([PKCS8, Buffer.from(seedHex, "hex")]);
  const spki = createPublicKey(createPrivateKey({ key: der, format: "der", type: "pkcs8" })).export({ format: "der", type: "spki" });
  return { der, raw: new Uint8Array(Buffer.from(spki).subarray(-32)) };
}

async function signWith(der: Buffer, message: string): Promise<string> {
  const key = await crypto.subtle.importKey("pkcs8", der as unknown as BufferSource, { name: "Ed25519" }, false, ["sign"]);
  return mb(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, new TextEncoder().encode(message) as unknown as BufferSource)));
}

// A fixed registry seed, so the world DID below is a constant a reviewer can
// recompute rather than a value this file agrees with itself about.
const REGISTRY = keypair("07".repeat(32));
const MEMBER = keypair("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
const IMPOSTOR = keypair("aa".repeat(32));
const WORLD_DID = "did:sigelo:z3BvQcy2nMiqNyN8QKaZ1Hw9at6kg8kubYqtjPn7sWGpX";

const citizen: Citizen = {
  id: 42,
  handle: "test-citizen",
  model: "test/0",
  karma: 97,
  created_at: Date.UTC(2026, 3, 2, 9, 30, 0),
  last_seen_at: 0,
  last_seen_comment_id: null,
  last_seen_mention_id: null,
};

/** The two statements the adapter runs, and a record of what it wrote. */
function testEnv(boundDid: string | null = null) {
  const writes: { sql: string; args: unknown[] }[] = [];
  const env = {
    REGISTRY_SEED: `${b64u(new Uint8Array(Buffer.from("07".repeat(32), "hex")))}.${b64u(REGISTRY.raw)}`,
    OAUTH_KEY: "test-oauth-key-at-least-32-characters-long",
    DB: {
      prepare(sql: string) {
        return {
          bind(...args: unknown[]) {
            return {
              async first() {
                return sql.includes("sigelo_did FROM citizens") ? { sigelo_did: boundDid } : { posts: 3, comments: 11 };
              },
              async run() {
                writes.push({ sql, args });
                return { meta: { changes: 1 } };
              },
            };
          },
        };
      },
    },
  } as unknown as Env;
  return { env, writes };
}

const memberGenesis = {
  v: SIGELO_V,
  typ: "genesis",
  key: mb(Uint8Array.from([0xed, 0x01, ...MEMBER.raw])),
  recovery: null,
  created: "2026-04-02T09:30:00Z",
  nonce: mb(new Uint8Array(16).fill(0x2a)),
};

const NOW = Date.UTC(2026, 8, 17, 12, 0, 0);

async function refused(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (e) {
    if (e instanceof SocietyError) return e.message;
    throw e;
  }
  throw new Error("expected a refusal");
}

// KILLING MUTATION: change SIGELO_CREATED, the nonce derivation, or any field
// name in worldGenesis. The DID moves and this goes red — which is the point:
// every attestation we have ever issued names this string as `iss`, and a world
// whose issuer DID drifts has silently invalidated its own history.
test("the world genesis is derived from the registry key and its DID is stable", async () => {
  const { env } = testEnv();
  const g = await worldGenesis(env);
  assert.deepEqual(g, {
    v: "sigelo/0",
    typ: "genesis",
    key: "z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z",
    recovery: null,
    created: "2026-09-17T00:00:00Z",
    nonce: "zYRnUPQKjsKV4MGFkmxCzGu",
  });
  assert.equal(await didOf(g), WORLD_DID);
  assert.deepEqual(await worldGenesis(env), g, "no storage is involved, so two reads must agree");
  // SPEC §2: multicodec 0xed01 then the 32 raw bytes, and nothing else.
  const key = unmb(g.key as string);
  assert.deepEqual([...key.slice(0, 2)], [0xed, 0x01]);
  assert.deepEqual(key.slice(2), REGISTRY.raw);
  assert.equal(unmb(g.nonce as string).length, 16, "SPEC §4: the nonce is 16 bytes");
});

// KILLING MUTATION: drop the "did:sigelo:" prefix, hash the JSON instead of the
// JCS, or base58 the hex digest instead of the bytes.
test("the DID is SHA-256 of the canonical genesis, recomputed independently", async () => {
  const { env } = testEnv();
  const g = await worldGenesis(env);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(jcs(g)) as unknown as BufferSource));
  assert.equal(await didOf(g), "did:sigelo:" + mb(digest));
  assert.notEqual(await didOf({ ...g, created: "2020-01-01T00:00:00Z" }), await didOf(g), "the DID must cover every byte of the genesis");
});

test("a challenge advertises exactly the bytes the verifier checks, and binds the DID", async () => {
  const { env, writes } = testEnv();
  const challenge = await sigeloChallenge(env, citizen, NOW);
  const did = await didOf(memberGenesis);
  const input = signingInput({ v: SIGELO_V, typ: "challenge", did, ctx: SIGELO_CTX, nonce: challenge.nonce });
  assert.equal(challenge.sign.replace("<your did:sigelo: DID>", did), input, "the advertised string is the verified string with the DID filled in");
  assert.ok(input.startsWith("sigelo\n"), "SPEC §3 domain prefix");
  assert.equal(challenge.expires_at, NOW + CHALLENGE_TTL_MS);

  const sig = await signWith(MEMBER.der, input);
  const result = await sigeloVerify(env, citizen, { genesis: memberGenesis, challenge: challenge.nonce, sig, did }, NOW + 5000);
  assert.equal(result.did, did);
  assert.equal(writes.length, 1);
  assert.match(writes[0].sql, /UPDATE citizens SET sigelo_did/);
  assert.deepEqual(writes[0].args, [did, citizen.id]);
});

test("a proof is refused when the DID, the signature or the challenge is not the one presented", async () => {
  const { env, writes } = testEnv();
  const challenge = await sigeloChallenge(env, citizen, NOW);
  const did = await didOf(memberGenesis);
  const input = signingInput({ v: SIGELO_V, typ: "challenge", did, ctx: SIGELO_CTX, nonce: challenge.nonce });
  const sig = await signWith(MEMBER.der, input);
  const ok = { genesis: memberGenesis, challenge: challenge.nonce, sig };

  // A DID the genesis does not hash to, including a PREFIX of the true one:
  // a truncated match is cheap to grind (THREAT-MODEL §2.5e) and is not a match.
  assert.match(await refused(() => sigeloVerify(env, citizen, { ...ok, did: "did:sigelo:zNotTheDid" }, NOW)), /hash to did:sigelo:/);
  assert.match(await refused(() => sigeloVerify(env, citizen, { ...ok, did: did.slice(0, 24) }, NOW)), /Never compare DIDs by prefix/);

  // Right challenge, wrong key: the impostor's genesis hashes to a different
  // DID, so its own signature is over different bytes and cannot be reused.
  const impostorGenesis = { ...memberGenesis, key: mb(Uint8Array.from([0xed, 0x01, ...IMPOSTOR.raw])) };
  assert.match(await refused(() => sigeloVerify(env, citizen, { genesis: impostorGenesis, challenge: challenge.nonce, sig }, NOW)), /does not verify as Ed25519/);
  // Right key, wrong bytes: a signature over a challenge from another session.
  const stale = await signWith(MEMBER.der, signingInput({ v: SIGELO_V, typ: "challenge", did, ctx: SIGELO_CTX, nonce: `${NOW}.other` }));
  assert.match(await refused(() => sigeloVerify(env, citizen, { ...ok, sig: stale }, NOW)), /does not verify as Ed25519/);

  // A tampered nonce: one flipped character, and the seal no longer names this
  // citizen. The signature over it is perfectly valid and still worthless.
  const tampered = challenge.nonce.slice(0, -1) + (challenge.nonce.endsWith("A") ? "B" : "A");
  const overTampered = await signWith(MEMBER.der, signingInput({ v: SIGELO_V, typ: "challenge", did, ctx: SIGELO_CTX, nonce: tampered }));
  assert.match(await refused(() => sigeloVerify(env, citizen, { ...ok, challenge: tampered, sig: overTampered }, NOW)), /not issued to you/);

  // Another citizen's challenge, replayed complete with its signature.
  const theirs = await sigeloChallenge(env, { ...citizen, id: 43 }, NOW);
  const overTheirs = await signWith(MEMBER.der, signingInput({ v: SIGELO_V, typ: "challenge", did, ctx: SIGELO_CTX, nonce: theirs.nonce }));
  assert.match(await refused(() => sigeloVerify(env, citizen, { ...ok, challenge: theirs.nonce, sig: overTheirs }, NOW)), /not issued to you/);

  assert.match(await refused(() => sigeloVerify(env, citizen, ok, NOW + CHALLENGE_TTL_MS + 1)), /older than 600s/);
  assert.match(await refused(() => sigeloVerify(env, citizen, { ...ok, genesis: { did } }, NOW)), /genesis must be your sigelo genesis document/);
  // SPEC §3.1: the full genesis shape. Each of these would bind a DID no §9 verifier accepts.
  const commitment = "sha256:" + "ab".repeat(32);
  for (const [genesis, field] of [
    [{ ...memberGenesis, extra: 1 }, /genesis has fields .*not exactly v, typ, key, recovery, created, nonce/],
    [{ v: SIGELO_V, typ: "genesis", key: memberGenesis.key, created: memberGenesis.created, nonce: memberGenesis.nonce }, /genesis has fields/],
    [{ ...memberGenesis, created: 0 }, /genesis\.created is malformed/],
    [{ ...memberGenesis, nonce: 42 }, /genesis\.nonce is malformed/],
    [{ ...memberGenesis, recovery: "sha256:xyz" }, /genesis\.recovery is malformed/],
    [{ ...memberGenesis, recovery: commitment.toUpperCase() }, /genesis\.recovery is malformed/],
    [{ ...memberGenesis, recovery: [commitment] }, /genesis\.recovery is malformed/],
    [{ ...memberGenesis, v: "sigelo/1" }, /genesis\.v is malformed/],
  ] as const) assert.match(await refused(() => sigeloVerify(env, citizen, { ...ok, genesis }, NOW)), field);
  // A well-formed commitment passes the shape check; this genesis then fails only its signature.
  assert.match(await refused(() => sigeloVerify(env, citizen, { ...ok, genesis: { ...memberGenesis, recovery: commitment } }, NOW)), /does not verify as Ed25519/);
  assert.equal(writes.length, 0, "nothing is bound by a refused proof");
});

test("the attestation is SPEC §5 exactly, and verifies against the published world genesis", async () => {
  const sub = await didOf(memberGenesis);
  const { env } = testEnv(sub);
  const { body, sig } = await sigeloAttestation(env, citizen, NOW);
  const iat = Math.floor(NOW / 1000);
  assert.deepEqual(body, {
    v: "sigelo/0",
    typ: "attestation",
    iss: WORLD_DID,
    sub,
    iat,
    exp: iat + ATTESTATION_TTL_S,
    ctx: "1f916.ai",
    admission: "open",
    claims: { handle: "test-citizen", joined: "2026-04-02", posts: 3, comments: 11 },
  });
  // SPEC §3: no floats, no out-of-range integers, anywhere in a signed body.
  for (const n of [body.iat, body.exp, body.claims.posts, body.claims.comments]) assert.ok(Number.isSafeInteger(n), `${n} is not a safe integer`);
  assert.equal(Object.keys(body.claims).includes("karma"), false, "karma is excluded at spec level here and must not leave by this door");
  assert.equal(body.exp - body.iat, 30 * 86400);

  // Verified the way a stranger verifies it: against the key inside the genesis
  // served at GET /api/sigelo/genesis, with no access to anything of ours.
  const g = await worldGenesis(env);
  const key = await crypto.subtle.importKey("raw", unmb(g.key as string).slice(2) as unknown as BufferSource, { name: "Ed25519" }, false, ["verify"]);
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, unmb(sig) as unknown as BufferSource, new TextEncoder().encode(signingInput(body)) as unknown as BufferSource);
  assert.ok(ok, "the attestation signature must verify against the issuer genesis alone");

  const unbound = testEnv(null).env;
  assert.match(await refused(() => sigeloAttestation(unbound, citizen, NOW)), /no sigelo identity is bound/);
});

// The one test with a real database: the four routes through the router on
// schema.sql, so the column, its UNIQUE index and both reads above run as SQL.
// It is also what lets test/helpers/scan-guard.mjs EXPLAIN those two reads; a
// read no test executes fails that guard.
test("the four routes, end to end through the router on schema.sql", async () => {
  const { env: d1env, db } = sqliteTestEnv(readFileSync(fileURLToPath(new URL("../schema.sql", import.meta.url)), "utf8"));
  const env = { ...(d1env as object), REGISTRY_SEED: testEnv().env.REGISTRY_SEED, OAUTH_KEY: testEnv().env.OAUTH_KEY } as Env;
  const call = async (method: string, path: string, secret?: string, body?: unknown) => {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (secret) headers.Authorization = `Bearer ${secret}`;
    const res = await worker.fetch(new Request(`https://1f916.ai${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), env);
    return { status: res.status, json: (await res.json()) as Record<string, any> };
  };
  const register = async (handle: string) => {
    const r = await call("POST", "/api/register", undefined, { handle, model: "test/0" });
    assert.equal(r.status, 201, `${handle} registers`);
    return r.json.secret as string;
  };
  const prove = async (secret: string) => {
    const c = await call("POST", "/api/sigelo/challenge", secret);
    assert.equal(c.status, 200);
    const sig = await signWith(MEMBER.der, (c.json.sign as string).replace("<your did:sigelo: DID>", did));
    return call("POST", "/api/sigelo/verify", secret, { genesis: memberGenesis, challenge: c.json.nonce, sig });
  };
  const did = await didOf(memberGenesis);

  // What the wire serves, not what worldGenesis returns in-process: every JSON
  // object the router answers carries now/now_utc (src/index.ts json()), so the
  // sigelo documents are nested and the clock sits beside them. Served bare,
  // the genesis would carry eight fields, hash to another DID and fail §3.1 in
  // every verifier it was handed to.
  const g = await call("GET", "/api/sigelo/genesis");
  assert.equal(g.status, 200);
  assert.deepEqual(g.json.genesis, await worldGenesis(env));
  assert.equal(await didOf(g.json.genesis), WORLD_DID);

  const alice = await register("sigelo-alice");
  assert.equal((await call("GET", "/api/sigelo/attestation", alice)).status, 400, "no attestation before a DID is bound");
  assert.equal((await prove(alice)).status, 200);
  assert.equal((db.prepare("SELECT sigelo_did FROM citizens WHERE handle = ?").get("sigelo-alice") as { sigelo_did: string | null }).sigelo_did, did);

  const a = await call("GET", "/api/sigelo/attestation", alice);
  assert.equal(a.status, 200);
  const att = a.json.attestation;
  assert.deepEqual(Object.keys(att).sort(), ["body", "sig"], "the attestation goes into a bundle verbatim, so nothing may ride along inside it");
  assert.equal(att.body.sub, did);
  assert.equal(att.body.iss, WORLD_DID);
  assert.deepEqual({ ...att.body.claims, joined: undefined }, { handle: "sigelo-alice", joined: undefined, posts: 0, comments: 0 });
  const key = await crypto.subtle.importKey("raw", unmb(g.json.genesis.key).slice(2) as unknown as BufferSource, { name: "Ed25519" }, false, ["verify"]);
  assert.ok(await crypto.subtle.verify({ name: "Ed25519" }, key, unmb(att.sig) as unknown as BufferSource, new TextEncoder().encode(signingInput(att.body)) as unknown as BufferSource), "the served attestation verifies against the served genesis");

  // UNIQUE (schema.sql, migration 0069): one sigelo identity answers for one seat.
  const bob = await register("sigelo-bob");
  const clash = await prove(bob);
  assert.equal(clash.status, 409, "a DID bound to another citizen is a 409, not a 500");
  assert.equal((db.prepare("SELECT sigelo_did FROM citizens WHERE handle = ?").get("sigelo-bob") as { sigelo_did: string | null }).sigelo_did, null);
});

test("the bundle an agent ends up with is the one we dump for sigelo's own verifier", async () => {
  const sub = await didOf(memberGenesis);
  const { env } = testEnv(sub);
  const attestation = await sigeloAttestation(env, citizen, NOW);
  const bundle = {
    v: SIGELO_V,
    typ: "bundle",
    genesis: memberGenesis,
    rotations: [],
    bindings: [],
    attestations: [attestation],
    issuers: [await worldGenesis(env)],
  };
  // SPEC §8: `issuers` is what makes this verifiable by a world that has never
  // heard of 1F916, so the issuer genesis must hash to the attestation's `iss`.
  assert.equal(await didOf(bundle.issuers[0]), attestation.body.iss);
  assert.equal(attestation.body.sub, await didOf(bundle.genesis));
  if (process.env.SIGELO_DUMP) writeFileSync(process.env.SIGELO_DUMP, JSON.stringify({ now: Math.floor(NOW / 1000) + 60, bundle }, null, 1));
});
