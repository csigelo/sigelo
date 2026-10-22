// SPDX-License-Identifier: MIT
// Which relay a 12-character short code was made on (ROADMAP §9 items 3 and 4): its relay tag
// (short.mjs relayTag) resolved to a host. No network here but loadRegistry's one fetch, which the
// carrier passes in; nothing in pairing by long code or in verification calls this file.
//
// Resolution, in order (resolveTag):
//   1. relays this agent knows: its own relay (SIGELO_RELAY), its contacts' relays, the relay its operator attestation names (claims.relay), and the local table;
//   2. the registry: sigelo.ai/relays.json as last cached (fetched at most once a day);
//   3. none: the person is asked once (accept --relay <host>), and the host goes into the table.
// Two known hosts with one tag (20 bits collide, by chance or on purpose): neither is guessed, the
// person is asked. The registry lists a tag once (first host keeps it), so it cannot collide.
//
// The local table: relays.local.json beside the identity, {"relays": ["corp.example.com", …]}, hosts
// as a long code names them (host[:port]); the tag is computed, never stored. The registry cache:
// relays.cache.local.json beside it, {"v": "sigelo-relays-cache/0", "fetched": <unix>, "registry": <bundle>}.
//
// The registry is a sigelo bundle (SPEC §8) of the RELEASE identity (release/release-identity.json,
// as release.json is: release/sign-release.sh), no bindings, and one self-issued attestation
// (iss = sub = its current DID, admission "open") with ctx "sigelo.ai/relays" and claims
//   { relays: { <tag>: { host, did?, tier?, note? } } }
// signed by relay/site/sign-relays.mjs. Here: SPEC §9 at now, the chain's first DID the pinned one,
// one attestation of the identity about itself with that ctx; then every entry whose tag is not
// relayTag(host), or whose host is no host[:port], is dropped (counted), never trusted.
// Files: the platform's (design/apps.md §4.2; the carrier passes its own), Node's by default.
import { verify } from 'sigelo';
import { files as nodeFiles } from './platform-node.mjs';
import { checkRelay } from './invite.mjs';
import { fail } from './kdf.mjs';
import { ALPHABET, TAG_LENGTH, relayTag } from './short.mjs';

export const REGISTRY_URL = 'https://sigelo.ai/relays.json', REGISTRY_CTX = 'sigelo.ai/relays', CACHE_V = 'sigelo-relays-cache/0';
// The release identity's original DID: did(release/release-identity.json); relay/site/test.mjs
// and test-short.mjs check the two agree.
export const RELEASE_DID = 'did:sigelo:zE1ikihiqKQ7KoFL492kfFrJdUSzPeHNunGnMXLqgVfci';
export const REGISTRY_EVERY = 86400, TABLE_MAX = 256;
const TAG_RE = new RegExp(`^[${ALPHABET}]{${TAG_LENGTH}}$`);
const isTag = (t) => typeof t === 'string' && TAG_RE.test(t);
const goodRelay = (h) => { try { checkRelay(h); return true; } catch { return false; } };
const isText = (s, max) => typeof s === 'string' && s.length <= max;

/** The registry's entries, tag → { host, did?, tier?, note? }, from a bundle; throws registry. */
export function checkRegistry(bundle, now, pin = RELEASE_DID) {
  let r;
  try { r = verify(bundle, now); } catch (e) { fail('registry', `relays.json does not verify: ${e.message}`); }
  if (r.chain[0] !== pin) fail('registry', `relays.json is signed by ${r.chain[0]}, not the release identity ${pin}`);
  const mine = r.attestations[r.did] ?? [];
  const a = mine.length === 1 ? mine[0] : null;
  const body = a?.body ?? a;
  if (!body || body.sub !== r.did || body.ctx !== REGISTRY_CTX) fail('registry', `relays.json: not one ${REGISTRY_CTX} attestation of the release identity about itself`);
  const relays = body.claims?.relays;
  if (relays === null || typeof relays !== 'object' || Array.isArray(relays)) fail('registry', 'relays.json: claims.relays is not an object');
  const out = new Map();
  let dropped = 0;
  for (const [tag, e] of Object.entries(relays)) {
    const ok = isTag(tag) && e && typeof e === 'object' && goodRelay(e.host) && relayTag(e.host) === tag
      && (e.did === undefined || isText(e.did, 128)) && (e.tier === undefined || isText(e.tier, 32)) && (e.note === undefined || isText(e.note, 200));
    if (ok) out.set(tag, { host: e.host, ...(e.did !== undefined && { did: e.did }), ...(e.tier !== undefined && { tier: e.tier }), ...(e.note !== undefined && { note: e.note }) });
    else dropped++;
  }
  return { relays: out, dropped, iat: body.iat, exp: body.exp, did: r.did };
}

// Written whole to a fresh 0600 name, then renamed, as the carrier's state is (files.write).
const save = (files, path, value) => files.write(path, new TextEncoder().encode(JSON.stringify(value, null, 2) + '\n'));
// UTF-8 as readFileSync(…, 'utf8') reads it: a byte order mark is kept (JSON.parse refuses it).
const readJson = (files, path) => {
  try {
    const raw = files.read(path);
    return raw === null ? null : JSON.parse(new TextDecoder('utf-8', { ignoreBOM: true }).decode(raw));
  } catch { return null; }
};

/** The hosts of the local table (relays.local.json), well-formed ones only; [] when there is none. */
export function readTable(path, files = nodeFiles) {
  const t = readJson(files, path);
  return Array.isArray(t?.relays) ? t.relays.filter(goodRelay).slice(0, TABLE_MAX) : [];
}
/** host added to the local table (the person named it once: accept --relay). → true if it was new. */
export function remember(path, host, files = nodeFiles) {
  checkRelay(host);
  const t = readJson(files, path), hosts = Array.isArray(t?.relays) ? t.relays : [];
  if (hosts.includes(host)) return false;
  save(files, path, { ...(t && typeof t === 'object' && !Array.isArray(t) ? t : {}), relays: [...hosts, host].slice(-TABLE_MAX) });
  return true;
}

/**
 * The registry's entries (a Map, empty when there is none to be had): the cache when it was fetched
 * less than REGISTRY_EVERY ago and still verifies; else a fetch of url (get(url) → { status, body },
 * the carrier's http), verified, then cached. A fetch that fails falls back to a cache that still
 * verifies. url false: the cache only. files: the platform's (Node's by default).
 */
export async function loadRegistry({ file, url = REGISTRY_URL, now, get, pin = RELEASE_DID, files = nodeFiles }) {
  const cached = readJson(files, file);
  let fromCache = null;
  if (cached?.v === CACHE_V && Number.isSafeInteger(cached.fetched)) {
    try { fromCache = checkRegistry(cached.registry, now, pin).relays; } catch {}
  }
  if (fromCache && (url === false || now - cached.fetched < REGISTRY_EVERY)) return fromCache;
  if (url === false) return new Map();
  try {
    const r = await get(url);
    if (r.status !== 200) throw new Error(`answered ${r.status}`);
    const got = checkRegistry(r.body, now, pin).relays;
    save(files, file, { v: CACHE_V, fetched: now, registry: r.body });
    return got;
  } catch { return fromCache ?? new Map(); }
}

/**
 * The host for `tag`. known: [{ host, from }] (step 1, any order; duplicates of a host are one);
 * registry: () => Promise<Map> (step 2, called only when step 1 has no host for the tag).
 * → { host, from }; throws relay_tag when two known hosts share the tag, or nothing has it.
 */
export async function resolveTag(tag, { known, registry, shown }) {
  const hits = new Map();
  for (const k of known) if (goodRelay(k.host) && relayTag(k.host) === tag && !hits.has(k.host)) hits.set(k.host, k.from);
  if (hits.size > 1) {
    fail('relay_tag', `short code ${shown}: its relay tag ${tag} fits ${[...hits.keys()].join(' and ')}, relays this agent knows: it does not guess. Ask the inviter which relay it used, then accept it with --relay <host>`);
  }
  if (hits.size === 1) { const [[host, from]] = hits; return { host, from }; }
  const e = (await registry()).get(tag);
  if (e) return { host: e.host, from: 'registry' };
  return fail('relay_tag', `short code ${shown} was made on a relay this agent does not know (relay tag ${tag}): ask the inviter which relay, then accept it with --relay <host> (remembered for its next code); or ask for the long code (invite --long)`);
}
