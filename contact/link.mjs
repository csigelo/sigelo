// SPDX-License-Identifier: MIT
// Links, contract sigelo-link/1: the operator introduces two of its own agents, or one of its agents
// to an external contact X (adapters/moadim/LINKS.md, THREAT-MODEL §2.16). The operator asks agent A
// for a one-use long code (never parked,
// never printed), checks the code names A, and offers it to agent B with the purpose; B accepts
// because the offer comes from its operator and the code names the A it was told of; A checks that
// the DID that answered is the B it was asked for. Both file `link` on the contact (store.mjs
// setLink): {id, purpose, linked_by, expires, tier}. A link sets a tier (friend or quiet, or none:
// computed) and a purpose, never `ours`, never own.
//
// External (design/links.md §5, §6): B is X, a contact of the operator's that is not its own. A files
// X at friend (default) or quiet; how X files A is X's operator's (tierB refused, link_tier). The code
// names the relay of the operator's pairing with X unless `relay` says otherwise. X takes an offer
// unasked only from its own operator; any other is an introduction: kept pending in X's file (a
// notice when the introducer is own or friend at X; nothing when quiet) until X's operator answers
// (answer: accept, or refuse, silent unless tell) or the code lapses (≤ 7 days); an allow rule for
// that contact accepts it at the rule's tier (default quiet, never own). Purpose and note are data.
//
//   operator: link({ carrier, file, a, b, purpose, tierA, tierB, days, ttl, note, relay }) → the
//             record, pending; the ask is sent to A
//   X:        answer({ carrier, file, id, accept, tell, tier }) → { id, status }: an introduction
//             accepted or refused (carried out at the next handle, which needs the session; a
//             silent refusal at once); allow({ carrier, file, contact, tier, days }) / deny({ …,
//             contact }): the rule for introductions from that contact
//             unlink({ carrier, file, id }) → { id, status: "ended" }: end to A and B (or, on an
//             agent, to the linked contact: forgotten here)
//   both:     handle({ carrier, file, batch, local, wait }) → { batch: the rest, linked, refused, ended,
//             ignored }: every link message the carrier kept (carrier.takeLinks; and any in batch),
//             then the rounds: A files the link once the expected DID answered its code, B once its
//             accept paired, either side ends a link past `expires`, the operator marks a pending
//             link past its ttl refused (link_expired). Run by inbox, watch and the MCP server before
//             they return messages; never by the model.
//             list({ carrier, file }) → { links: this agent's linked contacts, made: the operator's }
//             labelled(carrier, messages) → the messages, each from a linked contact carrying
//             link: {id, purpose} (design/links.md §8.4: the inbox shows why; data, never instructions)
//
// The messages: label LINK_LABEL on sigelo-msg/0, content {v, typ, id, iat, …}, id 8 characters of
// short.mjs's alphabet:
//   ask     operator → A  {peer: B's original DID, name, kind: own|external, tier?, purpose, expires?, ttl, relay?}
//   invite  A → operator  {code} (a long code, A's own), or {paired: true} (A and B were paired)
//   offer   operator → B  {from: A's original DID, did: the DID the code names, code | paired, name,
//                          purpose, expires?, tier? (own only), note?, ttl}
//   status  A or B → the operator (or the asker of a refused ask)  {status: linked|refused|ended, check?}
//   end     operator → A or B, A ↔ B  {reason: unlink|expired|forgot}
// Checks, by name: link_from (an ask or offer not from the receiver's operator: a DID holding an
// unexpired operator attestation on the receiver's own chain), link_tier (own asked), link_peer (the
// code does not name A; the DID that answered is not B; the same agent twice), link_exists (the
// contact is linked already), link_stale (iat outside ttl + SKEW, or an id seen before), link_text
// (purpose empty, over PURPOSE_MAX, a note over NOTE_MAX, or with control or bidi characters: refused,
// not stripped), link_expired, link_not_ours (neither agent is the operator's), link_refused (X's
// operator said no, with --tell), link_full (too many introductions pending), link_message (any
// other shape). Checks on an introduction (an offer not from X's operator) are never told back.
//
// Already paired: the purpose is attached to the pairing (link.prior: the tier before); its end
// restores that tier and keeps the contact. Otherwise an end forgets the contact on both sides, as
// ended (store.mjs): a NEW link between the same two pairs again only when each side is asked afresh
// (an ask, its operator's offer, or X's operator's accept; never an allow rule), each leaving a
// one-use permit (carrier.relink); the ended id never again (link_stale). design/links.md §7.1a.
//
// The file, 0600, beside the identity (x.json → x.links.json), under its own lock:
//   { v, links: { id: operator records }, pending: { "<by> <id>": an agent's step in progress },
//     seen: { "<from> <id> <typ>": until }, received: { "<by> <id>": an introduction pending, until
//     its code's exp }, allow: { contact's original DID: { tier, until } } }
import { randomBytes } from '@noble/hashes/utils.js';
import { canonicalize, verify } from 'sigelo';
import { LINK_LABEL, LINK_SEND, readCode } from './carrier.mjs';
import { MsgError, checkNow, fail } from './kdf.mjs';
import { ALPHABET } from './short.mjs';
// Files and the lock: the carrier's platform (design/apps.md §4.2), Node's without one.
import { platform as nodePlatform } from './platform-node.mjs';

export const LINK_V = 'sigelo-link/1', FILE_V = 'sigelo-links/1';
export { LINK_LABEL };
export const TYPS = ['ask', 'invite', 'offer', 'status', 'end'], STATUSES = ['linked', 'refused', 'ended'], REASONS = ['unlink', 'expired', 'forgot'];
export const LINK_TIERS = ['friend', 'quiet'], PURPOSE_MAX = 120, NOTE_MAX = 280, NAME_MAX = 64, DAYS_MAX = 365;
export const DAY = 86400, TTL = DAY, TTL_MIN = 60, TTL_MAX = 7 * DAY, SKEW = 300;
// External links: the code lives a week (X's operator answers by hand), the link 30 days unless
// --days says otherwise; at most RECEIVED_MAX introductions wait at once, a quarter of them from one
// contact (more: dropped, link_full).
export const TTL_EXTERNAL = TTL_MAX, DAYS_EXTERNAL = 30, RECEIVED_MAX = 32;
// An operator record that ended or was refused is kept so long, then purged.
const KEPT = 30 * DAY;
const OPERATOR_CTX = 'sigelo-relay/operator';
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;
const ID = /^[0-9A-HJKMNP-TV-Z]{8}$/, DID = /^did:sigelo:z[1-9A-HJ-NP-Za-km-z]{20,60}$/, CHECK = /^[a-z][a-z0-9_]{0,39}$/;

const isObject = (x) => typeof x === 'object' && x !== null && !Array.isArray(x);
const isTime = (x) => Number.isSafeInteger(x) && x >= 0;
export const isLink = (m) => m?.label === LINK_LABEL;
/** A link id: 8 characters of the short-code alphabet. */
export const newId = (rng = randomBytes) => [...rng(8)].map((b) => ALPHABET[b & 31]).join('');

/** A note (external links): up to NOTE_MAX characters, no control or bidi characters; none: null. */
export function checkNote(n) {
  if (n === undefined || n === null) return null;
  if (typeof n !== 'string' || n.trim() === '' || [...n.trim()].length > NOTE_MAX || CONTROL.test(n)) fail('link_text', `the note is 1 to ${NOTE_MAX} characters, no control or bidi characters`);
  return n.trim();
}
const RELAY = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:\d{1,5})?$/i;
/** The purpose: 1 to PURPOSE_MAX characters, trimmed, no control or bidi characters (refused, not stripped). */
export function checkPurpose(p) {
  if (typeof p !== 'string' || p.trim() === '' || [...p.trim()].length > PURPOSE_MAX || CONTROL.test(p)) fail('link_text', `the purpose is 1 to ${PURPOSE_MAX} characters, no control or bidi characters`);
  return p.trim();
}
const checkName = (n) => (n === undefined ? n : typeof n === 'string' && n.trim() !== '' && [...n].length <= NAME_MAX && !CONTROL.test(n) ? n : fail('link_text', `a name is 1 to ${NAME_MAX} characters, no control characters`));

const SHAPES = {
  ask: { need: ['peer', 'kind', 'purpose', 'ttl'], may: ['name', 'tier', 'expires', 'relay'] },
  invite: { need: [], may: ['code', 'paired'] },
  offer: { need: ['from', 'did', 'purpose', 'ttl'], may: ['code', 'paired', 'name', 'tier', 'expires', 'note'] },
  status: { need: ['status'], may: ['check'] },
  end: { need: ['reason'], may: [] },
};
/** A link message's content, checked for shape (link_message) and text (link_text). → it. */
export function checkMessage(x) {
  const bad = (why) => fail('link_message', `not a ${LINK_V} message: ${why}`);
  if (!isObject(x) || x.v !== LINK_V || !TYPS.includes(x.typ)) bad('v and typ');
  if (typeof x.id !== 'string' || !ID.test(x.id)) bad('id: 8 characters of the short-code alphabet');
  if (!isTime(x.iat)) bad('iat: unix seconds');
  const s = SHAPES[x.typ], keys = Object.keys(x).filter((k) => !['v', 'typ', 'id', 'iat'].includes(k));
  for (const k of s.need) if (!Object.hasOwn(x, k)) bad(`${x.typ} needs ${k}`);
  for (const k of keys) if (!s.need.includes(k) && !s.may.includes(k)) bad(`${x.typ} has no ${k}`);
  for (const k of ['peer', 'from', 'did']) if (Object.hasOwn(x, k) && (typeof x[k] !== 'string' || !DID.test(x[k]))) bad(`${k}: a did:sigelo`);
  if (Object.hasOwn(x, 'ttl') && (!Number.isSafeInteger(x.ttl) || x.ttl < TTL_MIN || x.ttl > TTL_MAX)) bad(`ttl: ${TTL_MIN} to ${TTL_MAX} seconds`);
  if (Object.hasOwn(x, 'expires') && !isTime(x.expires)) bad('expires: unix seconds');
  if (Object.hasOwn(x, 'tier') && !['own', ...LINK_TIERS].includes(x.tier)) bad('tier: friend or quiet');
  if (x.typ === 'ask' && x.kind !== 'own' && x.kind !== 'external') bad('kind: own or external');
  if (Object.hasOwn(x, 'relay') && (typeof x.relay !== 'string' || !RELAY.test(x.relay))) bad('relay: host[:port]');
  if (x.typ === 'invite' || x.typ === 'offer') {
    const code = typeof x.code === 'string' && x.code.length <= 8192, paired = x.paired === true;
    if (code === paired || (Object.hasOwn(x, 'paired') && !paired)) bad(`${x.typ}: a code, or paired: true`);
  }
  if (x.typ === 'status' && (!STATUSES.includes(x.status) || (Object.hasOwn(x, 'check') && (typeof x.check !== 'string' || !CHECK.test(x.check))))) bad('status: linked, refused or ended; check a name');
  if (x.typ === 'end' && !REASONS.includes(x.reason)) bad(`reason: ${REASONS.join(', ')}`);
  if (Object.hasOwn(x, 'purpose')) checkPurpose(x.purpose);
  if (Object.hasOwn(x, 'note')) { if (x.note === null) bad('note: a string'); checkNote(x.note); }
  checkName(x.name);
  return x;
}

// ---------------------------------------------------------------- the file

/** The links file beside an identity file: x.json → x.links.json. */
export const linksPath = (identityFile) => identityFile.replace(/\.json$/, '') + '.links.json';

const platformOf = (carrier) => carrier?.platform ?? nodePlatform;
// UTF-8 as readFileSync(…, 'utf8') reads it: a byte order mark is kept (JSON.parse refuses it).
const textOf = (b) => new TextDecoder('utf-8', { ignoreBOM: true }).decode(b);
// Written whole to a fresh 0600 name, then renamed (files.write), under the file's own lock
// (transact: `<file>.lock` on Node).
const writeJson = (files, path, value) => files.write(path, new TextEncoder().encode(JSON.stringify(value, null, 2)));
/** Load, purge, change (fn), save: under the file's lock. → fn's result. */
export function state(file, now, fn = () => undefined, platform = nodePlatform) {
  checkNow(now);
  const { files } = platform;
  return platform.transact(file, () => {
    let s = { v: FILE_V, links: {}, pending: {}, seen: {} };
    const raw = files.read(file);
    if (raw !== null) {
      try { s = JSON.parse(textOf(raw)); } catch (e) { fail('link_file', `${file} does not parse (${e.message}): delete it to drop the links in progress`); }
      if (s?.v !== FILE_V || !isObject(s.links) || !isObject(s.pending) || !isObject(s.seen)) fail('link_file', `${file} is not a ${FILE_V} file`);
      if (!isObject(s.received ?? {}) || !isObject(s.allow ?? {})) fail('link_file', `${file} is not a ${FILE_V} file`);
    }
    s.received ??= {}; s.allow ??= {};
    const before = canonicalize(s);
    for (const [k, t] of Object.entries(s.seen)) if (!(t > now)) delete s.seen[k];
    for (const [k, p] of Object.entries(s.pending)) if (!(p.exp > now)) delete s.pending[k];
    // An introduction lapses with its code; a rule at its until.
    for (const [k, r] of Object.entries(s.received)) if (!(r.exp > now)) delete s.received[k];
    for (const [k, r] of Object.entries(s.allow)) if (r.until !== null && !(r.until > now)) delete s.allow[k];
    for (const [k, r] of Object.entries(s.links)) if (r.status !== 'pending' && r.status !== 'linked' && r.at + KEPT < now) delete s.links[k];
    const out = fn(s);
    if (canonicalize(s) !== before) writeJson(files, file, s);
    return out;
  }, 'sigelo');
}

// ---------------------------------------------------------------- the carrier's side

const nowOf = (carrier) => checkNow(carrier.clock());
const readStore = (carrier) => { const raw = platformOf(carrier).files.read(carrier.storePath); return raw === null ? { contacts: {} } : JSON.parse(textOf(raw)); };
const exists = (carrier, file) => platformOf(carrier).files.read(file) !== null;
const live = (c) => c && !c.revoked && c.pair_key ? c : null;
// The contact an ended link (or a forget) revoked whose chain holds `did`, or null.
const gone = (carrier, did) => Object.values(readStore(carrier).contacts).find((c) => c.revoked && c.chain.includes(did)) ?? null;
// After an end, a new link pairs again only through a permit left by this fresh step (store.mjs relink).
const relink = (carrier, did, id, until) => (gone(carrier, did) ? carrier.relink(did, id, until) : null);
// The live contact whose chain holds `did`, or null.
const holding = (carrier, did) => live(Object.values(readStore(carrier).contacts).find((c) => !c.revoked && c.chain.includes(did)));
// This agent: its original DID, its chain, and its operators (issuers of the unexpired operator
// attestations its bundle carries that verify), as carrier.mjs #mine reads them.
function me(carrier, now) {
  const { bundle } = carrier.identity();
  const r = verify({ ...bundle, bindings: [] }, now), ops = new Set();
  for (const [iss, bodies] of Object.entries(r.attestations ?? {})) if (!r.chain.includes(iss) && bodies.some((b) => b.ctx === OPERATOR_CTX)) ops.add(iss);
  return { original: r.chain[0], chain: r.chain, operators: ops };
}
const isOperator = (c, mine) => Boolean(live(c)) && c.chain.some((d) => mine.operators.has(d));
const send = (carrier, to, content, local) => carrier.send(to, content, { label: LINK_LABEL, internal: LINK_SEND, local });
const msg = (typ, id, now, body) => ({ v: LINK_V, typ, id, iat: now, ...body });
// The contacts of the carrier as the owner's verbs name them: a name, or any DID of a chain.
function contactNamed(carrier, who) {
  const all = carrier.contacts().contacts.filter((c) => !c.revoked && c.pair);
  const hit = who.startsWith('did:') ? all.filter((c) => c.chain.includes(who)) : all.filter((c) => c.name === who);
  if (hit.length > 1) fail('name', `${hit.length} contacts are called ${JSON.stringify(who)}: use the DID`);
  return hit[0] ?? fail('not_contact', `${JSON.stringify(who)} is not a live contact`);
}

// ---------------------------------------------------------------- the operator

/**
 * The operator introduces agents a and b (names or DIDs of its contacts). Both ours: own kind. One
 * ours: external, the ours one is A, the other X (B). tierA: how A files B, tierB: how B files A
 * (friend or quiet; none: computed, own between two own agents; external: A files X at friend, and
 * tierB is refused: X's operator decides); days: the link's life (none: until unlinked; external:
 * DAYS_EXTERNAL); note: for X (external), data; relay: the relay A's code names (external default:
 * the relay of the operator's pairing with X). → the record { id, a, b, kind, …, status: "pending" }.
 */
export async function link({ carrier, file, a, b, purpose, tierA, tierB, days, ttl, note, relay }) {
  for (const t of [tierA, tierB]) {
    if (t === 'own') fail('link_tier', 'a link never makes a contact own: own comes from your operator attestation alone (leave the tier out: two of your agents find each other own)');
    if (t !== undefined && t !== null && !LINK_TIERS.includes(t)) fail('tier', `a link's tier is ${LINK_TIERS.join(' or ')}, not ${JSON.stringify(t)}`);
  }
  const p = checkPurpose(purpose), n = checkNote(note);
  if (days !== undefined && days !== null && (!Number.isSafeInteger(days) || days < 1 || days > DAYS_MAX)) fail('link_days', `days: 1 to ${DAYS_MAX}`);
  if (ttl !== undefined && (!Number.isSafeInteger(ttl) || ttl < TTL_MIN || ttl > TTL_MAX)) fail('link_ttl', `ttl: ${TTL_MIN} to ${TTL_MAX} seconds`);
  if (relay !== undefined && relay !== null && (typeof relay !== 'string' || !RELAY.test(relay))) fail('link_relay', `relay: host[:port], not ${JSON.stringify(relay)}`);
  let A = contactNamed(carrier, a), B = contactNamed(carrier, b);
  if (A.did === B.did) fail('link_peer', `${A.name} twice: a link joins two agents`);
  if (!A.ours && !B.ours) fail('link_not_ours', `neither ${A.name} nor ${B.name} is yours by key (an operator attestation of yours): a link introduces one of your agents`);
  if (!A.ours) [A, B] = [B, A];
  const kind = B.ours ? 'own' : 'external';
  if (kind === 'external' && tierB) fail('link_tier', `${B.name} is not yours: how it files ${A.name} is its operator's choice (leave --tier-b out)`);
  const tA = tierA ?? (kind === 'external' ? 'friend' : null), life = days ?? (kind === 'external' ? DAYS_EXTERNAL : null);
  const t = ttl ?? (kind === 'external' ? TTL_EXTERNAL : TTL), at = relay ?? (kind === 'external' && typeof B.relay === 'string' ? B.relay : null);
  const now = nowOf(carrier), expires = life ? now + life * DAY : null;
  const rec = state(file, now, (s) => {
    let id;
    do id = newId(); while (Object.hasOwn(s.links, id));
    s.links[id] = { id, a: A.did, b: B.did, a_name: A.name, b_name: B.name, kind, purpose: p, note: n, tier_a: tA, tier_b: tierB ?? null, expires, relay: at,
      status: 'pending', step: 'ask', check: null, at: now, exp: now + t, ttl: t, steps: { a: null, b: null } };
    return s.links[id];
  }, platformOf(carrier));
  try {
    await send(carrier, A.did, msg('ask', rec.id, now, { peer: B.did, name: B.name, kind, purpose: p, ttl: t, ...(tA && { tier: tA }), ...(expires && { expires }), ...(at && { relay: at }) }));
  } catch (e) {
    if (!(e instanceof MsgError)) throw e;
    state(file, nowOf(carrier), (s) => { Object.assign(s.links[rec.id], { status: 'refused', check: e.check, at: nowOf(carrier) }); }, platformOf(carrier));
    throw e;
  }
  return state(file, now, (s) => s.links[rec.id], platformOf(carrier));
}

/** Ends a link: the operator's (end to both agents), or, on an agent, one of its own (the contact forgotten). */
export async function unlink({ carrier, file, id }) {
  const now = nowOf(carrier), rec = state(file, now, (s) => s.links[id] ?? null, platformOf(carrier));
  if (rec) {
    const sent = [];
    for (const to of [rec.a, rec.b]) {
      try { await send(carrier, to, msg('end', id, now, { reason: 'unlink' })); sent.push(to); } catch (e) { if (!(e instanceof MsgError)) throw e; }
    }
    state(file, nowOf(carrier), (s) => { Object.assign(s.links[id], { status: 'ended', check: 'unlink', at: nowOf(carrier) }); }, platformOf(carrier));
    return { id, status: 'ended', role: 'operator', told: sent };
  }
  const c = Object.values(readStore(carrier).contacts).find((x) => live(x) && x.link && (x.link.id === id || x.name === id || x.chain.includes(id)));
  if (!c) fail('link_unknown', `no link ${JSON.stringify(id)} here (sigelo-agent links)`);
  const out = { linked: [], refused: [], ended: [], ignored: 0 };
  await endHere(carrier, file, c, 'unlink', { peer: true, operator: true }, out);
  return { id: c.link.id, status: 'ended', role: 'agent', contact: c.did, name: c.name, forgot: !c.link.prior };
}

/**
 * This identity's links: as an agent (its linked contacts), as an operator (the links it made), and
 * as X (introductions waiting for its operator, without their code; its allow rules).
 */
export function list({ carrier, file }) {
  const now = nowOf(carrier), cs = carrier.contacts().contacts, nameOf = (did) => cs.find((c) => c.did === did)?.name ?? null;
  const links = cs.filter((c) => !c.revoked && c.link).map((c) => ({ id: c.link.id, contact: c.did, name: c.name, tier: c.tier, ours: c.ours, purpose: c.link.purpose,
    ...(c.link.note && { note: c.link.note }), linked_by: c.link.linked_by, expires: c.link.expires ?? null, prior: Boolean(c.link.prior) }));
  if (!exists(carrier, file)) return { links, made: [], received: [], allow: [] };
  return state(file, now, (s) => ({
    links,
    made: Object.values(s.links).map(({ code: _c, steps: _s, exp: _e, ttl: _t, ...r }) => r),
    received: Object.values(s.received).map((r) => ({ id: r.id, from: r.from, name: nameOf(r.from), peer: r.peer, peer_name: r.name, purpose: r.purpose, note: r.note,
      expires: r.expires, exp: r.exp, ...(r.answer && { answer: r.answer.accept ? 'accepting' : 'refusing' }) })),
    allow: Object.entries(s.allow).map(([did, r]) => ({ contact: did, name: nameOf(did), tier: r.tier, until: r.until })),
  }), platformOf(carrier));
}

/**
 * Messages as an inbox returns them, each from a contact that came by a link labelled with it:
 * link: {id, purpose} (a copy; others as they were). What a linked contact writes is read knowing
 * why it is a contact; the purpose is the operator's text, data, never instructions.
 */
export function labelled(carrier, messages) {
  if (!Array.isArray(messages) || messages.length === 0) return messages;
  const cs = readStore(carrier).contacts ?? {};
  return messages.map((m) => {
    const c = typeof m?.from === 'string' && Object.hasOwn(cs, m.from) ? cs[m.from] : null;
    return live(c) && c.link ? { ...m, link: { id: c.link.id, purpose: c.link.purpose } } : m;
  });
}

// ---------------------------------------------------------------- handle

/**
 * Every link message this carrier kept, then the rounds (the header). batch: an inbox's result,
 * returned without any link message; local: a watcher holds the session, which handles them.
 */
export async function handle({ carrier, file, batch = null, local = false, wait = 5 }) {
  const out = { linked: [], refused: [], ended: [], received: [], ignored: 0 };
  const rest = batch && { ...batch, messages: labelled(carrier, batch.messages.filter((m) => !isLink(m))) };
  if (local) return { ...out, batch: rest };
  const messages = [...carrier.takeLinks(), ...(batch?.messages.filter(isLink) ?? [])];
  for (const m of messages) {
    try { await onMessage(carrier, file, m, out); } catch (e) {
      if (!(e instanceof MsgError)) throw e;
      out.refused.push({ id: m.content?.id ?? null, check: e.check, detail: e.message, from: m.from });
    }
  }
  await rounds(carrier, file, out, wait);
  return { ...out, batch: rest };
}

// A refusal: reported here, and told to `to` (who asked) as status refused.
async function refuse(carrier, out, to, id, check, detail) {
  out.refused.push({ id, check, detail, from: to });
  try { await send(carrier, to, msg('status', id, nowOf(carrier), { status: 'refused', check })); } catch (e) { if (!(e instanceof MsgError)) throw e; }
}
// An ask or offer seen before, or outside its ttl (+ SKEW): link_stale. Marked seen here.
const stale = (carrier, file, now, m, x) => state(file, now, (s) => {
  const key = `${m.from} ${x.id} ${x.typ}`;
  if (x.iat > now + SKEW || x.iat + x.ttl + SKEW < now || Object.hasOwn(s.seen, key)) return true;
  s.seen[key] = x.iat + x.ttl + SKEW;
  return false;
}, platformOf(carrier));

async function onMessage(carrier, file, m, out, wait) {
  const x = checkMessage(m.content), now = nowOf(carrier), from = readStore(carrier).contacts[m.from];
  if (!live(from)) { out.ignored++; return; }
  if (x.typ === 'invite' || x.typ === 'status') return onOperator(carrier, file, m, x, out);
  if (x.typ === 'end') return onEnd(carrier, file, m, x, out);
  // ask (to A) and offer (to B): only from this agent's operator, fresh, within the rules. An offer
  // from anyone else is an introduction, for this agent's operator to answer.
  const mine = me(carrier, now), who = `${m.name ?? m.from}`;
  if (!isOperator(from, mine) && x.typ === 'offer') return introduced(carrier, file, m, x, mine, out);
  if (!isOperator(from, mine)) return refuse(carrier, out, m.from, x.id, 'link_from', `an ${x.typ} from ${who}, not your operator (an operator attestation on your chain): only your operator links you`);
  if (stale(carrier, file, now, m, x)) return refuse(carrier, out, m.from, x.id, 'link_stale', `an ${x.typ} from ${who} seen before, or outside its ttl`);
  if (x.tier === 'own') return refuse(carrier, out, m.from, x.id, 'link_tier', 'a link never makes a contact own');
  if (x.expires !== undefined && x.expires <= now) return refuse(carrier, out, m.from, x.id, 'link_expired', 'the link expired before it was made');
  const peer = x.typ === 'ask' ? x.peer : x.from;
  if (mine.chain.includes(peer)) return refuse(carrier, out, m.from, x.id, 'link_peer', 'a link to this agent itself');
  const base = { id: x.id, purpose: x.purpose, linked_by: m.from, expires: x.expires ?? null, tier: x.tier ?? null };
  const had = holding(carrier, peer);
  if (had?.link) return refuse(carrier, out, m.from, x.id, had.link.id === x.id ? 'link_stale' : 'link_exists', `${had.name} is linked already (${had.link.id})`);
  if (x.typ === 'offer' && x.paired && !had) return refuse(carrier, out, m.from, x.id, 'link_peer', `the offer says this agent is paired with ${x.from}; it is not`);
  if (!had) {
    try { relink(carrier, peer, x.id, x.iat + x.ttl + 3600); } catch (e) {
      if (!(e instanceof MsgError)) throw e;
      return refuse(carrier, out, m.from, x.id, e.check, e.message);
    }
  }
  if (had && (x.typ === 'ask' || x.paired)) {
    // Paired already: the purpose attached to the pairing, its tier kept to restore at the end.
    if (x.tier) carrier.setTier(had.did, x.tier);
    carrier.setLink(had.did, { ...base, prior: { tier: had.tier, ...(had.tier_by !== undefined && { tier_by: had.tier_by }) } });
    out.linked.push({ id: x.id, contact: had.did, name: had.name, purpose: x.purpose, prior: true });
    await send(carrier, m.from, x.typ === 'ask' ? msg('invite', x.id, now, { paired: true }) : msg('status', x.id, now, { status: 'linked' }));
    return;
  }
  if (x.typ === 'ask') {
    if (x.tier) carrier.presetTier(x.peer, x.tier);
    const inv = await carrier.invite({ name: x.name, ttl: Math.max(TTL_MIN, x.iat + x.ttl - now), ...(x.relay && { relay: x.relay }) });
    const code = readCode(inv.code, now);
    state(file, now, (s) => { s.pending[`${m.from} ${x.id}`] = { ...base, role: 'a', peer: x.peer, nonce: code.nonce, exp: code.exp + 3600 }; }, platformOf(carrier));
    await send(carrier, m.from, msg('invite', x.id, now, { code: inv.code }));
    return;
  }
  // The offer: the code must name the A the operator named.
  let code;
  try { code = readCode(x.code, now); } catch (e) { return refuse(carrier, out, m.from, x.id, 'link_message', `the offer's code does not parse (${e.message})`); }
  if (code.did !== x.did) return refuse(carrier, out, m.from, x.id, 'link_peer', `the offer's code names ${code.did}, not ${x.did}`);
  state(file, now, (s) => { s.pending[`${m.from} ${x.id}`] = { ...base, role: 'b', peer: x.from, code_did: code.did, exp: code.exp + 3600 }; }, platformOf(carrier));
  try { await carrier.accept(x.code, { name: x.name, wait, ...(x.tier && { tier: x.tier }) }); } catch (e) {
    if (!(e instanceof MsgError)) throw e;
    state(file, nowOf(carrier), (s) => { delete s.pending[`${m.from} ${x.id}`]; }, platformOf(carrier));
    return refuse(carrier, out, m.from, x.id, e.check, `the link's code was not accepted (${e.message})`);
  }
}

// The operator: A's invite (forwarded to B as an offer once its code names A), and statuses.
async function onOperator(carrier, file, m, x, out) {
  const now = nowOf(carrier), rec = state(file, now, (s) => s.links[x.id] ?? null, platformOf(carrier));
  const side = rec && (m.from === rec.a ? 'a' : m.from === rec.b ? 'b' : null);
  if (!side || (x.typ === 'invite' && (side !== 'a' || rec.status !== 'pending' || rec.step !== 'ask'))) { out.ignored++; return; }
  const set = (f) => state(file, nowOf(carrier), (s) => { if (s.links[x.id]) f(s.links[x.id]); return s.links[x.id]; }, platformOf(carrier));
  if (x.typ === 'status') {
    const r = set((l) => {
      l.steps[side] = x.status; l.at = now;
      if (x.status === 'refused' && l.status === 'pending') Object.assign(l, { status: 'refused', check: x.check ?? 'link_refused' });
      else if (x.status === 'ended' && l.status !== 'refused') Object.assign(l, { status: 'ended', check: l.check ?? x.check ?? null });
      // External: A's word is enough (X need not tell, design/links.md §5.4).
      else if (l.status === 'pending' && l.steps.a === 'linked' && (l.steps.b === 'linked' || l.kind === 'external')) l.status = 'linked';
    });
    if (r.status === 'refused' && x.status === 'refused') out.refused.push({ id: x.id, check: r.check, detail: `${side === 'a' ? rec.a_name : rec.b_name} refused link ${x.id}`, from: m.from });
    if (r.status === 'refused' && x.status === 'refused' && side === 'b') await callOff(carrier, r, now);
    if (r.status === 'linked' && x.status === 'linked') out.linked.push({ id: x.id, a: rec.a, b: rec.b, a_name: rec.a_name, b_name: rec.b_name, purpose: rec.purpose, role: 'operator' });
    return;
  }
  const A = holding(carrier, rec.a);
  let offer;
  if (x.paired) {
    set((l) => { l.steps.a = 'linked'; });
    offer = { paired: true, did: A?.current_did ?? rec.a };
  } else {
    let code;
    try { code = readCode(x.code, now); } catch (e) { code = null; }
    if (!code || !A || code.did !== A.current_did) {
      set((l) => Object.assign(l, { status: 'refused', check: 'link_peer', at: now }));
      out.refused.push({ id: x.id, check: 'link_peer', detail: `${rec.a_name}'s code for link ${x.id} names ${code?.did ?? 'nothing readable'}, not ${A?.current_did ?? rec.a}: not forwarded`, from: m.from });
      return;
    }
    offer = { code: x.code, did: code.did };
  }
  try {
    await send(carrier, rec.b, msg('offer', x.id, now, { from: rec.a, ...offer, name: rec.a_name, purpose: rec.purpose, ttl: rec.ttl, ...(rec.tier_b && { tier: rec.tier_b }), ...(rec.expires && { expires: rec.expires }), ...(rec.note && { note: rec.note }) }));
    set((l) => { l.step = 'offer'; });
  } catch (e) {
    if (!(e instanceof MsgError)) throw e;
    set((l) => Object.assign(l, { status: 'refused', check: e.check, at: now }));
    out.refused.push({ id: x.id, check: e.check, detail: `the offer to ${rec.b_name} did not go (${e.message})`, from: rec.b });
  }
}

// An end: from the linked contact itself, or from the operator who made that link. Any other: ignored.
async function onEnd(carrier, file, m, x, out) {
  const cs = Object.values(readStore(carrier).contacts).filter((c) => live(c) && c.link?.id === x.id);
  const peer = cs.find((c) => c.did === m.from), byOp = cs.find((c) => c.link.linked_by === m.from && c.did !== m.from);
  if (peer) return endHere(carrier, file, peer, x.reason, { peer: false, operator: true }, out);
  if (byOp) return endHere(carrier, file, byOp, x.reason, { peer: true, operator: true }, out);
  // A link still being made: its step dropped (an introduction still pending: dropped, unanswered).
  const gone = state(file, nowOf(carrier), (s) => { const k = `${m.from} ${x.id}`; const had = Object.hasOwn(s.pending, k) || Object.hasOwn(s.received, k); delete s.pending[k]; delete s.received[k]; return had; }, platformOf(carrier));
  if (!gone) out.ignored++;
}

// This side of a link ends: the other side told (tell.peer), the contact forgotten (or, linked onto
// an earlier pairing, its tier restored), the operator told (tell.operator).
async function endHere(carrier, file, c, reason, tell, out) {
  const now = nowOf(carrier), l = c.link;
  if (tell.peer) { try { await send(carrier, c.did, msg('end', l.id, now, { reason })); } catch (e) { if (!(e instanceof MsgError)) throw e; } }
  if (l.prior) carrier.setLink(c.did, null);
  else await carrier.forget(c.did, { ended: { id: l.id, by: l.linked_by, at: now } });
  out.ended.push({ id: l.id, contact: c.did, name: c.name, reason, forgot: !l.prior });
  if (tell.operator && l.linked_by !== c.did && holding(carrier, l.linked_by)) {
    try { await send(carrier, l.linked_by, msg('status', l.id, now, { status: 'ended', check: `link_${reason === 'unlink' ? 'unlinked' : reason}` })); } catch (e) { if (!(e instanceof MsgError)) throw e; }
  }
}

// ---------------------------------------------------------------- X: introductions

// An offer not from this agent's operator: checked (never told back), then kept for X's operator
// (out.received, notice unless the introducer is quiet here), or accepted at once by its allow rule.
async function introduced(carrier, file, m, x, mine, out, wait) {
  const now = nowOf(carrier), who = m.name ?? m.from;
  const quietly = (check, detail) => { out.refused.push({ id: x.id, check, detail: `an introduction from ${who}: ${detail} (not told)`, from: m.from, silent: true }); };
  if (stale(carrier, file, now, m, x)) return quietly('link_stale', 'seen before, or outside its ttl');
  if (x.expires !== undefined && x.expires <= now) return quietly('link_expired', 'the link expired before it was made');
  if (mine.chain.includes(x.from)) return quietly('link_peer', 'a link to this agent itself');
  const had = holding(carrier, x.from);
  if (had?.link) return quietly('link_exists', `${had.name} is linked already (${had.link.id})`);
  if (x.paired && !had) return quietly('link_peer', `it says this agent is paired with ${x.from}; it is not`);
  // After an end: forgotten by hand, never; that link's own id, stale; a new one waits for the operator (never a rule).
  const was = had ? null : gone(carrier, x.from);
  if (was && !was.ended) return quietly('revoked', `${was.name} was forgotten here: never linked again`);
  if (was && was.ended.id === x.id) return quietly('link_stale', `link ${x.id} ended already`);
  let exp = x.iat + x.ttl;
  if (x.code !== undefined) {
    let code;
    try { code = readCode(x.code, now); } catch (e) { return quietly('link_message', `its code does not parse (${e.message})`); }
    if (code.did !== x.did) return quietly('link_peer', `its code names ${code.did}, not ${x.did}`);
    exp = code.exp;
  }
  const by = carrier.contacts().contacts.find((c) => c.did === m.from);
  const key = `${m.from} ${x.id}`, rec = { id: x.id, from: m.from, peer: x.from, did: x.did, name: x.name ?? null, purpose: x.purpose, note: x.note ?? null,
    expires: x.expires ?? null, ...(x.code !== undefined ? { code: x.code } : { paired: true }), exp, at: now };
  const kept = state(file, now, (s) => {
    // One contact cannot crowd out the others: at most a quarter of the places each.
    const all = Object.values(s.received);
    if (all.length >= RECEIVED_MAX || all.filter((r) => r.from === m.from).length >= RECEIVED_MAX / 4) return 'full';
    const rule = was ? null : s.allow[m.from];
    s.received[key] = rule ? { ...rec, answer: { accept: true, tier: rule.tier, by: 'allow' } } : rec;
    return rule ? 'allowed' : 'kept';
  }, platformOf(carrier));
  if (kept === 'full') return quietly('link_full', `${RECEIVED_MAX} introductions wait already (sigelo-agent links)`);
  if (kept === 'allowed') return;   // carried out by this handle's rounds
  out.received.push({ id: x.id, from: m.from, name: by?.name ?? who, peer: x.from, peer_name: x.name ?? null, purpose: x.purpose, note: x.note ?? null, exp, notice: by?.tier !== 'quiet' });
}

// X's operator's answer, carried out (it needs the session): accept the code at the tier (quiet by
// default, never own), or tell the introducer it was refused (link_refused).
async function answered(carrier, file, key, r, out, wait) {
  const now = nowOf(carrier), drop = () => state(file, nowOf(carrier), (s) => { delete s.received[key]; }, platformOf(carrier));
  if (!r.answer.accept) {
    drop();
    try { await send(carrier, r.from, msg('status', r.id, now, { status: 'refused', check: 'link_refused' })); } catch (e) { if (!(e instanceof MsgError)) throw e; }
    out.refused.push({ id: r.id, check: 'link_refused', detail: `the introduction from ${r.from} refused, and told`, from: r.from, silent: true });
    return;
  }
  const tier = r.answer.tier ?? 'quiet', base = { id: r.id, purpose: r.purpose, linked_by: r.from, expires: r.expires, tier, ...(r.note && { note: r.note }) };
  const had = holding(carrier, r.peer);
  if (r.paired || had) {
    drop();
    if (!had || had.link) { out.refused.push({ id: r.id, check: had ? 'link_exists' : 'link_peer', detail: `the introduction from ${r.from}: ${had ? `${had.name} is linked already` : 'not paired with its agent'} (not told)`, from: r.from, silent: true }); return; }
    // Paired already: the tier changes only when the operator (or its rule) named one.
    if (r.answer.tier) carrier.setTier(had.did, tier);
    carrier.setLink(had.did, { ...base, tier: r.answer.tier ?? null, prior: { tier: had.tier, ...(had.tier_by !== undefined && { tier_by: had.tier_by }) } });
    out.linked.push({ id: r.id, contact: had.did, name: had.name, purpose: r.purpose, prior: true });
    try { await send(carrier, r.from, msg('status', r.id, now, { status: 'linked' })); } catch (e) { if (!(e instanceof MsgError)) throw e; }
    return;
  }
  // After an end: only the operator's own accept relinks (its permit, store.mjs relink), never a rule.
  if (gone(carrier, r.peer) && r.answer.by !== 'operator') {
    drop();
    out.refused.push({ id: r.id, check: 'revoked', detail: `the introduction from ${r.from}: a link with it ended; only your operator links it again (not told)`, from: r.from, silent: true });
    return;
  }
  try { relink(carrier, r.peer, r.id, r.exp + 3600); } catch (e) {
    if (!(e instanceof MsgError)) throw e;
    drop();
    out.refused.push({ id: r.id, check: e.check, detail: `the introduction from ${r.from}: ${e.message} (not told)`, from: r.from, silent: true });
    return;
  }
  state(file, now, (s) => { delete s.received[key]; s.pending[key] = { ...base, role: 'b', peer: r.peer, code_did: r.did, exp: r.exp + 3600 }; }, platformOf(carrier));
  try { await carrier.accept(r.code, { ...(r.name && { name: r.name }), wait, tier }); } catch (e) {
    if (!(e instanceof MsgError)) throw e;
    state(file, nowOf(carrier), (s) => { delete s.pending[key]; }, platformOf(carrier));
    out.refused.push({ id: r.id, check: e.check, detail: `the introduction's code was not accepted (${e.message})`, from: r.from, silent: true });
  }
}

// The introduction `id` here (one id, or "<from> <id>" when two introducers chose the same).
function receivedOf(s, id) {
  const hits = Object.entries(s.received).filter(([k, r]) => k === id || r.id === id);
  if (hits.length > 1) fail('link_unknown', `${hits.length} introductions carry ${id}: name it as "<from> <id>" (sigelo-agent links --json)`);
  return hits[0] ?? fail('link_unknown', `no introduction ${JSON.stringify(id)} pending here (sigelo-agent links); it may have lapsed with its code`);
}

/**
 * X's operator answers an introduction: accept (at tier, friend or quiet, default quiet), or refuse
 * (tell: the introducer learns it, else nothing goes). A silent refusal is done here; the rest is
 * carried out by the next handle(), which needs the session. → { id, status: accepting|refusing|refused, told }.
 */
export function answer({ carrier, file, id, accept, tell = false, tier }) {
  if (tier === 'own') fail('link_tier', 'an introduced agent is never own: friend or quiet');
  if (tier !== undefined && tier !== null && !LINK_TIERS.includes(tier)) fail('tier', `tier: ${LINK_TIERS.join(' or ')}`);
  if (!accept && tier) fail('usage', 'a tier is for accept');
  return state(file, nowOf(carrier), (s) => {
    const [k, r] = receivedOf(s, id);
    if (!accept && !tell) { delete s.received[k]; return { id: r.id, from: r.from, status: 'refused', told: false }; }
    r.answer = { accept: Boolean(accept), ...(tier && { tier }), by: 'operator' };
    return { id: r.id, from: r.from, status: accept ? 'accepting' : 'refusing', told: !accept };
  }, platformOf(carrier));
}

/** An allow rule: introductions from that contact accepted at tier (default quiet), for days (none: until deny). */
export function allow({ carrier, file, contact, tier = 'quiet', days }) {
  if (tier === 'own') fail('link_tier', 'an introduced agent is never own: friend or quiet');
  if (!LINK_TIERS.includes(tier)) fail('tier', `tier: ${LINK_TIERS.join(' or ')}`);
  if (days !== undefined && days !== null && (!Number.isSafeInteger(days) || days < 1 || days > DAYS_MAX)) fail('link_days', `days: 1 to ${DAYS_MAX}`);
  const c = contactNamed(carrier, contact), now = nowOf(carrier), until = days ? now + days * DAY : null;
  state(file, now, (s) => { s.allow[c.did] = { tier, until }; }, platformOf(carrier));
  return { contact: c.did, name: c.name, allow: true, tier, until };
}

/** The allow rule for that contact (a name, or any DID of its chain, or an original DID no longer a contact) removed. */
export function deny({ carrier, file, contact }) {
  let did = contact, name = null;
  try { const c = contactNamed(carrier, contact); did = c.did; name = c.name; } catch (e) { if (!(e instanceof MsgError) || !contact.startsWith('did:')) throw e; }
  const had = state(file, nowOf(carrier), (s) => { const h = Object.hasOwn(s.allow, did); delete s.allow[did]; return h; }, platformOf(carrier));
  return { contact: did, name, allow: false, had };
}

// The rounds: answers to carry out, steps that wait on a pairing, expiry on every link, the
// operator's pending links.
async function rounds(carrier, file, out, wait) {
  for (const [k, r] of state(file, nowOf(carrier), (s) => Object.entries(s.received).filter(([, x]) => x.answer), platformOf(carrier))) {
    try { await answered(carrier, file, k, r, out, wait); } catch (e) {
      if (!(e instanceof MsgError)) throw e;
      out.refused.push({ id: r.id, check: e.check, detail: e.message, from: r.from, silent: true });
    }
  }
  const now = nowOf(carrier), pend = state(file, now, (s) => Object.entries(s.pending), platformOf(carrier));
  const done = (k) => state(file, nowOf(carrier), (s) => { delete s.pending[k]; }, platformOf(carrier));
  for (const [k, p] of pend) {
    // A: who answered its code; B: whether its accept has paired.
    const did = p.role === 'a' ? carrier.answeredBy(p.nonce) : holding(carrier, p.code_did)?.did ?? null;
    if (!did) continue;
    done(k);
    const c = holding(carrier, did);
    if (did !== p.peer) {
      if (c) await carrier.forget(c.did);
      await refuse(carrier, out, p.linked_by, p.id, 'link_peer', `${p.role === 'a' ? 'the code was answered by' : 'the code paired with'} ${did}, not ${p.peer}: forgotten`);
      continue;
    }
    if (!c) continue;
    const { role: _r, peer: _p, nonce: _n, code_did: _d, exp: _e, ...rec } = p;
    try { carrier.setLink(c.did, rec); } catch (e) {
      if (!(e instanceof MsgError)) throw e;
      await refuse(carrier, out, p.linked_by, p.id, e.check, e.message);
      continue;
    }
    out.linked.push({ id: p.id, contact: c.did, name: c.name, purpose: p.purpose, prior: false });
    try { await send(carrier, p.linked_by, msg('status', p.id, nowOf(carrier), { status: 'linked' })); } catch (e) { if (!(e instanceof MsgError)) throw e; }
  }
  for (const c of Object.values(readStore(carrier).contacts)) {
    if (live(c) && c.link?.expires && c.link.expires <= now) await endHere(carrier, file, c, 'expired', { peer: true, operator: true }, out);
  }
  if (exists(carrier, file)) {
    const lapsed = state(file, now, (s) => {
      const gone = [];
      for (const l of Object.values(s.links)) {
        if (l.status === 'pending' && l.exp <= now) {
          Object.assign(l, { status: 'refused', check: 'link_expired', at: now });
          gone.push(l);
          out.refused.push({ id: l.id, check: 'link_expired', detail: `link ${l.id} (${l.a_name} ↔ ${l.b_name}) was not made within its ${l.ttl} s`, from: null });
        } else if (l.status === 'linked' && l.expires && l.expires <= now) Object.assign(l, { status: 'ended', check: 'link_expired', at: now });
      }
      return gone;
    }, platformOf(carrier));
    for (const l of lapsed) await callOff(carrier, l, now);
  }
}

// An external link X refused or let lapse: A told to drop its step (or the purpose it attached to an
// earlier pairing). Own links are left as they were (each side's own checks end them).
async function callOff(carrier, l, now) {
  if (l.kind !== 'external') return;
  try { await send(carrier, l.a, msg('end', l.id, now, { reason: 'unlink' })); } catch (e) { if (!(e instanceof MsgError)) throw e; }
}
