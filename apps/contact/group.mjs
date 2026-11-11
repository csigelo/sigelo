// SPDX-License-Identifier: MIT
// Chat groups, contract sigelo-group/1 (design/groups.md, apps/agent/GROUPS.md, THREAT-MODEL
// §3.13): a label on sigelo-msg/0, no wire change. A group is {gid, name, creator, members, ver,
// brake}; the creator is paired with every member, members need not be paired with each other. Every
// message is {body, sig}: body JCS {v, typ, gid, mid, iat, from (the sender's current DID), …}, sig the
// sender's detached signature over it (SPEC §3), so whoever carried a copy, each member checks who said
// what. Handled here, in code, by whichever process reads the inbox (CLI inbox, MCP, page, watch);
// never by the model, which sees only the text, labelled with group, sender, role, tier and "not your
// operator".
//
//   typ msg     any member  {text, re?, mentions?}   one copy per member the sender is paired with;
//                           the rest through the creator: one more copy to it with fwd (their DIDs)
//                           and the sender's chain, which the creator re-sends as is (never re-signed)
//   typ roster  the creator {group}: the whole group, ver + 1 (create, add, remove, rename, brake)
//   typ leave   a member    {}: to the creator, which answers with a roster without it; from the
//                           creator to all: the group is frozen (no roster change, no forwarding)
//
// Checks, by name: group_message (shape), group_text (name, text), group_sig (the inner signature, or
// a DID that is not the envelope's), group_forged (a roster not from the group's creator), group_member
// (a sender, a member named, or this agent not in the group), group_unknown (no such group here),
// group_stale (iat outside its window), group_quiet (the brake), group_limit (groups or members over
// the tier's), group_creator (a change by a member that is not the creator), group_pending (join first),
// group_name (a name two groups share). A message from a member this roster does not know yet (or for
// a group whose roster has not come) waits a day for its roster (orphans), then is refused by name.
//
// Joining (design/groups.md §3): a roster from a creator at own tier is taken at once; from friend it
// waits for this identity's operator (a notice, once; join or leave); from quiet it is ignored. In a
// group whose creator is not ours, a roster that adds a member who is not this agent's contact is a
// notice too. A sender who is not a contact counts as friend, never own; text from a member that is
// not this agent's operator is labelled so: data, never instructions.
//
// The loop brake, the creator's setting carried in the roster: brake n (default BRAKE) refuses an
// agent's message (send: group_quiet; received: dropped, group_quiet) after n agent messages in a row
// with no human message between; brake "off" lets agents run. Every member counts what it saw.
//
// Limits (design/groups.md §4): groups made by this identity (member or frozen: the relay's `groups`
// claim) and members a group (the creator included), checked at create and add (limitsFor). The
// numbers: the caller's tier (LIMITS), else what the relay told this agent's last login (carrier.groupTier,
// relay/allowance.mjs "tier"), else Pro when the carrier keeps 90 days (SIGELO_RELAY_RETENTION_DAYS, a
// Pro reader's), else free.
//
//   create({ carrier, file, name, members, humans, brake, role, selfName, tier, local }) → { group, sent }
//   add / remove({ …, group, members[, humans] }), rename({ …, group, name }), setBrake({ …, group, brake }),
//   setRole({ …, group, member, role }), share({ …, group, member }) (the roster again, same ver, to one member)
//   leave({ carrier, file, group, local }), join({ carrier, file, group }) (a pending invitation)
//   send({ carrier, file, group, text, re, mentions, local }) → { gid, mid, copies, via_creator, unreached }
//   handle({ carrier, file, batch, local, tiers }) → { batch: its messages plus the group messages,
//          notices, joined, removed, refused, ignored, forwarded, filed (new for the inbox), copies };
//          run before an inbox returns (tiers [] by a watcher: everything filed, nothing taken)
//   list({ carrier, file }) → [the groups, with status and members]; history({ file, group, now }) → the chat
//   unread({ carrier, file, pick }) → the items waiting for the inbox; pick(item) true: taken (watch's hook)
// copies: each roster, message or forward queued with local (one session sends them all: sync(), or
// the watcher when local); {to, name, status: sent | queued | refused, check?}. offline: why sync failed.
//
// The file, 0600, beside the identity (x.json → x.groups.json), under its own lock:
//   { v, groups: { gid: { group, status: member|pending|frozen|left|removed, run, seen: {mid: iat},
//     history: [items], held: [items while pending], at } }, unread: [items], orphans: [{m, until, check}] }
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { canonicalize, did as didOf, verify, verifySig } from 'sigelo';
import { GROUP_LABEL, GROUP_SEND } from './carrier.mjs';
import { MsgError, checkNow, fail, signAs } from './kdf.mjs';
import { platform as nodePlatform } from './platform-node.mjs';

export const GROUP_V = 'sigelo-group/1', FILE_V = 'sigelo-groups/1';
export { GROUP_LABEL };
export const TYPS = ['msg', 'roster', 'leave'], ROLES = ['human', 'agent'], STATUSES = ['member', 'pending', 'frozen', 'left', 'removed'];
export const LIMITS = Object.freeze({ free: Object.freeze({ groups: 3, members: 8 }), pro: Object.freeze({ groups: 50, members: 64 }) });
export const BRAKE = 20, BRAKE_MAX = 10000, NAME_MAX = 40, MEMBER_NAME_MAX = 64, TEXT_MAX = 8000;
export const DAY = 86400, SKEW = 300, OLDEST = 91 * DAY, ORPHAN_TTL = DAY;
const SEEN_MAX = 4096, HISTORY_MAX = 500, UNREAD_MAX = 1000, HELD_MAX = 64, ORPHANS_MAX = 64, CHAIN_MAX = 64;
const OPERATOR_CTX = 'sigelo-relay/operator', NOT_OPERATOR = 'not your operator';
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;
const GID = /^[0-9a-f]{32}$/, MID = /^[0-9a-f]{16}$/, DID = /^did:sigelo:z[1-9A-HJ-NP-Za-km-z]{20,60}$/;
const LIVE = ['member', 'frozen'];

const isObject = (x) => typeof x === 'object' && x !== null && !Array.isArray(x);
const isTime = (x) => Number.isSafeInteger(x) && x >= 0;
const keysAre = (x, need, may = []) => need.every((k) => Object.hasOwn(x, k)) && Object.keys(x).every((k) => need.includes(k) || may.includes(k));
export const isGroup = (m) => m?.label === GROUP_LABEL;
export const newGid = (rng = randomBytes) => bytesToHex(rng(16));
export const newMid = (rng = randomBytes) => bytesToHex(rng(8));
/** The groups file beside an identity file: x.json → x.groups.json. */
export const groupsPath = (identityFile) => identityFile.replace(/\.json$/, '') + '.groups.json';

/** A group's name: 1 to NAME_MAX characters, trimmed, no control or bidi characters (refused, not stripped). */
export function checkName(n, max = NAME_MAX, what = 'a group name') {
  if (typeof n !== 'string' || n.trim() === '' || [...n.trim()].length > max || CONTROL.test(n)) fail('group_text', `${what} is 1 to ${max} characters, no control or bidi characters`);
  return n.trim();
}
/** The brake: "off", or a whole number of agent messages in a row, 1 to BRAKE_MAX. */
export function checkBrake(b) {
  if (b === 'off') return b;
  const n = typeof b === 'string' && /^\d+$/.test(b) ? Number(b) : b;
  if (!Number.isSafeInteger(n) || n < 1 || n > BRAKE_MAX) fail('group_message', `brake: "off" or 1 to ${BRAKE_MAX} agent messages in a row`);
  return n;
}
/** A message's text: 1 to TEXT_MAX characters. Shown escaped (the CLI's safeJson), never stripped. */
export function checkText(t) {
  if (typeof t !== 'string' || t.trim() === '' || [...t].length > TEXT_MAX) fail('group_text', `a message is 1 to ${TEXT_MAX} characters`);
  return t;
}

/** A roster: {gid, name, creator, members: [{did, current, name, role}], ver, brake}, the creator a member. */
export function checkRoster(g) {
  const bad = (why) => fail('group_message', `not a ${GROUP_V} roster: ${why}`);
  if (!isObject(g) || !keysAre(g, ['gid', 'name', 'creator', 'members', 'ver', 'brake'])) bad('{gid, name, creator, members, ver, brake}');
  if (typeof g.gid !== 'string' || !GID.test(g.gid)) bad('gid: 16 bytes, hex');
  checkName(g.name);
  if (typeof g.creator !== 'string' || !DID.test(g.creator)) bad('creator: a did:sigelo');
  if (!Number.isSafeInteger(g.ver) || g.ver < 1) bad('ver: a whole number from 1');
  checkBrake(g.brake);
  if (!Array.isArray(g.members) || g.members.length < 1 || g.members.length > LIMITS.pro.members) bad(`members: 1 to ${LIMITS.pro.members}`);
  const seen = new Set();
  for (const m of g.members) {
    if (!isObject(m) || !keysAre(m, ['did', 'current', 'name', 'role'])) bad('a member is {did, current, name, role}');
    if (typeof m.did !== 'string' || !DID.test(m.did) || typeof m.current !== 'string' || !DID.test(m.current)) bad('a member\'s did and current: did:sigelo');
    if (!ROLES.includes(m.role)) bad('role: human or agent');
    checkName(m.name, MEMBER_NAME_MAX, 'a member\'s name');
    if (seen.has(m.did)) bad(`${m.did} twice`);
    seen.add(m.did);
  }
  if (!seen.has(g.creator)) bad('the creator is not a member');
  return g;
}
/** A body: {v, typ, gid, mid, iat, from, …} as TYPS says. */
export function checkBody(b) {
  const bad = (why) => fail('group_message', `not a ${GROUP_V} message: ${why}`);
  if (!isObject(b) || b.v !== GROUP_V || !TYPS.includes(b.typ)) bad('v and typ');
  const more = { msg: [['text'], ['re', 'mentions']], roster: [['group'], []], leave: [[], []] }[b.typ];
  if (!keysAre(b, ['v', 'typ', 'gid', 'mid', 'iat', 'from', ...more[0]], more[1])) bad(`a ${b.typ} is {v, typ, gid, mid, iat, from${more[0].map((k) => `, ${k}`).join('')}${more[1].map((k) => `, ${k}?`).join('')}}`);
  if (typeof b.gid !== 'string' || !GID.test(b.gid)) bad('gid: 16 bytes, hex');
  if (typeof b.mid !== 'string' || !MID.test(b.mid)) bad('mid: 8 bytes, hex');
  if (!isTime(b.iat)) bad('iat: unix seconds');
  if (typeof b.from !== 'string' || !DID.test(b.from)) bad('from: a did:sigelo');
  if (b.typ === 'msg') {
    checkText(b.text);
    if (Object.hasOwn(b, 're') && (typeof b.re !== 'string' || !MID.test(b.re))) bad('re: a mid');
    if (Object.hasOwn(b, 'mentions') && (!Array.isArray(b.mentions) || b.mentions.length > LIMITS.pro.members || b.mentions.some((d) => typeof d !== 'string' || !DID.test(d)) || new Set(b.mentions).size !== b.mentions.length)) bad('mentions: distinct DIDs');
  }
  if (b.typ === 'roster' && checkRoster(b.group).gid !== b.gid) bad('the roster names another gid');
  return b;
}
/** A message's content: {body, sig}, a msg to the creator with fwd and the sender's chain {genesis, rotations}. */
export function checkContent(x) {
  const bad = (why) => fail('group_message', `not a ${GROUP_V} message: ${why}`);
  if (!isObject(x) || !keysAre(x, ['body', 'sig'], ['chain', 'fwd'])) bad('{body, sig, chain?, fwd?}');
  if (typeof x.sig !== 'string' || x.sig.length > 200) bad('sig: a multibase signature');
  checkBody(x.body);
  if (x.body.typ !== 'msg' && (x.chain !== undefined || x.fwd !== undefined)) bad('only a msg carries chain or fwd');
  if (x.chain !== undefined && (!isObject(x.chain) || !keysAre(x.chain, ['genesis', 'rotations']) || !Array.isArray(x.chain.rotations) || x.chain.rotations.length > CHAIN_MAX)) bad(`chain: {genesis, rotations} (at most ${CHAIN_MAX})`);
  if (x.fwd !== undefined && (!Array.isArray(x.fwd) || x.fwd.length < 1 || x.fwd.length > LIMITS.pro.members || x.fwd.some((d) => typeof d !== 'string' || !DID.test(d)) || x.chain === undefined)) bad('fwd: DIDs, with the sender\'s chain');
  return x;
}

// ---------------------------------------------------------------- the file

const platformOf = (carrier) => carrier?.platform ?? nodePlatform;
const textOf = (b) => new TextDecoder('utf-8', { ignoreBOM: true }).decode(b);
const writeJson = (files, path, value) => files.write(path, new TextEncoder().encode(JSON.stringify(value, null, 2)));
/** Load, purge, change (fn), save: under the file's lock. → fn's result. */
export function state(file, now, fn = () => undefined, platform = nodePlatform) {
  checkNow(now);
  const { files } = platform;
  return platform.transact(file, () => {
    let s = { v: FILE_V, groups: {}, unread: [], orphans: [] };
    const raw = files.read(file);
    if (raw !== null) {
      try { s = JSON.parse(textOf(raw)); } catch (e) { fail('group_file', `${file} does not parse (${e.message}): move it away to start without groups`); }
      if (s?.v !== FILE_V || !isObject(s.groups) || !Array.isArray(s.unread) || !Array.isArray(s.orphans)) fail('group_file', `${file} is not a ${FILE_V} file`);
    }
    const before = canonicalize(s);
    for (const g of Object.values(s.groups)) {
      const old = Object.entries(g.seen).filter(([, t]) => t + OLDEST < now);
      for (const [k] of old) delete g.seen[k];
      const keys = Object.keys(g.seen);
      if (keys.length > SEEN_MAX) for (const [k] of Object.entries(g.seen).sort((a, b) => a[1] - b[1]).slice(0, keys.length - SEEN_MAX)) delete g.seen[k];
    }
    const out = fn(s);
    if (canonicalize(s) !== before) writeJson(files, file, s);
    return out;
  }, 'sigelo');
}
const fresh = (group, status, now) => ({ group, status, run: 0, seen: {}, history: [], held: [], at: now });
const push = (list, item, max) => { list.push(item); if (list.length > max) list.splice(0, list.length - max); };
/** A group of the file by gid or name (one not left or removed: a name two share is group_name). */
function pick(s, group) {
  if (typeof group !== 'string' || group === '') fail('group_unknown', 'name a group, by name or gid');
  if (s.groups[group]) return s.groups[group];
  const named = Object.values(s.groups).filter((g) => g.group.name === group.trim() && !['left', 'removed'].includes(g.status));
  if (named.length > 1) fail('group_name', `${named.length} groups are called ${JSON.stringify(group)}: use the gid`);
  return named[0] ?? fail('group_unknown', `no group ${JSON.stringify(group)} here (sigelo-agent group list)`);
}

// ---------------------------------------------------------------- the carrier's side

const nowOf = (carrier) => checkNow(carrier.clock());
const readStore = (carrier) => { const raw = platformOf(carrier).files.read(carrier.storePath); return raw === null ? { contacts: {} } : JSON.parse(textOf(raw)); };
// This agent: its original and current DID, its chain as a bundle carries it, its operators (as
// link.mjs reads them), and its signer.
function me(carrier, now) {
  const id = carrier.identity(), { bundle } = id;
  const r = verify({ ...bundle, bindings: [] }, now), operators = new Set();
  for (const [iss, bodies] of Object.entries(r.attestations ?? {})) if (!r.chain.includes(iss) && bodies.some((b) => b.ctx === OPERATOR_CTX)) operators.add(iss);
  return { original: r.chain[0], current: r.did, chain: r.chain, operators, own: { genesis: bundle.genesis, rotations: bundle.rotations }, sign: (body) => signAs(id, body) };
}
// The contacts, one read: original DID → {did, name, tier, ours, chain, current_did, key, live}.
function contactsOf(carrier) {
  const keys = readStore(carrier).contacts, view = new Map();
  for (const c of carrier.contacts().contacts) view.set(c.did, { ...c, key: keys[c.did]?.current_key ?? null, live: !c.revoked && c.pair !== null });
  return view;
}
// A group whose creator is not this agent's own (not ours by key, nor filed own, nor its operator):
// its agent answers only when mentioned (design/groups.md §7), and a stranger added is a notice.
const foreignOf = (creator, mine, view) => creator !== mine.original && !mine.operators.has(creator) && !view.get(creator)?.ours && view.get(creator)?.tier !== 'own';
const holding = (view, did) => [...view.values()].find((c) => c.live && c.chain.includes(did)) ?? null;
/** A live contact by name or any DID of its chain; else not_contact. */
function contactFor(view, who) {
  if (typeof who !== 'string' || who === '') fail('not_contact', 'name a contact, by name or DID');
  const byDid = who.startsWith('did:') ? holding(view, who) : null;
  if (byDid) return byDid;
  const named = [...view.values()].filter((c) => c.live && c.name === who);
  if (named.length > 1) fail('name', `${named.length} contacts are called ${JSON.stringify(who)}: use the DID`);
  return named[0] ?? fail('not_contact', `${JSON.stringify(who)} is not a contact`);
}
/** The tier: what the relay told this agent's last login (carrier.groupTier), else Pro when the carrier keeps 90 days (a Pro reader), else free. */
export const tierOf = (carrier) => carrier?.groupTier?.tier ?? ((carrier?.retentionDays ?? 0) >= 90 ? 'pro' : 'free');
export function limitsOf(tier) { return LIMITS[tier] ?? fail('group_limit', `tier: ${Object.keys(LIMITS).join(' or ')}`); }
/** The limits a verb counts against: the caller's tier (LIMITS), else the relay's numbers (its groups claim for a pool,
 *  members within what a roster holds), else tierOf's LIMITS. → { lim: {groups, members}, tier }. */
export function limitsFor(carrier, tier) {
  if (tier !== undefined && tier !== null) return { lim: limitsOf(tier), tier };
  const told = carrier?.groupTier;
  if (told) return { lim: { groups: told.groups.max, members: Math.min(told.groups.members, LIMITS.pro.members) }, tier: told.tier };
  const t = tierOf(carrier);
  return { lim: limitsOf(t), tier: t };
}

// Every copy queued (local), then one session for all (sync), unless local: a watcher sends them.
async function deliver(carrier, copies, local) {
  const out = [];
  for (const { to, content } of copies) {
    try { const r = await carrier.send(to, content, { label: GROUP_LABEL, internal: GROUP_SEND, local: true }); out.push({ to, name: r.name, status: 'queued' }); } catch (e) {
      if (!(e instanceof MsgError)) throw e;
      out.push({ to, status: 'refused', check: e.check, detail: e.message });
    }
  }
  let offline = null;
  if (!local && out.some((x) => x.status === 'queued')) {
    try { await carrier.sync(); } catch (e) { offline = e.message; }
    const q = new Map(carrier.contacts().contacts.map((c) => [c.did, c.queued]));
    for (const x of out) if (x.status === 'queued' && q.get(x.to) === 0) x.status = 'sent';
  }
  return { copies: out, ...(offline !== null && { offline }) };
}
const signed = (mine, body) => ({ body, sig: mine.sign(body) });
const rosterCopies = (mine, R, now, to) => {
  const c = signed(mine, { v: GROUP_V, typ: 'roster', gid: R.gid, mid: newMid(), iat: now, from: mine.current, group: R });
  return to.filter((d) => d !== mine.original).map((d) => ({ to: d, content: c }));
};
const summary = (g, mine, view) => ({
  gid: g.group.gid, name: g.group.name, status: g.status, ver: g.group.ver, brake: g.group.brake, creator: g.group.creator,
  creator_name: g.group.creator === mine.original ? null : view.get(g.group.creator)?.name ?? null, mine: g.group.creator === mine.original,
  foreign: foreignOf(g.group.creator, mine, view), run: g.run,
  members: g.group.members.map((m) => ({ did: m.did, name: m.did === mine.original ? m.name : view.get(m.did)?.name ?? m.name, role: m.role, me: m.did === mine.original, contact: m.did !== mine.original && Boolean(holding(view, m.did)) })),
});

// ---------------------------------------------------------------- the creator's verbs

/** Make a group of live contacts (names or DIDs) and send each the roster. */
export async function create({ carrier, file, name, members, humans = [], brake = BRAKE, role, selfName = 'creator', tier: given, local = false }) {
  const now = nowOf(carrier), mine = me(carrier, now), view = contactsOf(carrier), { lim, tier } = limitsFor(carrier, given);
  const n = checkName(name), b = checkBrake(brake);
  if (!Array.isArray(members) || members.length === 0) fail('group_members', 'a group needs at least one member besides you');
  if (role !== undefined && !ROLES.includes(role)) fail('group_message', 'role: human or agent');
  const picked = [...new Map(members.map((w) => contactFor(view, w)).map((c) => [c.did, c])).values()];
  const hum = new Set(humans.map((w) => contactFor(view, w).did));
  if (picked.length + 1 > lim.members) fail('group_limit', `at most ${lim.members} members a group, you included (${tier} tier); ${picked.length + 1} asked`);
  const R = checkRoster({ gid: newGid(), name: n, creator: mine.original, ver: 1, brake: b, members: [
    { did: mine.original, current: mine.current, name: checkName(selfName, MEMBER_NAME_MAX, 'your name'), role: role ?? (mine.operators.size > 0 ? 'agent' : 'human') },
    ...picked.map((c) => ({ did: c.did, current: c.current_did, name: c.name, role: hum.has(c.did) ? 'human' : 'agent' }))] });
  const g = state(file, now, (s) => {
    const made = Object.values(s.groups).filter((x) => x.group.creator === mine.original && LIVE.includes(x.status)).length;
    if (made >= lim.groups) fail('group_limit', `at most ${lim.groups} groups made by you (${tier} tier): leave one first`);
    s.groups[R.gid] = fresh(R, 'member', now);
    return s.groups[R.gid];
  }, platformOf(carrier));
  const sent = await deliver(carrier, rosterCopies(mine, R, now, R.members.map((m) => m.did)), local);
  return { group: summary(g, mine, view), ...sent };
}

// A change by the creator: fn(R) edits a copy of the roster; ver + 1; the roster to every member and
// to `also` (those removed, so they know).
async function change({ carrier, file, group, local = false }, fn) {
  const now = nowOf(carrier), mine = me(carrier, now), view = contactsOf(carrier);
  const { g, also } = state(file, now, (s) => {
    const g = pick(s, group);
    if (g.group.creator !== mine.original) fail('group_creator', `${g.group.name} is ${view.get(g.group.creator)?.name ?? g.group.creator}'s: only its creator changes it`);
    if (g.status !== 'member') fail('group_member', `${g.group.name}: you ${g.status === 'left' ? 'left it' : 'are not in it'}`);
    const R = structuredClone(g.group), also = fn(R, view, mine) ?? [];
    R.ver = g.group.ver + 1;
    g.group = checkRoster(R);
    return { g, also };
  }, platformOf(carrier));
  const sent = await deliver(carrier, rosterCopies(mine, g.group, now, [...g.group.members.map((m) => m.did), ...also]), local);
  return { group: summary(g, mine, view), ...sent };
}
/** Add live contacts to a group of yours (humans: those of them with role human). */
export function add({ carrier, file, group, members, humans = [], tier: given, local }) {
  const { lim, tier } = limitsFor(carrier, given);
  return change({ carrier, file, group, local }, (R, view) => {
    if (!Array.isArray(members) || members.length === 0) fail('group_members', 'name a contact to add');
    const hum = new Set(humans.map((w) => contactFor(view, w).did));
    for (const c of members.map((w) => contactFor(view, w))) {
      if (R.members.some((m) => m.did === c.did)) fail('group_member', `${c.name} is in ${R.name} already`);
      R.members.push({ did: c.did, current: c.current_did, name: c.name, role: hum.has(c.did) ? 'human' : 'agent' });
    }
    if (R.members.length > lim.members) fail('group_limit', `at most ${lim.members} members a group, you included (${tier} tier)`);
  });
}
/** Remove members (names, DIDs or their roster names) from a group of yours; each is told by the roster. */
export function remove({ carrier, file, group, members, local }) {
  return change({ carrier, file, group, local }, (R, view, mine) => {
    if (!Array.isArray(members) || members.length === 0) fail('group_members', 'name a member to remove');
    const gone = members.map((w) => rosterMember(R, view, w));
    if (gone.some((m) => m.did === mine.original)) fail('group_member', 'you made it: leave it instead');
    R.members = R.members.filter((m) => !gone.includes(m));
    return gone.map((m) => m.did);
  });
}
/** Rename a group of yours. */
export const rename = ({ carrier, file, group, name, local }) => change({ carrier, file, group, local }, (R) => { R.name = checkName(name); });
/** The loop brake of a group of yours: "off" or n. */
export const setBrake = ({ carrier, file, group, brake, local }) => change({ carrier, file, group, local }, (R) => { R.brake = checkBrake(brake); });
/** A member's role in a group of yours (human or agent: the brake counts agents), by contact name, DID or roster name. */
export const setRole = ({ carrier, file, group, member, role, local }) => change({ carrier, file, group, local }, (R, view) => {
  if (!ROLES.includes(role)) fail('group_message', 'role: human or agent');
  rosterMember(R, view, member).role = role;
});
// A member of roster R by contact name, any DID of its chain, or its roster name; else group_member.
function rosterMember(R, view, w) {
  const c = typeof w === 'string' && w !== '' ? (w.startsWith('did:') ? holding(view, w) : [...view.values()].find((x) => x.live && x.name === w)) : null;
  return R.members.find((x) => x.did === c?.did || x.did === w || x.current === w) ?? R.members.filter((x) => x.name === w).at(0) ?? fail('group_member', `${JSON.stringify(w)} is not in ${R.name}`);
}
/** Share: the roster as it is (same ver) again to one member of a group of yours: a new device, a lost copy. */
export async function share({ carrier, file, group, member, local = false }) {
  const now = nowOf(carrier), mine = me(carrier, now), view = contactsOf(carrier);
  const { g, to } = state(file, now, (s) => {
    const g = pick(s, group);
    if (g.group.creator !== mine.original) fail('group_creator', `${g.group.name} is ${view.get(g.group.creator)?.name ?? g.group.creator}'s: only its creator sends its roster`);
    if (g.status !== 'member') fail('group_member', `${g.group.name}: you ${g.status === 'left' ? 'left it' : 'are not in it'}`);
    const m = rosterMember(g.group, view, member);
    if (m.did === mine.original) fail('group_member', 'that is you');
    return { g, to: holding(view, m.did)?.did ?? fail('not_contact', `${m.name} is not a live contact here`) };
  }, platformOf(carrier));
  const sent = await deliver(carrier, rosterCopies(mine, g.group, now, [to]), local);
  return { group: summary(g, mine, view), ...sent };
}

// ---------------------------------------------------------------- every member's verbs

/** Leave: pending, nothing is said; a member tells the creator; the creator tells all (frozen there). */
export async function leave({ carrier, file, group, local = false }) {
  const now = nowOf(carrier), mine = me(carrier, now), view = contactsOf(carrier);
  const { g, was } = state(file, now, (s) => {
    const g = pick(s, group), was = g.status;
    if (!['member', 'frozen', 'pending'].includes(was)) fail('group_member', `${g.group.name}: you ${was === 'left' ? 'left it already' : 'are not in it'}`);
    g.status = 'left'; g.held = [];
    return { g, was };
  }, platformOf(carrier));
  const R = g.group, to = was === 'pending' ? [] : R.creator === mine.original ? R.members.map((m) => m.did) : [R.creator];
  const c = signed(mine, { v: GROUP_V, typ: 'leave', gid: R.gid, mid: newMid(), iat: now, from: mine.current });
  const sent = await deliver(carrier, to.filter((d) => d !== mine.original && holding(view, d)).map((d) => ({ to: holding(view, d).did, content: c })), local);
  return { group: summary(g, mine, view), told: was !== 'pending', ...sent };
}
/** Join a group a friend made (pending): its held messages reach the next inbox. */
export function join({ carrier, file, group }) {
  const now = nowOf(carrier), mine = me(carrier, now), view = contactsOf(carrier);
  return state(file, now, (s) => {
    const g = pick(s, group);
    if (g.status !== 'pending') fail('group_member', `${g.group.name} is ${g.status}, not an invitation waiting`);
    g.status = 'member';
    for (const i of g.held) { push(s.unread, i, UNREAD_MAX); push(g.history, i, HISTORY_MAX); }
    g.held = [];
    return { group: summary(g, mine, view) };
  }, platformOf(carrier));
}

// @name tokens of the text that name a member (its roster name, or this agent's name for it).
function mentionsIn(text, R, view) {
  const names = new Map();
  for (const m of R.members) for (const n of [m.name, view.get(m.did)?.name]) if (n) names.set(n.toLowerCase(), m.did);
  const out = [];
  for (const [, n] of text.matchAll(/@([^\s@,;:!?()<>[\]{}"']+)/gu)) {
    const d = names.get(n.toLowerCase()) ?? names.get(n.replace(/[.]+$/, '').toLowerCase());
    if (d && !out.includes(d)) out.push(d);
  }
  return out;
}

/** A message to a group: one copy per member paired with, the rest through the creator. */
export async function send({ carrier, file, group, text, re, mentions = [], local = false }) {
  const now = nowOf(carrier), mine = me(carrier, now), view = contactsOf(carrier);
  const t = checkText(text);
  if (re !== undefined && (typeof re !== 'string' || !MID.test(re))) fail('group_message', 're: a message id (mid, 16 hex)');
  const { R, body, frozen } = state(file, now, (s) => {
    const g = pick(s, group), R = g.group;
    if (g.status === 'pending') fail('group_pending', `${R.name} waits for your operator: sigelo-agent group join ${R.gid}`);
    if (!LIVE.includes(g.status)) fail('group_member', `${R.name}: you ${g.status === 'left' ? 'left it' : 'were removed'}`);
    const self = R.members.find((m) => m.did === mine.original) ?? fail('group_member', `you are not in ${R.name}`);
    if (self.role === 'agent' && R.brake !== 'off' && g.run >= R.brake) fail('group_quiet', `${g.run} agent messages in a row in ${R.name} with no human between (brake ${R.brake}): wait until a human writes`);
    const named = mentions.map((w) => (R.members.find((m) => m.did === w || m.name === w || view.get(m.did)?.name === w) ?? fail('group_member', `${JSON.stringify(w)} is not in ${R.name}`)).did);
    const all = [...new Set([...named, ...mentionsIn(t, R, view)])];
    const body = { v: GROUP_V, typ: 'msg', gid: R.gid, mid: newMid(), iat: now, from: mine.current, text: t, ...(re !== undefined && { re }), ...(all.length > 0 && { mentions: all }) };
    g.seen[body.mid] = now;
    g.run = self.role === 'human' ? 0 : g.run + 1;
    push(g.history, { mid: body.mid, ...(re !== undefined && { re }), from: mine.original, name: self.name, role: self.role, content: t, ...(all.length > 0 && { mentions: all }), iat: now, received: now, mine: true }, HISTORY_MAX);
    return { R, body, frozen: g.status === 'frozen' };
  }, platformOf(carrier));
  const c = signed(mine, body), direct = [], fwd = [];
  for (const m of R.members) {
    if (m.did === mine.original) continue;
    const k = holding(view, m.did);
    (k ? direct : fwd).push(k ? k.did : m.did);
  }
  const creator = holding(view, R.creator);
  const via = fwd.length > 0 && creator && !frozen && R.creator !== mine.original ? fwd : [];
  // Not paired and no creator to carry it (this agent made the group, or the creator left: frozen).
  const unreached = fwd.filter((d) => !via.includes(d));
  // The creator's copy names the rest (fwd) and carries this agent's chain, to check it by.
  const copies = direct.map((d) => ({ to: d, content: d === creator?.did && via.length > 0 ? { ...c, chain: mine.own, fwd: via } : c }));
  const sent = await deliver(carrier, copies, local);
  const nameOf = (d) => view.get(d)?.name ?? R.members.find((m) => m.did === d)?.name ?? d;
  return { gid: R.gid, name: R.name, mid: body.mid, ...sent, via_creator: via.map((d) => ({ did: d, name: nameOf(d) })), unreached: unreached.map((d) => ({ did: d, name: nameOf(d) })) };
}

// ---------------------------------------------------------------- the inbox side

/**
 * Every group message the carrier kept (takeGroups; and any in batch), checked, deduplicated and
 * filed; forwards and roster answers sent (queued with local). → batch with the group messages that
 * reached this agent appended (only those of `tiers` when given; the rest wait in the file), plus what
 * was done. Run by inbox, watch, the page and the MCP server before they return messages.
 */
export async function handle({ carrier, file, batch = null, local = false, tiers }) {
  const now = nowOf(carrier), mine = me(carrier, now), view = contactsOf(carrier);
  const out = { notices: [], joined: [], removed: [], refused: [], ignored: 0, forwarded: 0, filed: 0 };
  const raw = [...carrier.takeGroups(), ...(batch?.messages.filter(isGroup) ?? [])];
  const ctx = { now, mine, view, out, copies: [] };
  const items = state(file, now, (s) => {
    const all = [...s.orphans.filter((o) => o.until > now).map((o) => o.m), ...raw];
    for (const o of s.orphans) if (!(o.until > now)) out.refused.push({ check: o.check, detail: `waited a day for a roster that names its sender: ${o.check}`, from: o.m.from });
    s.orphans = [];
    // Rosters first: a message that came before its roster finds it.
    const rank = (m) => (m.content?.body?.typ === 'roster' ? 0 : 1);
    for (const m of all.sort((a, b) => rank(a) - rank(b))) {
      try { onMessage(s, m, ctx); } catch (e) {
        if (!(e instanceof MsgError)) throw e;
        out.refused.push({ check: e.check, detail: e.message, from: m.from, gid: m.content?.body?.gid ?? null });
      }
    }
    const want = tiers === undefined || tiers === null ? null : new Set(tiers);
    const take = s.unread.filter((i) => !want || want.has(i.tier));
    s.unread = s.unread.filter((i) => !take.includes(i));
    return take;
  }, platformOf(carrier));
  const sent = ctx.copies.length > 0 ? await deliver(carrier, ctx.copies, local) : { copies: [] };
  const rest = batch ? { ...batch, messages: [...batch.messages.filter((m) => !isGroup(m)), ...items] } : { messages: items, events: [], dropped: {} };
  return { ...out, ...sent, batch: rest };
}

function orphan(s, m, check, now) {
  push(s.orphans, { m, until: (m.received ?? now) + ORPHAN_TTL, check }, ORPHANS_MAX);
}
// The member who signed body.from: by the envelope's sender (direct), else through the creator.
function onMessage(s, m, ctx) {
  const { now, mine, view, out } = ctx;
  const x = checkContent(m.content), b = x.body, from = view.get(m.from);
  if (!from?.live) { out.ignored++; return; }
  if (b.iat > now + SKEW || b.iat + OLDEST < now) fail('group_stale', `a ${b.typ} of ${new Date(b.iat * 1000).toISOString()}, outside its window`);
  if (b.typ === 'roster') return onRoster(s, m, x, ctx);
  const g = s.groups[b.gid];
  if (!g) return orphan(s, m, 'group_unknown', now);
  if (!['member', 'pending', 'frozen'].includes(g.status)) { out.ignored++; return; }
  const R = g.group;
  let sender = R.members.find((mm) => mm.did === m.from);
  let via = null;
  if (sender && b.from === m.current_did) {
    if (!from.key || !verifySig(from.key, b, x.sig)) fail('group_sig', `a ${b.typ} in ${R.name} that ${from.name}'s key did not sign`);
  } else if (m.from === R.creator && b.typ === 'msg') {
    // Carried by the creator: a member's own signature, under its own chain.
    sender = R.members.find((mm) => mm.did !== R.creator && (mm.current === b.from || holding(view, mm.did)?.current_did === b.from));
    if (!sender) return orphan(s, m, 'group_member', now);
    const k = holding(view, sender.did);
    let key = null;
    if (k && k.current_did === b.from) key = k.key;
    else if (x.chain && b.from === sender.current) {
      let r = null;
      try { r = verify({ v: 'sigelo/0', typ: 'bundle', genesis: x.chain.genesis, rotations: x.chain.rotations, bindings: [], attestations: [], issuers: [] }, now); } catch {}
      if (r && r.chain[0] === sender.did && r.did === b.from) key = [x.chain.genesis, ...x.chain.rotations.map((y) => y.next_genesis)].find((gg) => didOf(gg) === r.did)?.key ?? null;
    }
    if (!key || !verifySig(key, b, x.sig)) fail('group_sig', `a message in ${R.name} said to be ${sender.name}'s, carried by the creator, that ${sender.name}'s chain does not sign`);
    via = R.creator;
  } else if (sender) {
    fail('group_sig', `a ${b.typ} in ${R.name} from ${from.name} signed as ${b.from}, not its current DID`);
  } else return orphan(s, m, 'group_member', now);
  if (Object.hasOwn(g.seen, b.mid)) { out.ignored++; return; }
  g.seen[b.mid] = b.iat;
  if (b.typ === 'leave') return onLeave(s, g, sender, ctx);
  // The loop brake: agent messages in a row, as this member saw them.
  if (sender.role === 'agent' && R.brake !== 'off' && g.run >= R.brake) fail('group_quiet', `${g.run} agent messages in a row in ${R.name} (brake ${R.brake}): ${sender.name}'s dropped until a human writes`);
  g.run = sender.role === 'human' ? 0 : g.run + 1;
  // The creator carries a direct copy on to the members it names that the sender is not paired with.
  if (x.fwd && !via && R.creator === mine.original && sender.did !== mine.original) {
    const c = { body: b, sig: x.sig, chain: x.chain };
    for (const d of new Set(x.fwd)) {
      const k = R.members.some((mm) => mm.did === d) && d !== sender.did && d !== mine.original ? holding(view, d) : null;
      if (k) { ctx.copies.push({ to: k.did, content: c }); out.forwarded++; }
    }
  }
  const k = holding(view, sender.did), operator = sender.did === mine.original ? false : (k?.chain ?? [sender.did]).some((d) => mine.operators.has(d));
  const item = {
    label: GROUP_LABEL, group: { gid: R.gid, name: R.name }, mid: b.mid, ...(b.re !== undefined && { re: b.re }), from: sender.did, current_did: b.from,
    name: k?.name ?? sender.name, role: sender.role, tier: k?.tier === 'quiet' ? 'quiet' : k?.tier === 'own' ? 'own' : 'friend', operator, ...(!operator && { note: NOT_OPERATOR }),
    contact: Boolean(k), content: b.text, ...(b.mentions && { mentions: b.mentions }), mentioned: (b.mentions ?? []).includes(mine.original),
    foreign: foreignOf(R.creator, mine, view), ...(via && { via }), iat: b.iat, received: m.received ?? now,
  };
  if (g.status === 'pending') { push(g.held, item, HELD_MAX); return; }
  push(g.history, item, HISTORY_MAX);
  push(s.unread, item, UNREAD_MAX);
  out.filed++;
}

function onRoster(s, m, x, ctx) {
  const { now, mine, view, out } = ctx, b = x.body, R = b.group, from = view.get(m.from);
  // Only from the creator's own pairing, signed by its current key: a member cannot make a roster.
  if (m.from !== R.creator) fail('group_forged', `a roster of ${R.name} from ${from.name}, who is not the creator it names`);
  if (b.from !== m.current_did || !from.key || !verifySig(from.key, b, x.sig)) fail('group_sig', `a roster of ${R.name} that ${from.name}'s current key did not sign`);
  const g = s.groups[R.gid];
  if (g && g.group.creator !== R.creator) fail('group_forged', `a roster of ${g.group.name} from ${from.name}, not its creator`);
  if (g && R.ver <= g.group.ver) { out.ignored++; return; }
  const inIt = R.members.some((mm) => mm.did === mine.original), foreign = foreignOf(R.creator, mine, view);
  const invite = () => {
    // Joining by the creator's tier here: own at once, friend asks the operator once, quiet never.
    const tier = from.tier;
    if (tier === 'quiet') { out.ignored++; if (g) g.status = 'removed'; return; }
    const status = tier === 'own' ? 'member' : 'pending';
    s.groups[R.gid] = fresh(R, status, now);
    if (status === 'member') out.joined.push({ gid: R.gid, name: R.name, creator: from.did, creator_name: from.name });
    else out.notices.push({ type: 'group', why: 'invited', gid: R.gid, name: R.name, creator: from.did, creator_name: from.name, members: R.members.length });
  };
  if (!g) { if (inIt) invite(); else out.ignored++; return; }
  const before = new Set(g.group.members.map((mm) => mm.did));
  g.group = R;
  if (!inIt) {
    if (LIVE.includes(g.status) || g.status === 'pending') { out.removed.push({ gid: R.gid, name: R.name }); g.status = 'removed'; g.held = []; }
    return;
  }
  if (g.status === 'left' || g.status === 'removed') return invite();
  // A group not of ours: a stranger added is the operator's to know.
  const strangers = R.members.filter((mm) => !before.has(mm.did) && mm.did !== mine.original && !holding(view, mm.did));
  if (foreign && strangers.length > 0) out.notices.push({ type: 'group', why: 'stranger', gid: R.gid, name: R.name, creator: from.did, creator_name: from.name, added: strangers.map((mm) => ({ did: mm.did, name: mm.name, role: mm.role })) });
}

function onLeave(s, g, sender, ctx) {
  const { now, mine, out } = ctx, R = g.group;
  if (sender.did === R.creator) {
    // The creator gone: the roster is frozen; members paired with each other still talk.
    if (g.status === 'member') g.status = 'frozen';
    out.notices.push({ type: 'group', why: 'creator_left', gid: R.gid, name: R.name, creator: R.creator });
    return;
  }
  if (R.creator !== mine.original || g.status !== 'member') return;
  const next = checkRoster({ ...R, ver: R.ver + 1, members: R.members.filter((mm) => mm.did !== sender.did) });
  g.group = next;
  out.removed.push({ gid: R.gid, name: R.name, member: sender.did, left: true });
  ctx.copies.push(...rosterCopies(mine, next, now, [...next.members.map((mm) => mm.did), sender.did]));
}

/** The groups of this identity, with their status and members (names as this agent knows them). */
export function list({ carrier, file }) {
  const now = nowOf(carrier), mine = me(carrier, now), view = contactsOf(carrier);
  return state(file, now, (s) => Object.values(s.groups).map((g) => summary(g, mine, view)), platformOf(carrier));
}
/** The group messages waiting for the inbox (what handle filed and has not handed over): all, or those
 *  pick(item) takes, which leave the file (a watcher's hook took them). */
export function unread({ carrier, file, pick }) {
  return state(file, nowOf(carrier), (s) => {
    if (!pick) return s.unread.slice();
    const out = s.unread.filter((i) => pick(i));
    s.unread = s.unread.filter((i) => !out.includes(i));
    return out;
  }, platformOf(carrier));
}
/** A group's chat as this agent saw it, oldest first (the newest HISTORY_MAX), for a page. */
export function history({ carrier, file, group }) {
  return state(file, nowOf(carrier), (s) => pick(s, group).history.slice(), platformOf(carrier));
}
