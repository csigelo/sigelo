// SPDX-License-Identifier: MIT
// Links (link.mjs, contract sigelo-link/1): the message checks and the file first, the store's
// `link` (setLink, link_tier, revoke); then, with the relay checkout beside contact/ (SIGELO_RELAY_DIR,
// else ../relay), on a loopback relay with one clock: an operator links two of its agents (tiers,
// purpose, expiry on both sides), links two already paired (the purpose attached, the tier restored
// at the end), refuses by name (link_from, link_tier, link_stale, link_peer both ways, link_not_ours,
// link_text), unlinks; then external links (an agent and the operator's contact "hotel", not its
// own): the introduction pending at the hotel (a notice when the operator is friend or own there,
// none when quiet), never taken unasked, accepted at quiet, refused silently or told (--tell),
// lapsing with its code, auto-accepted by an allow rule at its tier, not after deny; and no link
// message reaches inbox(), the log or history().
//   node contact/test-link.mjs   → ALL PASS (n)
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { attest, keygen, verify } from 'sigelo';
import { Contacts, OPERATOR_CTX } from './store.mjs';
import { LINK_LABEL, LINK_V, NOTE_MAX, PURPOSE_MAX, allow, answer, checkMessage, checkNote, checkPurpose, deny, handle, link, linksPath, list, newId, state, unlink } from './link.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let count = 0;
const fails = [];
const ok = (cond, what, more) => { count++; if (!cond) fails.push(more === undefined ? what : `${what} (${String(more).slice(0, 600)})`); };
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.constructor.name}: ${e.message}`; } };
const failure = async (f) => { try { await f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.message}`; } };
const report = () => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
};

const CREATED = '2026-10-01T00:00:00Z', DAY = 86400;
let now = Date.parse('2026-10-21T12:00:00Z') / 1000;
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-link-test/0 ${l}`).digest());
function agent(label) {
  const k = keygen({ seed: seed(label), recovery: 'sha256:' + '0'.repeat(64), created: CREATED, nonce: seed(`${label} nonce`).slice(0, 16) });
  return { label, did: k.did, secret: k.secret, genesis: k.genesis, bundle: { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] } };
}
const operate = (op, a, days = 90, iat = now - 60) => {
  a.bundle.attestations.push(attest({ secret: op.secret, iss: op.did, sub: a.did, iat, exp: iat + days * DAY, ctx: OPERATOR_CTX, admission: 'invite', admission_by: op.did, claims: { relay: 'relay.test' } }));
  if (!a.bundle.issuers.some((g) => g === op.genesis)) a.bundle.issuers.push(op.genesis);
};
const D0 = 'did:sigelo:z' + '1'.repeat(44);

// ================================================================ the messages and the file
{
  const id = newId();
  ok(/^[0-9A-HJKMNP-TV-Z]{8}$/.test(id) && newId() !== id, `newId: 8 characters of the short-code alphabet (${id})`);
  const ask = { v: LINK_V, typ: 'ask', id: 'K7F3Q9ZP', iat: now, peer: D0, name: 'review', kind: 'own', purpose: 'review the project', ttl: DAY, tier: 'friend', expires: now + DAY };
  ok(checkOf(() => checkMessage(ask)) === 'accepted' && LINK_LABEL === 'sigelo-link/1' && LINK_V === 'sigelo-link/1', 'an ask: accepted; label and v sigelo-link/1');
  const shapes = [
    [{ ...ask, v: 'sigelo-link/0' }, 'link_message', 'another v'], [{ ...ask, typ: 'hello' }, 'link_message', 'an unknown typ'],
    [{ ...ask, id: 'k7f3q9zp' }, 'link_message', 'an id in lower case'], [{ ...ask, id: 'K7F3Q9Z' }, 'link_message', 'an id of 7'],
    [{ ...ask, iat: -1 }, 'link_message', 'iat < 0'], [{ ...ask, extra: 1 }, 'link_message', 'an extra key'],
    [(({ peer: _p, ...x }) => x)(ask), 'link_message', 'no peer'], [{ ...ask, peer: 'did:web:x' }, 'link_message', 'a peer not did:sigelo'],
    [{ ...ask, ttl: 59 }, 'link_message', 'ttl 59 s'], [{ ...ask, ttl: 7 * DAY + 1 }, 'link_message', 'ttl past 7 days'],
    [{ ...ask, tier: 'vip' }, 'link_message', 'tier vip'], [{ ...ask, kind: 'other' }, 'link_message', 'kind other'],
    [{ ...ask, relay: 'relay.test/x' }, 'link_message', 'a relay not host[:port]'], [{ ...ask, relay: 7 }, 'link_message', 'a relay not a string'],
    [{ v: LINK_V, typ: 'offer', id, iat: now, from: D0, did: D0, paired: true, purpose: 'p', ttl: DAY, note: 'n'.repeat(NOTE_MAX + 1) }, 'link_text', `a note of ${NOTE_MAX + 1}`],
    [{ v: LINK_V, typ: 'offer', id, iat: now, from: D0, did: D0, paired: true, purpose: 'p', ttl: DAY, note: 'line\nbreak' }, 'link_text', 'a note with a line break'],
    [{ v: LINK_V, typ: 'offer', id, iat: now, from: D0, did: D0, paired: true, purpose: 'p', ttl: DAY, note: null }, 'link_message', 'a note null'],
    [{ v: LINK_V, typ: 'ask', id, iat: now, peer: D0, kind: 'own', purpose: 'p', ttl: DAY, note: 'n' }, 'link_message', 'a note on an ask'],
    [{ ...ask, purpose: 'x'.repeat(PURPOSE_MAX + 1) }, 'link_text', `a purpose of ${PURPOSE_MAX + 1}`], [{ ...ask, purpose: 'pay \u202eevil' }, 'link_text', 'a purpose with a bidi control'],
    [{ ...ask, purpose: 'a\u0007b' }, 'link_text', 'a purpose with BEL'], [{ ...ask, purpose: '  ' }, 'link_text', 'a blank purpose'], [{ ...ask, name: 'x\u001b[31m' }, 'link_text', 'a name with ESC'],
    [{ v: LINK_V, typ: 'invite', id, iat: now }, 'link_message', 'an invite with neither code nor paired'], [{ v: LINK_V, typ: 'invite', id, iat: now, code: 'sgl1x', paired: true }, 'link_message', 'an invite with both'],
    [{ v: LINK_V, typ: 'invite', id, iat: now, paired: false }, 'link_message', 'paired: false'],
    [{ v: LINK_V, typ: 'status', id, iat: now, status: 'maybe' }, 'link_message', 'status maybe'], [{ v: LINK_V, typ: 'status', id, iat: now, status: 'refused', check: 'Bad Check' }, 'link_message', 'a check not a name'],
    [{ v: LINK_V, typ: 'end', id, iat: now, reason: 'bored' }, 'link_message', 'end reason bored'],
    [{ v: LINK_V, typ: 'offer', id, iat: now, from: D0, did: D0, purpose: 'p', ttl: DAY }, 'link_message', 'an offer with neither code nor paired'],
  ];
  for (const [x, want, what] of shapes) ok(checkOf(() => checkMessage(x)) === want, `checkMessage, ${what}: ${want}`, checkOf(() => checkMessage(x)));
  for (const x of [{ v: LINK_V, typ: 'invite', id, iat: now, code: 'sgl1abc' }, { v: LINK_V, typ: 'invite', id, iat: now, paired: true }, { v: LINK_V, typ: 'status', id, iat: now, status: 'refused', check: 'link_from' },
    { v: LINK_V, typ: 'end', id, iat: now, reason: 'expired' }, { v: LINK_V, typ: 'offer', id, iat: now, from: D0, did: D0, paired: true, purpose: 'p', ttl: DAY, name: 'a', tier: 'quiet' },
    { ...ask, kind: 'external', relay: 'relay.example:8883' }, { v: LINK_V, typ: 'offer', id, iat: now, from: D0, did: D0, paired: true, purpose: 'p', ttl: DAY, note: 'ü'.repeat(NOTE_MAX) }]) {
    ok(checkOf(() => checkMessage(x)) === 'accepted', `checkMessage: a well-formed ${x.typ}${x.paired ? ' (paired)' : ''}: accepted`);
  }
  ok(checkPurpose('  review the project ') === 'review the project' && checkPurpose('ü'.repeat(PURPOSE_MAX)).length === PURPOSE_MAX, 'checkPurpose: trimmed; counted in characters');
  ok(checkNote(undefined) === null && checkNote(' group rate ') === 'group rate' && checkOf(() => checkNote('a‮b')) === 'link_text' && checkOf(() => checkNote('')) === 'link_text', 'checkNote: none is null; trimmed; bidi or empty: link_text');
  const d = mkdtempSync(join(tmpdir(), 'sigelo-link-unit-')), f = linksPath(join(d, 'me.local.json'));
  try {
    ok(f === join(d, 'me.local.links.json'), 'linksPath: x.json → x.links.json');
    state(f, now, (s) => { s.seen.a = now + 10; s.pending.p = { exp: now + 10 }; s.links.L = { status: 'ended', at: now }; s.links.M = { status: 'linked', at: now };
      s.received.r = { exp: now + 10 }; s.allow.x = { tier: 'quiet', until: now + 10 }; s.allow.y = { tier: 'quiet', until: null }; });
    ok((statSync(f).mode & 0o777) === 0o600 && JSON.parse(readFileSync(f, 'utf8')).v === 'sigelo-links/1', 'the file: 0600, sigelo-links/1');
    ok(state(f, now + 11, (s) => Object.keys(s.seen).length + Object.keys(s.pending).length + Object.keys(s.received).length) === 0, 'seen ids, pending steps and introductions go at their exp');
    ok(state(f, now + 11, (s) => Object.keys(s.allow).join()) === 'y', 'an allow rule goes at its until; one without stays');
    ok(state(f, now + 31 * DAY, (s) => Object.keys(s.links).join()) === 'M', 'an ended record goes after 30 days; a linked one stays');
    writeFileSync(f, '{"v":"sigelo-enrol/1"}');
    ok(checkOf(() => state(f, now)) === 'link_file', 'another file in its place: link_file');
  } finally { rmSync(d, { recursive: true, force: true }); }
}

// ================================================================ the store's link
{
  const dir = mkdtempSync(join(tmpdir(), 'sigelo-link-store-'));
  try {
    const H = agent('store human'), F = agent('store friend'), A = agent('store agent');
    operate(H, A);
    const hs = new Contacts(join(dir, 'h.json'), H.did, { mine: () => ({ chain: [H.did], operators: [] }) });
    const key = (n) => n.toString(16).padStart(64, '0'), chainOnly = (a) => ({ ...a.bundle, attestations: [], issuers: [] });
    hs.admit(chainOnly(F), verify(chainOnly(F), now), 'friend', { relay: 'relay.test', pair_key: key(1) }, now);
    hs.admit(A.bundle, verify(A.bundle, now), 'agent', { relay: 'relay.test', pair_key: key(2) }, now);
    const l = { id: 'K7F3Q9ZP', purpose: 'p', linked_by: H.did, expires: null, tier: null };
    ok(JSON.stringify(hs.setLink('friend', l, now).link) === JSON.stringify(l), 'setLink: the record on the contact');
    ok(checkOf(() => hs.setTier('friend', 'own', now)) === 'link_tier' && hs.tiers(now).get(F.did) === 'friend', 'setTier own on a linked contact that is not ours: link_tier, unchanged');
    ok(hs.setTier('friend', 'quiet', now).tier === 'quiet', 'lowering it is allowed');
    ok(checkOf(() => hs.setLink('friend', { ...l, id: 'AAAAAAAA' }, now)) === 'link_exists', 'another link onto it: link_exists');
    hs.setLink('agent', { ...l, id: 'BBBBBBBB' }, now);
    ok(hs.setTier('agent', 'own', now).tier === 'own', 'a linked contact that is ours (the attestation) may be own');
    hs.admit(chainOnly(F), verify(chainOnly(F), now), null, { relay: 'relay.test', pair_key: key(3) }, now);
    ok(hs.load().s.contacts[F.did].link?.id === 'K7F3Q9ZP' && hs.load().s.contacts[F.did].operator_exp === undefined, 'a re-pair keeps the link, and a link writes no operator_exp (never ours)');
    hs.setLink('agent', null, now);
    hs.setLink('agent', { ...l, id: 'CCCCCCCC', prior: { tier: 'friend', tier_by: 'owner' } }, now);
    hs.setTier('agent', 'quiet', now);
    hs.setLink('agent', null, now);
    const a1 = hs.load().s.contacts[A.did];
    ok(a1.link === undefined && a1.tier === 'friend' && a1.tier_by === 'owner', 'setLink null with prior: the tier before restored');
    hs.revoke(F.did);
    ok(hs.load().s.contacts[F.did].link === undefined, 'revoke drops the link');
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs')) || !existsSync(join(RELAY_DIR, 'node_modules'))) {
  report();
  console.log(`ALL PASS (${count}): the unit part; SKIP the flow, no relay checkout with its dependencies beside contact/: set SIGELO_RELAY_DIR`);
  process.exit(0);
}

// ================================================================ on a loopback relay
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
const { Carrier, LINK_SEND, pathsFor } = await import('./carrier.mjs');
setTimeout(() => { console.log(`FAIL the run did not finish in 900 s (${count} checks so far)`); process.exit(1); }, 900000).unref();

const HOST = 'relay.test';
const dir = mkdtempSync(join(tmpdir(), 'sigelo-link-'));
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, clock: () => now, diskUsed: () => 0.1,
  log: () => {}, policy: (ctx) => relayPolicy(ctx, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 } }) });
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
const make = (a) => {
  const paths = pathsFor(join(dir, `${a.label}.local.json`));
  a.c = new Carrier({ identity: () => ({ secret: a.secret, bundle: a.bundle }), ...paths, relay: HOST, endpoints, clock: () => now, keep: true, backoff: [100, 400], retentionDays: 7 });
  a.f = linksPath(join(dir, `${a.label}.local.json`)); a.paths = paths; a.out = [];
  return a;
};
const contactOf = (a, did) => JSON.parse(readFileSync(a.paths.store, 'utf8')).contacts[did];
async function pair(ci, ca, name, back) {
  const inv = await ci.c.invite({ name });
  await ca.c.accept(inv.code, { name: back, wait: 0.3 });
  await ci.c.inbox(); await ca.c.inbox(); await ci.c.inbox();
}
// One turn: an inbox, then handle() on it, as sigelo-agent's inbox does. Results kept per agent.
const turn = async (a) => {
  now += 5;
  const b = await a.c.inbox();
  const r = await handle({ carrier: a.c, file: a.f, batch: b, wait: 0 });
  a.out.push(r);
  a.seen = [...(a.seen ?? []), ...r.batch.messages];
  return r;
};
const rounds = async (n, ...as) => { for (let i = 0; i < n; i++) for (const a of as) await turn(a); };
const refusedAt = (a, check) => a.out.some((r) => r.refused.some((x) => x.check === check));
const recOf = (h, id) => state(h.f, now, (s) => s.links[id] ?? null);
const sendLink = (from, to, content) => from.c.send(to.did, content, { label: LINK_LABEL, internal: LINK_SEND });

try {
  const H = make(agent('human')), A = make(agent('project')), B = make(agent('review')), C = make(agent('sibling')), Dd = make(agent('docs'));
  const E = make(agent('eve')), F = make(agent('friend')), G = make(agent('hotel'));
  for (const x of [A, B, C, Dd]) operate(H, x);
  for (const x of [A, B, C, Dd, F, G]) await pair(H, x, x.label, 'human');
  await pair(A, C, 'sibling', 'project');
  await pair(A, F, 'friend', 'project');
  await rounds(4, H, A, B, C, Dd, F, G);
  const ours = Object.fromEntries(H.c.contacts().contacts.map((c) => [c.name, c.ours]));
  ok(ours.project && ours.review && ours.sibling && ours.docs && !ours.friend && !ours.hotel, 'set up: the operator holds four agents ours, a friend and a hotel', JSON.stringify(ours));

  // Callers cannot send the label: only link.mjs, through the carrier's internal path.
  ok(await failure(() => A.c.send(F.did, { v: LINK_V }, { label: LINK_LABEL })) === 'body' && await failure(() => A.c.sendAll(F.did, ['x'], { label: 'sigelo-link/2' })) === 'body',
    'send and sendAll with a sigelo-link/ label from a caller: refused (body)');

  // The operator's refusals, before anything is sent.
  ok(await failure(() => link({ carrier: H.c, file: H.f, a: 'project', b: 'review', purpose: 'x', tierA: 'own' })) === 'link_tier', 'link --tier-a own: link_tier');
  ok(await failure(() => link({ carrier: H.c, file: H.f, a: 'project', b: 'review', purpose: 'x', tierB: 'own' })) === 'link_tier', 'link --tier-b own: link_tier');
  ok(await failure(() => link({ carrier: H.c, file: H.f, a: 'friend', b: 'hotel', purpose: 'x' })) === 'link_not_ours', 'neither agent ours: link_not_ours');
  ok(await failure(() => link({ carrier: H.c, file: H.f, a: 'project', b: 'hotel', purpose: 'x', tierB: 'quiet' })) === 'link_tier', 'external with --tier-b: link_tier (the hotel\'s operator decides)');
  ok(await failure(() => link({ carrier: H.c, file: H.f, a: 'project', b: 'hotel', purpose: 'x', note: 'n'.repeat(NOTE_MAX + 1) })) === 'link_text', `a note of ${NOTE_MAX + 1}: link_text`);
  ok(await failure(() => link({ carrier: H.c, file: H.f, a: 'project', b: 'hotel', purpose: 'x', relay: 'relay.test/x' })) === 'link_relay', 'a relay not host[:port]: link_relay');
  ok(await failure(() => link({ carrier: H.c, file: H.f, a: 'project', b: 'review', purpose: 'go \u202eevil' })) === 'link_text', 'a purpose with a bidi control: link_text');
  ok(await failure(() => link({ carrier: H.c, file: H.f, a: 'project', b: 'project', purpose: 'x' })) === 'link_peer', 'the same agent twice: link_peer');
  ok(await failure(() => link({ carrier: H.c, file: H.f, a: 'project', b: 'nobody', purpose: 'x' })) === 'not_contact', 'no such contact: not_contact');
  ok(await failure(() => link({ carrier: H.c, file: H.f, a: 'project', b: 'review', purpose: 'x', days: 0 })) === 'link_days', 'days 0: link_days');
  ok(!existsSync(H.f), 'and nothing was written for any of them');

  // ---- own ↔ own: project and review, tiers and purpose on both sides, 30 days.
  const L = await link({ carrier: H.c, file: H.f, a: 'project', b: 'review', purpose: 'review the project\'s pull requests', tierA: 'friend', tierB: 'quiet', days: 30 });
  ok(L.status === 'pending' && L.a === A.did && L.b === B.did && L.expires === now + 30 * DAY, `link: pending, a and b, expires in 30 days (${L.id})`);
  for (let i = 0; i < 4 && recOf(H, L.id)?.status === 'pending'; i++) await rounds(1, A, H, B, A, B, H);
  const rec = recOf(H, L.id), ab = contactOf(A, B.did), ba = contactOf(B, A.did);
  ok(rec.status === 'linked' && rec.steps.a === 'linked' && rec.steps.b === 'linked', 'the operator: linked once both said so', JSON.stringify(rec));
  ok(ab && !ab.revoked && ab.link?.id === L.id && ab.link.purpose === L.purpose && ab.link.linked_by === H.did && ab.link.expires === L.expires && ab.tier === 'friend' && ab.tier_by === 'owner',
    'project files review: link {id, purpose, linked_by, expires}, tier friend (the operator\'s --tier-a)', JSON.stringify(ab));
  ok(ba && !ba.revoked && ba.link?.id === L.id && ba.link.linked_by === H.did && ba.tier === 'quiet' && ba.tier_by === 'owner', 'review files project: the same link, tier quiet (--tier-b)', JSON.stringify(ba));
  ok(ab.operator_exp === undefined || ab.operator_exp === B.bundle.attestations[0].body.exp, 'ours stays the attestation\'s: the link wrote no operator_exp of its own');
  ok(A.out.some((r) => r.linked.some((x) => x.id === L.id && x.contact === B.did)) && H.out.some((r) => r.linked.some((x) => x.id === L.id && x.role === 'operator')), 'handle reports linked on the agent and on the operator');
  const la = list({ carrier: A.c, file: A.f }), lh = list({ carrier: H.c, file: H.f });
  ok(la.links.length === 1 && la.links[0].id === L.id && la.links[0].contact === B.did && la.links[0].purpose === L.purpose && la.links[0].tier === 'friend' && la.links[0].linked_by === H.did,
    'list on the agent: {id, contact, tier, purpose, linked_by, expires}', JSON.stringify(la));
  ok(lh.made.some((x) => x.id === L.id && x.status === 'linked' && x.tier_a === 'friend' && x.tier_b === 'quiet') && !JSON.stringify(lh).includes('sgl1'), 'list on the operator: the link made, no code', JSON.stringify(lh.made));
  ok(A.c.contacts().contacts.find((c) => c.did === B.did)?.link?.purpose === L.purpose, 'contacts() shows the purpose');

  // An end from a contact that is no party to the link: ignored.
  await sendLink(F, A, { v: LINK_V, typ: 'end', id: L.id, iat: now, reason: 'unlink' });
  await turn(A);
  ok(contactOf(A, B.did)?.link?.id === L.id && !contactOf(A, B.did).revoked && A.out.at(-1).ignored === 1, 'an end from a non-party (a friend naming the link): ignored, the link stays');

  // ---- already paired: project and sibling; the purpose attached, one day.
  const before = contactOf(A, C.did).tier;
  const P = await link({ carrier: H.c, file: H.f, a: 'project', b: 'sibling', purpose: 'share the build cache', days: 1 });
  for (let i = 0; i < 3 && recOf(H, P.id)?.status === 'pending'; i++) await rounds(1, A, H, C, H);
  const ac = contactOf(A, C.did), ca = contactOf(C, A.did);
  ok(recOf(H, P.id).status === 'linked' && ac.link?.id === P.id && ac.link.prior?.tier === before && ca.link?.id === P.id && ca.link.prior && !ac.revoked && !ca.revoked,
    'already paired: the purpose attached on both sides (prior: the tier before), linked; no new pairing', JSON.stringify([recOf(H, P.id), ac.link, ca.link]));

  // ---- link_from: an own agent that is not project's operator asks it.
  const X = await link({ carrier: C.c, file: C.f, a: 'project', b: 'human', purpose: 'sneak' });
  await rounds(1, A, C);
  ok(refusedAt(A, 'link_from') && recOf(C, X.id).status === 'refused' && recOf(C, X.id).check === 'link_from', 'an ask from a sibling (own, not its operator): link_from, told to the asker', JSON.stringify(recOf(C, X.id)));

  // ---- link_tier and link_stale: an ask crafted with tier own, then replayed, then old.
  const own = { v: LINK_V, typ: 'ask', id: newId(), iat: now, peer: Dd.did, kind: 'own', purpose: 'p', ttl: DAY, tier: 'own' };
  await sendLink(H, A, own); await turn(A);
  ok(A.out.at(-1).refused.some((x) => x.check === 'link_tier' && x.id === own.id), 'an ask with tier own: link_tier', JSON.stringify(A.out.at(-1)));
  await sendLink(H, A, own); await turn(A);
  ok(A.out.at(-1).refused.some((x) => x.check === 'link_stale' && x.id === own.id), 'the same ask again: link_stale');
  const old = { ...own, id: newId(), iat: now - 2 * DAY, tier: 'friend' };
  await sendLink(H, A, old); await turn(A);
  ok(A.out.at(-1).refused.some((x) => x.check === 'link_stale' && x.id === old.id) && !contactOf(A, Dd.did), 'an ask older than its ttl: link_stale, nothing made', JSON.stringify(A.out.at(-1)));

  // ---- link_peer at A: the code answered by someone else (eve, who saw it), not docs.
  const W = await link({ carrier: H.c, file: H.f, a: 'project', b: 'docs', purpose: 'p' });
  await turn(A);
  await H.c.inbox({ wait: 1 });
  const inv = H.c.takeLinks().find((m) => m.content.id === W.id && m.content.typ === 'invite');
  if (!inv) { report(); console.log('no invite reached the operator', JSON.stringify(A.out.at(-1))); process.exit(1); }
  ok(typeof inv?.content.code === 'string' && inv.content.code.startsWith('sgl1'), 'project answered with a long code (taken here instead of the operator)');
  await E.c.accept(inv.content.code, { name: 'project', wait: 0 });
  await rounds(1, A, H);
  const ea = contactOf(A, E.did);
  ok(refusedAt(A, 'link_peer') && ea?.revoked === true && recOf(H, W.id).status === 'refused' && recOf(H, W.id).check === 'link_peer',
    'the code answered by another DID: link_peer, that contact forgotten, the operator told', JSON.stringify([ea?.revoked, recOf(H, W.id)]));

  // ---- link_peer at the operator: project's invite carries a code naming another DID.
  const V = await link({ carrier: H.c, file: H.f, a: 'project', b: 'docs', purpose: 'p' });
  await turn(A);
  await H.c.inbox({ wait: 1 });
  H.c.takeLinks();
  const other = await E.c.invite({ name: 'x' });
  await sendLink(A, H, { v: LINK_V, typ: 'invite', id: V.id, iat: now, code: other.code });
  await turn(H); await turn(Dd);
  ok(recOf(H, V.id).status === 'refused' && recOf(H, V.id).check === 'link_peer' && refusedAt(H, 'link_peer') && !contactOf(Dd, A.did),
    'a code that does not name project: link_peer at the operator, nothing offered to docs', JSON.stringify(recOf(H, V.id)));

  // ---- project and docs, one day: then expiry forgets on both sides.
  const Z = await link({ carrier: H.c, file: H.f, a: 'project', b: 'docs', purpose: 'write the docs', days: 1 });
  for (let i = 0; i < 4 && recOf(H, Z.id)?.status === 'pending'; i++) await rounds(1, A, H, Dd, A, Dd, H);
  ok(recOf(H, Z.id).status === 'linked' && contactOf(A, Dd.did)?.link?.id === Z.id && contactOf(Dd, A.did)?.link?.id === Z.id, 'project and docs: linked', JSON.stringify(recOf(H, Z.id)));

  // ---- unlink: the operator ends project ↔ review; both forget.
  const u = await unlink({ carrier: H.c, file: H.f, id: L.id });
  await rounds(2, A, B);
  ok(u.status === 'ended' && recOf(H, L.id).status === 'ended' && contactOf(A, B.did).revoked === true && contactOf(B, A.did).revoked === true && contactOf(A, B.did).link === undefined,
    'unlink: ended at the operator; project and review forgot each other', JSON.stringify([u, contactOf(A, B.did).revoked, contactOf(B, A.did).revoked]));
  ok(A.out.some((r) => r.ended.some((x) => x.id === L.id && x.forgot)) && B.out.some((r) => r.ended.some((x) => x.id === L.id)), 'handle reports the end on both');
  ok(await failure(() => unlink({ carrier: H.c, file: H.f, id: 'ZZZZZZZZ' })) === 'link_unknown', 'unlink of no link: link_unknown');

  // ---- expiry: a day and more later, each side ends by itself.
  now += DAY + 60;
  await rounds(1, Dd, C);
  ok(contactOf(Dd, A.did).revoked === true && Dd.out.at(-1).ended.some((x) => x.id === Z.id && x.reason === 'expired'), 'expired: docs forgets project at its own next inbox');
  const c1 = contactOf(C, A.did);
  ok(!c1.revoked && c1.link === undefined && C.out.at(-1).ended.some((x) => x.id === P.id && !x.forgot), 'expired, linked onto an earlier pairing: the purpose dropped, the contact kept', JSON.stringify(c1));
  await rounds(1, A, H);
  const a1 = contactOf(A, C.did);
  ok(contactOf(A, Dd.did).revoked === true && !a1.revoked && a1.link === undefined && a1.tier === before, 'and project, at its next inbox: docs forgotten; sibling kept, its tier restored', JSON.stringify(a1));
  ok(recOf(H, Z.id).status === 'ended' && recOf(H, P.id).status === 'ended', 'the operator: both ended');

  // ================================================================ external: project ↔ hotel
  // The hotel (G) is the operator's contact, not its own: G takes no introduction unasked.
  const recvOf = (x, id) => list({ carrier: x.c, file: x.f }).received.find((r) => r.id === id);
  const noticed = (x, id) => x.out.flatMap((r) => r.received).find((r) => r.id === id);
  // Until the offer reached the hotel (the operator's record at step offer, and a hotel turn).
  const offered = async (id) => { for (let i = 0; i < 4 && recOf(H, id)?.step !== 'offer'; i++) await rounds(1, A, H); await turn(G); };
  const linkedAt = async (id) => { for (let i = 0; i < 5 && recOf(H, id)?.status === 'pending'; i++) await rounds(1, G, A, G, H); };
  const E1 = await link({ carrier: H.c, file: H.f, a: 'hotel', b: 'project', purpose: 'book rooms for the offsite', note: 'Ask for the group rate.' });
  ok(E1.kind === 'external' && E1.a === A.did && E1.b === G.did && E1.tier_a === 'friend' && E1.tier_b === null && E1.expires === now + 30 * DAY && E1.relay === HOST && E1.note === 'Ask for the group rate.' && E1.ttl === 7 * DAY,
    'external: the ours one is A, A files the hotel at friend, 30 days, the relay of the operator\'s pairing with it, the note kept, a week for the code', JSON.stringify(E1));
  await offered(E1.id);
  const n1 = noticed(G, E1.id), r1 = recvOf(G, E1.id);
  ok(n1?.notice === true && n1.from === H.did && n1.name === 'human' && n1.peer === A.did && n1.purpose === E1.purpose && n1.note === E1.note, 'the hotel: a notice (the operator is friend there) with from, purpose, note, id', JSON.stringify(G.out.at(-1)));
  ok(r1 && r1.peer === A.did && r1.peer_name === 'project' && r1.note === E1.note && r1.exp > now && !JSON.stringify(list({ carrier: G.c, file: G.f })).includes('sgl1'), 'links on the hotel: the introduction pending, without its code', JSON.stringify(r1));
  await rounds(2, G, A, H);
  ok(!contactOf(G, A.did) && !contactOf(A, G.did) && recOf(H, E1.id).status === 'pending' && recvOf(G, E1.id), 'never taken unasked: no pairing after more rounds, the operator\'s link pending');
  ok(checkOf(() => answer({ carrier: G.c, file: G.f, id: E1.id, accept: true, tier: 'own' })) === 'link_tier' && checkOf(() => answer({ carrier: G.c, file: G.f, id: 'ZZZZZZZZ', accept: true })) === 'link_unknown',
    'accept at own: link_tier; an unknown id: link_unknown');
  ok(answer({ carrier: G.c, file: G.f, id: E1.id, accept: true }).status === 'accepting', 'links accept: accepting, carried out at the next handle');
  await linkedAt(E1.id);
  const ga = contactOf(G, A.did), ag = contactOf(A, G.did);
  ok(recOf(H, E1.id).status === 'linked' && ga?.link?.id === E1.id && ga.link.linked_by === H.did && ga.link.note === E1.note && ga.link.purpose === E1.purpose && ga.tier === 'quiet' && ga.operator_exp === undefined,
    'accepted: the hotel files project at quiet (the default), with purpose and note; the operator\'s link linked', JSON.stringify([recOf(H, E1.id), ga]));
  ok(ag?.link?.id === E1.id && ag.tier === 'friend' && !A.c.contacts().contacts.find((c) => c.did === G.did).ours, 'project files the hotel at friend, not ours', JSON.stringify(ag));
  ok(checkOf(() => G.c.setTier(A.did, 'own')) === 'link_tier' && checkOf(() => A.c.setTier(G.did, 'own')) === 'link_tier', 'own refused on either linked side (link_tier)');
  ok(!recvOf(G, E1.id) && list({ carrier: G.c, file: G.f }).links.some((l) => l.id === E1.id && l.note === E1.note), 'links on the hotel: linked, nothing pending');
  await unlink({ carrier: H.c, file: H.f, id: E1.id });
  await rounds(2, A, G);
  ok(contactOf(A, G.did).revoked === true && contactOf(G, A.did).revoked === true, 'unlink: project and the hotel forget each other');

  // ---- refused, silently: the operator learns nothing; then lapse.
  const E2 = await link({ carrier: H.c, file: H.f, a: 'project', b: 'hotel', purpose: 'book rooms', ttl: 3600 });
  await offered(E2.id);
  ok(recvOf(G, E2.id) && noticed(G, E2.id)?.notice === true, 'a second introduction: pending at the hotel');
  const s2 = answer({ carrier: G.c, file: G.f, id: E2.id, accept: false });
  await rounds(2, G, H, A);
  ok(s2.status === 'refused' && s2.told === false && !recvOf(G, E2.id) && recOf(H, E2.id).status === 'pending' && recOf(H, E2.id).steps.b === null && !contactOf(G, A.did)?.link,
    'links refuse: dropped at once, nothing told: the operator still sees it pending', JSON.stringify(recOf(H, E2.id)));

  // ---- own at the hotel, not its operator: a notice too; refused with --tell.
  G.c.setTier(H.did, 'own');
  const E3 = await link({ carrier: H.c, file: H.f, a: 'project', b: 'hotel', purpose: 'book rooms' });
  await offered(E3.id);
  ok(noticed(G, E3.id)?.notice === true && recvOf(G, E3.id) && !contactOf(G, A.did)?.link, 'from an own contact that is not the hotel\'s operator: a notice, pending, never auto');
  ok(answer({ carrier: G.c, file: G.f, id: E3.id, accept: false, tell: true }).status === 'refusing', 'links refuse --tell: refusing');
  await rounds(1, G, H, A);
  ok(recOf(H, E3.id).status === 'refused' && recOf(H, E3.id).check === 'link_refused' && !recvOf(G, E3.id) && !state(A.f, now, (s) => Object.keys(s.pending).some((k) => k.endsWith(E3.id))),
    'told: the operator\'s link refused (link_refused); project told to drop its step', JSON.stringify(recOf(H, E3.id)));

  // ---- quiet at the hotel: pending, no notice; it lapses with its code (E2 too, at the operator).
  G.c.setTier(H.did, 'quiet');
  const E4 = await link({ carrier: H.c, file: H.f, a: 'project', b: 'hotel', purpose: 'book rooms', ttl: 3600 });
  await offered(E4.id);
  ok(recvOf(G, E4.id) && noticed(G, E4.id)?.notice === false, 'from a quiet contact: pending, no notice (seen in links)', JSON.stringify(G.out.at(-1).received));
  now += 3600 + 60;
  await rounds(1, G, H, A);
  ok(!recvOf(G, E4.id) && recOf(H, E4.id).status === 'refused' && recOf(H, E4.id).check === 'link_expired' && recOf(H, E2.id).check === 'link_expired' && !contactOf(G, A.did)?.link,
    'past the code\'s life: gone at the hotel; refused link_expired at the operator', JSON.stringify([recOf(H, E4.id), recOf(H, E2.id)]));

  // ---- a crafted introduction whose code names someone else: dropped, nothing told.
  const evil = await E.c.invite({ name: 'x' }), cid = newId();
  await sendLink(H, G, { v: LINK_V, typ: 'offer', id: cid, iat: now, from: A.did, did: A.did, code: evil.code, name: 'project', purpose: 'p', ttl: DAY });
  await turn(G); await turn(H);
  ok(G.out.at(-1).refused.some((x) => x.id === cid && x.check === 'link_peer' && x.silent) && !recvOf(G, cid) && H.out.at(-1).ignored === 0 && H.out.at(-1).refused.length === 0,
    'an introduction whose code does not name its agent: link_peer, kept nowhere, not told', JSON.stringify([G.out.at(-1), H.out.at(-1)]));

  // ---- allow: the operator's contact may introduce, at friend for 10 days; then deny. (The hotel
  // forgot project for good at the unlink: docs and review now.)
  const docsAt = async (id) => { for (let i = 0; i < 4 && recOf(H, id)?.step !== 'offer'; i++) await rounds(1, Dd, H); await turn(G); };
  ok(checkOf(() => allow({ carrier: G.c, file: G.f, contact: 'human', tier: 'own' })) === 'link_tier' && checkOf(() => allow({ carrier: G.c, file: G.f, contact: 'nobody' })) === 'not_contact', 'allow at own: link_tier; no such contact: not_contact');
  const al = allow({ carrier: G.c, file: G.f, contact: 'human', tier: 'friend', days: 10 });
  ok(al.contact === H.did && al.tier === 'friend' && al.until === now + 10 * DAY && list({ carrier: G.c, file: G.f }).allow.some((x) => x.contact === H.did && x.tier === 'friend'), 'links allow human --tier friend --days 10', JSON.stringify(al));
  const E5 = await link({ carrier: H.c, file: H.f, a: 'docs', b: 'hotel', purpose: 'book rooms' });
  await docsAt(E5.id);
  for (let i = 0; i < 5 && recOf(H, E5.id)?.status === 'pending'; i++) await rounds(1, G, Dd, G, H);
  ok(recOf(H, E5.id).status === 'linked' && contactOf(G, Dd.did)?.link?.id === E5.id && contactOf(G, Dd.did).tier === 'friend' && !noticed(G, E5.id) && !recvOf(G, E5.id),
    'allowed: accepted by the rule at its tier (friend), no notice, nothing pending', JSON.stringify([recOf(H, E5.id).status, contactOf(G, Dd.did)?.tier, contactOf(G, Dd.did)?.link, G.out.at(-1).refused]));
  const dn = deny({ carrier: G.c, file: G.f, contact: 'human' });
  ok(dn.had === true && list({ carrier: G.c, file: G.f }).allow.length === 0, 'links deny human: the rule gone');
  const E6 = await link({ carrier: H.c, file: H.f, a: 'review', b: 'hotel', purpose: 'book rooms' });
  for (let i = 0; i < 4 && recOf(H, E6.id)?.step !== 'offer'; i++) await rounds(1, B, H);
  await rounds(2, G, B);
  ok(recvOf(G, E6.id) && !contactOf(G, B.did), 'after deny: pending again, not taken');
  answer({ carrier: G.c, file: G.f, id: E6.id, accept: false });

  // ---- one contact cannot crowd the hotel's introductions: 8 wait, the 9th is dropped (link_full).
  const ids = Array.from({ length: 9 }, () => newId());
  for (const id of ids) await sendLink(H, G, { v: LINK_V, typ: 'offer', id, iat: now, from: H.did, did: H.did, paired: true, name: 'human', purpose: 'p', ttl: DAY });
  await turn(G);
  const full = G.out.at(-1).refused.filter((x) => x.check === 'link_full' && x.silent);
  ok(ids.filter((id) => recvOf(G, id)).length === 8 && full.length === 1 && !recvOf(G, full[0].id), '8 introductions from one contact wait; a 9th: link_full, not told',
    JSON.stringify(G.out.at(-1).refused));

  // ---- nothing of it in any inbox, log or history.
  const all = [H, A, B, C, Dd, E, F, G];
  const logs = all.map((a) => (existsSync(a.c.logPath) ? readFileSync(a.c.logPath, 'utf8') : '')).join('\n');
  ok(!logs.includes('sigelo-link') && !logs.includes('sgl1'), 'no link message (nor its code) in any inbox.log');
  ok(all.every((a) => !a.c.history().messages.some((m) => m.label === LINK_LABEL)) && all.every((a) => !(a.seen ?? []).some((m) => m.label === LINK_LABEL)), 'none in history() nor in what inbox() returned');
  ok(all.every((a) => (JSON.parse(readFileSync(a.paths.state, 'utf8')).links ?? []).length === 0), 'and none left in any state');
  for (const a of all) await a.c.stop();
} finally {
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}
report();
console.log(`ALL PASS (${count})`);
