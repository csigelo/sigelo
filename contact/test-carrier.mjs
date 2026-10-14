// SPDX-License-Identifier: MIT
// The carrier (carrier.mjs) against a loopback relay (relay/server.mjs in this process, an injected
// clock): two fixture agents pair by code while each is offline in turn, exchange messages, one goes
// offline across a week boundary and receives on return, one rotates its key mid-conversation and
// delivery continues, prekeys are replenished over the mailbox, the relay's refusals arrive by
// name, a relay restart is survived with backoff, a contact is forgotten, the MCP tools run the
// same verbs, and the relay's files and log hold no DID and no plaintext. Also: the sigelo-carrier/0
// frames against fixtures/carrier-v0.json (gen-carrier.mjs --check), and the invite handshake run
// with real X-Wing values to the fixture's K; poison frames of each kind dropped by name while the queue
// behind them flows; a delivery failing three times dropped; hostile notices (unwritable, not a
// chain, past 64 rotations, another's chain, a replay); replies that cannot reach the answerer
// undone and reported; hostile hosts (an endless answer, a greedy proof of work, proof of work
// asked again at every reconnection, redirects to a host inside, a 100 MB MQTT packet, a code
// naming an address or a local name); a 502 refuses nothing and a delivered answer outlives a refusal for good; a slow packet
// does not read as a drained queue; a thief's fork of 63 rotations loses to the owner's recovery,
// after which both sides hold the pairing key as burned (re_pair: only the notice goes, no new
// mailbox is claimed) until they pair again, and a thief holding the old key claims next week's
// mailboxes under it and gets nothing;
// a notice whose chain ends at a key its sender does not hold is refused (notice_sig); a refused
// first envelope gives its prekey back; 32 days with no bundle across heal without pairing again;
// a carrier with onEvent keeps no plaintext at rest; one code accepted twice; an epoch outlives its
// lost first envelope and a reader away longer than retention (relay-plan §11 "Epoch recovery"); an
// envelope longer than a relay takes in one packet is refused before it is queued; through a network
// that delivers packet by packet, each refusal read against its own publish, and a notice naming
// another packet id against none; an epoch begun on a key already spent (prekey_reused) heals,
// within an hour of pairing and, owed, at the first round after the hour; a rotation notice the
// relay expired unread is sent again until the contact says it holds the new DID; an invitee who
// rotates between his answer and the reply announces it first, a new contact or a re-keyed one;
// an envelope failing `from` owes its writer a bundle naming the DID held, at most hourly; under
// the relay's claim brake, this week's mailbox of every contact first, a round stopped at the
// brake, and what it refused asked again an hour later, not sooner; a full disk between the
// handshake's two files, on either side, heals at the next delivery; notices from whoever holds K:
// one refused is not checked again, past NOTICE_CHECKS an hour none is, a recovery still is.
//   node contact/test-carrier.mjs   → ALL PASS (n)
// The relay is its own AGPL package, absent from this one's export: SIGELO_RELAY_DIR, else ../relay;
// without it only the fixture part runs, and the run says SKIP for the rest.
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import fsModule, { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { syncBuiltinESMExports } from 'node:module';
import { connect as netConnect, createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { connect } from 'mqtt';
import { canonicalize, keygen, rotate, sign, verify, verifySig } from 'sigelo';
import { Carrier, INVITE_BYTES, KIND_PREKEYS, LABEL_PREKEYS, MAX_PACKET, MAX_ROTATIONS, NOTICE_CHECKS, POW_SEARCHES, TYP_NOTICE, V as CARRIER_V, limitPackets, noticeKey, pathsFor, prekeysKey, retentionOf, seal, solvePow, unseal } from './carrier.mjs';
import { MAX_ENVELOPE, header, pad } from './envelope.mjs';
import { V as STORE_V, answerId, buildAnswer, checkAnswer, checkReply, inviteKeys, makeInvite, parseInvite } from './invite.mjs';
import { isoWeek, pairId, topic } from './kdf.mjs';
import { checkPrekeys, kemDecapsulate, kemEncapsulate, kemKey } from './prekeys.mjs';
import { Contacts } from './store.mjs';
import { rng as fixtureRng } from './gen-carrier.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.constructor.name}: ${e.message}`; } };
const report = () => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
};

// ================================================================ sigelo-carrier/0 frames, fixtures/carrier-v0.json
// No relay needed. carrier.mjs must seal every frame the generator assembled by hand, byte for
// byte, open it to its value, and refuse each refusal by name in unseal's order (each a MsgError:
// anything else would hold the relay's queue, a delivery not acknowledged coming first again at
// every connection). Then the invite handshake inside those frames, run through invite.mjs and
// prekeys.mjs with the fixture's real X-Wing values, reaches the fixture's K on both sides.
{
  const gen = spawnSync(process.execPath, [join(HERE, 'gen-carrier.mjs'), '--check'], { encoding: 'utf8' });
  ok(gen.status === 0, `gen-carrier.mjs --check: ${(gen.stderr || gen.stdout).trim()}`);
  const F = JSON.parse(readFileSync(join(HERE, 'fixtures', 'carrier-v0.json'), 'utf8'));
  const unhex = (h) => new Uint8Array(Buffer.from(h, 'hex')), hexOf = (b) => Buffer.from(b).toString('hex'), sha = (b) => createHash('sha256').update(b).digest('hex');
  for (const x of F.frames) {
    const f = seal(x.kind, unhex(x.key), x.topic, x.value, () => unhex(x.nonce));
    ok(f.length === x.length && sha(f) === x.sha256 && (x.hex === undefined || hexOf(f) === x.hex), `frame ${x.case} (kind ${x.kind}): carrier.mjs seals the fixture's bytes`);
    ok(canonicalize(unseal(x.kind, unhex(x.key), x.topic, f)) === canonicalize(x.value), `frame ${x.case}: opens to its value`);
  }
  for (const r of F.refusals) {
    const got = checkOf(() => unseal(r.read_as, unhex(F.seeds['frame key']), r.topic, unhex(r.hex)));
    ok(got === r.error, `refusal ${r.case}: ${got}, expected ${r.error}`);
  }
  const d = F.derived, A0 = F.identities.A0, B0 = F.identities.B0, K = unhex(d.K.hex), value = (c) => F.frames.find((x) => x.case === c).value;
  ok(hexOf(noticeKey(K, B0.did, A0.did)) === d.notice_key.hex && hexOf(prekeysKey(K, B0.did, A0.did)) === d.prekeys_key.hex, 'the notice key and the prekeys frame\'s key');
  ok(pairId(K) === d.pair.hex && topic(K, B0.did, A0.did, d.week) === d.mailbox.topic, 'the pair id and the mailbox topic (kdf.mjs)');
  const ik = inviteKeys(unhex(d.invite.secret));
  ok(ik.answer_topic === d.invite.answer_topic && ik.reply_topic === d.invite.reply_topic && hexOf(ik.key) === d.invite.key, 'what the invite secret yields (invite.mjs)');
  ok(checkPrekeys(value('prekeys').prekeys, { did: B0.did, current_did: B0.did, current_key: B0.key }, d.pair.hex, F.t0 + 40).keys.length === 20, 'bob\'s bundle in the prekeys frame passes the sender\'s check');
  {
    // The recovery notice: its chain follows the recovery past the thief's B1 and ends at B2, whose
    // key signs the proof. A receiver that followed B1 marks bob re_pair (the relay part below).
    const n = value('notice_recovery'), r = verify(n.bundle, F.t0 + 300), B2 = F.identities.B2;
    ok(r.did === B2.did && r.chain.join() === `${B0.did},${B2.did}` && F.recovery.body.reason === 'recovery' && verifySig(B2.key, n.proof.body, n.proof.sig),
      'the recovery notice: the recovery from B0 beats the thief\'s B1, the chain ends at B2, the proof verifies under B2\'s key');
  }
  const sd = mkdtempSync(join(tmpdir(), 'sigelo-carrier-fixture-'));
  try {
    // alice's code from the fixture's inputs: its bytes, and a nonce that hashes all of them.
    const code = makeInvite({ did: A0.did, relay: d.invite.relay, now: F.t0, ttl: d.invite.exp - F.t0, secret: unhex(d.invite.secret) });
    ok(hexOf(code.bytes) === d.invite.code && code.nonce === d.invite.nonce, 'alice\'s code and its nonce, the hash of the whole code (invite.mjs)');
    const as = new Contacts(join(sd, 'alice.json'), A0.did), bs = new Contacts(join(sd, 'bob.json'), B0.did), answer = value('answer'), reply = value('reply');
    as.addInvite(code, 'bob', F.t0);
    let ct = null;
    const a = checkAnswer(answer, as, F.t0 + 10, (pk) => { const k = kemEncapsulate(pk, fixtureRng('kem ct')); ct = k.ct; return k.shared; });
    ok(a.pair_key === d.K.hex && ct === reply.kem_ct && a.answer_id === d.answer_id.value, 'alice checks bob\'s answer and encapsulates to his key: the fixture\'s kem_ct and K');
    const kem = kemKey(fixtureRng('kem key'));
    ok(kem.pk === answer.kem_pk, 'bob\'s one-time X-Wing key rebuilds from the seed');
    const pending = () => bs.addAccept(code, answerId(answer), 'alice', F.t0 + 5, hexOf(kemKey(fixtureRng('kem key')).secretKey));
    pending();
    // Swapped by a code holder on the path for an encapsulation of its own to the same key: the
    // reply's transcript, under alice's signature, covers kem_ct (relay-plan §11).
    const swapped = { ...reply, kem_ct: kemEncapsulate(answer.kem_pk, fixtureRng('mallory')).ct };
    ok(checkOf(() => checkReply(swapped, bs, F.t0 + 30, (c, sk) => kemDecapsulate(c, unhex(sk)))) === 'transcript', 'a reply whose kem_ct was swapped on the way fails transcript');
    pending();
    const b = checkReply(reply, bs, F.t0 + 30, (c, sk) => kemDecapsulate(c, unhex(sk)));
    ok(b.pair_key === d.K.hex && b.did === A0.did, 'bob checks alice\'s reply and decapsulates: the same K');
  } finally { rmSync(sd, { recursive: true, force: true }); }
}

const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs'))) {
  report();
  console.log(`ALL PASS (${count}): the fixture part; SKIP the rest, no relay checkout beside contact/ (the relay is its own AGPL package): set SIGELO_RELAY_DIR`);
  process.exit(0);
}
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { TIERS, relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (cond, ms = 8000) => { const end = Date.now() + ms; while (Date.now() < end) { if (cond()) return true; await sleep(20); } return cond(); };
const refuses = async (f, check, what) => {
  try { await f(); ok(false, `${what}: accepted, expected ${check}`); } catch (e) { ok(e.check === check, `${what}: ${e.check ?? 'exception'} (${e.message}), expected ${check}`); }
};
setTimeout(() => { console.log(`FAIL the run did not finish in 300 s (${count} checks so far)`); process.exit(1); }, 300000).unref();

const HOST = 'relay.test', DAY = 86400, CREATED = '2026-10-01T00:00:00Z';
const dir = mkdtempSync(join(tmpdir(), 'sigelo-carrier-'));
let now = Date.parse('2026-10-11T12:00:00Z') / 1000;   // a Sunday, ISO week 2026-W41
const lines = [];
// The scenarios below are written against a free tier of 7 days and 256 KB: the client's default
// retention (carrier.mjs RETENTION_DAYS) and the relay's free tier until 2026-10-14. Both have since
// grown (14 days, 512 KB); pinning the old ones here (TEST_FREE, and make's retentionDays) keeps
// each scenario's expiry and too_large at the client's own window, whatever the defaults.
const TEST_FREE = { ...TIERS.free, retentionDays: 7, maxMessage: 256 * 1024 };
const cfg = { host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, clock: () => now, diskUsed: () => 0.1,
  log: (l) => lines.push(l), policy: (ctx) => relayPolicy(ctx, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 }, freeQueue: 64 * 1024 * 1024, tiers: { free: TEST_FREE, pro: TIERS.pro } }) };
let relay = await startRelay(cfg);
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };

// Fixture agents from fixed seeds: secret = SHA-256("sigelo-carrier-test/0 " + label).
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-carrier-test/0 ${l}`).digest());
function agent(label) {
  const recovery = keygen({ seed: seed(`${label} recovery`), recovery: 'sha256:' + '0'.repeat(64), created: CREATED, nonce: seed(`${label} recovery nonce`).slice(0, 16) }).key;
  const k = keygen({ seed: seed(label), recovery, created: CREATED, nonce: seed(`${label} nonce`).slice(0, 16) });
  return { label, original: k.did, did: k.did, secret: k.secret, rotations: 0,
    bundle: { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] } };
}
// A voluntary rotation, as `sigelo-agent rotate` writes it to the identity file.
function rotateAgent(a) {
  const head = a.bundle.rotations.at(-1)?.next_genesis ?? a.bundle.genesis;
  a.rotations++;
  const next = keygen({ seed: seed(`${a.label} ${a.rotations}`), recovery: head.recovery, created: CREATED, nonce: seed(`${a.label} ${a.rotations} nonce`).slice(0, 16) });
  a.bundle.rotations.push(rotate({ genesis: head, next_genesis: next.genesis, iat: now, reason: 'voluntary', secret: a.secret }));
  a.secret = next.secret;
  a.did = next.did;
}
// A recovery rotation at the chain's first rotated key, signed by the offline recovery key: what
// the owner does after a theft (SPEC §7.1).
function recoverAgent(a) {
  const at = a.bundle.rotations[0].next_genesis, next = keygen({ seed: seed(`${a.label} recovered`), recovery: at.recovery, created: CREATED, nonce: seed(`${a.label} recovered nonce`).slice(0, 16) });
  a.bundle.rotations = [a.bundle.rotations[0], rotate({ genesis: at, next_genesis: next.genesis, iat: now - 3600, reason: 'recovery', secret: seed(`${a.label} recovery`) })];
  a.secret = next.secret;
  a.did = next.did;
}
const events = {};
const make = (a, extra = {}) => {
  events[a.label] = [];
  return new Carrier({ identity: () => ({ secret: a.secret, bundle: a.bundle }), ...pathsFor(join(dir, `${a.label}.local.json`)), relay: HOST, endpoints,
    clock: () => now, onEvent: (e) => events[a.label].push(e), keep: true, backoff: [100, 400], retentionDays: 7, ...extra });
};
const seen = (who, f) => events[who].filter(f);
const texts = (who) => seen(who, (e) => e.type === 'message').map((e) => e.content);
const stateOf = (a) => JSON.parse(readFileSync(pathsFor(join(dir, `${a.label}.local.json`)).state, 'utf8'));
// The contact's re_pair as the carrier's contacts() lists it.
const marked = (carrier, peer) => carrier.contacts().contacts.find((c) => c.did === peer.original)?.re_pair;
const claimsOf = (a) => Object.keys(stateOf(a).relays[HOST]?.claims ?? {});
const editState = (a, f) => { const file = pathsFor(join(dir, `${a.label}.local.json`)).state, s = JSON.parse(readFileSync(file, 'utf8')); f(s); writeFileSync(file, JSON.stringify(s)); };
const oneTimeLeft = (holder, peer) => stateOf(holder).peers[peer.original].session.in.prekeys.oneTime.length;
const q = (sql, ...p) => relay.db.raw.prepare(sql).all(...p);
const accountOf = (d) => createHash('sha256').update(d, 'utf8').digest('hex');
// A plain MQTT client logged in as `a` (the relay lets anyone logged in write to any mailbox): a
// hostile writer, or the relay replaying what it holds.
async function rawClient(a, ep = endpoints) {
  const base = ep[HOST].http, { challenge: ch, pow_bits } = await (await fetch(`${base}/challenge?did=${encodeURIComponent(a.did)}`)).json();
  const sig = sign(a.secret, { v: 'sigelo-relay/0', typ: 'relay-login', did: a.did, relay: HOST, nonce: ch.nonce });
  const password = canonicalize({ v: 'sigelo-relay/0', nonce: ch.nonce, sig, bundle: a.bundle, pow: await solvePow(HOST, a.original, ch.nonce, pow_bits) });
  return new Promise((resolve, reject) => {
    const c = connect(ep[HOST].mqtt, { protocolVersion: 4, clean: false, clientId: 's' + accountOf(a.original).slice(0, 24), username: a.did, password, reconnectPeriod: 0 });
    c.once('connect', () => resolve(c)); c.once('error', reject);
  });
}

const publish = (client, t, bytes) => new Promise((resolve) => client.publish(t, Buffer.from(bytes), { qos: 1 }, resolve));
const utf8 = (s) => new Uint8Array(Buffer.from(s, 'utf8'));
// A frame around any plaintext, canonical or not: what a hostile writer holding the key can send.
const FRAME_NONCE = Uint8Array.from({ length: 24 }, (_, i) => i + 1);
function rawFrame(kind, key, t, plaintext) {
  const head = header(kind, new Uint8Array(16), 1);
  return Buffer.concat([head, FRAME_NONCE, xchacha20poly1305(key, FRAME_NONCE, Buffer.concat([head, utf8(t)])).encrypt(plaintext)]);
}
// A rejection a JCS parser accepts but JCS cannot write, one per kind of failure.
const UNWRITABLE = [['a float', '{"a":1.5}'], ['a lone surrogate', '{"x":"\\ud800"}'], ['an integer past 2^53', '{"n":9007199254740993}']];
const storeOf = (a) => JSON.parse(readFileSync(pathsFor(join(dir, `${a.label}.local.json`)).store, 'utf8'));
// One rename into `target` fails as a full disk fails it (ENOSPC): the first whose new content
// passes when(text). Through node:fs's own exports, which carrier.mjs and store.mjs import by name:
// syncBuiltinESMExports carries the change to those bindings. → { fired(), restore() }.
function failRenameOnce(target, when) {
  const real = fsModule.renameSync;
  let hit = false;
  const restore = () => { fsModule.renameSync = real; syncBuiltinESMExports(); };
  fsModule.renameSync = (from, to) => {
    if (!hit && to === target && when(readFileSync(from, 'utf8'))) {
      hit = true;
      restore();
      rmSync(from, { force: true });
      throw Object.assign(new Error(`ENOSPC: no space left on device, rename '${from}' -> '${to}'`), { code: 'ENOSPC' });
    }
    return real(from, to);
  };
  syncBuiltinESMExports();
  return { fired: () => hit, restore };
}

// MQTT 3.1.1 packets by hand (§2.2: a type byte, the length in 7-bit groups, the body).
const vbi = (n) => { const out = []; do { let b = n % 128; n = Math.floor(n / 128); if (n > 0) b |= 0x80; out.push(b); } while (n > 0); return Buffer.from(out); };
const mqttPacket = (first, body) => Buffer.concat([Buffer.from([first]), vbi(body.length), body]);
const str16 = (s) => { const b = Buffer.from(s, 'utf8'), n = Buffer.alloc(2); n.writeUInt16BE(b.length); return Buffer.concat([n, b]); };
const CONNACK = mqttPacket(0x20, Buffer.from([0, 0]));
// A scripted MQTT server, a host a code can name: on(type, body, socket) for each whole packet it reads.
async function fakeBroker(on) {
  const sockets = new Set();
  const server = createNetServer((sock) => {
    sockets.add(sock);
    sock.on('error', () => {});
    sock.on('close', () => sockets.delete(sock));
    let buf = Buffer.alloc(0);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        let len = 0, mult = 1, i = 1, end = false;
        for (; i < 5 && i < buf.length; i++) { len += (buf[i] & 0x7f) * mult; mult *= 128; if (!(buf[i] & 0x80)) { end = true; break; } }
        if (!end || buf.length < i + 1 + len) return;
        const type = buf[0] >> 4, body = buf.subarray(i + 1, i + 1 + len);
        buf = buf.subarray(i + 1 + len);
        on(type, body, sock);
      }
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { port: server.address().port, close: () => { for (const s of sockets) s.destroy(); server.close(); } };
}
// Splits a byte stream into whole MQTT packets: each(packet) for each, in order.
function packets(each) {
  let buf = Buffer.alloc(0);
  return (d) => {
    buf = Buffer.concat([buf, d]);
    for (;;) {
      let len = 0, mult = 1, i = 1, end = false;
      for (; i < 5 && i < buf.length; i++) { len += (buf[i] & 0x7f) * mult; mult *= 128; if (!(buf[i] & 0x80)) { end = true; break; } }
      if (!end || buf.length < i + 1 + len) return;
      const pkt = buf.subarray(0, i + 1 + len);
      buf = buf.subarray(i + 1 + len);
      each(pkt);
    }
  };
}
// A network between the agents and a relay on loopback that hands the client each MQTT packet the
// relay sends `gap` ms after the one before, on its own: separate reads, as TCP segments and TLS
// records over a real path arrive. Loopback hands over what the relay wrote together in one read.
// onClient(packet, toClient): each packet the client sends, before it goes on; toClient(packet)
// puts a packet of the test's own in line for the client.
async function splitProxy(port, { gap = 2, onClient = null } = {}) {
  const sockets = new Set();
  const server = createNetServer((down) => {
    const up = netConnect(port, '127.0.0.1');
    for (const x of [down, up]) { sockets.add(x); x.on('error', () => {}); x.on('close', () => sockets.delete(x)); }
    let line = Promise.resolve();
    const toClient = (pkt) => { line = line.then(() => new Promise((r) => setTimeout(() => { if (!down.destroyed) down.write(pkt); r(); }, gap))); };
    up.on('data', packets(toClient));
    down.on('data', packets((pkt) => { onClient?.(pkt, toClient); up.write(pkt); }));
    up.on('close', () => down.destroy()); down.on('close', () => up.destroy());
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { port: server.address().port, close: () => { for (const x of sockets) x.destroy(); server.close(); } };
}
// The topics of a SUBSCRIBE body: packet id, then (length, topic, QoS) each.
function subscribed(body) {
  const out = [];
  for (let i = 2; i < body.length; i += 3 + body.readUInt16BE(i)) out.push(body.toString('utf8', i + 2, i + 2 + body.readUInt16BE(i)));
  return out;
}

const A = agent('alice'), B = agent('bob'), C = agent('carol');
const alice = make(A), bob = make(B), carol = make(C);
const secrets = new Set();   // every DID and every message text: none may reach the relay's files or log
const say = (s) => { secrets.add(s); return s; };
for (const x of [A, B, C]) secrets.add(x.original);

// The relay's database, its WAL and its log, read as bytes: no DID, no message text; topics only
// m/ and i/ with 32 hex digits.
function blind(what) {
  const raw = Buffer.concat([cfg.db, `${cfg.db}-wal`].filter(existsSync).map((f) => readFileSync(f)));
  const found = [...secrets].filter((s) => raw.includes(Buffer.from(s)) || lines.some((l) => l.includes(s)));
  ok(found.length === 0, `${what}: the relay's database, WAL and log hold no DID and no message text (found ${found.length})`);
  ok(q('SELECT topic FROM claims').every((r) => /^[mi]\/[0-9a-f]{32}$/.test(r.topic)), `${what}: every topic the relay holds is m/ or i/ and 32 hex digits`);
  ok(!lines.some((l) => /did:sigelo|[mi]\/[0-9a-f]{32}/.test(l)), `${what}: the relay's log names no DID and no topic`);
}

try {
  // ================================================================ carrier constants
  ok(LABEL_PREKEYS === 'sigelo-msg/0 prekeys' && KIND_PREKEYS === 5 && TYP_NOTICE === 'contact-notice' && INVITE_BYTES === 65536 && MAX_ROTATIONS === 64,
    'the earlier prekeys label, the prekeys frame\'s kind, the notice proof\'s typ, the invite-topic cap and the rotation cap');

  // ================================================================ the proof of work yields
  {
    let ticks = 0, worst = 0, last = Date.now();
    const timer = setInterval(() => { const t = Date.now(); worst = Math.max(worst, t - last); last = t; ticks++; }, 20);
    const r = await solvePow('relay.test', A.original, 'n', 48, Date.now() + 1500);
    clearInterval(timer);
    ok(r === null && ticks >= 15 && worst < 300, `a 1.5 s search leaves the event loop running: ${ticks} timer ticks, the longest gap ${worst} ms`);
  }

  // ================================================================ MQTT packets past the limit
  {
    const run = async (chunks, max) => {
      const s = new PassThrough();
      let why = null;
      limitPackets(s, max, (w) => { why = w; });
      for (const c of chunks) s.write(c);
      await new Promise((r) => setImmediate(r));
      return why;
    };
    // Packets of 3 and 200 bytes (the second's length in two bytes), split mid-header and mid-body.
    const two = Buffer.concat([mqttPacket(0x30, Buffer.alloc(3)), mqttPacket(0x32, Buffer.alloc(200))]);
    ok(await run([two.subarray(0, 4), two.subarray(4, 7), two.subarray(7, 100), two.subarray(100)], 200) === null, 'packets up to the limit pass, split anywhere');
    ok(/201 bytes, more than 200/.test(await run([mqttPacket(0x30, Buffer.alloc(201)).subarray(0, 3)], 200)), 'the first packet past it is cut at its header, before its body arrives');
    ok(/longer than 4 bytes/.test(await run([Buffer.from([0x30, 0xff, 0xff, 0xff, 0xff, 0x01])], 2 ** 30)), 'a length in five bytes is cut');
    ok(MAX_PACKET === 1024 * 1024 + 1024, 'the limit: a 1 MB message and its header, the largest packet a relay forwards');
    // The PUBLISH of the longest envelope a sender writes: 2 bytes of topic length, the topic
    // ("m/" and 32 hex), a packet id. Within what a relay takes in one packet (relay/server.mjs).
    ok(2 + 34 + 2 + MAX_ENVELOPE <= MAX_PACKET, 'the longest envelope\'s PUBLISH fits one packet at the relay');
  }

  // ================================================================ a host a stranger's code names
  {
    // One HTTP server playing two hostile relays: /flood answers GET /challenge with endless
    // chunks and no Content-Length; /greedy answers a well-formed challenge asking 24 bits.
    let flooded = 0;
    const fake = createServer((req, res) => {
      const url = new URL(req.url, 'http://x');
      if (url.pathname === '/flood/challenge') {
        res.writeHead(200, { 'content-type': 'application/json' });
        const chunk = Buffer.alloc(16384, 0x20);
        const more = () => { while (!res.destroyed && flooded < 64 * 1024 * 1024) { flooded += chunk.length; if (!res.write(chunk)) { res.once('drain', more); return; } } res.end(); };
        more();
      } else if (url.pathname === '/greedy/challenge') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ challenge: { v: 'sigelo-relay/0', typ: 'relay-login', did: url.searchParams.get('did'), relay: 'greedy.test', nonce: randomBytes(32).toString('base64url') }, pow_bits: 24 }));
      } else { res.writeHead(404); res.end(); }
    });
    await new Promise((r) => fake.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${fake.address().port}`, nowhere = 'mqtt://127.0.0.1:9';
    const X = agent('xena'), xena = make(X, { relay: 'flood.test', endpoints: { 'flood.test': { mqtt: nowhere, http: `${base}/flood` } } });
    const t0 = Date.now();
    await refuses(() => xena.invite(), 'connect', 'GET /challenge answered with endless chunks');
    ok(Date.now() - t0 < 10000 && flooded < 16 * 1024 * 1024, `the answer is cut off past 64 KB whatever the headers say (${Math.round(flooded / 1024)} KB written by the server, ${Date.now() - t0} ms)`);
    const Y = agent('yuri'), yuri = make(Y, { endpoints: { ...endpoints, 'greedy.test': { mqtt: nowhere, http: `${base}/greedy` } } });
    const code = makeInvite({ did: A.did, relay: 'greedy.test', now }).text;
    await refuses(() => yuri.accept(code, { wait: 0.3 }), 'pow', 'a relay other than the agent\'s own asking 24 bits');
    ok(yuri.contacts().answers.length === 0 && stateOf(Y).pending.length === 0, 'is refused for good: the answer is withdrawn, so no later round dials that host for it');
    // A code naming an address or a local name, neither the agent's own relay nor configured:
    // refused before anything is stored or dialled.
    const Vi = agent('vic'), vic = make(Vi);
    // 127.0.0.0x1 and the like: an IPv4 address to fetch (WHATWG URL) and to inet_aton.
    // db.corp and the like: top-level names ICANN never delegates, kept for private networks.
    for (const r of ['10.0.0.1:8883', 'localhost', 'relay', 'relay.local', 'mail.internal', '127.0.0.0x1', '169.254.169.0xfe', '10.0.0.0x1:8883', 'localhost.localdomain',
      'db.corp', 'nas.home', 'smtp.mail', 'wiki.intranet', 'git.private']) {
      await refuses(() => vic.accept(makeInvite({ did: A.did, relay: r, now }).text, { wait: 0.3 }), 'code_relay', `a code naming ${r}`);
    }
    ok(vic.contacts().answers.length === 0 && !existsSync(pathsFor(join(dir, 'vic.local.json')).state) && !seen('vic', (e) => e.type === 'connected').length, 'nothing stored, queued or dialled');
    fake.closeAllConnections();
    await new Promise((r) => fake.close(r));
  }

  // ================================================================ hosts whose MQTT side is scripted
  {
    // GET /<relay>/challenge: a well-formed login body for that relay, no proof of work asked.
    const http = createServer((req, res) => {
      const url = new URL(req.url, 'http://x'), [, name, what] = url.pathname.split('/');
      if (what !== 'challenge') { res.writeHead(404); res.end(); return; }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ challenge: { v: 'sigelo-relay/0', typ: 'relay-login', did: url.searchParams.get('did'), relay: name, nonce: randomBytes(32).toString('base64url') }, pow_bits: 0 }));
    });
    await new Promise((r) => http.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${http.address().port}`;

    // evil.test sends CONNACK, then one PUBLISH announcing 100 MB. MQTT.js alone buffered it whole
    // (MQTT 3.1.1 allows 256 MB) and the answer stayed queued for the next round to dial again.
    let wrote = 0;
    const flood = (sock) => {
      wrote = 0;
      sock.write(Buffer.concat([Buffer.from([0x30]), vbi(100 * 1024 * 1024)]));
      const chunk = Buffer.alloc(65536);
      const more = () => { while (!sock.destroyed && wrote < 100 * 1024 * 1024) { wrote += chunk.length; if (!sock.write(chunk)) { sock.once('drain', more); return; } } };
      more();
    };
    const evil = await fakeBroker((type, _body, sock) => { if (type === 1) { sock.write(CONNACK); flood(sock); } });
    const Z = agent('zora'), zora = make(Z, { endpoints: { ...endpoints, 'evil.test': { mqtt: `mqtt://127.0.0.1:${evil.port}`, http: `${base}/evil.test` } } });
    const t0 = Date.now();
    await refuses(() => zora.accept(makeInvite({ did: A.did, relay: 'evil.test', now }).text, { wait: 0.3 }), 'too_large', 'a host sending a 100 MB MQTT packet');
    ok(Date.now() - t0 < 10000 && wrote < 16 * 1024 * 1024, `the connection is cut at that packet's header (${Math.round(wrote / 1024)} KB written by the host, ${Date.now() - t0} ms)`);
    ok(zora.contacts().answers.length === 0 && stateOf(Z).pending.length === 0, 'refused for good by a host other than the agent\'s own: the answer is withdrawn');
    evil.close();

    // later.test plays a relay until it has acknowledged the answer, and floods 300 ms after.
    const later = await fakeBroker((type, body, sock) => {
      if (type === 1) sock.write(CONNACK);
      else if (type === 8) sock.write(mqttPacket(0x90, Buffer.concat([body.subarray(0, 2), Buffer.alloc(subscribed(body).length, 1)])));
      else if (type === 3) {
        const at = 2 + body.readUInt16BE(0);
        sock.write(mqttPacket(0x40, body.subarray(at, at + 2)));
        setTimeout(() => flood(sock), 300);
      } else if (type === 14) sock.end();
    });
    const W = agent('wendy'), wendy = make(W, { endpoints: { ...endpoints, 'later.test': { mqtt: `mqtt://127.0.0.1:${later.port}`, http: `${base}/later.test` } } });
    await refuses(() => wendy.accept(makeInvite({ did: A.did, relay: 'later.test', now }).text, { wait: 1 }), 'too_large', 'a host flooding once it holds the answer');
    ok(wrote < 16 * 1024 * 1024 && wendy.contacts().answers.length === 1 && stateOf(W).pending.length === 0, `cut at that packet's header too; the answer it holds is kept, for the reply (${Math.round(wrote / 1024)} KB written)`);
    later.close();

    // sam reads one contact at quiet.test and holds a claim there past its time. The host delivers
    // a packet 200 ms after granting the claims, and sam takes 600 ms over it (his identity is slow
    // to read once). A stale claim is given up only once deliveries stop: the UNSUBSCRIBE must not
    // follow that PUBACK at once, as it did when the packet's time was stamped at its start.
    const S = agent('sam'), P = agent('pia'), files = pathsFor(join(dir, 'sam.local.json')), stale = 'm/' + 'e'.repeat(32);
    writeFileSync(files.store, JSON.stringify({ v: STORE_V, self: S.original, invites: {}, accepts: {}, contacts: { [P.original]: {
      name: 'pia', did: P.original, current_did: P.original, current_key: P.bundle.genesis.key, revoked: false, chain: [P.original], rotations: [], relay: 'quiet.test', pair_key: '11'.repeat(32) } } }), { mode: 0o600 });
    writeFileSync(files.state, JSON.stringify({ v: CARRIER_V, self: S.original, relays: { 'quiet.test': { proven: true, claims: { [stale]: { peer: P.original, until: now - 60 } } } },
      peers: {}, pending: [], inbox: [], events: [], dropped: {}, failing: {} }), { mode: 0o600 });
    let slow = false, puback = 0, unsub = 0, sent = false;
    const quiet = await fakeBroker((type, body, sock) => {
      if (type === 1) sock.write(CONNACK);
      else if (type === 8) {
        const topics = subscribed(body);
        sock.write(mqttPacket(0x90, Buffer.concat([body.subarray(0, 2), Buffer.alloc(topics.length, 1)])));
        if (!sent && topics.some((t) => t.startsWith('m/'))) {
          sent = true;
          setTimeout(() => { slow = true; sock.write(mqttPacket(0x32, Buffer.concat([str16('m/' + 'f'.repeat(32)), Buffer.from([0, 1]), Buffer.alloc(300)]))); }, 200);
        }
      } else if (type === 4) puback ||= Date.now();
      else if (type === 10) { unsub ||= Date.now(); sock.write(mqttPacket(0xb0, body.subarray(0, 2))); }
      else if (type === 14) sock.end();
    });
    const sam = make(S, {
      identity: () => { if (slow) { slow = false; const end = Date.now() + 600; while (Date.now() < end); } return { secret: S.secret, bundle: S.bundle }; },
      endpoints: { 'quiet.test': { mqtt: `mqtt://127.0.0.1:${quiet.port}`, http: `${base}/quiet.test` } },
    });
    const sb = await sam.inbox();
    ok(!sb.offline && sb.dropped.route === 1 && puback > 0, `the slow packet is read and acknowledged (${JSON.stringify(sb.dropped)}${sb.offline ? `, offline: ${sb.offline}` : ''})`);
    ok(unsub - puback >= 300, `the stale claim is given up only once deliveries have stopped: ${unsub - puback} ms after that PUBACK`);
    ok(Object.keys(stateOf(S).relays['quiet.test'].claims).every((t) => t !== stale), 'and it is given up');
    quiet.close();
    http.close();
  }

  // ================================================================ a relay's redirects; a relay that makes proof of work endless
  {
    // inside: a host on the agent's own network, which no redirect may reach. hop.test answers GET
    // /challenge with a 302 there; hop2.test answers it and sends POST /check, which the carrier
    // makes once the MQTT dial fails, a 307 there. fetch followed both, past the code_relay check.
    const reached = [], checks = [];
    const inside = createServer((req, res) => { reached.push(`${req.method} ${req.url}`); res.writeHead(200, { 'content-type': 'application/json' }); res.end('{}'); });
    await new Promise((r) => inside.listen(0, '127.0.0.1', r));
    const there = `http://localhost:${inside.address().port}`;
    const http = createServer((req, res) => {
      const url = new URL(req.url, 'http://x'), [, name, what] = url.pathname.split('/');
      if (name === 'hop.test' && what === 'challenge') { res.writeHead(302, { location: `${there}/latest/meta-data/` }); res.end(); return; }
      if (name === 'hop2.test' && what === 'check') { checks.push(req.method); res.writeHead(307, { location: `${there}/admin/action` }); res.end(); return; }
      if (what !== 'challenge') { res.writeHead(404); res.end(); return; }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ challenge: { v: 'sigelo-relay/0', typ: 'relay-login', did: url.searchParams.get('did'), relay: name, nonce: randomBytes(32).toString('base64url') }, pow_bits: name === 'loop.test' ? 4 : 0 }));
    });
    await new Promise((r) => http.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${http.address().port}`, nowhere = 'mqtt://127.0.0.1:9';
    const H = agent('hana'), hana = make(H, { endpoints: { ...endpoints, 'hop.test': { mqtt: nowhere, http: `${base}/hop.test` }, 'hop2.test': { mqtt: nowhere, http: `${base}/hop2.test` } } });
    let said = '';
    try { await hana.accept(makeInvite({ did: A.did, relay: 'hop.test', now }).text, { wait: 0.3 }); } catch (e) { said = `${e.check}: ${e.message}`; }
    ok(/^connect: .*302, a redirect/.test(said), `GET /challenge answered with a 302: connect, the redirect named (${said})`);
    await refuses(() => hana.accept(makeInvite({ did: A.did, relay: 'hop2.test', now }).text, { wait: 0.3 }), 'connect', 'POST /check answered with a 307');
    ok(checks.length === 1 && reached.length === 0, `no redirect is followed: ${checks.length} POST /check sent, ${reached.length} requests reached the host inside (${reached.join(', ')})`);

    // loop.test grants the claims of a login that carried a proof of work and closes 300 ms later;
    // the next login, proven, has its SUBSCRIBE refused `pow`, as by a relay that forgot the proof.
    // Each connection that held reset the carrier's bounds, so it searched again at every
    // reconnection, without end: one core for as long as the relay stayed in use.
    let searches = 0;
    const loop = await fakeBroker((type, body, sock) => {
      if (type === 1) { sock.proven = body.includes('"pow":'); if (sock.proven) searches++; sock.write(CONNACK); }
      else if (type === 8) {
        const topics = subscribed(body), id = body.subarray(0, 2);
        if (topics.length === 1 && topics[0] === '$sigelo/notice') sock.write(mqttPacket(0x90, Buffer.concat([id, Buffer.from([0])])));
        else if (sock.proven) { sock.write(mqttPacket(0x90, Buffer.concat([id, Buffer.alloc(topics.length, 1)]))); setTimeout(() => sock.destroy(), 300); }
        else {
          sock.write(mqttPacket(0x30, Buffer.concat([str16('$sigelo/notice'), Buffer.from(JSON.stringify({ code: 'pow', detail: 'prove work again' }))])));
          sock.write(mqttPacket(0x90, Buffer.concat([id, Buffer.alloc(topics.length, 0x80)])));
        }
      } else if (type === 3) { const at = 2 + body.readUInt16BE(0); sock.write(mqttPacket(0x40, body.subarray(at, at + 2))); }
      else if (type === 14) sock.end();
    });
    let uNow = now;
    const U = agent('una'), una = make(U, { clock: () => uNow, endpoints: { ...endpoints, 'loop.test': { mqtt: `mqtt://127.0.0.1:${loop.port}`, http: `${base}/loop.test` } } });
    const powErrors = () => seen('una', (e) => e.type === 'error' && e.check === 'pow' && /searches at loop\.test within 24 hours/.test(e.detail)).length;
    ok((await una.accept(makeInvite({ did: A.did, relay: 'loop.test', now, ttl: 7 * DAY }).text, { wait: 0.3 })).status === 'waiting' && searches === 1, `una answers a code naming loop.test: one search (${searches}), the answer delivered`);
    await una.start();
    ok(await until(() => powErrors() === 1, 30000), 'started, una stops at loop.test with pow, the searches of the day spent');
    await sleep(1500);
    ok(searches === POW_SEARCHES, `${searches} searches at loop.test, ${POW_SEARCHES} allowed in 24 hours`);
    await una.sync();
    ok(await until(() => powErrors() === 2, 10000) && searches === POW_SEARCHES, `the next round refuses without searching (${searches} searches)`);
    uNow += DAY + 60;
    await una.sync();
    ok(await until(() => powErrors() === 3, 30000), '24 hours later, una searches again, and stops again');
    await sleep(1500);
    ok(searches === 2 * POW_SEARCHES, `${searches} searches in all, ${POW_SEARCHES} in each 24 hours`);
    await una.stop();
    loop.close();
    inside.close();
    http.close();
  }

  // ================================================================ a 502 refuses nothing; a delivered answer outlives a refusal for good
  {
    // otto's own relay is home.test, so HOST is a stranger's relay to him. A proxy before HOST's
    // HTTP side answers as told: pass; 502, as nginx does while the relay restarts; or a 200
    // holding another relay's challenge, a refusal no retry fixes.
    let mode = 'pass';
    const proxy = createServer(async (req, res) => {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      if (mode === '502') { res.writeHead(502); res.end('bad gateway'); return; }
      const up = await fetch(endpoints[HOST].http + req.url, { method: req.method, ...(req.method === 'POST' && { body: Buffer.concat(chunks) }) });
      let body = Buffer.from(await up.arrayBuffer());
      if (mode === 'ctx' && req.url.startsWith('/challenge')) { const j = JSON.parse(body); j.challenge.relay = 'elsewhere.test'; body = Buffer.from(JSON.stringify(j)); }
      res.writeHead(up.status, { 'content-type': 'application/json' });
      res.end(body);
    });
    await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
    const N = agent('nora'), O = agent('otto'), nora = make(N);
    const otto = make(O, { relay: 'home.test', endpoints: { [HOST]: { mqtt: endpoints[HOST].mqtt, http: `http://127.0.0.1:${proxy.address().port}` } } });
    const one = (await nora.invite({ name: 'otto' })).code, two = (await nora.invite({ name: 'otto again' })).code;
    ok((await otto.accept(one, { name: 'nora', wait: 0.3 })).status === 'waiting', 'otto answers nora\'s first code: the relay holds the answer');
    mode = '502';
    await refuses(() => otto.accept(two, { name: 'nora again', wait: 0.3 }), 'connect', 'GET /challenge answering 502');
    ok(otto.contacts().answers.length === 2 && stateOf(O).pending.filter((p) => p.control === 'answer').length === 1, 'a 502 refuses nothing: the second answer stays queued beside the delivered one');
    await otto.start();
    ok(await until(() => seen('otto', (e) => e.type === 'error' && e.check === 'connect').length >= 2), 'started, otto retries through the 502s with backoff');
    ok(otto.contacts().answers.length === 2, 'and withdraws nothing');
    mode = 'ctx';
    ok(await until(() => seen('otto', (e) => e.type === 'pairing_failed').length === 1), 'a 200 holding another relay\'s challenge is a refusal for good');
    await otto.stop();
    ok(otto.contacts().answers.length === 1 && stateOf(O).pending.length === 0 && seen('otto', (e) => e.type === 'pairing_failed')[0].code === 'challenge',
      'the answer still waiting to go is withdrawn; the one the relay holds is kept');
    mode = 'pass';
    ok((await nora.inbox()).events.some((e) => e.type === 'paired' && e.did === O.original), 'nora reads the delivered answer and replies');
    ok((await otto.inbox()).events.some((e) => e.type === 'paired' && e.did === N.original), 'otto reads the reply with the secret he kept: paired');
    proxy.closeAllConnections();
    proxy.close();
  }

  // ================================================================ pairing by code, each side offline in turn
  const inv = await alice.invite({ name: 'bob' });
  ok(inv.code.startsWith('sgl1') && inv.relay === HOST && inv.did === A.did, 'invite: a code for alice\'s current DID at the relay');
  ok(alice.contacts().invites.length === 1, 'the invite is pending in alice\'s store');
  ok(stateOf(A).relays[HOST].proven === true, 'the first login carried a proof of work (relay-plan §3), remembered for this relay');
  const acc = await bob.accept(inv.code, { name: 'alice', wait: 0.3 });
  ok(acc.status === 'waiting', `accept while alice is offline: the answer reaches the relay, the pairing waits (${acc.status})`);
  ok(bob.contacts().answers.length === 1, 'bob\'s answer is pending in his store');
  const first = await alice.inbox();
  ok(seen('alice', (e) => e.type === 'paired' && e.did === B.original && e.name === 'bob').length === 1, 'alice, back online, checks bob\'s answer and stores him under his original DID');
  ok(first.events.some((e) => e.type === 'paired' && e.did === B.original && e.name === 'bob'), 'and her inbox says so: an agent without onEvent sees the pairing');
  await bob.inbox();
  ok(seen('bob', (e) => e.type === 'paired' && e.did === A.original && e.name === 'alice').length === 1, 'bob, back online, checks alice\'s reply and stores her under her original DID');
  ok(seen('bob', (e) => e.type === 'sent' && e.control === 'prekeys').length === 1, 'bob sends his prekeys as his first message');
  await alice.inbox();
  ok(seen('alice', (e) => e.type === 'prekeys' && e.did === B.original).length === 1, 'alice holds bob\'s prekeys: both can begin epochs');
  const [ab] = alice.contacts().contacts, [ba] = bob.contacts().contacts;
  ok(ab.did === B.original && ab.current_did === B.did && !ab.revoked && ab.relay === HOST, 'alice\'s contact: bob, original DID, the code\'s relay');
  ok(ba.did === A.original && ba.current_did === A.did, 'bob\'s contact: alice');
  ok(alice.contacts().invites.length === 0 && bob.contacts().answers.length === 0, 'the code is spent on both sides');
  ok((statSync(pathsFor(join(dir, 'alice.local.json')).state).mode & 0o777) === 0o600 && (statSync(pathsFor(join(dir, 'alice.local.json')).store).mode & 0o777) === 0o600,
    'the carrier state and the contact store are 0600: chain keys, prekey secrets, pairing keys');
  // Single use at the relay too: the answer topic died with the first answer read.
  // Single use at the relay too: the code's reply topic is bob's, so a second holder cannot wait on it.
  await refuses(() => carol.accept(inv.code, { name: 'alice', wait: 0.3 }), 'mailbox_taken', 'a second answer to a spent code');
  await alice.inbox();
  ok(alice.contacts().contacts.length === 1 && carol.contacts().contacts.length === 0 && carol.contacts().answers.length === 0, 'it pairs nobody, and carol keeps no pending answer');

  // ================================================================ one code accepted twice
  {
    // Two answers to one code share its reply topic. Before, both went into one SUBSCRIBE: the
    // relay refused it and closed the connection, at every connection until the code expired.
    const Te = agent('tess'), U = agent('uma'), tess = make(Te), uma = make(U);
    const code = (await tess.invite({ name: 'uma' })).code;
    ok((await uma.accept(code, { name: 'tess', wait: 0.3 })).status === 'waiting', 'uma answers tess\'s code');
    const again = await uma.accept(code, { name: 'tess again', wait: 0.3 }).then((r) => r.status, (e) => `${e.check}: ${e.message}`);
    ok(again === 'waiting' && uma.contacts().answers.length === 2, `and answers it again: the reply topic is claimed once and the connection stays (${again})`);
    ok(!seen('uma', (e) => e.type === 'notice' || e.type === 'error').length, `no refusal from the relay (${seen('uma', (e) => e.type === 'notice' || e.type === 'error').map((e) => e.code ?? e.check).join() || 'none'})`);
    const tb = await tess.inbox();
    ok(tb.events.filter((e) => e.type === 'paired').length === 1, 'tess pairs once: the first answer spends the code');
    const ub = await uma.inbox();
    ok(!ub.offline && ub.events.some((e) => e.type === 'paired' && e.did === Te.original) && uma.contacts().answers.length === 0,
      `uma reads the reply: paired, and both answers are spent, the reply topic having died with it (${ub.offline ?? 'online'})`);
  }

  // ================================================================ messages, both agents one-shot
  for (let i = 0; i < 5; i++) {
    const r = await alice.send('bob', say(`one-shot ${i}`));
    ok(r.status === 'sent' && r.to === B.original, `send ${i}: acknowledged by the relay (${r.status})`);
  }
  const box = await bob.inbox();
  ok(box.messages.map((m) => m.content).join('|') === [0, 1, 2, 3, 4].map((i) => `one-shot ${i}`).join('|'), 'bob receives the five, in order');
  ok(box.messages.every((m) => m.from === A.original && m.name === 'alice' && m.current_did === A.did && m.label === ''), 'each from alice\'s original DID, signed by her current key');
  ok(box.messages.every((m) => m.last_resort === false), 'each in an epoch begun on a one-time prekey (last_resort false)');
  ok((await bob.inbox()).messages.length === 0, 'the inbox is taken once');
  {
    // Receiving keys have a time, saved with the session (envelope.mjs expire): with the free
    // tier's 7 days of retention, an epoch goes 7 + 7 days + SKEW after its first envelope was
    // opened. Each session deletes what is past it, for every contact, whether it wrote since or not.
    const epochs = () => stateOf(B).peers[A.original].session.in.epochs;
    const until = epochs()[0]?.[7];
    ok(epochs().length === 1 && until > now && until <= now + 14 * DAY + 300, `bob's state keeps alice's epoch with its end (${until - now} s from now)`);
    editState(B, (st) => { st.peers[A.original].session.in.epochs[0][7] = now; });
    await bob.inbox();
    ok(epochs().length === 0, 'once its time is up, the next session deletes it from the file');
    // Alice's next message begins a new epoch, as it would after that much time.
    editState(A, (st) => { st.peers[B.original].session.out.epoch = null; });
  }
  ok((await bob.send(A.original, say('one-shot back'), { label: 'tests' })).status === 'sent', 'bob answers by DID');
  const back = (await alice.inbox()).messages;
  ok(back.length === 1 && back[0].content === 'one-shot back' && back[0].label === 'tests', 'alice receives it, label inside the encryption');
  await refuses(() => alice.send('nobody', 'x'), 'not_contact', 'send to an unknown name');
  await refuses(() => alice.send('bob', 1.5), 'body', 'send a float');
  await refuses(() => alice.send('bob', 'x', { label: LABEL_PREKEYS }), 'body', 'send under the carrier\'s own label');

  // ================================================================ several messages, one login
  {
    const logins = () => seen('alice', (e) => e.type === 'connected').length, l0 = logins();
    const all = await alice.sendAll('bob', ['batch 1', 'batch 2', 'batch 3'].map(say));
    ok(all.length === 3 && all.every((r) => r.status === 'sent') && logins() === l0 + 1, `sendAll: three messages sent over one login (${all.map((r) => r.status).join()}, ${logins() - l0} logins)`);
    ok((await bob.inbox()).messages.map((m) => m.content).join() === 'batch 1,batch 2,batch 3', 'bob receives the three, in order');
  }

  // ================================================================ poison frames: dropped by name, the queue behind them flows
  {
    const mal = await rawClient(agent('mallory'));
    // Kind 1, on one of alice's codes: decrypts, pads, parses, but has no canonical form. Before,
    // that was an exception: alice closed the connection unacknowledged, and the relay delivered
    // it first again at every connection, with all her mail queued behind it.
    for (const [what, text] of UNWRITABLE) {
      const code = await alice.invite({ name: 'poison' }), k = inviteKeys(parseInvite(code.code, now).secret);
      await publish(mal, k.answer_topic, rawFrame(1, k.key, k.answer_topic, pad(utf8(text))));
      ok((await bob.send('alice', say(`behind ${what}`))).status === 'sent', `bob writes to alice behind a kind 1 frame holding ${what}`);
      const box = await alice.inbox();
      ok(!box.offline && box.dropped.plaintext === 1 && box.messages.some((m) => m.content === `behind ${what}`), `kind 1 with ${what}: dropped as plaintext, bob's message delivered (${JSON.stringify(box.dropped)}${box.offline ? `, offline: ${box.offline}` : ''})`);
      ok(!alice.contacts().invites.some((p) => p.name === 'poison'), `and the code is spent: acknowledging that delivery killed its topic at the relay`);
    }
    // Kind 4 on bob's mailbox to alice, sealed under the notice key: any contact (or a thief of K) can.
    const K = Buffer.from(storeOf(B).contacts[A.original].pair_key, 'hex'), nk = noticeKey(K, B.original, A.original), t = topic(K, B.original, A.original, isoWeek(now));
    // A notice is {bundle, proof}: the proof signed by the key the chain ends at (signer), for this pairing.
    const proofBy = (signer, did) => { const body = { v: CARRIER_V, typ: TYP_NOTICE, did, pair: pairId(K) }; return { body, sig: sign(signer.secret, body) }; };
    const notice = (bundle, proof = proofBy(B, B.did)) => seal(4, nk, t, { bundle, proof });
    const G = agent('george');
    rotateAgent(G);
    // The audit's case: bob, a contact holding K, ends his chain at a third party's public genesis.
    // A voluntary rotation needs only bob's key and the commitment carried forward, so dora's
    // genesis made with bob's commitment is enough: the chain verifies, and resolves to dora's DID.
    // Merged, alice's store filed dora's DIDs under bob (her own answers then refused, messages to
    // her DID queued for bob). bob holds no key of dora's, so no proof for that chain verifies.
    const dora = keygen({ seed: seed('dora'), recovery: B.bundle.genesis.recovery, created: CREATED, nonce: seed('dora nonce').slice(0, 16) });
    const intoDora = { ...B.bundle, rotations: [rotate({ genesis: B.bundle.genesis, next_genesis: dora.genesis, iat: now, reason: 'voluntary', secret: B.secret })] };
    const hostile = [
      ...UNWRITABLE.map(([, text]) => rawFrame(4, nk, t, pad(utf8(text)))),                                        // plaintext ×3
      notice({ ...B.bundle, attestations: [{ body: { x: 1 }, sig: 'y' }] }),                                         // bundle: not a chain only
      notice({ ...B.bundle, rotations: Array.from({ length: MAX_ROTATIONS + 1 }, (_, i) => ({ body: { i }, sig: 'z' })) }),  // bundle: past the cap, unverified
      notice(G.bundle, proofBy(G, G.did)),                                                                            // notice_chain: another identity's chain
      notice(B.bundle),                                                                                               // nothing new: skipped
      notice(B.bundle),
      notice(C.bundle),                                                                                               // no rotation to merge: skipped unchecked
      notice({ ...B.bundle, rotations: G.bundle.rotations }),                                                         // a rotation no walk from bob's genesis reaches
      notice(intoDora),                                                                                               // notice_sig: the proof names bob, the chain ends at dora
      notice(intoDora, proofBy(B, dora.did)),                                                                         // notice_sig: names dora, signed by bob
    ];
    for (const f of hostile) await publish(mal, t, f);
    mal.end(true);
    ok((await bob.send('alice', say('behind the notices'))).status === 'sent', 'bob writes to alice behind eleven hostile notices');
    const t0 = Date.now(), box = await alice.inbox();
    ok(!box.offline && box.messages.some((m) => m.content === 'behind the notices'), `alice receives it (${box.offline ?? 'online'})`);
    ok(box.dropped.plaintext === 3 && box.dropped.bundle === 2 && box.dropped.notice_chain === 1 && box.dropped.notice_sig === 2,
      `kind 4: 3 plaintext, 2 bundle (an attestation; ${MAX_ROTATIONS + 1} rotations, refused before any signature check), 1 notice_chain, 2 notice_sig (${JSON.stringify(box.dropped)})`);
    ok(storeOf(A).contacts[B.original].current_did === B.did && !storeOf(A).contacts[B.original].chain.includes(dora.did) && !Object.values(storeOf(A).contacts).some((x) => x.chain.includes(dora.did)),
      'a chain ending at a genesis whose key its sender does not hold: refused before the store sees it; no record holds dora\'s DID');
    ok(seen('alice', (e) => e.type === 'dropped' && e.check === 'bundle' && /more than 64/.test(e.detail)).length === 1, 'the long one is refused by the cap, not by a signature check');
    ok(!box.events.some((e) => e.type === 'rotated') && Date.now() - t0 < 15000, 'a notice bringing no rotation alice has not merged (bob\'s own, twice; carol\'s) is skipped unchecked: no event, nothing counted');
    ok(storeOf(A).contacts[B.original].rotations.length === 0, 'a rotation no walk from bob\'s genesis reaches is merged and not kept: the store keeps the chain followed, so nobody holding K can grow it');
  }

  // ================================================================ an answer naming another code than its topic's
  {
    const mal = await rawClient(agent('mallory'));
    const one = await alice.invite({ name: 'one' }), two = await alice.invite({ name: 'two' });
    const c1 = parseInvite(one.code, now), c2 = parseInvite(two.code, now), k1 = inviteKeys(c1.secret), M = agent('mallory');
    const answer = buildAnswer({ code: c2, identity: { secret: M.secret, genesis: M.bundle.genesis }, bundle: M.bundle, kem_pk: kemKey().pk, prekeys: null });
    await publish(mal, k1.answer_topic, seal(1, k1.key, k1.answer_topic, answer));
    mal.end(true);
    const box = await alice.inbox(), left = alice.contacts().invites.map((p) => p.name);
    ok(box.dropped.challenge_unknown === 1 && !left.includes('one') && left.includes('two'), `on code one's topic, an answer to code two: challenge_unknown; one is spent (its topic is dead), two is not (${left.join()})`);
  }

  // ================================================================ a code that re-wraps another's secret
  {
    // Mallory holds a code alice gave her and re-wraps its secret in a code naming herself (the
    // checksum is no MAC). bob, alice's contact, answers it meaning to pair with mallory, and his
    // answer lands on alice's answer topic, which the secret alone sets. His proof's nonce hashes
    // the code he read, which alice never made: dropped, and alice's pairing with bob stays as it
    // was. Before, she re-keyed bob to a K he never derived, and the pairing died both ways.
    const k0 = storeOf(A).contacts[B.original].pair_key, M = agent('mallory');
    const forMallory = parseInvite((await alice.invite({ name: 'mallory' })).code, now);
    const forged = makeInvite({ did: M.did, relay: forMallory.relay, now, ttl: forMallory.exp - now, secret: forMallory.secret });
    ok((await bob.accept(forged.text, { name: 'mallory', wait: 0.3 })).status === 'waiting', 'bob answers the code naming mallory');
    const box = await alice.inbox();
    ok(box.dropped.challenge_unknown === 1 && !box.events.some((e) => e.type === 'paired') && storeOf(A).contacts[B.original].pair_key === k0,
      `alice drops bob's answer to the re-wrapped code (challenge_unknown) and keeps her key with bob (${JSON.stringify(box.dropped)})`);
    ok((await bob.send('alice', say('after the re-wrapped code'))).status === 'sent' && (await alice.inbox()).messages.some((m) => m.content === 'after the re-wrapped code'),
      'bob and alice still read each other');
  }

  // ================================================================ a delivery that fails three times is dropped
  {
    // bob's session for alice made unreadable: opening anything from her throws a TypeError, an
    // exception nobody named. The first two deliveries close the connection unacknowledged (this
    // process failing); the third, with bob's files sound each time, drops it as undeliverable.
    const file = pathsFor(join(dir, 'bob.local.json')).state, saved = readFileSync(file);
    editState(B, (s) => { s.peers[A.original].session.in.epochs = 7; });
    ok((await alice.send('bob', 'into a broken state')).status === 'sent', 'alice writes to bob');
    const tries = [], held = () => q('SELECT count(*) AS n FROM messages WHERE account = ?', accountOf(B.original))[0].n;
    for (let i = 0; i < 4; i++) { const r = await bob.inbox(); tries.push(r.dropped.undeliverable ? 'dropped' : `held ${held()}`); if (r.dropped.undeliverable) break; }
    ok(tries.join() === 'held 1,held 1,dropped' && held() === 0, `two connections leave it unacknowledged at the relay, the third drops it (${tries.join()})`);
    writeFileSync(file, saved);   // bob's session as it was: alice's next message opens past the lost one
    ok((await alice.send('bob', say('after the undeliverable'))).status === 'sent' && (await bob.inbox()).messages.some((m) => m.content === 'after the undeliverable'), 'and the next one arrives');
  }

  // ================================================================ staying connected
  await alice.start();
  await bob.start();
  ok(await until(() => seen('alice', (e) => e.type === 'connected').length > 0 && seen('bob', (e) => e.type === 'connected').length > 0), 'both carriers connect and stay connected');
  ok((await alice.send('bob', say('live 1'))).status === 'sent', 'a send while connected');
  ok(await until(() => texts('bob').includes('live 1')), 'bob\'s carrier delivers it as it arrives');

  // ================================================================ offline across a week boundary
  await bob.stop();
  now += DAY;   // Monday: alice writes in a week bob has not been online in
  ok(isoWeek(now) !== isoWeek(now - DAY), 'the day offline crosses into a new ISO week');
  for (let i = 0; i < 5; i++) ok((await alice.send('bob', say(`while away ${i}`))).status === 'sent', `send while bob is offline ${i}`);
  ok(q('SELECT count(*) AS n FROM messages WHERE account = ?', accountOf(B.original))[0].n === 5, 'the relay queues the five for bob (he claimed next week\'s mailbox before he left)');
  const held = q('SELECT topic, payload FROM messages WHERE account = ? ORDER BY id', accountOf(B.original));
  blind('while bob is offline');
  await bob.start();
  ok(await until(() => texts('bob').filter((t) => t.startsWith('while away')).length === 5), 'bob, back, receives all five');
  ok(texts('bob').filter((t) => t.startsWith('while away')).join('|') === [0, 1, 2, 3, 4].map((i) => `while away ${i}`).join('|'), 'in order');
  ok(await until(() => q('SELECT count(*) AS n FROM messages WHERE account = ?', accountOf(B.original))[0].n === 0), 'acknowledged, they leave the relay');

  // ================================================================ a hostile writer, a replaying relay
  {
    const mal = await rawClient(agent('mallory')), d0 = seen('bob', (e) => e.type === 'dropped').length;
    const forged = new Uint8Array(22 + 24 + 256 + 16);
    forged.set(createHash('sha256').update('forged').digest().subarray(0, 16), 2);   // an epoch nobody began, counter 7
    forged[0] = 1; forged[21] = 7;
    for (const [what, payload] of [['replayed', held[0].payload], ['forged', forged]]) {
      await new Promise((resolve) => mal.publish(held[0].topic, Buffer.from(payload), { qos: 1 }, resolve));
    }
    mal.end(true);
    const drops = () => seen('bob', (e) => e.type === 'dropped').slice(d0);
    ok(await until(() => drops().length === 2), 'bob\'s carrier drops both');
    ok(drops().map((e) => e.check).join() === 'replay,epoch_unknown', `by name: the copy fails replay, the forgery epoch_unknown (${drops().map((e) => e.check).join()})`);
    const after = await bob.inbox();
    ok(after.dropped.replay >= 1 && after.dropped.epoch_unknown >= 1 && !after.messages.some((m) => !String(m.content).startsWith('while away') && m.content !== 'live 1'), 'inbox reports them counted, never as messages');
  }

  // ================================================================ a rotation mid-conversation
  const before = A.did;
  rotateAgent(A);
  secrets.add(A.did);
  ok(A.did !== before, 'alice rotates her key (her identity file changes under the carrier)');
  ok((await alice.send('bob', say('after rotation'))).status === 'sent', 'alice sends under her new key');
  ok(await until(() => texts('bob').includes('after rotation')), 'bob receives it');
  const rot = seen('bob', (e) => e.type === 'message' && e.content === 'after rotation')[0];
  ok(rot?.from === A.original && rot?.current_did === A.did, 'from alice\'s original DID, signed by her new current DID');
  ok(rot?.last_resort === true, 'in an epoch on bob\'s last-resort key (her state may be a thief\'s copy), and the message says so');
  ok(seen('bob', (e) => e.type === 'rotated' && e.did === A.original && e.current_did === A.did).length === 1, 'bob\'s store merged her rotation from her notice');
  ok(bob.contacts().contacts[0].current_did === A.did, 'bob\'s contact record follows her current DID');
  ok((await bob.send('alice', say('reply after rotation'))).status === 'sent', 'bob answers: alice\'s fresh prekeys came right after her notice');
  ok(await until(() => texts('alice').includes('reply after rotation')), 'alice receives it under her new key');

  // ================================================================ prekeys replenished over the mailbox
  // Each epoch begins on one of bob's one-time prekeys. Here each message begins one, as if the
  // relay had lost each epoch's first envelope (alice's state forgets the epoch): bob's keys fall
  // below five and he sends a fresh bundle to alice inside their mailbox, his last one being an
  // hour old (prekeys.mjs REISSUE; a minute more: bundles issued within one second here got iat
  // one apart, a little ahead of the clock).
  await alice.stop();
  const left = oneTimeLeft(B, A);
  ok(left >= 5, `bob holds one-time keys for alice (${left} left; her rotation had him list twenty fresh ones, and her epoch on his last-resort key kept them)`);
  now += 3660;
  const sentBefore = seen('bob', (e) => e.type === 'sent' && e.control === 'prekeys').length, pk = seen('alice', (e) => e.type === 'prekeys').length;
  for (let i = 0; i < left - 4; i++) {
    editState(A, (s) => { s.peers[B.original].session.out.epoch = null; });
    ok((await alice.send('bob', say(`epoch ${i}`))).status === 'sent', `message ${i} begins a new epoch`);
  }
  ok(await until(() => texts('bob').includes(`epoch ${left - 5}`)), 'bob opens every one of them');
  ok(await until(() => seen('bob', (e) => e.type === 'sent' && e.control === 'prekeys').length === sentBefore + 1), 'below five, bob sends a fresh prekey bundle');
  ok(oneTimeLeft(B, A) === 20, 'bob holds twenty one-time keys again');
  await alice.inbox();
  ok(seen('alice', (e) => e.type === 'prekeys').length === pk + 1, 'alice accepts the fresh bundle');
  ok((await alice.send('bob', say('on fresh prekeys'))).status === 'sent' && await until(() => texts('bob').includes('on fresh prekeys')), 'and the conversation goes on');

  // ================================================================ the relay's refusals, by name
  editState(A, (s) => { s.peers[B.original].session.out.epoch = null; });
  await refuses(() => alice.send('bob', 'x'.repeat(300 * 1024)), 'too_large', 'a 300 KB message to a free reader');
  ok(seen('alice', (e) => e.type === 'refused' && e.code === 'too_large').length === 1, 'the refusal came as the relay\'s $sigelo/notice');
  ok((await alice.send('bob', say('after too_large'))).status === 'sent' && await until(() => texts('bob').includes('after too_large')),
    'the refused message began an epoch; the next one begins another, and arrives');
  // Review of the epoch recovery: a message whose JCS falls in the last 256 bytes below 1 MiB, its
  // envelope carrying the encapsulation, is 1,049,774 bytes. The relay closed the connection on it
  // with no notice, the frame stayed pending, and went first at every later connection: nothing
  // else reached bob. Now refused here, before it is queued.
  editState(A, (s) => { s.peers[B.original].session.out.epoch = null; });
  await refuses(() => alice.send('bob', 'x'.repeat(1048076)), 'message_too_large', 'a carrying envelope longer than a relay takes in one packet');
  ok(stateOf(A).pending.length === 0 && stateOf(A).peers[B.original].outbox.length === 0 && stateOf(A).peers[B.original].session.out.epoch === null,
    'nothing is queued, and no epoch is begun for it');
  ok((await alice.send('bob', say('after message_too_large'))).status === 'sent' && await until(() => texts('bob').includes('after message_too_large')),
    'the next message goes, and arrives');
  // The relay no longer holds this identity's proof of work (it goes with an idle account; here the
  // row alone). A message refused "pow" stays pending: the carrier logs in again with a proof.
  relay.db.raw.prepare('DELETE FROM pow_proofs WHERE account = ?').run(accountOf(A.original));
  ok((await alice.send('bob', say('after the proof was forgotten'))).status === 'sent' && await until(() => texts('bob').includes('after the proof was forgotten')),
    'a message the relay refused for want of a proof of work goes after a login with one, not lost');
  // An operator with no contact logs in by `inbox` (relay/site/pro.md step 2): the relay keeps its
  // account only once it has proven work, and takes its licence only then.
  {
    const P = agent('pia'), pia = make(P);
    const pb = await pia.inbox();
    ok(!pb.offline && relay.db.account(accountOf(P.original)) !== undefined && stateOf(P).relays[HOST]?.proven === true,
      `inbox with no contact logs in at the agent's own relay, with a proof of work: the relay keeps its account (${pb.offline ?? 'online'})`);
  }

  // ================================================================ a relay restart, reconnect with backoff
  await alice.start();
  ok(await until(() => seen('alice', (e) => e.type === 'connected').length >= 3), 'alice connected again');
  const ca = seen('alice', (e) => e.type === 'connected').length, cb = seen('bob', (e) => e.type === 'connected').length;
  await relay.close();
  relay = await startRelay({ ...cfg, tcpPort: Number(new URL(endpoints[HOST].mqtt).port), httpPort: Number(new URL(endpoints[HOST].http).port) });
  ok(await until(() => seen('alice', (e) => e.type === 'connected').length > ca && seen('bob', (e) => e.type === 'connected').length > cb, 15000),
    'both reconnect on their own; alice logs in with her rotated chain, which the relay kept');
  ok(seen('bob', (e) => e.type === 'disconnected').length > 0, 'bob saw the connection drop');
  ok((await alice.send('bob', say('after restart'))).status === 'sent' && await until(() => texts('bob').includes('after restart')), 'delivery continues after the restart');

  // ================================================================ a client signs no other relay's challenge
  const M = agent('mallory'), mallory = make(M, { relay: 'other.test', endpoints: { 'other.test': endpoints[HOST] } });
  await refuses(() => mallory.invite(), 'challenge', 'a relay answering with another relay\'s challenge (ctx)');
  ok(mallory.contacts().invites.length === 0, 'and the invite it would have printed is withdrawn');
  {
    // A relay answering GET /challenge with a SPEC §5.2 challenge for its own name: what a world
    // gets signed by sign-challenge. The carrier signs only its own login body, never this.
    const fake = createServer((req, res) => {
      const url = new URL(req.url, 'http://x');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ challenge: { v: 'sigelo/0', typ: 'challenge', did: url.searchParams.get('did'), ctx: 'oracle.test', nonce: randomBytes(32).toString('base64url') }, pow_bits: 0 }));
    });
    await new Promise((r) => fake.listen(0, '127.0.0.1', r));
    const W = agent('wren'), wren = make(W, { relay: 'oracle.test', endpoints: { 'oracle.test': { mqtt: 'mqtt://127.0.0.1:9', http: `http://127.0.0.1:${fake.address().port}` } } });
    await refuses(() => wren.invite(), 'challenge', 'a relay answering GET /challenge with a SPEC §5.2 challenge for its own name');
    fake.closeAllConnections();
    await new Promise((r) => fake.close(r));
  }
  ok(await solvePow('relay.test', A.original, 'n', 8) === await solvePow('relay.test', A.original, 'n', 8), 'the proof of work is deterministic');
  ok(await solvePow('relay.test', A.original, 'n', 48, Date.now() + 200) === null, 'and stops at its deadline, before the challenge would expire');

  // ================================================================ a thief's rotation loses to recovery
  {
    // A thief copies alice's key and her contact files, rotates 63 times to keys of its own and
    // writes to bob. Nothing offline tells that chain from hers: bob follows it. Then alice
    // recovers with her offline recovery key, and her chain beats the thief's at bob's store and at
    // the relay. 63: with alice's one rotation, bob holds 64, the most a notice may carry. Counted
    // with what bob held, her recovery notice was refused, and every notice of hers after it.
    await alice.stop();
    const T = { ...A, label: 'thief', bundle: structuredClone(A.bundle) };
    for (const k of ['store', 'state']) copyFileSync(pathsFor(join(dir, 'alice.local.json'))[k], pathsFor(join(dir, 'thief.local.json'))[k]);
    for (let i = 0; i < 63; i++) rotateAgent(T);
    secrets.add(T.did);
    const thief = make(T), heldBy = (x) => storeOf(x).contacts[A.original];
    ok((await thief.send('bob', say('from the thief'))).status === 'sent' && await until(() => texts('bob').includes('from the thief')), 'the thief, holding alice\'s key and files, rotates 63 times and writes to bob');
    ok(bob.contacts().contacts.find((c) => c.did === A.original).current_did === T.did && heldBy(B).rotations.length === 64, 'bob follows the thief\'s chain, 64 rotations: nothing offline can tell it from alice\'s');
    // A message alice queued for bob before the recovery, as a send that returned `queued` leaves
    // it: that send has exited, so only her inbox can tell her it never went.
    const QUEUED = 'queued-before-the-recovery';
    editState(A, (s) => s.peers[B.original].outbox.push({ id: QUEUED, label: '', content: say('queued before the recovery') }));
    recoverAgent(A);
    const recovered = A.did;
    secrets.add(recovered);
    // The thief copied K with the key: after the recovery both sides hold it as burned (re_pair).
    ok(marked(alice, B) === 'own_recovery' && storeOf(A).contacts[B.original].re_pair === 'own_recovery', 'alice recovers: her store marks bob re_pair, own_recovery, before any connection');
    await refuses(() => alice.send('bob', 'after recovery'), 're_pair', 'and she sends him nothing under the old K');
    const afterRecovery = (await alice.inbox()).events;
    ok(afterRecovery.some((e) => e.type === 're_pair' && e.did === B.original && e.re_pair === 'own_recovery'), 'her next inbox says so');
    ok(afterRecovery.some((e) => e.type === 'refused' && e.id === QUEUED && e.peer === B.original && e.code === 're_pair')
      && stateOf(A).peers[B.original].outbox.length === 0 && seen('alice', (e) => e.type === 'refused' && e.id === QUEUED).length === 1,
    'and that the message queued for him before the recovery was refused, unsent (a refused event, code re_pair)');
    ok(await until(() => heldBy(B).current_did === recovered), 'her rotation notice still goes: bob\'s store merged both chains, the recovery wins (SPEC §7.1)');
    ok(heldBy(B).rotations.length === 2, `and keeps the chain followed: her first rotation and the recovery, the thief's fork gone (${heldBy(B).rotations.length})`);
    ok(marked(bob, A) === 'contact_recovery' && seen('bob', (e) => e.type === 'rotated' && e.current_did === recovered && e.re_pair === 'contact_recovery').length === 1,
      'bob marks alice re_pair, contact_recovery, and his rotated event says so');
    // She rotates again. First a notice from whoever holds K, with a copy of that rotation whose
    // signature is not valid ahead of the real one: refused, and bob's record left as it was.
    rotateAgent(A);
    secrets.add(A.did);
    {
      const K = Buffer.from(heldBy(B).pair_key, 'hex'), t = topic(K, A.original, B.original, isoWeek(now)), real = A.bundle.rotations.at(-1);
      const mal = await rawClient(agent('mallory'));
      const body = { v: CARRIER_V, typ: TYP_NOTICE, did: A.did, pair: pairId(K) };
      await publish(mal, t, seal(4, noticeKey(K, A.original, B.original), t,
        { bundle: { ...A.bundle, rotations: [...A.bundle.rotations.slice(0, -1), { ...real, sig: A.bundle.rotations[0].sig }, real] }, proof: { body, sig: sign(A.secret, body) } }));
      mal.end(true);
      ok(await until(() => seen('bob', (e) => e.type === 'dropped' && e.check === 'bundle' && /two rotations on one edge/.test(e.detail)).length === 1), 'a notice with two rotations on one edge, the first not valid: refused');
      ok(heldBy(B).current_did === recovered && heldBy(B).rotations.length === 2, 'and bob\'s record is as it was');
    }
    await alice.inbox();
    ok(await until(() => heldBy(B).current_did === A.did) && heldBy(B).rotations.length === 3 && heldBy(B).re_pair === 'contact_recovery', 'her own notice follows: bob follows her rotation after the recovery, the mark kept');
    await refuses(() => thief.send('bob', 'thief again'), 'bundle', 'the relay, which kept alice\'s recovery, refuses the thief\'s login');
    await refuses(() => bob.send('alice', 'to the recovered key'), 're_pair', 'bob sends nothing to alice under the old K either');
  }

  // ================================================================ pairing again replaces K
  {
    // The thief also copied K, and with it every later mailbox topic of the pair, which it can
    // claim first from any identity. A recovery does not change K, so neither side claims a new
    // mailbox under it (re_pair); pairing again does: a code between two contacts keeps the
    // contact, replaces K, and its topics with it, and clears the mark. A week passes first.
    const K0 = storeOf(A).contacts[B.original].pair_key, K0b = Buffer.from(K0, 'hex');
    now += 7 * DAY;
    await bob.sync();
    await alice.inbox();
    const ahead = isoWeek(now + 7 * DAY), squat = [topic(K0b, B.original, A.original, ahead), topic(K0b, A.original, B.original, ahead)];
    ok(!squat.some((t) => claimsOf(A).includes(t) || claimsOf(B).includes(t)), 'a week after the recovery, neither has claimed next week\'s mailboxes under the burned K');
    const squatter = await rawClient(agent('squatter')), squatted = [], takenBefore = seen('alice', (e) => e.code === 'mailbox_taken').length;
    squatter.on('message', (t) => { if (squat.includes(t)) squatted.push(t); });
    // The SUBACK's codes: MQTT.js hands back the topics asked, at the QoS asked, when one is refused.
    const claim = (topics) => new Promise((resolve) => squatter.subscribe(topics, { qos: 1 }, (_err, _subs, packet) => resolve(packet?.granted ?? [])));
    ok((await claim(squat)).join() === '1,1', 'the thief, holding K0, claims both of them first: the relay cannot tell (the live test\'s squat)');
    const code = (await alice.invite({ name: 'bob again' })).code;
    ok((await bob.accept(code, { name: 'alice', wait: 0.3 })).status === 'waiting', 'bob answers a new code from alice, his contact already');
    const a1 = await alice.inbox();
    ok(a1.events.some((e) => e.type === 'paired' && e.did === B.original && e.rekeyed === true), 'alice: the same contact, re-keyed');
    ok(await until(() => seen('bob', (e) => e.type === 'paired' && e.did === A.original && e.rekeyed === true).length === 1), 'bob: the same, on reading her reply');
    const K1 = storeOf(A).contacts[B.original].pair_key;
    ok(K1 !== K0 && K1 === storeOf(B).contacts[A.original].pair_key, 'both hold a new K, unknown to whoever copied the old one');
    ok(alice.contacts().contacts.filter((c) => c.did === B.original).map((c) => c.name).join() === 'bob', 'one contact, its name kept');
    ok(marked(alice, B) === null && marked(bob, A) === null, 'and neither marks the other any more: the new K is not burned');
    await alice.inbox();   // bob's prekeys for the new pairing
    ok((await alice.send('bob', say('under the new K'))).status === 'sent' && await until(() => texts('bob').includes('under the new K')), 'alice writes under the new K, bob reads it');
    ok(seen('bob', (e) => e.type === 'message' && e.content === 'under the new K')[0]?.current_did === A.did, 'signed by her key after the recovery');
    ok((await bob.send('alice', say('back under the new K'))).status === 'sent' && (await alice.inbox()).messages.some((m) => m.content === 'back under the new K'), 'and back');
    // Next week's mailboxes of the pair are now K1's, held ahead by the pair: a thief with K0 cannot
    // derive them, and one that learnt them could not claim them.
    const K1b = Buffer.from(K1, 'hex'), theirs = [topic(K1b, B.original, A.original, ahead), topic(K1b, A.original, B.original, ahead)];
    ok(await until(() => claimsOf(A).includes(theirs[0]) && claimsOf(B).includes(theirs[1])), 'next week\'s mailboxes under the new K are already claimed, each by its reader');
    const refused = await claim(theirs);
    ok(refused.join() === '128,128', `claimed by anyone else: refused (mailbox_taken; SUBACK ${refused.join()})`);
    now += 7 * DAY;
    await alice.inbox();
    ok((await bob.send('alice', say('next week, under the new K'))).status === 'sent' && (await alice.inbox()).messages.some((m) => m.content === 'next week, under the new K'),
      'a week later bob writes in that week\'s mailbox and alice reads it');
    await sleep(300);
    squatter.end(true);
    ok(squatted.length === 0 && seen('alice', (e) => e.code === 'mailbox_taken').length === takenBefore, `the thief's mailboxes under K0 got nothing (${squatted.length}), and alice never met mailbox_taken`);
  }

  // ================================================================ the MCP tools: the same verbs
  {
    const mcp = await import(pathToFileURL(join(HERE, '..', 'integrations', 'mcp', 'contact.mjs')).href);
    const id = await import(pathToFileURL(join(HERE, '..', 'adapters', 'moadim', 'sigelo-agent.ts')).href);
    const env = { SIGELO_RELAY: HOST, SIGELO_RELAY_ENDPOINTS: JSON.stringify(endpoints) };
    const tools = await mcp.load({ installed: false, id, env, clock: () => now });
    ok(tools && tools.tools.map(([n]) => n).join() === 'sigelo_invite,sigelo_accept,sigelo_contacts,sigelo_send,sigelo_inbox,sigelo_forget_contact', 'the MCP module lists the six tools');
    ok(tools.tools.every(([, d, s]) => typeof d === 'string' && s.type === 'object' && s.additionalProperties === false && s.properties.identity), 'each with a closed schema and the profile argument');
    const daveFile = join(dir, 'dave.local.json');
    id.init(daveFile, keygen({ seed: seed('dave recovery'), recovery: 'sha256:' + '0'.repeat(64) }).key);
    const daveDid = id.chainOf(id.load(daveFile))[0];
    secrets.add(daveDid);
    const h = tools.handlers;
    // sigelo_inbox answers its result, or that result rendered as the text the client gets (a
    // handler's { text } goes through server.mjs as it is).
    const inboxOf = async (args) => { const r = await h.sigelo_inbox(args, daveFile); return typeof r?.text === 'string' ? JSON.parse(r.text) : r; };
    const code = await h.sigelo_invite({ name: 'bob' }, daveFile);
    ok(code.code.startsWith('sgl1'), 'sigelo_invite: a code');
    ok((await bob.accept(code.code, { name: 'dave', wait: 0.3 })).status === 'waiting', 'bob answers dave\'s code');
    const di = await inboxOf({});
    ok(di.events.some((e) => e.type === 'paired' && e.name === 'bob') && /pairings/.test(tools.tools.find(([n]) => n === 'sigelo_inbox')[1]), 'sigelo_inbox returns the pairing, as its description says');
    ok(await until(() => seen('bob', (e) => e.type === 'paired' && e.did === daveDid).length === 1), 'dave\'s sigelo_inbox replies; bob is paired with dave');
    await until(() => seen('bob', (e) => e.type === 'sent' && e.control === 'prekeys' && e.peer === daveDid).length === 1);
    await inboxOf({ wait: 1 });
    const s = await h.sigelo_send({ to: 'bob', text: say('from dave') }, daveFile);
    ok(s.status === 'sent', `sigelo_send (${s.status})`);
    ok(await until(() => texts('bob').includes('from dave')), 'bob receives dave\'s message');
    ok((await bob.send(daveDid, say('to dave'))).status === 'sent', 'bob answers dave');
    const got = await inboxOf({ wait: 2 });
    ok(got.messages.length === 1 && got.messages[0].content === 'to dave' && got.messages[0].from === B.original, 'sigelo_inbox: bob\'s answer');
    const list = await h.sigelo_contacts({}, daveFile);
    ok(list.contacts.length === 1 && list.contacts[0].did === B.original, 'sigelo_contacts');
    const gone = await h.sigelo_forget_contact({ did: B.original }, daveFile);
    ok(gone.revoked === true && gone.released === true, 'sigelo_forget_contact: revoked, its mailboxes given up at the relay');
  }

  // ================================================================ replies that cannot reach the answerer
  const kinds = (box) => box.events.map((e) => `${e.type}${e.code ? `:${e.code}` : ''}`).join();
  {
    // 30 attestation-sized items in the inviter's bundle: the reply used to carry the whole bundle
    // beside 21 prekeys (~35 KB), past the invite topic's 64 KB, refused with nobody told.
    const H = agent('hana'), I = agent('ivan');
    H.bundle.attestations = Array.from({ length: 30 }, (_, i) => ({ body: { i, claims: 'x'.repeat(1000) }, sig: 'y' }));
    const hana = make(H), ivan = make(I);
    const code = (await hana.invite({ name: 'ivan' })).code;
    ok((await ivan.accept(code, { name: 'hana', wait: 0.3 })).status === 'waiting', 'ivan answers the code of hana, whose bundle holds 30 KB of attestations');
    const hb = await hana.inbox();
    // Her two answers to the hop codes above (queued, never delivered) expired meanwhile: said once each.
    const lapsed = hb.events.filter((e) => e.code === 'code_expired');
    ok(kinds({ events: hb.events.filter((e) => e.code !== 'code_expired') }) === 'paired' && lapsed.length === 2 && lapsed.every((e) => e.type === 'pairing_failed' && e.did === lapsed[0].did)
      && seen('hana', (e) => e.type === 'refused').length === 0, `hana pairs and the relay takes her reply, which carries her chain only; her two hop answers reported expired (${kinds(hb)})`);
    ok((await ivan.inbox()).events.some((e) => e.type === 'paired' && e.did === H.original), 'ivan pairs');
  }
  {
    // A code holder fills milo's reply topic (4 messages) before lena replies: the relay refuses
    // her reply. Before, lena kept as a contact someone who never heard of her.
    const L = agent('lena'), Mi = agent('milo'), lena = make(L), milo = make(Mi);
    const code = (await lena.invite({ name: 'milo' })).code;
    ok((await milo.accept(code, { name: 'lena', wait: 0.3 })).status === 'waiting', 'milo answers lena\'s code');
    const k = inviteKeys(parseInvite(code, now).secret), mal = await rawClient(agent('mallory'));
    for (let i = 0; i < 4; i++) await publish(mal, k.reply_topic, randomBytes(400));
    mal.end(true);
    const lb = await lena.inbox();
    ok(kinds(lb) === 'paired,pairing_failed:quota_storage', `lena's inbox: paired, then the refusal by name (${kinds(lb)})`);
    ok(lena.contacts().contacts.length === 0 && stateOf(L).pending.length === 0, 'and she keeps no contact: the half pairing is undone');
  }
  {
    // A chain of 52 rotations (~30 KB) and 21 prekeys pass 64 KB: refused before it is queued.
    const J = agent('june'), Ki = agent('kim');
    for (let i = 0; i < 52; i++) rotateAgent(J);
    const june = make(J), kim = make(Ki);
    const code = (await june.invite({ name: 'kim' })).code;
    ok((await kim.accept(code, { name: 'june', wait: 0.3 })).status === 'waiting', 'kim answers the code of june, 52 rotations long');
    const jb = await june.inbox();
    ok(kinds(jb) === 'pairing_failed:too_large' && june.contacts().contacts.length === 0 && stateOf(J).pending.length === 0, `june's reply would pass 64 KB: nothing is queued, no contact kept, and her inbox says why (${kinds(jb)})`);
  }
  {
    // Kind 2 on frank's reply topic, from a code holder: dropped, and the answer it killed is spent.
    const E = agent('erin'), F = agent('frank'), erin = make(E), frank = make(F);
    const code = (await erin.invite({ name: 'frank' })).code;
    ok((await frank.accept(code, { name: 'erin', wait: 0.3 })).status === 'waiting', 'frank answers erin\'s code');
    const k = inviteKeys(parseInvite(code, now).secret), mal = await rawClient(agent('mallory'));
    await publish(mal, k.reply_topic, rawFrame(2, k.key, k.reply_topic, pad(utf8(UNWRITABLE[1][1]))));
    mal.end(true);
    const fb = await frank.inbox();
    ok(!fb.offline && fb.dropped.plaintext === 1, `kind 2 holding a lone surrogate: dropped as plaintext (${JSON.stringify(fb.dropped)})`);
    ok(frank.contacts().answers.length === 0, 'and frank\'s answer is spent: that delivery killed the reply topic, nothing else can come');
  }

  // ================================================================ a full disk between the handshake's two files
  {
    // Audit finding: the inviter saved her contact store (the code spent, the contact admitted)
    // before her state (the session, the queued reply). A crash or a full disk between the two
    // renames left a contact and no reply, and the answer's next delivery was dropped as
    // challenge_unknown: the invitee waited until his code expired and every send to him was
    // refused no_reader; on a re-key she held a K he never derived. The invitee likewise. Now the
    // state is written first and the store after it; a write failing at either step leaves the
    // code or the answer unspent and the delivery unacknowledged, and the next one pairs.
    const files = (a) => pathsFor(join(dir, `${a.label}.local.json`)), holds = (a, b) => Boolean(storeOf(a).contacts[b.original]);
    const Ro = agent('rosa'), Sa = agent('saul'), rosa = make(Ro), saul = make(Sa);
    ok((await saul.accept((await rosa.invite({ name: 'saul' })).code, { name: 'rosa', wait: 0.3 })).status === 'waiting', 'saul answers rosa\'s code');
    let f = failRenameOnce(files(Ro).state, (x) => JSON.parse(x).pending.some((p) => p.control === 'reply'));
    await rosa.inbox();
    f.restore();
    ok(f.fired() && !holds(Ro, Sa) && rosa.contacts().invites.some((p) => p.name === 'saul'),
      `rosa's state write carrying her reply fails: her store holds no contact and the code is unspent (contact: ${holds(Ro, Sa)})`);
    ok((await rosa.inbox()).events.some((e) => e.type === 'paired' && e.did === Sa.original) && holds(Ro, Sa), 'her next connection gets the answer again: she pairs, and her reply goes');
    ok((await saul.inbox()).events.some((e) => e.type === 'paired' && e.did === Ro.original), 'saul reads the reply: paired');
    await rosa.inbox();   // saul's prekeys
    ok((await rosa.send('saul', say('after the full disk'))).status === 'sent' && (await saul.inbox()).messages.some((m) => m.content === 'after the full disk'), 'rosa writes to saul, and he reads it');
    ok((await saul.send('rosa', say('saul answers'))).status === 'sent' && (await rosa.inbox()).messages.some((m) => m.content === 'saul answers'), 'and back');
    // A re-key, the store's write failing after the state's: the reply the state kept names the
    // code's reply topic, and is put back before the answer runs again; its K never goes out.
    const K0 = storeOf(Ro).contacts[Sa.original].pair_key;
    ok((await saul.accept((await rosa.invite({ name: 'saul again' })).code, { name: 'rosa', wait: 0.3 })).status === 'waiting', 'saul answers a fresh code of hers: a re-key');
    f = failRenameOnce(files(Ro).store, (x) => { const c = JSON.parse(x).contacts[Sa.original]; return Boolean(c) && c.pair_key !== K0; });
    await rosa.inbox();
    f.restore();
    ok(f.fired() && storeOf(Ro).contacts[Sa.original].pair_key === K0 && rosa.contacts().invites.some((p) => p.name === 'saul again'),
      'rosa\'s store write with the new K fails after her state\'s: the store keeps the old K and the code');
    const r2 = await rosa.inbox();
    ok(r2.events.some((e) => e.type === 'paired' && e.rekeyed) && stateOf(Ro).pending.every((p) => p.control !== 'reply'), 'her next connection runs the answer again: re-keyed, and one reply sent');
    ok((await saul.inbox()).events.some((e) => e.type === 'paired' && e.rekeyed), 'saul re-keys on her reply');
    const K1 = storeOf(Ro).contacts[Sa.original].pair_key;
    ok(K1 !== K0 && K1 === storeOf(Sa).contacts[Ro.original].pair_key, 'both hold the same new K');
    await rosa.inbox();
    ok((await rosa.send('saul', say('under the K after the full disk'))).status === 'sent' && (await saul.inbox()).messages.some((m) => m.content === 'under the K after the full disk'), 'rosa writes under it, saul reads');
    ok((await saul.send('rosa', say('saul under the new K'))).status === 'sent' && (await rosa.inbox()).messages.some((m) => m.content === 'saul under the new K'), 'and back');
    // The invitee: his store's write admitting her fails after his state's.
    const In = agent('ines'), Jo = agent('joel'), ines = make(In), joel = make(Jo);
    ok((await joel.accept((await ines.invite({ name: 'joel' })).code, { name: 'ines', wait: 0.3 })).status === 'waiting', 'joel answers ines\'s code');
    ok((await ines.inbox()).events.some((e) => e.type === 'paired'), 'ines pairs and replies');
    f = failRenameOnce(files(Jo).store, (x) => Boolean(JSON.parse(x).contacts[In.original]));
    await joel.inbox();
    f.restore();
    ok(f.fired() && !holds(Jo, In) && joel.contacts().answers.length === 1, 'joel\'s store write admitting her fails: his answer stays pending');
    ok((await joel.inbox()).events.some((e) => e.type === 'paired' && e.did === In.original) && holds(Jo, In) && stateOf(Jo).peers[In.original].session.out.prekeys !== null,
      'his next connection reads the reply again: paired, holding her prekeys');
    await ines.inbox();   // joel's prekeys
    ok((await ines.send('joel', say('to joel'))).status === 'sent' && (await joel.inbox()).messages.some((m) => m.content === 'to joel'), 'ines writes to joel, he reads it');
    ok((await joel.send('ines', say('to ines'))).status === 'sent' && (await ines.inbox()).messages.some((m) => m.content === 'to ines'), 'and back');
  }

  // ================================================================ notices from whoever holds K
  {
    // Audit finding: a notice refused after its chain was verified was verified again at every
    // delivery, and again in store.admit: 0.27 s a 64-rotation chain on a phone-class CPU, from
    // anyone holding K (the contact, a thief of either side's state). Now one refused after that
    // check is refused again unchecked, and at most NOTICE_CHECKS notices of a contact's are
    // checked an hour, unless one brings its owner's recovery. Its own relay and clock.
    let t = now;
    const relay4 = await startRelay({ ...cfg, db: join(dir, 'notices.db'), tcpPort: 0, httpPort: 0, clock: () => t, log: () => {} });
    const ep4 = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay4.ports.tcp}`, http: `http://127.0.0.1:${relay4.ports.http}` } };
    const O = agent('odile'), Pi = agent('piet'), odile = make(O, { endpoints: ep4, clock: () => t }), piet = make(Pi, { endpoints: ep4, clock: () => t });
    await piet.accept((await odile.invite({ name: 'piet' })).code, { name: 'odile', wait: 0.3 });
    await odile.inbox(); await piet.inbox(); await odile.inbox();
    rotateAgent(O);
    ok((await odile.send('piet', say('odile rotated'))).status === 'sent' && (await piet.inbox()).messages.some((m) => m.content === 'odile rotated'), 'odile rotates; piet follows her notice and reads her');
    t += 3601;   // a fresh hour for the count
    const K = Buffer.from(storeOf(Pi).contacts[O.original].pair_key, 'hex'), nk = noticeKey(K, O.original, Pi.original), tp = () => topic(K, O.original, Pi.original, isoWeek(t));
    // Each brings a rotation piet does not hold (junk's, which no walk from odile's genesis reaches),
    // so each reaches the check, and fails it at the proof's signature.
    const junk = (i) => { const J = agent(`junk ${i}`); rotateAgent(J); return seal(4, nk, tp(), { bundle: { ...O.bundle, rotations: [...O.bundle.rotations, J.bundle.rotations[0]] },
      proof: { body: { v: CARRIER_V, typ: TYP_NOTICE, did: O.did, pair: pairId(K) }, sig: 'x' } }); };
    const first = junk(0), frames = [first, first, first, first, ...Array.from({ length: NOTICE_CHECKS + 1 }, (_, i) => junk(i + 1))];
    const mal = await rawClient(agent('mallory'), ep4);
    for (const x of frames) await publish(mal, tp(), x);
    await piet.inbox();
    const drops = (f) => seen('piet', (e) => e.type === 'dropped' && f(e)).length;
    ok(drops((e) => e.check === 'notice_sig' && !/refused before/.test(e.detail)) === NOTICE_CHECKS && drops((e) => /refused before \(notice_sig\)/.test(e.detail)) === 3,
      `a refused notice delivered 3 more times is refused unchecked; ${NOTICE_CHECKS} distinct ones are checked within the hour`);
    ok(drops((e) => e.check === 'notice_rate') === 2 && stateOf(Pi).peers[O.original].notices_refused.length === NOTICE_CHECKS, `past ${NOTICE_CHECKS}, the hour's last two are dropped unchecked (notice_rate)`);
    recoverAgent(O);
    const recovered = O.did;
    secrets.add(recovered);
    await refuses(() => odile.send('piet', 'odile recovered'), 're_pair', 'within that hour odile recovers: she writes nothing to piet under the old K');
    await odile.inbox();
    await piet.inbox();
    ok(storeOf(Pi).contacts[O.original].current_did === recovered && storeOf(Pi).contacts[O.original].re_pair === 'contact_recovery',
      'her notice, bringing the recovery, is checked all the same: piet follows it, and marks her re_pair');
    t += 3601;
    await publish(mal, tp(), junk(NOTICE_CHECKS + 2));
    mal.end(true);
    await piet.inbox();
    ok(drops((e) => e.check === 'notice_rate') === 2 && drops((e) => e.check === 'notice_sig' && !/refused before/.test(e.detail)) === NOTICE_CHECKS + 1, 'an hour later a new one is checked again');
    await relay4.close();
  }

  // ================================================================ a lost first envelope does not lose its epoch
  {
    // Its own relay and clock: days pass here. quill and rhea pair, then rhea is away 16 days.
    let t = now;
    const relay3 = await startRelay({ ...cfg, db: join(dir, 'epochs.db'), tcpPort: 0, httpPort: 0, clock: () => t, log: () => {} });
    const ep3 = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay3.ports.tcp}`, http: `http://127.0.0.1:${relay3.ports.http}` } };
    const Q = agent('quill'), Rh = agent('rhea'), quill = make(Q, { endpoints: ep3, clock: () => t }), rhea = make(Rh, { endpoints: ep3, clock: () => t });
    const inv3 = await quill.invite({ name: 'rhea' });
    await rhea.accept(inv3.code, { name: 'quill', wait: 0.3 });
    await quill.inbox(); await rhea.inbox(); await quill.inbox();
    ok((await quill.send('rhea', 'hello')).status === 'sent' && (await rhea.inbox()).messages.length === 1, 'quill and rhea pair and talk');
    // Day 15: quill's epoch is past 7 days, so this message begins one, in an ISO week rhea, away
    // since day 0, never claimed. The relay drops it, and says so: before, quill was told "sent",
    // and every later message of that epoch failed epoch_unknown at rhea. Then it was refused,
    // lost; now it stays queued at quill's, unsealed, and goes once rhea is back.
    t += 15 * DAY;
    const d15 = await quill.send('rhea', 'day 15');
    ok(d15.status === 'queued' && /does not hold its mailbox/.test(d15.detail) && stateOf(Q).peers[Rh.original].outbox.map((x) => x.content).join() === 'day 15',
      `day 15, to a mailbox rhea has not claimed: queued, kept in quill's outbox, not "sent" and not lost (${d15.status}: ${d15.detail})`);
    t += DAY;
    await rhea.inbox();   // back: she claims the weeks around now
    const st5 = [];
    for (let i = 0; i < 5; i++) { t += 3600; st5.push((await quill.send('rhea', `after return ${i}`)).status); }
    const box3 = await rhea.inbox();
    ok(st5.every((x) => x === 'sent') && box3.messages.map((m) => m.content).join() === 'day 15,after return 0,after return 1,after return 2,after return 3,after return 4' && !box3.dropped.epoch_unknown,
      `the kept one goes first, then the next five, in a new epoch (${st5.join()}; ${box3.messages.length} read, dropped ${JSON.stringify(box3.dropped)})`);
    const contents = (box) => box.messages.map((m) => m.content).join();
    const carrying = () => stateOf(Q).peers[Rh.original].session.out.epoch.carry;
    // A relay that acknowledges an epoch's first envelope and throws it away: the next carries the
    // epoch's encapsulation too (relay-plan §11 "Epoch recovery"), so rhea opens it.
    editState(Q, (x) => { x.peers[Rh.original].session.out.epoch = null; });
    ok((await quill.send('rhea', 'withheld')).status === 'sent', 'a message beginning an epoch: acknowledged by the relay');
    relay3.db.raw.prepare('DELETE FROM messages WHERE account = ?').run(accountOf(Rh.original));
    t += 60;
    ok((await quill.send('rhea', 'after the withheld one')).status === 'sent', 'and the next, of that epoch');
    const box4 = await rhea.inbox();
    ok(contents(box4) === 'after the withheld one' && !box4.dropped.epoch_unknown, `rhea opens it: the withheld message is lost, not its epoch (${contents(box4)}; dropped ${JSON.stringify(box4.dropped)})`);
    // rhea away longer than the relay keeps a message: the epoch's first envelope expires unread,
    // its third, written two days later, does not, and begins the epoch when she is back.
    editState(Q, (x) => { x.peers[Rh.original].session.out.epoch = null; });
    t += 60;
    ok((await quill.send('rhea', 'early')).status === 'sent', 'day 0 of an epoch: a message rhea will not read in time');
    t += 2 * DAY;
    ok((await quill.send('rhea', 'late')).status === 'sent' && carrying() === true, 'day 2: the next of that epoch, still carrying its encapsulation (no reply from rhea)');
    t += 5 * DAY + 12 * 3600;
    const box5 = await rhea.inbox();
    ok(contents(box5) === 'late' && !box5.dropped.epoch_unknown, `rhea, back after 7.5 days: "early" expired at the relay, "late" opens and begins the epoch (${contents(box5)}; dropped ${JSON.stringify(box5.dropped)})`);
    // Back, rhea sends her weekly bundle (prekeys.mjs REPLACE_DAYS), which may end quill's epoch.
    // Then her reply, signed more than SKEW after quill's epoch began: quill's later envelopes of
    // it carry no encapsulation.
    t += 60;
    await quill.inbox();
    t += 60;
    ok((await quill.send('rhea', 'this week')).status === 'sent' && carrying() === true && contents(await rhea.inbox()) === 'this week', 'quill writes on, carrying the encapsulation');
    t += 600;
    ok((await rhea.send('quill', 'reply')).status === 'sent' && contents(await quill.inbox()) === 'reply' && carrying() === false, 'quill reads rhea\'s reply: the encapsulation is carried no more');
    ok((await quill.send('rhea', 'without it')).status === 'sent' && contents(await rhea.inbox()) === 'without it', 'and rhea opens the next without it');
    // A reply is no proof: rhea writes without having read the epoch's only carrying envelope (the
    // relay threw it away). quill's next fails epoch_unknown at rhea, she sends quill a fresh
    // prekey bundle, and quill, which still sees the epoch's key listed there, begins a new one.
    // (An hour on: rhea answers an epoch she cannot open with a bundle at most hourly, carrier.mjs RESYNC.)
    editState(Q, (x) => { x.peers[Rh.original].session.out.epoch = null; });
    t += 3600;
    ok((await quill.send('rhea', 'withheld again')).status === 'sent', 'a new epoch\'s first envelope: acknowledged, then thrown away');
    relay3.db.raw.prepare('DELETE FROM messages WHERE account = ?').run(accountOf(Rh.original));
    t += 600;
    const pk0 = seen('rhea', (e) => e.type === 'sent' && e.control === 'prekeys').length;
    ok((await rhea.send('quill', 'written without reading')).status === 'sent' && contents(await quill.inbox()) === 'written without reading' && carrying() === false, 'rhea writes, quill takes it for a reply');
    t += 60;
    ok((await quill.send('rhea', 'after the reply')).status === 'sent', 'quill\'s next carries no encapsulation');
    const box6 = await rhea.inbox();
    ok(box6.messages.length === 0 && box6.dropped.epoch_unknown === 1 && seen('rhea', (e) => e.type === 'sent' && e.control === 'prekeys').length > pk0,
      `rhea cannot open it (epoch_unknown) and sends quill fresh prekeys (${JSON.stringify(box6.dropped)})`);
    t += 60;
    await quill.inbox();
    ok((await quill.send('rhea', 'resynced')).status === 'sent' && contents(await rhea.inbox()) === 'resynced',
      'quill reads them and begins a new epoch: its next message arrives');
    await relay3.close();
  }

  // ================================================================ a refused first envelope; 32 days of silence; no plaintext at rest
  {
    // Its own relay and clock. otto runs with onEvent and no inbox (keep: false): messages reach
    // him as events only, and none is left in his state file.
    let t = now;
    const relay4 = await startRelay({ ...cfg, db: join(dir, 'audit.db'), tcpPort: 0, httpPort: 0, clock: () => t, log: () => {} });
    const ep4 = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay4.ports.tcp}`, http: `http://127.0.0.1:${relay4.ports.http}` } };
    const Pi = agent('piper'), O = agent('otto'), piper = make(Pi, { endpoints: ep4, clock: () => t }), otto = make(O, { endpoints: ep4, clock: () => t, keep: false });
    const inv4 = await piper.invite({ name: 'otto' });
    await otto.accept(inv4.code, { name: 'piper', wait: 0.3 });
    await piper.inbox(); await otto.inbox(); await piper.inbox();
    ok((await piper.send('otto', 'hello otto')).status === 'sent' && (await otto.inbox()) && texts('otto').includes('hello otto'), 'piper and otto pair and talk');
    const outOf = () => stateOf(Pi).peers[O.original].session.out, ottoFile = () => readFileSync(pathsFor(join(dir, 'otto.local.json')).state, 'utf8');
    ok(JSON.parse(ottoFile()).inbox.length === 0 && !ottoFile().includes('hello otto'), 'otto took it by onEvent: his state file holds no message, in plaintext or otherwise');
    // otto is away 22 days, longer than he claims ahead: each of piper's sends begins an epoch the
    // relay refuses (no_reader). Before, each burned one of otto's one-time prekeys for good: after
    // twenty, every epoch began on his last-resort key. Each message stays queued in her outbox.
    t += 22 * DAY;
    // Her own weekly bundle went just before (state edited): else it goes first, is refused
    // no_reader as well, and her messages wait unsealed, beginning no epoch at all.
    editState(Pi, (x) => { x.peers[O.original].session.in.prekeys.replaced = t; });
    const used0 = outOf().used.length, refusals = [];
    for (let i = 0; i < 3; i++) { t += 600; refusals.push(await piper.send('otto', `try ${i}`).then((r) => r.status, (e) => e.check)); }
    const out = outOf();
    ok(refusals.join() === 'queued,queued,queued' && out.used.length === used0 && out.returned.length === 1 && stateOf(Pi).peers[O.original].outbox.length === 3,
      `three sends to a mailbox nobody holds: queued, kept unsealed; no prekey burned, the one the first began on put back (${refusals.join()}; used ${used0} → ${out.used.length}, returned ${out.returned.length})`);
    t += 600;
    await otto.inbox(); await piper.inbox();
    ok(stateOf(Pi).peers[O.original].outbox.length === 0, 'otto back: piper\'s next inbox sends the three');
    const back = texts('otto').length;
    ok((await piper.send('otto', 'after return')).status === 'sent' && (await otto.inbox()) && texts('otto').slice(back).join() === 'try 0,try 1,try 2,after return'
      && seen('otto', (e) => e.type === 'message' && e.content === 'try 0')[0]?.last_resort === false, `otto reads them in order: they begin an epoch on that one-time key, not the last-resort one (${texts('otto').slice(back).join()})`);
    // 32 days in which neither runs: both bundles held are past their 31 days. Before, neither side
    // could send its fresh bundle (it went inside an envelope, which needs an epoch, which needs
    // the other's bundle): every send answered "queued" for good. Now bundles travel in frames.
    t += 32 * DAY;
    await piper.inbox();   // piper is back first: her bundle goes when otto has claimed his mailbox again
    t += 60;
    const w0 = seen('otto', (e) => e.type === 'waiting').length, o1 = await otto.sendAll('piper', ['otto after the silence']);
    ok(o1[0].status === 'queued' && /prekeys/.test(o1[0].detail) && seen('otto', (e) => e.type === 'waiting').length === w0 + 1,
      `otto writes: queued, and said why: piper's bundle has expired, a fresh one is asked for (${o1[0].status}: ${o1[0].detail})`);
    t += 60;
    await piper.inbox();   // otto's bundle and his request: piper answers with hers
    t += 60;
    await otto.inbox();    // piper's bundle: otto's queued message goes
    t += 60;
    const pb = await piper.inbox();
    ok(pb.messages.some((m) => m.content === 'otto after the silence'), `piper receives it: the pairing healed without pairing again (${pb.messages.map((m) => m.content).join()})`);
    ok((await piper.send('otto', 'and back')).status === 'sent' && (await otto.inbox()) && texts('otto').includes('and back'), 'and piper writes back');
    await relay4.close();
  }

  // ================================================================ a contact asking for prekeys without end
  {
    // Its own relay and clock. wally, paired with wanda, asks for her prekeys in every frame
    // (want: true), 45 frames in a row, each with a bundle of his own that is newer and lists no
    // key. Each answer is a bundle of ~35 KB that counts as one of her messages per day at the
    // relay: before, she sent one per frame, and a contact sending her free tier's 1,000 a day
    // left her unable to write to anyone until 00:00 UTC, while it saw from each answer when she
    // was online. Now she answers at most once an hour, and not within an hour of her last bundle.
    let t = now;
    const relay5 = await startRelay({ ...cfg, db: join(dir, 'want.db'), tcpPort: 0, httpPort: 0, clock: () => t, log: () => {} });
    const ep5 = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay5.ports.tcp}`, http: `http://127.0.0.1:${relay5.ports.http}` } };
    const Wa = agent('wanda'), Wl = agent('wally'), Ws = agent('wes');
    const wanda = make(Wa, { endpoints: ep5, clock: () => t }), wally = make(Wl, { endpoints: ep5, clock: () => t }), wes = make(Ws, { endpoints: ep5, clock: () => t });
    for (const [peer, name] of [[wally, 'wally'], [wes, 'wes']]) {
      await peer.accept((await wanda.invite({ name })).code, { name: 'wanda', wait: 0.3 });
      await wanda.inbox(); await peer.inbox(); await wanda.inbox();
    }
    ok(wanda.contacts().contacts.length === 2, 'wanda pairs with wally and wes');
    const K = Buffer.from(storeOf(Wl).contacts[Wa.original].pair_key, 'hex'), pair = pairId(K);
    const lr = stateOf(Wl).peers[Wa.original].session.in.prekeys.lastResort[0];
    const asking = (iat) => {
      const body = { v: 'sigelo-msg/0', typ: 'prekeys', did: Wl.did, pair, iat, exp: iat + 31 * DAY, keys: [], last_resort: { id: lr[0], pk: Buffer.from(lr[2], 'base64').toString('base64url') } };
      const mt = topic(K, Wl.original, Wa.original, isoWeek(t));
      return [mt, seal(KIND_PREKEYS, prekeysKey(K, Wl.original, Wa.original), mt, { prekeys: { body, sig: sign(Wl.secret, body) }, want: true, known: Wa.did })];
    };
    const answers = () => seen('wanda', (e) => e.type === 'sent' && e.control === 'prekeys' && e.peer === Wl.original).length;
    const sentToday = () => relay5.db.sentToday(accountOf(Wa.original), t);
    const a0 = answers(), q0 = sentToday();
    const mal = await rawClient(Wl, ep5);
    for (let i = 1; i <= 45; i++) { const [mt, bytes] = asking(t + 100 + i); await publish(mal, mt, bytes); }
    mal.end(true);
    const box = await wanda.inbox();
    ok(seen('wanda', (e) => e.type === 'prekeys' && e.did === Wl.original).length >= 45 && !box.offline, 'wanda takes the 45 bundles');
    ok(answers() === a0 && sentToday() === q0, `within the hour of her last bundle to wally she sends none back (${answers() - a0} sent; her count today ${q0} → ${sentToday()})`);
    ok((await wanda.send('wes', 'still writing')).status === 'sent', 'and writes to wes as before');
    t += 3600;
    const mal2 = await rawClient(Wl, ep5);
    for (let i = 1; i <= 10; i++) { const [mt, bytes] = asking(t + 100 + i); await publish(mal2, mt, bytes); }
    mal2.end(true);
    await wanda.inbox();
    ok(answers() === a0 + 1, `an hour later, ten more requests: one bundle back (${answers() - a0})`);
    await relay5.close();
  }

  // ================================================================ a refusal is read against its own publish
  {
    // Its own relay, behind splitProxy: each packet the relay sends reaches the agent in a read of
    // its own. The relay wrote a refusal's notice after the PUBACK of the publish it refused, and
    // loopback handed both over in one read, which hid it: through a real network the carrier took
    // the refusal for the next publish's, said "sent" of the message the relay dropped and
    // "refused" of the next, which arrived.
    let t = now;
    const relay7 = await startRelay({ ...cfg, db: join(dir, 'split.db'), tcpPort: 0, httpPort: 0, clock: () => t, log: () => {} });
    let stale = null;
    const noticePacket = (n) => mqttPacket(0x30, Buffer.concat([str16('$sigelo/notice'), Buffer.from(JSON.stringify(n))]));
    const proxy = await splitProxy(relay7.ports.tcp, { gap: 2, onClient: (pkt, toClient) => { if (stale && pkt[0] >> 4 === 3) toClient(noticePacket(stale)); } });
    const ep7 = { [HOST]: { mqtt: `mqtt://127.0.0.1:${proxy.port}`, http: `http://127.0.0.1:${relay7.ports.http}` } };
    const Ta = agent('tara'), Vo = agent('vos'), tara = make(Ta, { endpoints: ep7, clock: () => t }), vos = make(Vo, { endpoints: ep7, clock: () => t });
    await vos.accept((await tara.invite({ name: 'vos' })).code, { name: 'tara', wait: 0.3 });
    await tara.inbox(); await vos.inbox(); await tara.inbox();
    ok(tara.contacts().contacts.length === 1 && vos.contacts().contacts.length === 1, 'tara and vos pair through a network that delivers packet by packet');
    const r = await tara.sendAll('vos', ['x'.repeat(300 * 1024), 'small', 'third']), said = r.map((x) => x.status + (x.code ? ` ${x.code}` : '')).join();
    const box = await vos.inbox(), got = box.messages.map((m) => m.content).join();
    ok(said === 'refused too_large,sent,sent' && got === 'small,third', `300 KB, then two small ones: tara is told "refused too_large, sent, sent", and vos receives the two small ones (${said}; ${got})`);
    // A notice naming another packet id before a publish's PUBACK (one sent late, or by a hostile
    // relay): not that publish's refusal, only a notice.
    stale = { code: 'no_reader', detail: 'stale', id: 65000 };
    const r2 = await tara.sendAll('vos', ['after a stale notice']);
    stale = null;
    ok(r2[0].status === 'sent' && seen('tara', (e) => e.type === 'notice' && e.code === 'no_reader' && e.detail === 'stale').length >= 1,
      `a notice for packet 65000 before the PUBACK: the message is "sent", the notice reported as one (${r2[0].status} ${r2[0].code ?? ''})`);
    ok((await vos.inbox()).messages.map((m) => m.content).join() === 'after a stale notice', 'and vos receives it');
    proxy.close();
    await relay7.close();
  }

  // ================================================================ an epoch begun on a key already spent
  {
    // The writer took its epoch's first envelope for refused while the relay had stored it (its
    // PUBACK lost and the retransmit refused; or before, another publish's notice read against it)
    // and put the one-time key back (envelope.mjs restartEpoch): its next epoch begins on that key
    // again, and every envelope of it fails prekey_reused at the reader. The reader answers with a
    // fresh bundle, as for epoch_unknown, on which the writer begins a new epoch. Before, nothing
    // went until the reader's own bundle fell due, up to 7 days on. Its own relay and clock.
    // Within an hour of pairing: the hour (carrier.mjs RESYNC) runs from the last bundle sent in
    // answer to a failing epoch, not from the pairing's; before, every envelope of the broken epoch
    // in that hour was acknowledged and lost (audit: six messages ten minutes apart).
    let t = now;
    const relay8 = await startRelay({ ...cfg, db: join(dir, 'reused.db'), tcpPort: 0, httpPort: 0, clock: () => t, log: () => {} });
    const ep8 = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay8.ports.tcp}`, http: `http://127.0.0.1:${relay8.ports.http}` } };
    const Sa = agent('sara'), Um = agent('uma'), sara = make(Sa, { endpoints: ep8, clock: () => t }), uma = make(Um, { endpoints: ep8, clock: () => t });
    await uma.accept((await sara.invite({ name: 'uma' })).code, { name: 'sara', wait: 0.3 });
    await sara.inbox(); await uma.inbox(); await sara.inbox();
    const contents = (box) => box.messages.map((m) => m.content).join();
    t += 60;
    ok((await sara.send('uma', 'first')).status === 'sent' && contents(await uma.inbox()) === 'first', 'sara writes, uma reads: an epoch on one of uma\'s one-time keys');
    // What restartEpoch(s, refused) leaves in sara's state: the epoch ended, its key put back.
    editState(Sa, (x) => { const o = x.peers[Um.original].session.out, k = o.epoch.oneTime; o.used = o.used.filter((id) => id !== k); o.returned.push(k); o.epoch = null; });
    t += 60;
    ok((await sara.send('uma', 'on a spent key')).status === 'sent', 'sara\'s next message begins an epoch on that key again');
    const pk0 = seen('uma', (e) => e.type === 'sent' && e.control === 'prekeys').length, box = await uma.inbox();
    ok(box.messages.length === 0 && box.dropped.prekey_reused === 1 && seen('uma', (e) => e.type === 'sent' && e.control === 'prekeys').length > pk0,
      `uma cannot open it (prekey_reused) and sends sara fresh prekeys (${JSON.stringify(box.dropped)})`);
    t += 60;
    await sara.inbox();
    ok((await sara.send('uma', 'healed')).status === 'sent' && contents(await uma.inbox()) === 'healed', 'sara reads them and begins a new epoch: her next message arrives');
    // The same within the hour of that bundle: owed, not thrown away. uma sends it at her first
    // round once the hour has passed, with nothing more from sara; before, nothing went until an
    // envelope failed after the hour, and each one before it was lost.
    const resyncs = () => seen('uma', (e) => e.type === 'sent' && e.control === 'prekeys').length, owed = () => stateOf(Um).peers[Sa.original].resync_due;
    editState(Sa, (x) => { const o = x.peers[Um.original].session.out, k = o.epoch.oneTime; o.used = o.used.filter((id) => id !== k); o.returned.push(k); o.epoch = null; });
    t += 60;
    ok((await sara.send('uma', 'on a spent key again')).status === 'sent', 'ten minutes later, sara begins an epoch on a spent key again');
    const pk1 = resyncs(), box2 = await uma.inbox();
    ok(box2.dropped.prekey_reused === 1 && resyncs() === pk1 && owed() === true, `uma cannot open it, within the hour of her last such bundle: a bundle owed, none sent yet (${JSON.stringify(box2.dropped)})`);
    t += 3600;
    await uma.sync();
    ok(resyncs() === pk1 + 1 && owed() === false, 'an hour on, at her next round, with nothing more from sara: uma sends the owed bundle');
    t += 60;
    await sara.inbox();
    ok((await sara.send('uma', 'healed again')).status === 'sent' && contents(await uma.inbox()) === 'healed again', 'sara reads it and begins a new epoch: her next message arrives');
    await relay8.close();
  }

  // ================================================================ a rotation while the contact is away longer than the relay keeps a notice
  {
    // Audit finding: the notice went once. The relay expired it unread (bruno away 9 days, the free
    // tier keeps 7), and every later envelope of alba's failed `from` at bruno and every bundle
    // `prekeys`, acknowledged and lost while alba was told "sent", for good. Now alba sends the
    // notice again before her next frame, at most hourly, until bruno's prekeys frame says he holds
    // her new DID (`known`). Its own relay and clock.
    let t = now;
    const relay9 = await startRelay({ ...cfg, db: join(dir, 'notice.db'), tcpPort: 0, httpPort: 0, clock: () => t, log: () => {} });
    const ep9 = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay9.ports.tcp}`, http: `http://127.0.0.1:${relay9.ports.http}` } };
    const Al = agent('alba'), Br = agent('bruno'), alba = make(Al, { endpoints: ep9, clock: () => t }), bruno = make(Br, { endpoints: ep9, clock: () => t });
    await bruno.accept((await alba.invite({ name: 'bruno' })).code, { name: 'alba', wait: 0.3 });
    await alba.inbox(); await bruno.inbox(); await alba.inbox();
    const contents = (box) => box.messages.map((m) => m.content).join(), notices = () => seen('alba', (e) => e.type === 'sent' && e.control === 'notice').length;
    t += 60;
    ok((await alba.send('bruno', 'before')).status === 'sent' && contents(await bruno.inbox()) === 'before', 'alba and bruno pair and talk');
    await alba.inbox();
    t += DAY;
    rotateAgent(Al);
    ok((await alba.send('bruno', 'after rotating')).status === 'sent' && notices() === 1, 'a day later alba rotates and writes: her notice, then the message, reach the relay');
    t += 8 * DAY;
    const away = await bruno.inbox();
    ok(away.messages.length === 0 && !away.events.some((e) => e.type === 'rotated'), 'bruno back after 9 days: the notice and the message expired unread at the relay');
    t += 3 * 3600;
    ok((await alba.send('bruno', 'later')).status === 'sent' && notices() === 2, 'alba writes again: her notice goes again first');
    const back = await bruno.inbox();
    ok(contents(back) === 'later' && back.events.some((e) => e.type === 'rotated' && e.current_did === Al.did) && !back.dropped.from && !back.dropped.prekeys,
      `bruno merges her rotation from it and reads her message (${contents(back)}; dropped ${JSON.stringify(back.dropped)})`);
    ok(bruno.contacts().contacts[0].current_did === Al.did, 'bruno files alba under her new DID');
    t += 60;
    await alba.inbox();
    ok(stateOf(Al).peers[Br.original].known === Al.did, 'bruno\'s prekeys frame names her new DID: alba knows he holds it');
    t += 2 * 3600;
    ok((await alba.send('bruno', 'confirmed')).status === 'sent' && contents(await bruno.inbox()) === 'confirmed' && notices() === 2, 'two hours on her next message goes without a notice');
    ok((await bruno.send('alba', 'reply')).status === 'sent' && contents(await alba.inbox()) === 'reply', 'and bruno writes back');
    // A prekeys frame of bruno's naming her old DID (as from a store restored from a backup): alba
    // sends her notice again with nothing else to send; bruno, holding her rotation already, skips
    // it unchecked and answers with a bundle naming her new DID.
    t += 2 * 3600;
    const K9 = Buffer.from(storeOf(Br).contacts[Al.original].pair_key, 'hex'), lr9 = stateOf(Br).peers[Al.original].session.in.prekeys.lastResort[0];
    const body9 = { v: 'sigelo-msg/0', typ: 'prekeys', did: Br.did, pair: pairId(K9), iat: t, exp: t + 31 * DAY, keys: [], last_resort: { id: lr9[0], pk: Buffer.from(lr9[2], 'base64').toString('base64url') } };
    const mt9 = topic(K9, Br.original, Al.original, isoWeek(t)), raw9 = await rawClient(Br, ep9);
    await publish(raw9, mt9, seal(KIND_PREKEYS, prekeysKey(K9, Br.original, Al.original), mt9, { prekeys: { body: body9, sig: sign(Br.secret, body9) }, want: false, known: Al.original }));
    raw9.end(true);
    await alba.inbox();
    ok(notices() === 3 && stateOf(Al).peers[Br.original].known === Al.original, 'a prekeys frame of bruno\'s naming her old DID: alba sends her notice again, with nothing else to send');
    t += 60;
    const bb = await bruno.inbox();
    t += 60;
    await alba.inbox();
    ok(!bb.events.some((e) => e.type === 'rotated') && stateOf(Al).peers[Br.original].known === Al.did, 'bruno, holding the rotation already, answers it with a bundle naming her new DID');
    await relay9.close();
  }

  // ================================================================ a rotation between the answer and the reply
  {
    // Audit finding: the invitee set what the inviter holds of him (known) and the DID he last
    // announced to his DID at the moment he read the reply. The inviter holds the DID his answer's
    // chain ended at, so a rotation in between (by choice, or a recovery) was never announced: she
    // refused his prekeys and every envelope (`from`) while he was told "sent", until her own bundle
    // fell due a week later. Now he starts from the DID his answer carried and announces first; the
    // same when an existing contact re-keys by answering a fresh code. And, behind that, an
    // envelope failing `from` owes the writer a bundle naming the DID held, at most every RESYNC, on
    // which it announces again. Its own relay and clock.
    let t = now;
    const relay10 = await startRelay({ ...cfg, db: join(dir, 'between.db'), tcpPort: 0, httpPort: 0, clock: () => t, log: () => {} });
    const ep10 = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay10.ports.tcp}`, http: `http://127.0.0.1:${relay10.ports.http}` } };
    const Ce = agent('cleo'), Da = agent('dario'), cleo = make(Ce, { endpoints: ep10, clock: () => t }), dario = make(Da, { endpoints: ep10, clock: () => t });
    const contents = (box) => box.messages.map((m) => m.content).join(), notices = () => seen('dario', (e) => e.type === 'sent' && e.control === 'notice').length;
    const entry = () => stateOf(Da).peers[Ce.original], held = () => storeOf(Ce).contacts[Da.original].current_did;
    await dario.accept((await cleo.invite({ name: 'dario' })).code, { name: 'cleo', wait: 0.3 });
    t += 600;
    const d0 = Da.did;
    rotateAgent(Da);
    t += 60;
    await cleo.inbox();
    ok(held() === d0, 'dario rotates after his answer went: cleo pairs and files him under the DID his answer carried');
    t += 60;
    const paired = await dario.inbox();
    ok(paired.events.some((e) => e.type === 'paired') && notices() === 1 && entry().announced === Da.did && entry().known === d0,
      `dario reads her reply: his rotation notice goes first, and he holds that cleo knows his old DID (notices ${notices()}, known ${entry().known === d0 ? 'the old DID' : entry().known})`);
    t += 60;
    ok((await dario.sendAll('cleo', ['one', 'two', 'three'])).every((r) => r.status === 'sent'), 'he writes three messages: sent');
    const box = await cleo.inbox();
    ok(contents(box) === 'one,two,three' && box.events.some((e) => e.type === 'rotated' && e.current_did === Da.did) && !box.dropped.from && !box.dropped.prekeys,
      `cleo merges his rotation from the notice and reads all three (${contents(box)}; dropped ${JSON.stringify(box.dropped)})`);
    t += 60;
    await dario.inbox();
    ok(entry().known === Da.did && held() === Da.did, 'her bundle names his new DID: dario knows she holds it');
    // Re-keyed: an existing contact answers a fresh code, and rotates before the reply.
    t += 2 * 3600;
    await dario.accept((await cleo.invite({ name: 'dario again' })).code, { name: 'cleo', wait: 0.3 });
    t += 600;
    const d1 = Da.did;
    rotateAgent(Da);
    t += 60;
    const rk = await cleo.inbox();
    ok(rk.events.some((e) => e.type === 'paired' && e.rekeyed) && held() === d1, 'he answers a fresh code of hers and rotates again before the reply: she re-keys and holds the DID that answer carried');
    t += 60;
    await dario.inbox();
    t += 60;
    ok((await dario.send('cleo', 'after the re-key')).status === 'sent' && notices() === 2, 'he reads the reply and writes: his notice went first');
    const box2 = await cleo.inbox();
    ok(contents(box2) === 'after the re-key' && held() === Da.did && !box2.dropped.from, `she merges the rotation and reads his message (${contents(box2)}; dropped ${JSON.stringify(box2.dropped)})`);
    t += 60;
    await dario.inbox();
    ok(entry().known === Da.did, 'her fresh bundle names his new DID');
    // Behind it: dario's state says she holds his current DID when she does not (as the earlier
    // version wrote it). His envelope fails `from` at her; an hour after her last bundle she sends
    // one at once, naming the DID she holds, and he announces again.
    t += 2 * 3600;
    const d2 = Da.did;
    rotateAgent(Da);
    editState(Da, (x) => { const p = x.peers[Ce.original]; p.announced = Da.did; p.known = Da.did; });
    const pk0 = seen('cleo', (e) => e.type === 'sent' && e.control === 'prekeys').length;
    ok((await dario.send('cleo', 'unheard')).status === 'sent' && notices() === 2, 'he rotates, his state wrongly sure she knows: his message goes without a notice');
    const lost = await cleo.inbox();
    ok(lost.messages.length === 0 && lost.dropped.from === 1 && held() === d2 && seen('cleo', (e) => e.type === 'sent' && e.control === 'prekeys').length === pk0 + 1 && stateOf(Ce).peers[Da.original].known_due === false,
      `she cannot open it (from) and sends him a bundle naming the DID she holds (dropped ${JSON.stringify(lost.dropped)})`);
    t += 60;
    await dario.inbox();
    ok(notices() === 3 && entry().known === d2, 'he reads it: his notice goes again');
    t += 60;
    const healed = await cleo.inbox();
    ok(held() === Da.did && healed.events.some((e) => e.type === 'rotated' && e.current_did === Da.did), 'she merges his rotation');
    t += 60;
    ok((await dario.send('cleo', 'heard')).status === 'sent' && contents(await cleo.inbox()) === 'heard', 'and reads his next message');
    // Within the hour of her last bundle the bundle is owed, not sent, and goes at her first round
    // once the hour has passed, with nothing more from him.
    t += 60;
    rotateAgent(Da);
    editState(Da, (x) => { const p = x.peers[Ce.original]; p.announced = Da.did; p.known = Da.did; });
    const pk1 = seen('cleo', (e) => e.type === 'sent' && e.control === 'prekeys').length;
    await dario.send('cleo', 'unheard again');
    const owed = await cleo.inbox();
    ok(owed.dropped.from === 1 && stateOf(Ce).peers[Da.original].known_due === true && seen('cleo', (e) => e.type === 'sent' && e.control === 'prekeys').length === pk1,
      `minutes after her last bundle: a bundle owed, none sent yet (dropped ${JSON.stringify(owed.dropped)})`);
    t += 3600;
    await cleo.sync();
    ok(stateOf(Ce).peers[Da.original].known_due === false && seen('cleo', (e) => e.type === 'sent' && e.control === 'prekeys').length === pk1 + 1, 'an hour on, at her next round: she sends it');
    t += 60;
    await dario.inbox();
    t += 60;
    await cleo.inbox();
    t += 60;
    ok(held() === Da.did && (await dario.send('cleo', 'heard again')).status === 'sent' && contents(await cleo.inbox()) === 'heard again', 'he announces again, she merges it and reads his next message');
    await relay10.close();
  }

  // ================================================================ the relay's claim brake
  {
    // The relay brakes new claims (relay/allowance.mjs RATE.claim). The carrier asked contact by
    // contact, so with 90 days (14 or 15 weeks each) the first contacts took the brake's tokens and
    // the later ones missed this week's mailbox; it sent every SUBSCRIBE of 128 however the first
    // was refused, each refused topic a strike toward the 500 a minute that close the connection;
    // and it never asked a refused topic again while the connection lasted. hugo pairs with ten
    // contacts on one relay; then, with 90 days, he meets a relay that holds none of his claims (a
    // fresh file) and lets an identity claim 20 at once, 1 a second. Its own relays and clock.
    let t = now;
    const relay11 = await startRelay({ ...cfg, db: join(dir, 'brake1.db'), tcpPort: 0, httpPort: 0, clock: () => t, log: () => {} });
    const ep11 = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay11.ports.tcp}`, http: `http://127.0.0.1:${relay11.ports.http}` } };
    const Hu = agent('hugo'), hugo = make(Hu, { endpoints: ep11, clock: () => t });
    const Ps = Array.from({ length: 10 }, (_, i) => agent(`hugo's contact ${i}`));
    for (const P of Ps) await make(P, { endpoints: ep11, clock: () => t }).accept((await hugo.invite({ name: P.label })).code, { name: 'hugo', wait: 0.3 });
    await hugo.inbox();
    await relay11.close();
    ok(hugo.contacts().contacts.length === 10, 'hugo pairs with ten contacts');
    let subscribes = 0;
    const braked = (ctx) => {
      const p = relayPolicy(ctx, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 }, freeQueue: 64 * 1024 * 1024, tiers: { free: { ...TEST_FREE, mailboxes: 1000 }, pro: TIERS.pro }, rate: { claim: { perSecond: 1, burst: 20 } } });
      const rate = p.rate;
      p.rate = (x) => { if (x.kind === 'subscribe') subscribes++; return rate(x); };
      return p;
    };
    const relay12 = await startRelay({ ...cfg, db: join(dir, 'brake2.db'), tcpPort: 0, httpPort: 0, clock: () => t, log: () => {}, policy: braked });
    const ep12 = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay12.ports.tcp}`, http: `http://127.0.0.1:${relay12.ports.http}` } };
    // A relay that never saw him: he logs in with a proof (this one's state says he gave one).
    editState(Hu, (x) => { x.relays[HOST].proven = false; });
    const hugo90 = make(Hu, { endpoints: ep12, clock: () => t, retentionDays: 90 });
    const held = () => new Set(relay12.db.raw.prepare('SELECT topic FROM claims WHERE account = ?').all(accountOf(Hu.original)).map((r) => r.topic));
    const mailboxes = (week) => Object.values(storeOf(Hu).contacts).map((c) => topic(Buffer.from(c.pair_key, 'hex'), c.did, Hu.original, week));
    const connects = () => seen('hugo', (e) => e.type === 'connected').length;
    const W = isoWeek(t), ahead = isoWeek(t + 7 * DAY), behind = isoWeek(t - 7 * DAY);
    await hugo90.start();
    ok(await until(() => held().size === 20 && subscribes >= 128), `started, hugo asks for his topics: 20 claimed (${held().size}), ${subscribes} asked`);
    await sleep(500);
    ok(subscribes === 128 && connects() === 1, `one SUBSCRIBE of 128 and no more: the round stops at the brake, the rest wait (${subscribes} asked, ${connects()} connection)`);
    const h1 = held();
    ok([...mailboxes(W), ...mailboxes(ahead)].every((x) => h1.has(x)), 'the 20 claimed: this week\'s mailbox and next week\'s of each of the ten contacts');
    t += 600;
    await hugo90.sync();
    ok(subscribes === 128 && held().size === 20, `a round 10 minutes later asks for nothing refused (${subscribes} asked)`);
    t += 3000;
    await hugo90.sync();
    const h2 = held();
    ok(h2.size === 40 && mailboxes(behind).every((x) => h2.has(x)) && connects() === 1, `an hour after the refusals: asked again, 20 more claimed, last week's of each contact first (${h2.size}, ${connects()} connection)`);
    await hugo90.stop();
    await relay12.close();
  }

  // ================================================================ the 0.1.3 live re-test (2026-10-14)
  {
    // Its own relay and clock. connect.html's order: ines invites, jon accepts while she is offline
    // (waiting), ines runs inbox (paired), then send. Jon's mailbox for the pairing needs K, which
    // only her reply carries: until jon's agent reads it, nobody holds that mailbox (no_reader).
    let t = now;
    const relayL = await startRelay({ ...cfg, db: join(dir, 'live.db'), tcpPort: 0, httpPort: 0, clock: () => t, log: () => {} });
    const epL = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relayL.ports.tcp}`, http: `http://127.0.0.1:${relayL.ports.http}` } };
    const In = agent('isla'), Jo = agent('jude'), ines = make(In, { endpoints: epL, clock: () => t }), jon = make(Jo, { endpoints: epL, clock: () => t });
    const code1 = (await ines.invite({ name: 'jon' })).code, prefix = In.original.slice('did:sigelo:'.length, 'did:sigelo:'.length + 8);
    ok((await jon.accept(code1, { wait: 0.3 })).status === 'waiting' && jon.contacts().answers[0]?.name === prefix,
      `L1: accept without --name names the inviter by its DID's first digits (${jon.contacts().answers[0]?.name})`);
    ok((await ines.inbox()).events.some((e) => e.type === 'paired' && e.name === 'jon'), 'M1: ines\'s inbox pairs');
    const hello = await ines.send('jon', say('hello jon'));
    ok(hello.status === 'queued' && /jon's agent does not hold its mailbox for this pairing yet/.test(hello.detail) && stateOf(In).peers[Jo.original].outbox.length === 1,
      `M1: her first send is queued, kept in her outbox, and says why: jon's agent, not hers (${hello.status}: ${hello.detail})`);
    const hi = await jon.send(prefix, say('hi ines'));
    ok(hi.status === 'sent' && jon.contacts().contacts.map((c) => c.name).join() === prefix, `M1: jon's first send after accept reads her reply first, pairs and goes (${hi.status})`);
    const ib = await ines.inbox();
    ok(ib.messages.map((m) => m.content).join() === 'hi ines' && stateOf(In).peers[Jo.original].outbox.length === 0, 'M1: ines\'s next inbox reads him and sends her kept message');
    ok((await jon.inbox()).messages.map((m) => m.content).join() === 'hello jon', 'M1: jon reads it');
    await refuses(() => make(agent('noor'), { endpoints: epL, clock: () => t }).send('nobody', 'x'), 'not_contact', 'a name nobody answered stays not_contact');

    // L1: on a re-pair, the name accept is given wins over the name kept.
    const code2 = (await ines.invite({ name: 'jonny' })).code;
    ok((await jon.accept(code2, { name: 'ines', wait: 0.3 })).status === 'waiting', 'L1: jon answers a new code of ines\'s, naming her');
    await refuses(() => jon.send('ines', 'too soon'), 'not_paired', 'M1: a send to the name of an answer the inviter has not read yet says so, by name');
    await ines.inbox();
    const jp = await jon.send('ines', say('re-paired'));
    ok(jp.status === 'sent' && jon.contacts().contacts.map((c) => c.name).join() === 'ines', `L1: once paired again, she is "ines" on his side (${jon.contacts().contacts.map((c) => c.name).join()})`);
    ok((await ines.inbox()).messages.some((m) => m.content === 're-paired') && ines.contacts().contacts.map((c) => c.name).join() === 'jon', 'L1: on hers he keeps his name: invite --name names new contacts only');

    // L4: a code answered before is refused at once, not after the whole wait.
    const Ka = agent('kai'), kai = make(Ka, { endpoints: epL, clock: () => t }), t0 = Date.now();
    await refuses(() => kai.accept(code1, { wait: 10 }), 'mailbox_taken', 'L4: a replayed code');
    ok(Date.now() - t0 < 6000, `L4: refused in ${Date.now() - t0} ms, not after the 10 s wait`);

    // H1: a thief copies phone's identity and files, writes to vps (an MCP agent), rotates, writes
    // twice more; the relay holds the last back. Then phone recovers from its genesis.
    const mcp = await import(pathToFileURL(join(HERE, '..', 'integrations', 'mcp', 'contact.mjs')).href);
    const id = await import(pathToFileURL(join(HERE, '..', 'adapters', 'moadim', 'sigelo-agent.ts')).href);
    const tools = await mcp.load({ installed: false, id, env: { SIGELO_RELAY: HOST, SIGELO_RELAY_ENDPOINTS: JSON.stringify(epL) }, clock: () => t });
    const vFile = join(dir, 'vps.local.json');
    id.init(vFile, keygen({ seed: seed('vps recovery'), recovery: 'sha256:' + '0'.repeat(64) }).key);
    const vDid = id.chainOf(id.load(vFile))[0], h = tools.handlers, vInbox = async () => JSON.parse((await h.sigelo_inbox({}, vFile)).text);
    secrets.add(vDid);
    const Ph = agent('phone'), phone = make(Ph, { endpoints: epL, clock: () => t });
    await h.sigelo_accept({ code: (await phone.invite({ name: 'vps' })).code, name: 'phone', wait: 1 }, vFile);
    await phone.inbox(); await vInbox(); await phone.inbox();
    ok((await phone.send('vps', say('from the phone'))).status === 'sent' && (await vInbox()).messages.some((m) => m.content === 'from the phone'), 'H1: phone and vps (MCP) pair and talk');
    const T = { ...Ph, label: 'phone thief', bundle: structuredClone(Ph.bundle) };
    for (const k of ['store', 'state']) copyFileSync(pathsFor(join(dir, 'phone.local.json'))[k], pathsFor(join(dir, 'phone thief.local.json'))[k]);
    const thief = make(T, { endpoints: epL, clock: () => t });
    ok((await thief.send('vps', say('THIEF before recovery'))).status === 'sent', 'H1: the thief writes under the copied key');
    rotateAgent(T);
    secrets.add(T.did);
    ok((await thief.send('vps', say('THIEF after rotating'))).status === 'sent', 'H1: rotates, and writes again under its own key');
    ok((await thief.send('vps', say('THIEF late'))).status === 'sent', 'H1: and once more');
    const late = relayL.db.raw.prepare('SELECT id, topic, payload FROM messages WHERE account = ? ORDER BY seq DESC LIMIT 1').get(accountOf(vDid));
    relayL.db.raw.prepare('DELETE FROM messages WHERE id = ?').run(late.id);
    const R = keygen({ seed: seed('phone recovered'), recovery: Ph.bundle.genesis.recovery, created: CREATED, nonce: seed('phone recovered nonce').slice(0, 16) });
    Ph.bundle.rotations = [rotate({ genesis: Ph.bundle.genesis, next_genesis: R.genesis, iat: t - 60, reason: 'recovery', secret: seed('phone recovery') })];
    Ph.secret = R.secret; Ph.did = R.did;
    secrets.add(R.did);
    await phone.inbox();   // the recovered chain logs in; its notice goes to vps
    const vb = await vInbox();
    ok(!vb.messages.some((m) => /THIEF/.test(m.content)), `H1: vps, in one sigelo_inbox after the recovery, delivers none of the thief's messages (${vb.messages.map((m) => m.content).join() || 'none'})`);
    const refusedNow = vb.events.filter((e) => e.type === 'refused' && e.code === 're_pair' && e.from === Ph.original).map((e) => e.current_did);
    ok(refusedNow.length === 2 && refusedNow.includes(Ph.original) && refusedNow.includes(T.did),
      `H1: both are reported refused, re_pair, with the key each was signed by: the recovered-from key and the thief's (${refusedNow.join()})`);
    const rot = vb.events.find((e) => e.type === 'rotated' && e.re_pair === 'contact_recovery');
    ok(rot?.current_did === R.did && rot.overruled.includes(Ph.original) && rot.overruled.includes(T.did) && !rot.overruled.includes(R.did),
      'H1: the recovery\'s rotated event names the DIDs it overruled');
    const mal = await rawClient(agent('mallory'), epL);
    await publish(mal, late.topic, late.payload);
    mal.end(true);
    const vb2 = await vInbox();
    ok(vb2.messages.length === 0 && vb2.events.some((e) => e.type === 'refused' && e.code === 're_pair' && e.from === Ph.original && e.current_did === undefined) && !vb2.dropped.from,
      `H1: the one the relay held back, delivered after the recovery: refused re_pair too, not dropped as "from" (${JSON.stringify(vb2.events.map((e) => e.type + ':' + (e.code ?? '')))})`);

    // The retention: relay.json's at the agent's own relay, unless told; 14 when it says nothing.
    ok(retentionOf({ limits: { free: { retention_days: 14 } } }) === 14 && retentionOf({ limits: { free: { retention_days: 91 } } }) === null && retentionOf({ limits: { free: { retention_days: '14' } } }) === null && retentionOf(null) === null,
      'retentionOf: whole days, 1 to 90, else nothing');
    const info = createServer(async (req, res) => {
      if (req.url === '/relay.json') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ limits: { free: { retention_days: 21 } } })); return; }
      const r = await fetch(`${epL[HOST].http}${req.url}`);
      res.writeHead(r.status, { 'content-type': 'application/json' });
      res.end(Buffer.from(await r.arrayBuffer()));
    });
    await new Promise((r) => info.listen(0, '127.0.0.1', r));
    const epI = { [HOST]: { mqtt: epL[HOST].mqtt, http: `http://127.0.0.1:${info.address().port}` } };
    const asked = make(agent('luz'), { endpoints: epI, clock: () => t, retentionDays: undefined });
    ok(asked.retentionDays === 14, `the default before any login: 14 days (${asked.retentionDays})`);
    await asked.inbox();
    ok(asked.retentionDays === 21, `after its first login: relay.json's 21 (${asked.retentionDays})`);
    const told = make(agent('mia'), { endpoints: epI, clock: () => t, retentionDays: 7 });
    await told.inbox();
    const none = make(agent('ned'), { endpoints: epL, clock: () => t, retentionDays: undefined });
    await none.inbox();
    ok(told.retentionDays === 7 && none.retentionDays === 14, `told 7 (SIGELO_RELAY_RETENTION_DAYS): 7 (${told.retentionDays}); a relay with no relay.json: 14 (${none.retentionDays})`);
    info.closeAllConnections();
    await new Promise((r) => info.close(r));
    await relayL.close();
  }

  // ================================================================ forget
  const claimsBefore = q('SELECT count(*) AS n FROM claims WHERE account = ? AND topic LIKE ?', accountOf(B.original), 'm/%')[0].n;
  const f = await bob.forget(A.original);
  ok(f.revoked === true && f.released === true && f.did === A.original, 'bob forgets alice: revoked, and his mailboxes for her given up');
  ok(q('SELECT count(*) AS n FROM claims WHERE account = ? AND topic LIKE ?', accountOf(B.original), 'm/%')[0].n < claimsBefore, 'the relay holds fewer of bob\'s mailboxes');
  const af = await alice.send('bob', say('after forget'));
  ok(af.status === 'queued' && /bob's agent does not hold its mailbox/.test(af.detail) && alice.contacts().contacts.find((c) => c.did === B.original).queued === 1,
    `alice writes on: nobody holds that mailbox now, so it stays queued with her, and contacts says so (${af.status})`);
  await sleep(500);
  ok(!texts('bob').includes('after forget') && q('SELECT count(*) AS n FROM messages WHERE account = ?', accountOf(B.original))[0].n === 0, 'nobody reads it, and nothing is queued for bob');
  await refuses(() => bob.send('alice', 'x'), 'not_contact', 'bob cannot write to a forgotten contact by name');
  await refuses(() => bob.send(A.original, 'x'), 'revoked', 'nor by DID');

  blind('after the whole run');
} catch (e) {
  fails.push(`exception: ${e.stack}`);
} finally {
  await Promise.allSettled([alice.stop(), bob.stop(), carol.stop()]);
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}

for (const f of fails) console.log('FAIL ' + f);
if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
console.log(`ALL PASS (${count})`);
process.exit(0);
