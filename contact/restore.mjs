// SPDX-License-Identifier: MIT
// Restore from seed in an app (design/apps-seed.md, pass A9): the operator's files from the 25 words,
// exactly as `sigelo-agent keeper --from-words` writes them, and this device as the first FULL device
// of a new device list holding the seat (`device seat init`), or as a standby when the human says the
// seat is on another device. No network, no storage and no clock here: the page (apps/web/seed.mjs)
// seals what this returns, the tests compare it with the CLI's files.
//
//   checkWords(text)            → { count, ok, error, bad }   live, for the form: the first word not in
//                                 the Monero list (by position, never echoed), then the checksum
//   parseRestore(text, now)     → {} | { restore_height } | { restore_date }   the height-or-date field
//   restoreFromWords(text, o)   → { identity, keeper, device, list, notes, did, worker }
//       identity  me.local.json: operatorIdentity(S, 0) (contact/enrol.mjs), `derived` marked
//       keeper    me.local.keeper.json: sigelo-keeper-hot/0, keeper j (1), root_hex = K_j, the seed's
//                 recovery commitment, `created` (the UTC day), the wallet metadata `net` and
//                 `restore_height` | `restore_date`, workers {0: this device}, me {n, did, original}
//       device    worker 0 of K_j, rotation 0, attested by the operator for DEVICE_DAYS (the file
//                 `device seat init` writes into the agents' directory)
//       list      seat "here": the signed sigelo-devices/1 list, seq 1, this device FULL, seat epoch 1;
//                 seat "elsewhere": null (the seat's list is on the other device)
//       notes     me.local.seat.json: { v, here: {name, did, worker}, imported: 1 } or, elsewhere,
//                 { v, here, elsewhere: true, entry } (the list entry `takeSeat` signs later)
//   takeSeat(notes, identity, now) → { list, notes }   standby → seat: the list naming this device
//                                 (epoch 1: the other device's list is not known here, so this is
//                                 `seat take --force` semantics; the caller warns first)
//
// S, K_j and the operator key are zeroed before return; the words are never kept. What stays in the
// files is what the CLI writes (the identity's secret and K_j as hex).
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { did as didOf, sign as signWith } from 'sigelo';
import { keeperRoot, recoveryCommitment, rootFromMnemonic } from 'sigelo/dist/keys.js';
import { MONERO_WORDS } from 'sigelo/dist/monero-words.js';
import { DEVICE_DAYS, KEEPER_V, checkName, nextSeat, signList } from './device.mjs';
import { operatorAttestation, operatorIdentity, workerChain, workerIdentity } from './enrol.mjs';
import { checkRelay } from './invite.mjs';
import { checkNow, fail } from './kdf.mjs';

export const WORD_COUNT = 25, KEEPER_J = 1, NETS = Object.freeze(['mainnet', 'stagenet']), SEATS = Object.freeze(['here', 'elsewhere']);
export const SEAT_LOCAL_V = 'sigelo-seat-local/1';
// Monero's first block (2014-04-18): no wallet is older. A height above this is not a Monero height.
const FIRST_DAY = Date.UTC(2014, 3, 18), HEIGHT_MAX = 2 ** 31 - 1;
// Words match on their first three letters (keys.ts decodeMoneroWords): the whole word or exactly the prefix.
const BY_PREFIX = new Map(MONERO_WORDS.map((w) => [w.slice(0, 3), w]));
const inList = (w) => { const x = BY_PREFIX.get(w.slice(0, 3)); return x !== undefined && (w === x || w === x.slice(0, 3)); };
const split = (text) => String(text ?? '').toLowerCase().trim().split(/\s+/).filter(Boolean);
const day = (now) => new Date(now * 1000).toISOString().slice(0, 10);

/** The words as typed so far: their count, the first one not in the list, and, at 25, the checksum. */
export function checkWords(text) {
  const words = split(text), at = words.findIndex((w) => !inList(w));
  if (at >= 0) return { count: words.length, ok: false, bad: at + 1, error: `word ${at + 1} is not in the Monero word list` };
  if (words.length < WORD_COUNT) return { count: words.length, ok: false, bad: null, error: null };
  if (words.length > WORD_COUNT) return { count: words.length, ok: false, bad: null, error: `${words.length} words: a Monero seed has ${WORD_COUNT}` };
  try { rootFromMnemonic(words.join(' ')).fill(0); } catch (e) {
    return { count: WORD_COUNT, ok: false, bad: null, error: /checksum/.test(e.message) ? 'the checksum (the 25th word) does not match: a word is mistyped or out of order'
      : 'these words are not a seed this app can restore (not a canonical Monero seed)' };
  }
  return { count: WORD_COUNT, ok: true, bad: null, error: null };
}

/** The "restore height or date" field: digits = a block height, YYYY-MM-DD = a UTC day; empty = neither. */
export function parseRestore(text, now) {
  const t = String(text ?? '').trim();
  if (t === '') return {};
  if (/^\d{1,10}$/.test(t)) {
    const h = Number(t);
    if (h > HEIGHT_MAX) fail('restore_height', `${t} is not a block height`);
    return { restore_height: h };
  }
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(t), at = m && Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  if (!m || new Date(at).toISOString().slice(0, 10) !== t) fail('restore_date', 'a block height (digits) or a date as YYYY-MM-DD');
  if (at < FIRST_DAY) fail('restore_date', `${t} is before Monero's first block (2014-04-18)`);
  if (now !== undefined && at > checkNow(now) * 1000) fail('restore_date', `${t} is in the future`);
  return { restore_date: t };
}

function checkMeta(restore) {
  const keys = Object.keys(restore ?? {});
  if (keys.length > 1 || keys.some((k) => !['restore_height', 'restore_date'].includes(k))) fail('restore', 'restore: {} or one of restore_height, restore_date');
  if (keys[0] === 'restore_height' && !(Number.isSafeInteger(restore.restore_height) && restore.restore_height >= 0 && restore.restore_height <= HEIGHT_MAX)) fail('restore_height', 'a block height');
  if (keys[0] === 'restore_date') parseRestore(restore.restore_date);
  return restore ?? {};
}

/**
 * The operator's files from the 25 words (see the header). o: { name (this device, devices.md names),
 * relay (the host its attestation names), net, restore ({} | {restore_height} | {restore_date}),
 * seat ("here" | "elsewhere"), now (unix seconds), j (the keeper index, 1; never 0) }.
 */
export function restoreFromWords(text, { name, relay, net = 'mainnet', restore = {}, seat = 'here', now, j = KEEPER_J } = {}) {
  checkNow(now); checkName(name); checkRelay(relay);
  if (!NETS.includes(net)) fail('restore_net', `net: ${NETS.join(' or ')}`);
  if (!SEATS.includes(seat)) fail('restore_seat', `seat: ${SEATS.join(' or ')}`);
  if (!Number.isSafeInteger(j) || j < 1) fail('restore', 'keeper: 1 or more (K_0 is the ceremony\'s agents\' keeper)');
  const meta = checkMeta(restore), c = checkWords(text);
  if (!c.ok) fail('restore_words', c.error ?? `${c.count} of ${WORD_COUNT} words`);
  let S = null, K = null, secret = null;
  try {
    S = rootFromMnemonic(split(text).join(' '));
    const identity = operatorIdentity(S, 0), original = didOf(identity.genesis), recovery = recoveryCommitment(S);
    K = keeperRoot(S, j);
    secret = hexToBytes(identity.secret);
    const w = workerChain(K, 0, 0, recovery);
    w.secret.fill(0);
    const attestation = operatorAttestation({ secret, iss: original, sub: w.original, relay, now, days: DEVICE_DAYS });
    const device = workerIdentity({ K, i: 0, n: 0, recovery, attestation, issuer: identity.genesis });
    const keeper = { v: KEEPER_V, keeper: j, root_hex: bytesToHex(K), recovery, created: day(now), net, ...meta,
      workers: { 0: { name, n: 0, did: w.did, original: w.original, placed: 'device', rank: 'full', via: 'here', at: now, attestation, until: attestation.body.exp } },
      me: { n: 0, did: original, original } };
    const entry = { name, worker: 0, did: w.original, rank: 'full', added: now, by: original }, here = { name, did: w.original, worker: 0 };
    const list = seat === 'here' ? signList({ operator: original, seq: 1, iat: now, devices: [entry], seat: nextSeat(undefined, w.original, now) }, (b) => signWith(secret, b)) : null;
    const notes = list ? { v: SEAT_LOCAL_V, here, imported: 1 } : { v: SEAT_LOCAL_V, here, elsewhere: true, entry };
    return { identity, keeper, device, list, notes, did: original, worker: w.original };
  } catch (e) {
    // Never a message that could carry a word: the words were checked above, anything else is ours.
    if (e?.check) throw e;
    return fail('restore', `the restore failed (${e?.constructor?.name ?? 'error'})`);
  } finally { S?.fill(0); K?.fill(0); secret?.fill(0); }
}

/** A standby restored device takes the seat: the list naming it, signed by the operator key in `identity`. */
export function takeSeat(notes, identity, now) {
  checkNow(now);
  if (notes?.v !== SEAT_LOCAL_V || !notes.elsewhere || !notes.entry) fail('seat_here', 'this device holds the seat already, or was not restored as a standby');
  const original = didOf(identity.genesis);
  if (notes.entry.by !== original) fail('seat_here', 'the seat notes are another operator\'s');
  const secret = hexToBytes(identity.secret);
  try {
    const entry = { ...notes.entry, added: now };
    const list = signList({ operator: original, seq: 1, iat: now, devices: [entry], seat: nextSeat(undefined, entry.did, now) }, (b) => signWith(secret, b));
    return { list, notes: { v: SEAT_LOCAL_V, here: notes.here, imported: 1 } };
  } finally { secret.fill(0); }
}
