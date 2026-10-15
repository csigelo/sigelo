// SPDX-License-Identifier: MIT
// The MQTT carrier of sigelo-contact (design/relay-plan.md §2, §3 "Login", "Topics", "Errors"): moves
// invite answers and replies and sigelo-msg/0 envelopes between contacts through a relay. The relay
// sees random topics and ciphertext; everything here that decides who someone is runs offline.
//
//   const c = new Carrier({ identity, store, state, relay, endpoints, retentionDays, clock, onEvent, keep })
//   await c.invite({ name, ttl, short })   → { code, did, relay, exp, short?, short_exp? }   the answer topic is claimed first;
//                                            short: the long code is also parked at the relay under a short one
//   await c.unpark(short)                  → the long code parked under a short one, taken from the relay (one use)
//   await c.accept(code, { name, wait })   → { status: 'connected' | 'waiting' | 'pending', … }   a long code or a short one
//                                            (refused after a short code was fetched: .long, keepLong)
//   await c.cancelInvite(code)             → { cancelled, name }: an unanswered invite of this agent's withdrawn
//   c.rename(who, name)                    the owner's name for a contact (store.mjs rename) → { did, name }
//   c.contacts()                           → { contacts, invites, answers, failed }   each contact with its four words (fingerprint),
//                                            pair id, chain, tier (store.mjs: own, friend, quiet) and tier_by, prekeys: its
//                                            bundle is here (false: messages wait for it), waiting: why they wait, or null;
//                                            failed: pairing_failed events (code_expired: an answer that outlived its code) until inbox
//   await c.send(to, content, { label, local }) → { status: 'sent' | 'queued', … }, or throws the relay's code
//   await c.sendAll(to, contents, { label, local }) → one result each ('refused' with its code), one login
//   await c.sendFile(to, path, { local })  → { status, to, name, file: {id, name, size, sha256, chunks} }: a file of at most
//                                            8 MiB as FILE_LABEL messages (file.mjs), one login; throws as send does. Chunks
//                                            queued wait in files/.out (0600), the state names them; gone once sent or refused.
//                                            local (all three): no session, queued in the state file for a started carrier
//                                            of the same identity elsewhere (a watcher), which sends it at its next sync()
//   await c.inbox({ wait, tiers, local, paired }) → { messages, events, dropped, offline? }: all are taken (messages: those kept;
//                                            tiers: only those from contacts of these tiers, the rest stay); local: no
//                                            session, the state file only (a started carrier elsewhere is connected);
//                                            paired: the wait also ends at a pairing (enrol.mjs)
//   c.peek(), c.take(pick)                 the messages kept for inbox(), each with its sender's tier: read, or those
//                                            pick(message, tier) chooses taken; no session (a started carrier's owner)
//   c.setTier(who, tier)                   the owner's tier for a contact (store.mjs setTier) → { did, name, tier }
//   c.observe(bundle)                      a contact's full bundle seen: its operator attestations (store.mjs observe)
//                                            a file received whole is one item {type: "file", from, contact, name, size,
//                                            sha256, path, …}, saved under `files` (pathsFor), never opened
//   await c.forget(did)                    → { name, did, revoked: true, released, offline? }
//   c.lastError                            the error behind the last offline of inbox or forget (SIGELO_DEBUG)
//   c.clockOffset(), await c.checkClock()  → { relay, offset, checked } | null: the relay's clock less this one's, seconds
//   await c.start(), c.sync(), c.stop()    stay connected, reconnecting with backoff; events reach onEvent
//
// identity() → { secret, bundle }: the agent's current secret key and SPEC §8 bundle, read again at
// every operation, so a rotation made by another process is seen at once. store: the contact store
// (store.mjs); state: this file's own JSON (sessions, outbox, inbox), both 0600 and written under one
// lock file, `<state>.lock`. pathsFor(identityFile) names both beside the identity file. onEvent(e):
// each event as it happens, messages included, and `pow` / `pow_done` around a proof-of-work search
// (seconds to a minute on a phone: say so to the operator). keep: messages also wait in the state file for
// inbox(), in plaintext, until taken (INBOX_MAX at most: the oldest go, counted as inbox_full); by
// default only without onEvent, so a message onEvent took is not left at rest after the keys that
// opened it are gone (contacts.md §3: keys stolen today must not open yesterday's messages).
// One connected carrier per identity: every process logs in with the identity's one MQTT client
// id, so a second login takes the session from a started carrier (the files stay sound under the
// lock; the started one reconnects with backoff). Beside one, use inbox and send with local: the
// state file only (sigelo-agent's one-owner rule, adapters/moadim/WATCH.md).
//
// What this adds to the wire, beside the envelope (envelope.mjs) and the invite (invite.mjs); the
// bytes are pinned in fixtures/carrier-v0.json (gen-carrier.mjs --check):
//   - Frames for the invite answer (kind 1), the invite reply (kind 2), the contact notice (kind 4)
//     and prekeys (kind 5): version 0x01 | kind | 16 zero bytes | counter 1 (u32 BE) | nonce (24) |
//     XChaCha20-Poly1305 of pad(JCS(value)); additional data = the 22-byte header ‖ UTF-8 topic.
//     Answer and reply use inviteKeys(secret).key on the invite's two topics. Refusals, in order:
//     frame, aead, padding, plaintext.
//   - Answer and reply carry the sender's chain as their bundle (genesis and rotations, as the
//     notice does): the store keeps nothing else, and an invite topic holds 64 KB, which a bundle
//     full of attestations would pass. A frame over 64 KB is refused before it is queued.
//   - Sizes: a relay closes the connection, with no notice, on a packet longer than MAX_PACKET
//     (relay/server.mjs MAX_FRAME), and what is pending goes first at every connection, so no frame
//     here may pass it: an envelope is at most envelope.mjs MAX_ENVELOPE (1 MiB, refused
//     message_too_large before it is queued), its PUBLISH 38 bytes more; a notice or prekeys frame
//     is tens of KB. A message that fits the reader's cap (256 KiB free, 1 MiB Pro) uncarried may
//     not while its epoch carries the encapsulation: a padded plaintext of at most the cap less
//     1,198 bytes always fits. Over the cap, the relay refuses it too_large.
//   - The contact notice: after its own rotation an agent sends each contact
//     {bundle: its chain (genesis and rotations, nothing else), proof: {body: {v: V, typ:
//     "contact-notice", did: its current DID, pair: kdf.pairId(K)}, sig}} under HKDF-SHA256(K, salt
//     "sigelo-notice/0", info = sender original DID ‖ "\n" ‖ recipient original DID), on its mailbox
//     topic. Messages signed by the new key fail `from` until the contact knows the rotation, and
//     only the old key could sign it inside an envelope, so the notice is authenticated by the
//     pairing key and decided by the chain itself: SPEC §9 verify, then store.admit merges every
//     rotation seen (recovery beats a thief). The proof, signed by the key the chain ends at, is
//     what a chain cannot give: a rotation is signed by the key it leaves (or the recovery key),
//     never by the one it enters, so without it a contact could end its chain at a third party's
//     public genesis, and the store would file that party's DIDs under the contact. The receiver
//     merges a notice only if its chain holds the sender's original DID (notice_chain) and the
//     proof verifies under the chain's current key for this pairing (notice_sig); it refuses one
//     that carries more than 64 rotations, or whose merged chain is longer (bundle), and skips one
//     that brings no rotation it has not merged already, unverified (and answers it with a bundle,
//     at most every RESYNC, whose `known` says it holds the rotation). One refused after its chain
//     was checked is refused again unchecked, and past NOTICE_CHECKS checked an hour per contact a
//     notice is dropped unchecked (notice_rate), unless it brings its owner's recovery rotation,
//     signed by the recovery key the chain held commits to. Of the merge the store keeps
//     the rotation followed on each edge of the chain, as relay/auth.mjs keeps a login's: a thief's
//     fork that a recovery superseded goes, so it cannot crowd out the owner. The relay expires a
//     notice like any message, so a sender sends it again, at most every RESYNC, before a bundle or
//     an envelope goes and when the contact's prekeys frame names another of its DIDs, until a
//     prekeys frame from the contact names the current one (`known`). A contact whose envelope fails
//     `from` sends such a frame, at most every RESYNC. An invitee holds, from its pairing, the DID
//     its answer's chain ended at as announced and known, so a rotation between the answer and the
//     reply is announced before any other frame.
//   - Prekeys (prekeys.mjs) travel in a frame of their own (kind 5), {prekeys: the signed bundle,
//     want: boolean, known: the receiver's current DID as the sender holds it}, under
//     HKDF-SHA256(K, salt "sigelo-prekeys/0", info = sender original DID ‖
//     "\n" ‖ recipient original DID), on the mailbox topic. Not in an envelope: an envelope needs an
//     epoch, an epoch the contact's bundle, so once both bundles held had expired (31 days with no
//     fresh one across) neither side could ever send again. The bundle is signed by the identity key
//     (checkPrekeys); one no newer than the bundle held is refused before its signature is checked,
//     so a replay costs nothing. want: the sender holds no bundle of the receiver's it could begin
//     an epoch on (none, expired, or signed by a key the receiver left), so the receiver sends a
//     fresh one; honoured only beside a bundle accepted, so a replay asks nothing, and only when
//     this agent has sent the contact no bundle for RESYNC seconds: each bundle is one of this
//     agent's messages per day at the relay, so a contact asking without end spent its allowance
//     toward everyone, and saw when it was online; a bundle sent within the hour is the answer
//     (it crossed the request). Messages waiting
//     for a bundle stay queued and are reported once (event `waiting`); the bundle is asked for at
//     most once a day. The invite answer carries none (`prekeys: null`): a prekey bundle names its
//     pairing (`pair`), which does not exist before the reply. The inviter's reply carries hers; the
//     invitee sends his as his first frame. Bundles to one contact get strictly increasing iat. A
//     bundle inside a message (label LABEL_PREKEYS, as an earlier version sent it) is still taken.
//   - After a rotation, both sides assume the old state may be a thief's copy: the rotated agent
//     begins epochs on the contact's last-resort key until fresh prekeys come, and the contact,
//     on reading the notice, retires the prekeys it listed and sends fresh ones. The pairing key
//     K stays: whoever copied the store can compute and claim later mailbox topics until the two
//     pair again (invite and accept between existing contacts replace K: `rekeyed`).
//   - After a recovery, K is burned on both sides (re_pair, in the contact store): the recovered
//     agent marks every contact it paired with before the recovery (`own_recovery`, #markRecovered),
//     and a contact marks it on merging a notice that brings a recovery it had not followed
//     (`contact_recovery`). Toward a marked contact nothing goes but the rotation notice, and no
//     new mailbox of the pair is claimed: a thief holding K claims weeks nobody writes in. A
//     message queued for it before the mark is refused, and noted (`refused`, code re_pair). A new
//     invite and accept replace K and clear the mark (store.admit writes the record afresh). A
//     contact on sigelo-contact 0.1.2 follows the recovery but marks nothing and keeps writing
//     under K, to weeks nobody may read but a thief: the recovered side pairs again at once.
//   - Recovery beats key, for messages too: a contact's envelope signed by a DID that a recovery
//     this agent follows has overruled (any DID of the contact's chain up to the node recovered
//     from, or on a fork the recovery left) is refused, and noted (`refused`, code re_pair, `from`
//     the contact): it may be the thief's. The relay delivers in the order written, so a thief's
//     messages written before the owner recovered arrive before the recovery's notice, and were
//     taken as the contact's. So a notice that brings a recovery checks again every message of
//     that contact still waiting for inbox() against the chain it ends at (the recovery is not
//     taken first: the relay alone decides what comes when), and one that arrives after it fails
//     `from`, reported as re_pair. A message signed by the recovered-from key before the theft
//     cannot be told from the thief's: refused alike; the owner writes again once paired again.
//     What an earlier inbox() returned, or onEvent got, cannot be taken back: the `rotated` event
//     of such a notice lists the DIDs it overruled (`overruled`).
//   - Operator hints (label OPERATOR_LABEL, a message like any other): an agent attested by
//     operators (sigelo-relay/operator) tells each contact {hints: HMAC-SHA256(K, "sigelo-operator/0
//     hint\n" ‖ its original DID ‖ "\n" ‖ operator DID)}, once per pairing and set of operators. A
//     contact run by the same operator, or that operator itself, recognises one and answers {asks}
//     (the same with "ask" and its own DID: it knows the operator's DID, an echo does not), and only
//     then the agent sends {proof}: its chain with those attestations and their issuers, which the
//     contact verifies (SPEC §9) and files (store.mjs observe): the contact's tier becomes own. A
//     proof is taken only after asks of ours, at most NOTICE_CHECKS an hour, and only if its chain
//     ends at the sender's current DID as held (store.mjs current_did). A renewed attestation is
//     hinted and proved again; asks for the same operators go at most every RESYNC. A contact
//     learns from the hints only which operator DIDs it guesses right (THREAT-MODEL §2.12). An
//     agent on an older version gets the hints as messages with that label. send refuses the label.
//   - Mailboxes: an agent holds the topics of every ISO week from `retention` ago to AHEAD (7 days,
//     or its retention if shorter) ahead. The relay drops a publish to a topic nobody claimed (and
//     says no_reader), so next week's topic must be claimed before a contact writes in it while
//     this agent is offline. An invitee's mailbox cannot be claimed before it reads the inviter's
//     reply (the topic needs K, which the reply carries), so the inviter's first frames to it meet
//     no_reader until the invitee next connects. A no_reader never loses a message: it stays queued
//     here, unsealed (its epoch restarted when it began one, its prekey given back), with
//     everything else to that contact until the next round, and goes at the next connection that
//     finds the mailbox held (`queued`, the reason in its detail). Free tier: 14 days, 4 weeks
//     (5 within 5 minutes of Monday 00:00 UTC), so 4 or 5 mailboxes per contact; Pro's 90 days:
//     14 or 15 (relay/allowance.mjs counts 15). A reader away longer than a week is told nothing of
//     contacts writing in a week it did not claim: their messages wait on their side (no_reader).
//     The retention: the constructor's, else relay.json's free tier at this agent's own relay
//     (read once, at the first login), else RETENTION_DAYS. A Pro reader must say its 90 days
//     (SIGELO_RELAY_RETENTION_DAYS): nothing tells the carrier its tier. A claim past its time is
//     given up only once deliveries have stopped, so what is queued on it is read first. The relay
//     brakes new claims (relay/allowance.mjs RATE.claim: 128 at once per identity, then 2 a second):
//     a round stops at the first SUBSCRIBE refused "rate", and what is left waits for the next
//     round, so topics are asked in the order they matter (#want). A refused topic is asked again
//     at the next hourly round (ASK_AGAIN).
import { createHash } from 'node:crypto';
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { connect } from 'mqtt';
import { canonicalize, commitmentOf, did as didOf, parseBytes, sign, verify, verifySig } from 'sigelo';
import { KIND, acceptPrekeys, expire, header, open, pad, prekeysMissing, restartEpoch, send, session, unpad } from './envelope.mjs';
import { answerId, buildAnswer, buildReply, checkAnswer, checkReply, inviteKeys, keyOf, makeInvite, parseInvite } from './invite.mjs';
import { MsgError, checkNow, fail, hex, isoWeek, pairId, topic } from './kdf.mjs';
import { Prekeys, exact, kemDecapsulate, kemEncapsulate, kemKey } from './prekeys.mjs';
import { Contacts, OPERATOR_CTX, TIERS } from './store.mjs';
import { SHORT_TTL, codeHash, codeKind, fingerprint, formatShort, makeShort, normaliseShort } from './short.mjs';
import { FILE_LABEL, MAX_FILE, assemble, checkChunk, checkManifest, chunkHead, isManifest, safeName, splitFile } from './file.mjs';

export const V = 'sigelo-carrier/0';
export const DEFAULT_RELAY = 'relay.sigelo.ai', MQTT_PORT = 8883, NOTICE = '$sigelo/notice';
export const LABEL_PREKEYS = 'sigelo-msg/0 prekeys', KIND_NOTICE = 4, KIND_PREKEYS = 5, TYP_NOTICE = 'contact-notice';
export const OPERATOR_LABEL = 'sigelo-operator/0';
// The relay login (relay-plan §3 "Login"): the body GET /challenge answers and the agent signs. A
// type of its own, never a SPEC §5.2 challenge: a world that passed the relay's nonce on as its own
// challenge would get the agent's relay login back from sign-challenge.
export const LOGIN_V = 'sigelo-relay/0', TYP_LOGIN = 'relay-login';
// RETENTION_DAYS: the relay's free tier (relay/allowance.mjs TIERS.free), when relay.json says nothing.
export const RETENTION_DAYS = 14, RETENTION_MAX_DAYS = 90, DAY = 86400, SKEW = 300, AHEAD = 7 * DAY;
// The relay closes a connection whose SUBSCRIBE holds more topics (relay/mailbox.mjs MAX_TOPICS).
const MAX_TOPICS = 128;
// An invite topic holds 4 messages and 64 KB (relay/mailbox.mjs INVITE_BYTES); a bundle at most 64
// items (relay-plan §3 "Login"), so no honest contact's chain passes 64 rotations.
export const INVITE_BYTES = 64 * 1024, MAX_ROTATIONS = 64;
// A contact notice that reaches its chain's check costs SPEC §9 twice (here, then in store.admit):
// 0.27 s each for 64 rotations on a phone-class CPU (the audit's measurement, 2026-10-13), and
// whoever holds K can send one: the contact, or a thief of either side's state, since K outlives a
// recovery. At most NOTICE_CHECKS of one contact's are checked per RESYNC (an honest contact sends
// one per rotation, and again at most hourly), and the last REFUSED_NOTICES refused after that
// check are refused again unchecked (#onContactNotice).
export const NOTICE_CHECKS = 4, REFUSED_NOTICES = 16;
// A proof of work must be sent within the challenge's 300 s. Node on a phone-class ARM64 CPU
// hashes ~180,000 a second (measured 2026-10-07): 22 bits take 23 s on average, 24 bits 92 s, 26
// bits 6 minutes. A relay asking more than POW_MAX is refused rather than spun for, and the search
// stops at POW_MS, before the challenge expires. Any host can be named by a stranger's code, so a
// relay other than this agent's own (SIGELO_RELAY) gets the plan's normal 22 bits at most.
export const POW_MAX = 26, POW_MAX_OTHER = 22, POW_MS = 280000;
// Searches at one relay in any 24 hours, each counted in the state file as it begins, found or not.
// An honest relay asks once per identity, and again only if it forgot it. Without a count, a relay
// that grants a proven login, closes, then refuses the next login's SUBSCRIBE `pow` had this client
// search again at each reconnection, without end: success reset every other bound.
export const POW_SEARCHES = 3;
// A delivery this process failed on this many times, its files sound each time, is dropped.
const POISON_TRIES = 3;
// Events kept for the next inbox(): pairings, rotations, failed pairings. The oldest go first.
// Messages kept for it (keep), likewise.
const EVENTS_MAX = 1000, INBOX_MAX = 1000;
// Files arriving at once from one contact (#onFile): each holds up to 8 MiB of parts here.
const FILES_OPEN = 8;
// Half the relay's publish brake (20 a second, 200 at once): past it the relay refuses publishes
// ("rate"), and closes the connection after 500 refusals in a minute (every refused publish
// counts, a no_reader too).
const RATE = { perSecond: 10, burst: 100 };
// Milliseconds. QUIET: no delivery for this long after connecting = the relay's queue is drained.
const QUIET = 400, DRAIN = 4000, ACK_MS = 15000, CONNECT_MS = 15000, HTTP_MS = 15000, HTTP_MAX = 65536;
// MQTT.js buffers a packet whole before handing it over, up to MQTT's 256 MB (its own size check
// applies only to protocol version 5), and a code can name any host: a packet longer than the
// largest a relay forwards (relay/server.mjs MAX_FRAME: a 1 MB message and its header) cuts the
// connection (limitPackets).
export const MAX_PACKET = 1024 * 1024 + 1024;
const TICK = 3600 * 1000, BACKOFF = [1000, 60000];
// A connection that held this long resets the backoff when it closes; a shorter one does not, so a
// relay that accepts and closes at once is dialled ever more slowly, as one that refuses is.
const STABLE_MS = 60000;
// Login refusals no retry can fix.
const PERMANENT = new Set(['password', 'bundle', 'sig', 'client_id', 'challenge', 'relay', 'identity']);
// A refusal by one of these is this process failing, not a message: the delivery is not acknowledged.
const INTERNAL = new Set(['lock', 'state', 'store', 'identity', 'time']);
// The login checks relay/auth.mjs names on POST /check. Any other word from the relay is `connect`:
// a check name decides what this client does next, so a relay cannot pick one.
const LOGIN_CHECKS = new Set(['rate', 'password', 'challenge_unknown', 'challenge_expired', 'bundle', 'sig', 'client_id', 'pow', 'relay_full']);
// Refusals of an invite reply that a later round may get past: the reply stays queued.
const REPLY_RETRY = new Set(['rate', 'relay_full', 'quota_messages']);
// $sigelo/notice codes that refuse the publish, or the SUBSCRIBE, in flight (relay-plan §3 "Errors").
const PUBLISH_CODES = new Set(['too_large', 'quota_storage', 'quota_messages', 'rate', 'relay_full', 'pow', 'no_reader']);
// A contact's envelope this agent cannot open for want of its epoch asks the writer for a new epoch
// by a fresh prekey bundle (RESYNC_CHECKS), at most once in this many seconds per contact after
// the last such bundle: the check comes before any decryption, so a relay can make one up. A
// failure inside that time is owed a bundle (resync_due), sent at the first round once the time
// has passed: dropped instead, every later envelope of a broken epoch was acknowledged and lost
// until one failed after the hour. Measured from the last bundle of any kind (pairing, top-up, an
// answer to `want`), a failure soon after pairing waited an hour for a bundle that cannot have been
// its answer. That bundle replaces every one-time key: its epoch's key may have been retired
// unopened, and a bundle listing none of the keys the writer holds ends its epoch (envelope.mjs
// acceptPrekeys). An envelope that begins an epoch here settles what is owed. A contact's request
// for a bundle (want) is held to the same pace, measured from the last bundle of any kind (a bundle
// sent within it crossed the request). So is a rotation notice sent again (the header's "contact
// notice").
const RESYNC = 3600;
// epoch_unknown: no envelope that carried the epoch's encapsulation came, and the writer has
// stopped carrying it, having read a reply of ours (envelope.mjs "Epoch recovery").
// prekey_reused, prekey_unknown: the epoch begins on a one-time key this agent has spent or no
// longer holds, as when the writer took a first envelope the relay stored for refused (a lost
// PUBACK, then a retransmit refused) and put its key back (envelope.mjs restartEpoch). Each of
// the writer's envelopes fails alike until its epoch ends: before, only by chance, up to 7 days
// later, when this agent's bundle fell due.
const RESYNC_CHECKS = new Set(['epoch_unknown', 'prekey_reused', 'prekey_unknown']);
// Seconds after which a topic the relay refused on a connection is asked again (the brake refilled,
// a claim expired, the disk freed): under the hourly round, so each round asks what the one before
// was refused. Refused once, it was never asked again while the connection lasted. Not at every
// round either: sync() may run often, and each topic the brake refuses again is a strike there.
const ASK_AGAIN = 3000;
const SUBSCRIBE_CODES = new Set(['mailbox_taken', 'quota_mailboxes', 'pow', 'relay_full', 'rate']);
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);
// Special-use and local names (RFC 6761, 6762, 7686, 8375), the top-level names ICANN will never
// delegate for their collisions with private networks (.corp, .home, .mail), and the habitual
// .internal, .intranet, .private, .lan and .localdomain.
const LOCAL_NAME = /(^|\.)(localhost|local|localdomain|test|example|invalid|onion|internal|intranet|private|corp|home|mail|lan|home\.arpa)$/;
// A host the dialer reads as an IPv4 address: its last label is a number, decimal or 0x and hex
// (the WHATWG URL parser's "ends in a number", which fetch uses; inet_aton reads the same). So
// 127.0.0.0x1 is 127.0.0.1. Codes spell hosts in lowercase (invite.mjs), so 0X never comes.
const IPV4_LIKE = /\.(?:[0-9]+|0x[0-9a-f]*)$/;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const b64 = (b) => Buffer.from(b).toString('base64');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const randomId = () => hex(randomBytes(8));
const clientIdOf = (original) => 's' + createHash('sha256').update(original, 'utf8').digest('hex').slice(0, 24);
// Operators as hinted and proved: each with its attestation's expiry, so a renewal goes again.
const opKey = (mine, ops) => [...ops].sort().map((d) => `${d} ${mine.exp.get(d)}`).join();
// Whether a session as the state holds it (dumpSession) has a prekey bundle of contact c's that an
// epoch can begin on (envelope.mjs prekeysMissing): of this pairing, signed as c's current DID, unexpired.
const theirPrekeys = (c, d, pair, now) => {
  const p = d?.pair === pair ? d.out.prekeys : null;
  return Boolean(p) && p.did === c.current_did && now < p.exp;
};
// The four words of a pairing (short.mjs), from its pairing key as the store holds it (hex), or null.
const wordsOf = (pairKey) => (typeof pairKey === 'string' ? fingerprint(pairId(hexToBytes(pairKey))) : null);
// The refusals of POST /park this client names (relay/park.mjs, and the login's: auth.mjs).
const PARK_CHECKS = new Set(['park', 'park_taken', 'park_full', 'pow', ...LOGIN_CHECKS]);

// ---------------------------------------------------------------- configuration

/** The contact store, this carrier's state and the files received, beside the identity file: x.json → x.contacts.json, x.carrier.json, x.files/. */
export function pathsFor(identityFile) {
  const base = identityFile.replace(/\.json$/, '');
  return { store: `${base}.contacts.json`, state: `${base}.carrier.json`, files: `${base}.files` };
}

/**
 * Where relay "host[:port]" is reached: MQTT over TLS on port (8883), HTTPS on 443. endpoints:
 * { [relay]: { mqtt, http } } overrides, e.g. a relay on loopback; plain mqtt:// and http:// only
 * to a loopback address, so nothing leaves the machine in clear.
 */
export function endpointOf(relay, endpoints = {}) {
  const o = endpoints && Object.hasOwn(endpoints, relay) ? endpoints[relay] : null;
  if (!o) {
    const [host, port] = relay.split(':');
    return { mqtt: `mqtts://${host}:${port ?? MQTT_PORT}`, http: `https://${host}` };
  }
  for (const [k, secure, plain] of [['mqtt', 'mqtts:', 'mqtt:'], ['http', 'https:', 'http:']]) {
    let u;
    try { u = new URL(o[k]); } catch { fail('relay', `${relay}: endpoints.${k} is not a URL`); }
    if (u.protocol !== secure && !(u.protocol === plain && LOOPBACK.has(u.hostname))) fail('relay', `${relay}: endpoints.${k} must be ${secure}// (${plain}// only to a loopback address)`);
  }
  return { mqtt: o.mqtt, http: o.http.replace(/\/+$/, '') };
}

/**
 * Whether relay "host[:port]" is a public DNS name. Accepting a code dials its relay (HTTPS, then
 * MQTT over TLS) with this agent's DID, and anyone can make a code: a stranger's must not point
 * the agent at its own network. Not public: an IP address in any spelling the dialer reads as one
 * (IPV4_LIKE; codes hold no IPv6 literal), a single label, a special-use or local name. The check
 * reads the name only, and the address is not checked at connect time: a name whose DNS answers
 * an inside address passes, as does one the resolver completes with a search domain inside
 * (kubernetes.default under ndots:5). Such a host gets GET /challenge with this agent's DID and an
 * MQTT dial, over TLS; nothing it answers reaches the code's author.
 */
export function publicRelay(relay) {
  const host = relay.split(':')[0];
  return host.includes('.') && !IPV4_LIKE.test(host) && !LOCAL_NAME.test(host);
}

const retentionOk = (n) => Number.isSafeInteger(n) && n >= 1 && n <= RETENTION_MAX_DAYS;

/** The free tier's retention in days that a relay's relay.json states (limits.free.retention_days), or null. */
export function retentionOf(info) {
  const n = info?.limits?.free?.retention_days;
  return retentionOk(n) ? n : null;
}

/** SIGELO_RELAY (the relay new invites name), SIGELO_RELAY_ENDPOINTS (JSON, as endpointOf), SIGELO_RELAY_RETENTION_DAYS. */
export function optionsFromEnv(env = process.env) {
  const o = {};
  if (env.SIGELO_RELAY) o.relay = env.SIGELO_RELAY;
  if (env.SIGELO_RELAY_ENDPOINTS) {
    try { o.endpoints = JSON.parse(env.SIGELO_RELAY_ENDPOINTS); } catch { fail('relay', 'SIGELO_RELAY_ENDPOINTS is not JSON: want {"<relay>": {"mqtt": "mqtts://…", "http": "https://…"}}'); }
  }
  if (env.SIGELO_RELAY_RETENTION_DAYS) {
    const n = Number(env.SIGELO_RELAY_RETENTION_DAYS);
    if (!retentionOk(n)) fail('relay', `SIGELO_RELAY_RETENTION_DAYS: whole days, 1 to ${RETENTION_MAX_DAYS} (the reader's tier)`);
    o.retentionDays = n;
  }
  return o;
}

// ---------------------------------------------------------------- files

// One lock file for the store and the state: every change is load, change, save inside it, so a
// CLI verb and a long-running carrier on the same identity cannot undo each other. As
// adapters/moadim/sigelo-agent-monero.ts withLock.
const LOCK_TRIES = 200, LOCK_MS = 25;
function withLock(path, fn) {
  const lock = `${path}.lock`, idle = new Int32Array(new SharedArrayBuffer(4));
  for (let i = 0; ; i++) {
    try { closeSync(openSync(lock, 'wx', 0o600)); break; } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      if (i === LOCK_TRIES) fail('lock', `${lock} is still held after ${(LOCK_TRIES * LOCK_MS) / 1000} s: another sigelo-contact process holds it, or one was killed holding it; delete the file to continue`);
      Atomics.wait(idle, 0, 0, LOCK_MS);
    }
  }
  try { return fn(); } finally { rmSync(lock, { force: true }); }
}

function loadState(path, self) {
  const s = existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : { v: V, self, relays: {}, peers: {}, pending: [], inbox: [], events: [], dropped: {}, failing: {} };
  if (s.v !== V || s.self !== self) fail('state', `${path} is not the ${V} state of ${self}`);
  // Written by an earlier version of this file, which kept neither.
  s.events ??= []; s.failing ??= {};
  return s;
}

// The state holds chain keys and prekey secrets: 0600, a fresh temporary name created exclusively,
// then renamed (store.mjs save()).
function saveState(path, s) {
  const tmp = join(dirname(path), `.${basename(path)}.${randomId()}.tmp`);
  writeFileSync(tmp, JSON.stringify(s), { mode: 0o600, flag: 'wx' });
  renameSync(tmp, path);
}

// A session (envelope.mjs) as JSON: every key and counter, bytes as base64. Restored from the
// state at every operation and saved only when the operation succeeded, so a failed one leaves
// nothing half-done.
function dumpSession(s) {
  const p = s.out.prekeys, e = s.out.epoch, h = s.in.prekeys;
  return {
    pair: s.pair,
    out: {
      prekeys: p && { did: p.did, iat: p.iat, exp: p.exp, keys: p.keys.map((k) => [k.id, b64(k.pk)]), last_resort: [p.last_resort.id, b64(p.last_resort.pk)] },
      used: [...s.out.used], returned: [...s.out.returned],
      epoch: e && { id: b64(e.id), ck: b64(e.ck), n: e.n, started: e.started, kem: b64(e.kem), lastResort: e.lastResort, oneTime: e.oneTime, again: e.again, self: e.self, peer: e.peer, carry: e.carry },
    },
    in: {
      prekeys: {
        did: h.did, used: [...h.used], replaced: h.replaced, issued: h.issued, acked: h.acked,
        oneTime: [...h.oneTime].map(([id, k]) => [id, b64(k.publicKey), b64(k.secretKey), k.iat]),
        lastResort: h.lastResort.map((k) => [k.id, k.iat, b64(k.publicKey), b64(k.secretKey)]),
        retired: [...h.retired].map(([id, k]) => [id, b64(k.secretKey), k.lastResort, k.until, k.iat]),
      },
      epochs: [...s.in.epochs].map(([id, x]) => [id, x.ck && b64(x.ck), x.high, [...x.skipped].map(([i, k]) => [i, b64(k.mk), k.until]), [...x.seen], x.lastResort, x.prekey, x.until]),
      ended: [...s.in.ended],
    },
  };
}

function loadSession(s, d) {
  const p = d.out.prekeys, e = d.out.epoch, h = d.in.prekeys;
  s.out.prekeys = p && { did: p.did, iat: p.iat, exp: p.exp, keys: p.keys.map(([id, pk]) => ({ id, pk: unb64(pk) })), last_resort: { id: p.last_resort[0], pk: unb64(p.last_resort[1]) } };
  s.out.used = new Set(d.out.used);
  s.out.returned = new Set(d.out.returned ?? []);   // written before keys were put back: none
  // An epoch written before envelopes repeated the encapsulation: it repeats it from now on until
  // a reply (envelope.mjs, "Epoch recovery"), which costs bytes only.
  s.out.epoch = e && { ...e, id: unb64(e.id), ck: unb64(e.ck), kem: unb64(e.kem), carry: e.carry ?? true };
  const k = new Prekeys();
  k.did = h.did;
  // Written before used ids had a time (an array of ids), and before keys had their issue time and
  // replaced, issued and acked: Prekeys expire gives each id one, a reissue is due at once, and a
  // key of no known time counts as listed in every bundle (consume).
  k.used = new Map(h.used.map((x) => (typeof x === 'string' ? [x, undefined] : [x[0], x[1] ?? undefined])));
  k.replaced = h.replaced ?? 0; k.issued = h.issued ?? 0; k.acked = h.acked ?? 0;
  for (const [id, pk, sk, iat] of h.oneTime) k.oneTime.set(id, { publicKey: unb64(pk), secretKey: unb64(sk), iat: iat ?? 0 });
  k.lastResort = h.lastResort.map(([id, iat, pk, sk]) => ({ id, iat, publicKey: unb64(pk), secretKey: unb64(sk) }));
  for (const [id, sk, lastResort, until, iat] of h.retired) k.retired.set(id, { secretKey: unb64(sk), lastResort, until, iat: iat ?? 0 });
  s.in.prekeys = k;
  // Entries written before receiving keys had a time carry none: envelope.mjs expire gives them one.
  s.in.epochs = new Map(d.in.epochs.map(([id, ck, high, skipped, seen, lastResort, prekey, until]) =>
    [id, { ck: ck === null ? null : unb64(ck), high, skipped: new Map(skipped.map(([i, mk, at]) => [i, { mk: unb64(mk), until: at ?? undefined }])), seen: new Set(seen), lastResort, prekey, until: until ?? undefined }]));
  s.in.ended = new Map(d.in.ended ?? []);
  return s;
}

// ---------------------------------------------------------------- frames

const ZERO_EPOCH = new Uint8Array(16), FRAME_HEAD = 22, NONCE = 24;
/** The contact notice's key: HKDF-SHA256(K, salt "sigelo-notice/0", info = from ‖ "\n" ‖ to), original DIDs. */
// The header's "Operator hints": what `from` (an original DID) shows of operator `op`, as hex.
export const operatorHint = (K, kind, from, op) => hex(hmac(sha256, K, utf8ToBytes(`${OPERATOR_LABEL} ${kind}\n${from}\n${op}`)));
export const noticeKey = (K, from, to) => hkdf(sha256, K, utf8ToBytes('sigelo-notice/0'), utf8ToBytes(`${from}\n${to}`), 32);
/** The prekeys frame's key: HKDF-SHA256(K, salt "sigelo-prekeys/0", info = from ‖ "\n" ‖ to), original DIDs. */
export const prekeysKey = (K, from, to) => hkdf(sha256, K, utf8ToBytes('sigelo-prekeys/0'), utf8ToBytes(`${from}\n${to}`), 32);

/** A kind 1, 2, 4 or 5 frame (the header's "Frames"). rng(24) gives the nonce: a parameter so a test fixes every byte. */
export function seal(kind, key, t, value, rng = randomBytes) {
  const head = header(kind, ZERO_EPOCH, 1), nonce = rng(NONCE);
  return concatBytes(head, nonce, xchacha20poly1305(key, nonce, concatBytes(head, utf8ToBytes(t))).encrypt(pad(utf8ToBytes(canonicalize(value)))));
}

/** Checks, in order: frame (header), aead, padding, plaintext (strict JSON that is its own JCS). Throws MsgError only. */
export function unseal(kind, key, t, bytes) {
  const head = header(kind, ZERO_EPOCH, 1);
  if (bytes.length < FRAME_HEAD + NONCE + 256 + 16 || Buffer.compare(bytes.subarray(0, FRAME_HEAD), head) !== 0) fail('frame', `not a kind ${kind} frame`);
  let pt;
  try { pt = xchacha20poly1305(key, bytes.subarray(FRAME_HEAD, FRAME_HEAD + NONCE), concatBytes(head, utf8ToBytes(t))).decrypt(bytes.subarray(FRAME_HEAD + NONCE)); } catch {
    fail('aead', 'does not decrypt: tampered, or not for this topic');
  }
  const text = unpad(pt);
  let v;
  try { v = parseBytes(text); } catch (e) { fail('plaintext', `not JSON: ${e.message}`); }
  // parseBytes reads what JCS cannot write (a float, a lone surrogate, an integer past 2^53), and
  // canonicalize throws on it. That is this frame's refusal: any other exception would read as
  // this process failing, and the relay would deliver the frame again at every connection.
  let jcs;
  try { jcs = canonicalize(v); } catch (e) { fail('plaintext', `no canonical form: ${e.message}`); }
  if (Buffer.compare(utf8ToBytes(jcs), text) !== 0) fail('plaintext', 'not the JCS form of its value');
  return v;
}

// What a contact needs to follow a rotation, and to check a pairing: the chain. Attestations and
// bindings stay out (the store keeps neither).
const chainOf = (b) => ({ v: 'sigelo/0', typ: 'bundle', genesis: b.genesis, rotations: b.rotations, bindings: [], attestations: [], issuers: [] });
const BUNDLE_KEYS = ['v', 'typ', 'genesis', 'rotations', 'bindings', 'attestations', 'issuers'];
// What a relay reads: the chain, and operator attestations for this relay with their issuers (plan
// §3 "Operator attestation", at most 4). Never bindings: a Monero address is no relay's business.
function loginBundle(b, relay) {
  const ops = (b.attestations ?? []).filter((a) => a?.body?.ctx === 'sigelo-relay/operator' && a.body.claims?.relay === relay).slice(0, 4);
  const iss = new Set(ops.map((a) => a.body.iss));
  return { ...chainOf(b), attestations: ops, issuers: (b.issuers ?? []).filter((g) => iss.has(didOf(g))) };
}

// What the store keeps of a contact's chain after a notice: the rotation followed on each edge of
// `chain` (verify's result over `rotations`), as relay/auth.mjs chainRotations keeps a login's. It
// is bounded by the chain's length and holds every recovery the walk followed, so a recovery seen
// once still beats the thief; superseded forks and rotations no walk reaches are not kept. One
// rotation on an edge is the one followed. Two on one edge can only be a copy that differs (SPEC
// §7.3 passes over an invalid one): the first is kept, and the walk over the kept ones alone must
// give the same chain, or the notice is refused.
function followed(genesis, rotations, chain, now) {
  if (chain.length - 1 > MAX_ROTATIONS) fail('bundle', `the merged chain holds ${chain.length - 1} rotations, more than ${MAX_ROTATIONS}`);
  const edge = new Map(chain.slice(1).map((d, i) => [`${chain[i]} ${d}`, i]));
  const picked = [];
  let two = false;
  for (const x of rotations) {
    const i = edge.get(`${x.body.id} ${x.body.next}`);
    if (i === undefined) continue;
    if (picked[i]) two = true; else picked[i] = x;
  }
  // The walk followed a rotation on every edge, from these same rotations: a gap is a store file
  // that changed under the lock.
  for (let i = 0; i < chain.length - 1; i++) if (!picked[i]) fail('store', `no rotation from ${chain[i]} to ${chain[i + 1]} among those merged`);
  if (!two) return picked;
  let again;
  try { again = verify(chainOf({ genesis, rotations: picked }), now); } catch (e) { fail('bundle', `REJECT: ${e.message}`); }
  if (again.chain.join(' ') !== chain.join(' ')) fail('bundle', 'two rotations on one edge of the chain, the first not valid');
  return picked;
}

// Whether `fresh` (a notice's rotations the store does not hold) brings a recovery rotation signed
// by a recovery key contact c's chain commits to: the one its original genesis names (the notice's
// genesis, when its DID is c's original one) or one a held rotation's genesis names. Only the
// contact's owner holds that key, so such a notice is checked past NOTICE_CHECKS: a thief spending
// the count must not keep the owner's recovery out. It decides only whether the notice is checked
// now; verify() and store.admit decide the rest. Two at most are tried: an honest notice brings one.
function recovers(c, bundle, fresh) {
  const commits = new Set(c.rotations.map((x) => x.next_genesis.recovery));
  try { if (didOf(bundle.genesis) === c.did) commits.add(bundle.genesis.recovery); } catch {}
  return fresh.filter((x) => x?.body?.reason === 'recovery').slice(0, 2).some((x) => {
    try { return commits.has(commitmentOf(x.body.recovery_key)) && verifySig(x.body.recovery_key, x.body, x.sig); } catch { return false; }
  });
}

// ---------------------------------------------------------------- relay login (plan §3 "Login")

const zeroBits = (d) => { let n = 0; for (const x of d) { if (x !== 0) return n + Math.clz32(x) - 24; n += 8; } return n; };

/**
 * The first c (0, 1, 2, …) with SHA-256("sigelo-relay-pow/0\n" ‖ host ‖ original DID ‖ nonce ‖ c)
 * starting with `bits` zero bits (relay-plan §3 "Proof of work"), or null once Date.now() passes
 * `deadline`. It yields to the event loop every 4,096 hashes (about 20 ms on a phone), so the
 * process's connections, keepalives and other identities carry on during a search of minutes.
 */
export async function solvePow(host, original, nonce, bits, deadline = Infinity) {
  const prefix = `sigelo-relay-pow/0\n${host}${original}${nonce}`;
  for (let i = 0; ; i++) {
    if (zeroBits(createHash('sha256').update(prefix + i, 'utf8').digest()) >= bits) return String(i);
    if ((i & 0xfff) === 0xfff) {
      if (Date.now() > deadline) return null;
      await new Promise((r) => setImmediate(r));
    }
  }
}

// The answer body is read as it arrives and cut off past HTTP_MAX, whatever Content-Length says:
// a chunked answer has none, and a code can name any host. A redirect is not followed: through
// one, a relay would send this GET, or POST /check and the login in it, to any host, port and path,
// past publicRelay's check on the code's host. A relay never needs one: `connect`.
async function http(url, init = {}) {
  let res;
  const at = where(url), http = { url, method: init.method ?? 'GET' };
  const t0 = Date.now();
  try { res = await fetch(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(HTTP_MS) }); } catch (e) {
    const why = e.name === 'TimeoutError' ? `no answer within ${HTTP_MS / 1000} s` : e.cause?.code ?? e.cause?.message ?? e.message;
    fail('connect', `cannot reach the relay at ${at} (${why}): check the network and SIGELO_RELAY / SIGELO_RELAY_ENDPOINTS, then try again`, { cause: e, http });
  }
  http.status = res.status;
  // The relay's clock (Date, whole seconds) and the round trip to it, for clockOffset.
  const rtt = Date.now() - t0, date = Date.parse(res.headers.get('date') ?? '');
  if ((res.status >= 300 && res.status < 400) || res.type === 'opaqueredirect') {
    try { await res.body?.cancel(); } catch {}
    fail('connect', `${at}: answered ${res.status}, a redirect, which this client does not follow`, { http });
  }
  if (Number(res.headers.get('content-length') ?? 0) > HTTP_MAX) fail('connect', `${at}: answer over ${HTTP_MAX} bytes`, { http });
  const chunks = [];
  let n = 0;
  try {
    // Leaving the loop by a throw cancels the stream: nothing more is read.
    for await (const chunk of res.body ?? []) {
      n += chunk.length;
      if (n > HTTP_MAX) fail('connect', `${at}: answer over ${HTTP_MAX} bytes`, { http });
      chunks.push(chunk);
    }
  } catch (e) {
    if (e instanceof MsgError) throw e;
    fail('connect', `${at}: the answer broke off (${e.cause?.code ?? e.message}): try again`, { cause: e, http });
  }
  let body = null;
  const raw = concatBytes(...chunks);
  try { body = parseBytes(raw); } catch {}
  // Seconds the relay asks to wait (Retry-After), when it says.
  const after = Number(res.headers.get('retry-after'));
  // What a refusal carries for SIGELO_DEBUG: the status and the start of the body as received.
  http.body = new TextDecoder().decode(raw.subarray(0, 512));
  return { status: res.status, body, retryAfter: Number.isSafeInteger(after) && after > 0 ? after : null, http, date: Number.isNaN(date) ? null : date, rtt };
}

// A URL as a refusal shows it: no query (it carries the DID), no code hash.
function where(url) {
  try { const u = new URL(url); return u.origin + u.pathname.replace(/\/[0-9a-f]{64}$/, '/<code hash>'); } catch { return String(url); }
}
// A refusal of a relay's HTTP answer r, with the answer kept for SIGELO_DEBUG.
const refuse = (check, why, r) => fail(check, why, { http: r.http });
// When to try again after a 429: the relay's Retry-After, else the window its brake counts in.
const retryIn = (r, window) => (r.retryAfter ? `wait ${r.retryAfter} s` : `wait ${window}`);
// A status no answer about this agent: the relay is down, restarting, or behind a proxy that is.
const statusWhy = (r, what) => `the relay answered ${r.status} to ${what}${r.status >= 500 ? ': it is down or restarting; try again in a few minutes' : ': try again later; SIGELO_DEBUG=1 shows the answer'}`;
/** A long code (or one fetched by a short one: parked) read with parseInvite; a malformed one
 *  is refused saying how the input was read, so a mistyped short code never reads "does not
 *  start with sgl1". */
export function readCode(text, now, how = 'long') {
  try { return parseInvite(text, now); } catch (e) {
    if (!(e instanceof MsgError) || !['code_checksum', 'code_length', 'code_version'].includes(e.check)) throw e;
    const as = how === 'parked' ? 'the long code the relay holds for this short code does not parse; ask the inviter for a new one'
      : `read as a long code (it starts sgl1, or has more than 12 characters; a short code has 8, like K7F3-Q9ZP): ${reason(e)}`;
    throw new MsgError(e.check, how === 'parked' ? `${as} (${reason(e)})` : as, { cause: e });
  }
}

// A short code is spent once fetched (unpark): a refusal after that would lose the long code it
// stood for, so the refusal carries it (.long, and in its words). Not when the answer it made
// still stands (queued, or held by the relay: .kept) nor when the code was answered already.
export function keepLong(e, long) {
  if (e?.kept || e?.lapsed || e?.check === 'mailbox_taken') return e;
  const k = new MsgError(e instanceof MsgError ? e.check : 'error', `${e instanceof Error ? reason(e) : String(e)}. The short code is used up; its long code: ${long} (keep this; accept it with the long code)`, { cause: e, http: e?.http });
  k.long = long;
  return k;
}

// Text a relay writes reaches the operator, and perhaps a model, inside this client's messages:
// quoted and cut short, so it reads as data.
const relaySays = (s) => `the relay says ${JSON.stringify(String(s ?? '').slice(0, 200))}`;
// A refusal's words without its check: a verb that adds to them keeps one "check: " in front.
const reason = (e) => (e instanceof MsgError && e.message.startsWith(`${e.check}: `) ? e.message.slice(e.check.length + 2) : e.message);
// Why nothing goes to a contact marked re_pair (the header's "After a recovery").
const rePairWhy = (c) => (c.re_pair === 'contact_recovery'
  ? `${c.name} recovered its identity after a theft: the pairing key may be the thief's; pair again (invite, accept) before writing`
  : `this agent recovered its identity: the pairing key with ${c.name} may be the thief's; pair again (invite, and ${c.name}'s operator accepts the code) before writing`);

// A re-pair keeps a known contact's name (store.admit), unless the owner named the answer
// (`accept --name`): then that name. The inviter's `invite --name` names a new contact only: the
// code may be answered by anyone, and a re-key code's name is the contact's own. → the contact.
function renamed(store, c, entry) {
  if (entry.named === true && c.name !== entry.name) { c.name = entry.name; store.save(); }
  return c;
}

// Why messages to a contact wait after a no_reader (the header's "Mailboxes"): its agent has not
// claimed the mailbox they go to, not this one.
const noReader = (name) => `${name}'s agent does not hold its mailbox for this pairing yet (it has not run inbox since the pairing, or has been away longer than a week): kept here, it goes at your next inbox or send once ${name}'s agent has connected`;

// MQTT 3.1.1 says only "bad user name or password": POST /check with the same credentials names
// the failing check (relay/auth.mjs).
async function named(ep, creds, err) {
  try {
    const r = await http(`${ep.http}/check`, { method: 'POST', body: JSON.stringify({ username: creds.username, client_id: creds.clientId, password: creds.password }) });
    if (r.body?.ok === false && typeof r.body.check === 'string') {
      const check = LOGIN_CHECKS.has(r.body.check) ? r.body.check : 'connect';
      return new MsgError(check, `the relay refused the login (${relaySays(`${r.body.check}: ${r.body.detail}`)})${LOGIN_NEXT[check] ? `: ${LOGIN_NEXT[check]}` : ''}`, { cause: err, http: r.http });
    }
  } catch {}
  return err instanceof MsgError ? err : new MsgError('connect', `the relay at ${ep.mqtt} did not take the connection (${err.message}): check the network and SIGELO_RELAY / SIGELO_RELAY_ENDPOINTS, then try again`, { cause: err });
}
// What to do after a login refusal, by its check (relay/auth.mjs). bundle: sigelo-agent adds the lockout.
const LOGIN_NEXT = {
  rate: 'too many logins from this network: wait a minute, then try again',
  relay_full: 'the relay is full: try again later',
  challenge_expired: 'the login took longer than its challenge lives (a slow proof of work): try again',
  challenge_unknown: 'try again',
  connect: 'try again later',
};

/**
 * Reads each MQTT packet's fixed header (a type byte, then its length in 1 to 4 bytes of 7 bits,
 * MQTT 3.1.1 §2.2) as the bytes arrive on `stream`, and calls cut(why) at the first packet longer
 * than max, or with a malformed length. MQTT.js reads the same bytes beside it, so at most the
 * chunk in hand (64 KB) is buffered past the limit before the caller destroys the stream.
 */
export function limitPackets(stream, max, cut) {
  let at = 'type', len = 0, mult = 1, bytes = 0, skip = 0, done = false;
  stream.on('data', (chunk) => {
    for (let i = 0; i < chunk.length && !done;) {
      if (at === 'body') {
        const n = Math.min(skip, chunk.length - i);
        skip -= n; i += n;
        if (skip === 0) at = 'type';
        continue;
      }
      const b = chunk[i++];
      if (at === 'type') { at = 'length'; len = 0; mult = 1; bytes = 0; continue; }
      len += (b & 0x7f) * mult; mult *= 128; bytes++;
      if (b & 0x80) {
        if (bytes === 4) { done = true; cut('a packet length longer than 4 bytes'); }
        continue;
      }
      if (len > max) { done = true; cut(`a packet of ${len} bytes, more than ${max}`); continue; }
      skip = len;
      at = len === 0 ? 'type' : 'body';
    }
  });
}

function mqttConnect(url, creds, link, onPacket) {
  return new Promise((resolve, reject) => {
    const client = connect(url, { protocolVersion: 4, clean: false, clientId: creds.clientId, username: creds.username, password: Buffer.from(creds.password, 'utf8'),
      reconnectPeriod: 0, connectTimeout: CONNECT_MS, keepalive: 60, resubscribe: false });
    link.client = client;
    // connect() has built the socket and nothing has arrived yet. The cut is permanent at a relay
    // other than this agent's own (#retry, accept): it would send the same packet again.
    limitPackets(client.stream, MAX_PACKET, (why) => {
      link.cut = new MsgError('too_large', `the relay sent ${why}: connection cut`);
      link.cut.permanent = !link.own;
      client.stream.destroy();
    });
    // QoS 1: MQTT.js acknowledges once this calls back, so a delivery is acknowledged only after
    // what it carried is saved. Packets are handled one at a time, in order.
    client.handleMessage = (packet, done) => { onPacket(packet).then((ack) => { if (ack) done(); }, () => client.end(true)); };
    const cleanup = () => { client.off('connect', ok); client.off('error', no); client.off('close', closed); };
    const ok = () => { cleanup(); resolve(client); };
    const no = (e) => { cleanup(); client.end(true); reject(e); };
    const closed = () => no(link.cut ?? new Error('the relay closed the connection'));
    client.once('connect', ok); client.once('error', no); client.once('close', closed);
  });
}

class Link {
  constructor(relay, own) {
    this.relay = relay; this.own = own; this.client = null; this.subscribed = new Set(); this.refused = new Map();   // topic → when refused
    this.absent = new Set();   // contacts whose mailbox nobody held at a publish (no_reader), until the next round
    this.collect = null; this.lastIn = 0; this.since = Date.now(); this.tokens = RATE.burst; this.at = Date.now(); this.pow = false; this.closing = false;
    this.abort = null;   // rejects the PUBLISH or SUBSCRIBE in flight when the connection closes
    this.cut = null;     // the MsgError of limitPackets, once it cut the connection
  }
  // Nothing delivered for QUIET ms since connecting: the relay's queue for this agent is drained.
  get quiet() { return Date.now() - Math.max(this.lastIn, this.since) >= QUIET; }
  // One request in flight: its acknowledgement, with a timeout and an abort on close. A request
  // the cut ended fails with the cut, whichever close reached it first.
  request(what, send) {
    return new Promise((resolve, reject) => {
      const done = (f, v) => { clearTimeout(timer); this.abort = null; f(v); };
      const timer = setTimeout(() => done(reject, this.cut ?? new MsgError('timeout', `no ${what} from the relay`)), ACK_MS);
      this.abort = (e) => done(reject, this.cut ?? e);
      send((err, v) => (err ? done(reject, this.cut ?? err) : done(resolve, v)));
    });
  }
  get up() { return this.client?.connected === true && !this.closing; }
}

// ---------------------------------------------------------------- the carrier

export class Carrier {
  #links = new Map(); #work = Promise.resolve(); #busy = 0; #lastWork = 0; #routes = new Map(); #results = new Map();
  #claimed = new Set(); #refusedTopics = new Map(); #handshakes = new Map(); #soon = new Set();
  #started = false; #tick = null; #timers = new Map(); #attempts = new Map(); #connecting = new Set(); #powFails = new Map(); #ask = false;
  #mineMemo = null; #clocks = new Map();

  constructor({ identity, store, state, relay = DEFAULT_RELAY, endpoints = {}, retentionDays, clock = () => Math.floor(Date.now() / 1000),
    onEvent, keep, backoff = BACKOFF, tick = TICK, files }) {
    if (typeof identity !== 'function') throw new TypeError('identity: a function returning { secret, bundle }');
    if (typeof store !== 'string' || typeof state !== 'string') throw new TypeError('store, state: file paths (pathsFor(identityFile))');
    if (retentionDays !== undefined && !retentionOk(retentionDays)) throw new TypeError(`retentionDays: 1 to ${RETENTION_MAX_DAYS}`);
    // Not given: relay.json's at the first login to this agent's own relay may set it (#relayInfo).
    this.#ask = retentionDays === undefined;
    retentionDays ??= RETENTION_DAYS;
    if (onEvent !== undefined && typeof onEvent !== 'function') throw new TypeError('onEvent: a function');
    if (keep !== undefined && typeof keep !== 'boolean') throw new TypeError('keep: true or false');
    Object.assign(this, { identity, storePath: store, statePath: state, relay, endpoints, retention: retentionDays * DAY, clock, onEvent: onEvent ?? (() => {}),
      keep: keep ?? onEvent === undefined, backoff, tick });
    // Files received (#onFile): files, else beside the state as pathsFor names it (x.carrier.json → x.files).
    if (files !== undefined && typeof files !== 'string') throw new TypeError('files: a directory path (pathsFor(identityFile))');
    this.filesDir = resolve(files ?? state.replace(/(\.carrier)?\.json$/, '') + '.files');
  }

  // ---- files, under the lock

  // The identity as of now: original and current DID, the current genesis and secret.
  #me(now) {
    const { secret, bundle } = this.identity();
    let r;
    try { r = verify(chainOf(bundle), now); } catch (e) { fail('identity', `this agent's bundle does not verify: ${e.message}`); }
    const genesis = [bundle.genesis, ...bundle.rotations.map((x) => x.next_genesis)].find((g) => didOf(g) === r.did);
    // The last edge of the chain followed that a recovery rotation took (-1: none): chain[recovery]
    // is the node the owner recovered from (#markRecovered).
    let recovery = -1;
    for (let i = 0; i + 1 < r.chain.length; i++) {
      if (bundle.rotations.some((x) => x.body.id === r.chain[i] && x.body.next === r.chain[i + 1] && x.body.reason === 'recovery')) recovery = i;
    }
    return { did: r.chain[0], current_did: r.did, secret, genesis, bundle, chain: r.chain, recovery };
  }

  // The state is saved before the store's held writes (store.mjs hold: a handshake's), so a crash
  // or a full disk between the two leaves the store as it was and the delivery unacknowledged.
  #with(write, fn) {
    return withLock(this.statePath, () => {
      const now = checkNow(this.clock()), me = this.#me(now);
      const ctx = { now, me, store: new Contacts(this.storePath, me.did, { mine: () => this.#mine(me, now) }), st: loadState(this.statePath, me.did) };
      // Before anything reads the store: a recovery made by another process (sigelo-agent recover)
      // is seen at once. The store's marks are written first; the state keeps the events.
      if (this.#markRecovered(ctx)) saveState(this.statePath, ctx.st);
      if (this.#lapse(ctx)) saveState(this.statePath, ctx.st);
      const out = fn(ctx);
      // Answers that fn's adds and takes found expired.
      if (this.#lapse(ctx) && !write) saveState(this.statePath, ctx.st);
      if (write) { saveState(this.statePath, ctx.st); ctx.store.commit(); }
      return out;
    });
  }
  #locked(fn) { return this.#with(true, fn); }

  // For tiers (store.mjs): this agent's chain, and its operators: the issuers of the unexpired
  // sigelo-relay/operator attestations its bundle carries that verify (operator DID → exp). Kept
  // until the bundle changes or one of them expires.
  #mine(me, now) {
    const key = JSON.stringify([me.chain, me.bundle.attestations ?? [], me.bundle.issuers ?? []]), m = this.#mineMemo;
    if (m && m.key === key && now < m.until) return m.value;
    const operators = new Map();
    try {
      const r = verify({ ...me.bundle, bindings: [] }, now);
      for (const [iss, bodies] of Object.entries(r.attestations)) {
        for (const b of bodies) if (b.ctx === OPERATOR_CTX && !me.chain.includes(iss)) operators.set(iss, Math.max(operators.get(iss) ?? 0, b.exp));
      }
    } catch {}
    const value = { chain: me.chain, operators: [...operators.keys()], exp: operators };
    this.#mineMemo = { key, until: Math.min(Infinity, ...operators.values()), value };
    return value;
  }

  // An answer that expired before the inviter's reply came: the accept said "waiting", so the next
  // inbox (and contacts until then) says it failed, rather than nothing at all.
  #lapse({ now, store, st }) {
    const gone = store.lapsed(now);
    for (const p of gone) {
      this.#emit(this.#note(st, now, { type: 'pairing_failed', did: p.code_did, name: p.name, code: 'code_expired',
        detail: `the code from ${p.name} expired at ${new Date(p.exp * 1000).toISOString().replace('.000', '')} before the inviter's agent replied: ask the inviter for a new code` }));
    }
    return gone.length > 0;
  }
  #read(fn) { return this.#with(false, fn); }

  // This agent recovered after it last told a contact of its keys (`announced`: a DID at or before
  // the node it recovered from, or one the recovery dropped, or none known): K and the session sat
  // in the files a thief copied with the key. The contact is marked re_pair, `own_recovery` (the
  // header's "After a recovery"), and the next inbox says so. A contact paired after the recovery
  // was announced a later DID: not marked.
  #markRecovered({ now, me, store, st }) {
    if (me.recovery < 0) return false;
    const marked = [];
    for (const c of Object.values(store.load().s.contacts)) {
      if (c.revoked || !c.pair_key || c.re_pair) continue;
      const e = st.peers[c.did];
      if (e && me.chain.indexOf(e.announced) > me.recovery) continue;
      c.re_pair = 'own_recovery';
      marked.push(c);
    }
    if (marked.length === 0) return false;
    store.save();
    for (const c of marked) this.#note(st, now, { type: 're_pair', did: c.did, name: c.name, re_pair: c.re_pair });
    return true;
  }

  // announced: the current DID this agent last sent its rotation notice for, noticed: when; known:
  // the current DID of this agent's the contact last said it holds (a prekeys frame's `known`;
  // pairing: the one it checked); notice_asked: that was another one, so the notice goes again.
  // asked: when a fresh bundle was last asked of the contact (want); waiting: why its messages wait,
  // as last reported (event `waiting`), until a bundle comes; resync_due: an epoch of the contact's
  // could not begin here, owed a bundle that replaces every one-time key (RESYNC), resync_at: when
  // the last such bundle went. renew: an earlier version's resync_due, sent at once. known_due: an
  // envelope of the contact's failed `from`, owed a bundle that says which of its DIDs is held here.
  // notice_checks: when the contact's notices were last checked (NOTICE_CHECKS), notices_refused:
  // [hash, check] of those refused after that check (REFUSED_NOTICES).
  #entry(st, did) {
    return (st.peers[did] ??= { session: null, announced: null, noticed: 0, known: null, notice_asked: false, outbox: [], prekeys_resend: false, prekeys_iat: 0, asked: 0, waiting: null,
      resync_due: false, resync_at: 0, known_due: false });
  }

  #restore(st, store, me, did) {
    const c = store.lookup(did);
    if (!c || c.revoked || !c.pair_key) return null;
    const s = session({ me: { did: me.did, current_did: me.current_did, secret: me.secret }, peer: c, K: hexToBytes(c.pair_key), hold: this.retention });
    const d = st.peers[c.did]?.session;
    // A session of an earlier pairing key belongs to a pairing that was replaced: start afresh.
    if (d && d.pair === s.pair) loadSession(s, d);
    return s;
  }
  #persist(st, s) { this.#entry(st, s.peer.did).session = dumpSession(s); }

  // Receiving keys past their time go from every session (envelope.mjs expire), at each session
  // and each hourly round: opening an envelope expires only its own contact's, and a contact that
  // writes no more would leave its keys in this file.
  #expireKeys({ now, me, store, st }) {
    for (const did of Object.keys(st.peers)) {
      // A session that does not load is its own contact's to fail on (its deliveries, which count
      // a poison frame, and its sends): the other contacts' keys do not wait for it.
      try {
        const s = st.peers[did].session && this.#restore(st, store, me, did);
        if (s && expire(s, now)) this.#persist(st, s);
      } catch { continue; }
    }
  }

  #queue(st, p) {
    const e = { ...p, id: p.id ?? randomId(), bytes: b64(p.bytes) };
    st.pending.push(e);
    return e;
  }

  #emit(ev) { try { this.onEvent(ev); } catch {} }

  // An event kept for the next inbox() as well: a CLI or MCP agent has no onEvent.
  #note(st, now, ev) {
    st.events.push({ ...ev, at: now });
    if (st.events.length > EVENTS_MAX) st.events.splice(0, st.events.length - EVENTS_MAX);
    return ev;
  }

  // The ISO weeks whose mailboxes this agent holds (the header's "Mailboxes"). until: when the last
  // message written in that week, by a clock up to SKEW off, has expired at the relay.
  #weeks(now, back = this.retention, ahead = Math.min(this.retention, AHEAD)) {
    const out = new Map(), last = now + ahead + SKEW;
    for (let t = now - back - SKEW; ; t += DAY) {
      const at = Math.min(t, last), day = Math.floor(at / DAY), nextMonday = (day - ((day + 3) % 7) + 7) * DAY;
      out.set(isoWeek(at), nextMonday + this.retention + SKEW);
      if (at === last) break;
    }
    return [...out].map(([week, until]) => ({ week, until }));
  }

  #liveContacts(store, relay) {
    return Object.values(store.load().s.contacts).filter((c) => !c.revoked && c.pair_key && (relay === undefined || c.relay === relay));
  }

  // Topics to hold at `relay`: each contact's mailboxes to us, and the invite topics in use. Each
  // topic once: two answers to one code (accept run twice) share its reply topic, and a SUBSCRIBE
  // naming a topic twice is refused by the relay with the connection closed, at every connection
  // until the code expired (up to 7 days). In the order they matter, as a round may claim only some
  // (the relay's claim brake: the header's "Mailboxes"): invite topics, whose code is out or whose
  // answer is sent, then every contact's mailbox of this week, the weeks ahead, and the weeks
  // behind, latest first (those hold only what was queued while this agent was away). Asked
  // contact by contact, the first contacts' weeks (90 days: 15 each) took the brake's tokens and
  // the later contacts missed this week's mailbox.
  #want({ now, me, store }, relay) {
    const out = [], seen = new Set();
    const add = (x) => { if (!seen.has(x.topic)) { seen.add(x.topic); out.push(x); } };
    for (const p of Object.values(store.s.invites)) if (p.relay === relay && p.exp > now) add({ topic: inviteKeys(hexToBytes(p.secret)).answer_topic });
    for (const p of Object.values(store.s.accepts)) if (p.relay === relay && p.exp > now) add({ topic: inviteKeys(hexToBytes(p.secret)).reply_topic });
    // No new mailbox under a burned K (re_pair): those held run out at their time (#refresh).
    const contacts = this.#liveContacts(store, relay).filter((c) => !c.re_pair).map((c) => ({ did: c.did, K: hexToBytes(c.pair_key) }));
    const weeks = this.#weeks(now), at = Math.max(0, weeks.findIndex((w) => w.week === isoWeek(now)));
    for (const w of [...weeks.slice(at), ...weeks.slice(0, at).reverse()]) {
      for (const c of contacts) add({ topic: topic(c.K, c.did, me.did, w.week), peer: c.did, until: w.until });
    }
    return out;
  }

  // Topic → what arrives on it. A week either side more than #want, for messages queued long ago.
  #rebuildRoutes() {
    this.#routes = this.#read(({ now, me, store }) => {
      const m = new Map(), wide = this.retention + 7 * DAY;
      for (const c of this.#liveContacts(store)) for (const w of this.#weeks(now, wide, wide)) m.set(topic(hexToBytes(c.pair_key), c.did, me.did, w.week), { type: 'peer', did: c.did });
      for (const [nonce, p] of Object.entries(store.s.invites)) m.set(inviteKeys(hexToBytes(p.secret)).answer_topic, { type: 'answer', nonce });
      for (const [id, p] of Object.entries(store.s.accepts)) m.set(inviteKeys(hexToBytes(p.secret)).reply_topic, { type: 'reply', id });
      return m;
    });
  }

  #relaysInUse() {
    return this.#read(({ now, store, st }) => {
      const s = store.load().s, r = new Set();
      for (const c of Object.values(s.contacts)) if (!c.revoked) r.add(c.relay);
      for (const p of [...Object.values(s.invites), ...Object.values(s.accepts)]) if (p.exp > now) r.add(p.relay);
      for (const p of st.pending) r.add(p.relay);
      for (const [name, x] of Object.entries(st.relays)) if (Object.keys(x.claims ?? {}).length > 0) r.add(name);
      return [...r];
    });
  }

  #resolve(store, to) {
    if (typeof to !== 'string' || to === '') fail('not_contact', 'name a contact: its DID or its name');
    let c;
    if (to.startsWith('did:sigelo:')) {
      c = store.lookup(to) ?? fail('not_contact', `${to} is not a contact`);
      if (c.revoked) fail('revoked', `${c.did} was revoked by this owner`);
    } else {
      const hits = this.#liveContacts(store).filter((x) => x.name === to);
      if (hits.length === 0) fail('not_contact', `no contact named ${JSON.stringify(to)}: contacts lists them; a contact comes from an invite and its accept`);
      if (hits.length > 1) fail('name', `${hits.length} contacts are named ${JSON.stringify(to)}: use the DID`);
      c = hits[0];
    }
    if (c.re_pair) fail('re_pair', rePairWhy(c));
    return c;
  }

  // ---- incoming

  // → true when the delivery may be acknowledged: what it carried is saved, or it is refused for
  // good (counted under its check). False: this process failed; the connection is closed without
  // the acknowledgement and the relay delivers it again.
  async #onPacket(link, packet) {
    link.lastIn = Date.now();
    const t = packet.topic, bytes = Uint8Array.from(packet.payload);
    if (t === NOTICE) { this.#onNotice(link, bytes); return true; }
    let route;
    try {
      if (!this.#routes.has(t)) this.#rebuildRoutes();
      route = this.#routes.get(t) ?? fail('route', 'a message on a topic this agent does not read');
      const events = this.#locked((ctx) => (route.type === 'peer' ? this.#onPeer(ctx, route.did, t, bytes)
        : route.type === 'answer' ? this.#onAnswer(ctx, t, bytes) : this.#onReply(ctx, t, bytes)));
      for (const e of events) this.#emit(e);
    } catch (e) {
      if (e instanceof MsgError && !INTERNAL.has(e.check)) this.#drop(e.check, e.message, route);
      else if (!this.#undeliverable(t, bytes, e)) {
        this.#emit({ type: 'error', relay: link.relay, check: e.check ?? 'internal', detail: e.message });
        link.client?.end(true);
        return false;
      }
    }
    // Stamped again at the end: a packet that took QUIET ms or more (a long notice, a large state
    // file) must not make the round below see a drained queue and give up claims (#refresh).
    link.lastIn = Date.now();
    this.#refreshSoon(link.relay);
    return true;
  }

  // → true once this delivery has failed POISON_TRIES times with the files sound: it is then
  // counted as `undeliverable` and acknowledged. The count is written under the same lock and
  // checks as every operation, so a held lock, a broken state or store file or an identity that
  // does not verify fails the count too, and the delivery waits for the next connection as before.
  // What fails three times with all of those sound is the frame itself (an exception nobody named),
  // and the relay would otherwise deliver it first at every connection, ahead of everything else.
  #undeliverable(t, bytes, e) {
    const id = hex(sha256(concatBytes(utf8ToBytes(`${t}\n`), bytes)).subarray(0, 16));
    let n;
    try {
      n = this.#locked(({ st }) => {
        const f = st.failing;
        // At most 64 deliveries counted: the oldest count goes first.
        if (!Object.hasOwn(f, id) && Object.keys(f).length >= 64) delete f[Object.keys(f)[0]];
        f[id] = (f[id] ?? 0) + 1;
        const tries = f[id];
        if (tries >= POISON_TRIES) { delete f[id]; st.dropped.undeliverable = (st.dropped.undeliverable ?? 0) + 1; }
        return tries;
      });
    } catch { return false; }
    if (n < POISON_TRIES) return false;
    this.#emit({ type: 'dropped', check: 'undeliverable', detail: `failed ${POISON_TRIES} times: ${e.message}` });
    return true;
  }

  // route: what the topic carries (#rebuildRoutes). An envelope whose epoch cannot begin here
  // (RESYNC_CHECKS): every later one of that epoch fails alike, so the writer is owed a fresh prekey
  // bundle that replaces every one-time key (resync_due; #next sends it, RESYNC): on reading it the
  // writer begins a new epoch (envelope.mjs acceptPrekeys). An envelope signed as a DID that is not
  // the writer's current one here (`from`, checked after the AEAD: a relay can cause it only by
  // holding back an envelope signed before a rotation): the writer rotated and believes this agent
  // knows, so every later envelope fails alike. It is owed a bundle whose `known` names the DID held here (known_due; #next, at
  // most every RESYNC after the last bundle), on which it sends its rotation notice again
  // (#onPrekeys): within the hour, not when this agent next writes or its bundle falls due.
  #drop(check, detail, route) {
    try {
      this.#locked(({ st }) => {
        st.dropped[check] = (st.dropped[check] ?? 0) + 1;
        const p = route?.type === 'peer' ? st.peers[route.did] : null;
        if (p && RESYNC_CHECKS.has(check)) p.resync_due = true;
        if (p && check === 'from') p.known_due = true;
      });
    } catch {}
    this.#emit({ type: 'dropped', check, detail });
  }

  #onNotice(link, bytes) {
    let n;
    try { n = parseBytes(bytes); } catch { return; }
    if (n === null || typeof n !== 'object' || typeof n.code !== 'string') return;
    const note = { code: n.code.slice(0, 64), detail: typeof n.detail === 'string' ? n.detail.slice(0, 200) : '' };
    // id: the packet id of the PUBLISH a refusal names (#publish), kept out of events.
    if (link.collect) link.collect.push(Number.isSafeInteger(n.id) ? { ...note, id: n.id } : note);
    else this.#emit({ type: 'notice', relay: link.relay, ...note });
  }

  // A contact's mailbox: an envelope (kind 0), its rotation notice (kind 4) or its prekeys (kind 5).
  #onPeer(ctx, did, t, bytes) {
    const { now, me, store, st } = ctx;
    if (bytes[1] === KIND_NOTICE) return this.#onContactNotice(ctx, did, t, bytes);
    if (bytes[1] === KIND_PREKEYS) return this.#onPrekeys(ctx, did, t, bytes);
    const s = this.#restore(st, store, me, did) ?? fail('not_contact', 'no live pairing with the writer of this topic');
    // Bytes 2 to 18 are the epoch id (envelope.mjs "Layout"); a frame too short fails open() below.
    const begins = !s.in.epochs.has(hex(bytes.subarray(2, 18)));
    let r;
    try { r = open(s, bytes, t, now); } catch (e) {   // checks by name; the session is unchanged when one fails
      // Not signed as the contact's current DID, after a recovery of the contact's this agent
      // followed: a key the recovery overruled, maybe the thief's (the header's "Recovery beats
      // key"). Refused and noted, and no bundle is owed for it (`from`'s known_due): nothing goes
      // under this K. The claimed DID is unverified: not echoed.
      if (e instanceof MsgError && e.check === 'from' && s.peer.re_pair === 'contact_recovery') {
        return [this.#note(st, now, { type: 'refused', from: s.peer.did, name: s.peer.name, code: 're_pair',
          detail: `a message not signed by ${s.peer.name}'s key after its recovery: maybe the thief's, not delivered` })];
      }
      throw e;
    }
    const c = s.peer, events = [];
    // The writer's epochs begin here again: a bundle owed for one that could not (RESYNC) is not.
    if (begins) this.#entry(st, did).resync_due = false;
    if (r.body.label === LABEL_PREKEYS) {
      // An earlier version's bundle, inside a message. The message is opened and its keys spent
      // whatever the bundle is worth: the session is saved either way, and a bundle refused (older,
      // not this contact's) is counted.
      try {
        acceptPrekeys(s, r.body.content, now);
        events.push(this.#tookPrekeys(st, s, false, now));
      } catch (e) {
        if (!(e instanceof MsgError)) throw e;
        st.dropped[e.check] = (st.dropped[e.check] ?? 0) + 1;
        events.push({ type: 'dropped', check: e.check, detail: e.message });
      }
    } else if (r.body.label === FILE_LABEL) {
      // A file's manifest or chunk (file.mjs): kept apart until the file is whole (#onFile).
      events.push(...this.#onFile(ctx, c, r, now));
    } else if (r.body.label === OPERATOR_LABEL) {
      // Operator hints, asks and proofs (the header): taken here, never an inbox message. One refused is counted.
      try { events.push(...this.#onOperator(ctx, c, r.body.content)); } catch (e) {
        if (!(e instanceof MsgError)) throw e;
        st.dropped[e.check] = (st.dropped[e.check] ?? 0) + 1;
        events.push({ type: 'dropped', check: e.check, detail: e.message });
      }
    } else {
      // last_resort: the epoch began on the last-resort prekey, which may serve many epochs: weaker
      // forward secrecy (plan §3 "Prekeys"), and routine for a while after a rotation (#next).
      const m = { from: c.did, name: c.name, current_did: r.body.from, label: r.body.label, content: r.body.content, iat: r.body.iat, received: now, last_resort: r.last_resort };
      // Plaintext at rest: kept only for inbox() (keep), and only so many (the header).
      if (this.keep) {
        st.inbox.push(m);
        if (st.inbox.length > INBOX_MAX) { const n = st.inbox.length - INBOX_MAX; st.inbox.splice(0, n); st.dropped.inbox_full = (st.dropped.inbox_full ?? 0) + n; }
      }
      events.push({ type: 'message', ...m });
    }
    this.#persist(st, s);
    return events;
  }

  // The header's "Operator hints". Hints of contact c's operators: those this agent knows (its own
  // operators, or itself) are asked for, once per set. Asks: proofs of this agent's operators the
  // contact showed it knows, once per set. A proof: c's chain with operator attestations, filed.
  // Answers go first in c's outbox. → events: `tier` when c's tier changed.
  #onOperator({ now, me, store, st }, c, v) {
    const K = hexToBytes(c.pair_key), e = this.#entry(st, c.did), mine = this.#mine(me, now);
    const list = (x) => (Array.isArray(x) && x.length <= 8 && x.every((h) => typeof h === 'string') ? x : fail('operator', 'hints and asks: at most 8 strings'));
    if (v?.hints !== undefined) {
      const hints = list(v.hints), known = [...mine.operators, ...mine.chain].filter((d) => hints.includes(operatorHint(K, 'hint', c.did, d))).sort();
      // Again for the same operators at most every RESYNC: the contact hints anew once their
      // attestations are renewed (#next), and its proof must come again before the old one lapses.
      if (known.length > 0 && (e.op_asked !== known.join() || now - (e.op_asked_at ?? 0) >= RESYNC)) {
        e.op_asked = known.join(); e.op_asked_at = now;
        e.outbox.unshift({ id: randomId(), label: OPERATOR_LABEL, content: { asks: known.map((d) => operatorHint(K, 'ask', me.did, d)) } });
      }
      return [];
    }
    if (v?.asks !== undefined) {
      // Proved again once an attestation shown is renewed (its expiry is in the key).
      const asks = list(v.asks), shown = mine.operators.filter((d) => asks.includes(operatorHint(K, 'ask', c.did, d))).sort(), key = opKey(mine, shown);
      if (shown.length > 0 && e.op_proved !== key) {
        e.op_proved = key;
        const b = me.bundle, iss = new Set(shown);
        const proof = { v: b.v, typ: 'bundle', genesis: b.genesis, rotations: b.rotations, bindings: [],
          attestations: (b.attestations ?? []).filter((a) => a?.body?.ctx === OPERATOR_CTX && iss.has(a.body.iss)), issuers: (b.issuers ?? []).filter((g) => iss.has(didOf(g))) };
        e.outbox.unshift({ id: randomId(), label: OPERATOR_LABEL, content: { proof } });
      }
      return [];
    }
    if (v?.proof !== undefined) {
      // Only in answer to asks of ours, and so many an hour: each costs SPEC §9 (THREAT-MODEL §2.12).
      if (!e.op_asked) fail('operator', 'an operator proof nobody asked for');
      const recent = (e.op_checks ?? []).filter((x) => x > now - RESYNC);
      if (recent.length >= NOTICE_CHECKS) fail('operator_rate', `${recent.length} operator proofs of this contact checked within ${RESYNC} s, the most`);
      e.op_checks = [...recent, now];
      const p = v.proof;
      if (![p?.rotations, p?.attestations, p?.issuers].every(Array.isArray) || p.rotations.length > MAX_ROTATIONS || p.attestations.length > 8 || p.issuers.length > 8) {
        fail('operator', `an operator proof is a bundle of at most ${MAX_ROTATIONS} rotations, 8 attestations and 8 issuers`);
      }
      let r;
      try { r = verify(p, now); } catch (err) { fail('operator', `the contact's operator proof does not verify: ${err.message}`); }
      if (r.chain[0] !== c.did) fail('operator', 'the operator proof is not the chain of the contact that sent it');
      // store.observe refuses a chain that ends anywhere but the contact's current DID (current_did).
      const before = store.tierOf(c, now), after = store.observe(c.did, r, now);
      return after === before ? [] : [{ type: 'tier', did: c.did, name: c.name, tier: after }];
    }
    fail('operator', 'an operator message is {hints}, {asks} or {proof}');
  }

  // ---- files (file.mjs; design/human-ui-plan.md §4)

  // A FILE_LABEL message from contact c, opened (r). The manifest is kept in the state (files,
  // under a key of the contact and the file's id), each chunk under filesDir/.partial/<key>/<i>
  // (0600, directories 0700); once all have come, the file is checked (size, SHA-256), saved as
  // filesDir/<contact>/<sha256[0..8]>-<name> (0600), and given to inbox() as one item of type
  // "file". Never opened, never made executable. Anything wrong with the message is counted in
  // dropped by its check, as a refused bundle is above; the envelope stays opened either way.
  // A chunk before its manifest (none: the sender sends the manifest first, in one login) is
  // dropped, file_chunk. The disk is written before the state: a crash between them leaves a
  // chunk that the delivery, unacknowledged, writes again.
  #onFile(ctx, c, r, now) {
    const { st } = ctx, content = r.body.content;
    st.files ??= {};
    const drop = (e) => {
      if (!(e instanceof MsgError)) throw e;
      st.dropped[e.check] = (st.dropped[e.check] ?? 0) + 1;
      return [{ type: 'dropped', check: e.check, detail: `a file from ${c.name}: ${e.message}` }];
    };
    const keyOf = (id) => hex(sha256(utf8ToBytes(`${c.did}\n${id}`)).subarray(0, 16));
    let key, p;
    try {
      if (isManifest(content)) {
        const m = checkManifest(content);
        key = keyOf(m.id);
        const had = st.files[key];
        if (had) {
          if (had.sha256 !== m.sha256 || had.size !== m.size) fail('file', 'a second manifest for one file id, with another content');
          return [];
        }
        // At most FILES_OPEN files arriving at once per contact: each holds up to 8 MiB here.
        if (Object.values(st.files).filter((x) => x.from === c.did).length >= FILES_OPEN) fail('file_busy', `${FILES_OPEN} files from this contact are incomplete already`);
        p = st.files[key] = { from: c.did, ...m, got: [], first: now };
      } else {
        const h = chunkHead(content);
        key = keyOf(h.id);
        p = st.files[key] ?? fail('file_chunk', 'a chunk of a file whose manifest has not come');
        const bytes = checkChunk(content, p);
        if (!p.got.includes(h.i)) {
          const dir = this.#partDir(key);
          mkdirSync(dir, { recursive: true, mode: 0o700 });
          writeFileSync(join(dir, String(h.i)), bytes, { mode: 0o600 });
          p.got.push(h.i);
        }
      }
    } catch (e) { return drop(e); }
    if (p.got.length < p.chunks) return [];
    // Whole: checked, saved, and the parts gone whatever the check said.
    let bytes;
    try {
      bytes = assemble(p, Array.from({ length: p.chunks }, (_, i) => readFileSync(join(this.#partDir(key), String(i)))));
    } catch (e) {
      delete st.files[key];
      rmSync(this.#partDir(key), { recursive: true, force: true });
      return drop(e);
    }
    const dir = join(this.filesDir, safeName(c.name || c.did));
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    chmodSync(this.filesDir, 0o700); chmodSync(dir, 0o700);
    const path = join(dir, `${p.sha256.slice(0, 8)}-${p.name}`), tmp = join(dir, `.${randomId()}.tmp`);
    writeFileSync(tmp, bytes, { mode: 0o600, flag: 'wx' });
    renameSync(tmp, path);
    delete st.files[key];
    rmSync(this.#partDir(key), { recursive: true, force: true });
    const item = { type: 'file', from: c.did, contact: c.name, current_did: r.body.from, label: FILE_LABEL, name: p.name, size: p.size, sha256: p.sha256, path,
      iat: r.body.iat, received: now, last_resort: r.last_resort };
    // Kept for inbox() as a message is (#onPeer), and so many at most.
    if (this.keep) {
      st.inbox.push(item);
      if (st.inbox.length > INBOX_MAX) { const n = st.inbox.length - INBOX_MAX; st.inbox.splice(0, n); st.dropped.inbox_full = (st.dropped.inbox_full ?? 0) + n; }
    }
    return [item];
  }

  #partDir(key) { return join(this.filesDir, '.partial', key); }

  // A file's chunks wait in filesDir/.out/<item id>.json (0600, directory 0700), not in the state:
  // base64 in an outbox item, 8 MiB were rewritten with the state at every chunk sent. The outbox
  // item keeps { id, label, spool: true }. A contact's name never starts with a dot (safeName), so
  // .out is no contact's directory. Written under the lock with the items that name them.
  #spoolDir() { return join(this.filesDir, '.out'); }
  #spool(id, content) {
    const dir = this.#spoolDir();
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    chmodSync(this.filesDir, 0o700); chmodSync(dir, 0o700);
    writeFileSync(join(dir, `${id}.json`), JSON.stringify(content), { mode: 0o600, flag: 'wx' });
  }
  #spooled(id) {
    try { return JSON.parse(readFileSync(join(this.#spoolDir(), `${id}.json`), 'utf8')); } catch (e) {
      fail('file', `a queued part of a file is gone from ${this.#spoolDir()} (${e.code ?? e.message}): send the file again`);
    }
  }
  // Spooled parts no outbox or pending entry names any more (sent, refused, forgotten): removed.
  #sweepSpool(st) {
    let names;
    try { names = readdirSync(this.#spoolDir()); } catch { return; }
    const held = new Set();
    for (const e of Object.values(st.peers)) for (const x of e.outbox ?? []) if (x.spool) held.add(x.id);
    for (const p of st.pending) if (p.item?.spool) held.add(p.item.id);
    for (const n of names) if (/^[0-9a-f]{16}\.json$/.test(n) && !held.has(n.slice(0, -5))) rmSync(join(this.#spoolDir(), n), { force: true });
  }

  // Files still incomplete after the retention (the relay has dropped whatever of them was left to
  // come): their parts go, counted file_incomplete, and inbox() says which.
  #sweepFiles(st, now) {
    for (const [key, p] of Object.entries(st.files ?? {})) {
      if (p.first + this.retention > now) continue;
      rmSync(this.#partDir(key), { recursive: true, force: true });
      delete st.files[key];
      st.dropped.file_incomplete = (st.dropped.file_incomplete ?? 0) + 1;
      this.#emit(this.#note(st, now, { type: 'dropped', check: 'file_incomplete', from: p.from,
        detail: `${p.name} (${p.size} bytes): ${p.got.length} of ${p.chunks} parts came within the retention; the rest will not: ask for it again` }));
    }
  }

  // A bundle from the contact was accepted into s (acceptPrekeys). want: it asked for ours, which
  // goes unless one went within RESYNC (the header's "Prekeys").
  #tookPrekeys(st, s, want, now) {
    // A fresh bundle ends an epoch begun on the last-resort key (#next, after a rotation): the
    // next message begins one on a single-use key again.
    if (s.out.epoch?.lastResort) restartEpoch(s);
    const e = this.#entry(st, s.peer.did);
    if (want && now - (e.prekeys_iat ?? 0) >= RESYNC) e.prekeys_resend = true;
    e.waiting = null;
    return { type: 'prekeys', did: s.peer.did, name: s.peer.name };
  }

  // The contact's prekeys (kind 5, the header's "Prekeys"). A refusal changes nothing. known: the
  // current DID of this agent's the contact holds; another than ours, and it missed our rotation
  // notice (expired at the relay before it read it, or lost): the notice goes again, unless one went
  // within RESYNC (it crossed this frame). Taken only beside a bundle accepted, so a replayed frame
  // says nothing.
  #onPrekeys({ now, me, store, st }, did, t, bytes) {
    const s = this.#restore(st, store, me, did) ?? fail('not_contact', 'no live pairing with the writer of this topic');
    const v = unseal(KIND_PREKEYS, prekeysKey(s.K, s.peer.did, me.did), t, bytes);
    if (!exact(v, ['prekeys', 'want', 'known']) || typeof v.want !== 'boolean' || typeof v.known !== 'string') fail('prekeys', 'a prekeys frame carries exactly {prekeys, want, known}');
    acceptPrekeys(s, v.prekeys, now);
    const ev = this.#tookPrekeys(st, s, v.want, now), e = this.#entry(st, did);
    e.known = v.known;
    if (v.known !== me.current_did && now - (e.noticed ?? 0) >= RESYNC) e.notice_asked = true;
    this.#persist(st, s);
    return [ev];
  }

  // The contact rotated: its chain, merged by the store with every rotation seen before. A notice
  // that brings a rotation not held is checked (SPEC §9 here and in store.admit) only if it was not
  // refused before and, unless it brings the owner's recovery (recovers), only NOTICE_CHECKS times
  // per contact and RESYNC; else it is dropped unchecked. Before, the same refused frame was
  // verified again at every delivery, and frames from a K holder, handled one at a time, held
  // every other delivery behind several seconds of CPU a second.
  #onContactNotice({ now, me, store, st }, did, t, bytes) {
    const c = store.lookup(did);
    if (!c || c.revoked || !c.pair_key) fail('not_contact', 'no live pairing with the writer of this topic');
    const K = hexToBytes(c.pair_key), v = unseal(KIND_NOTICE, noticeKey(K, c.did, me.did), t, bytes);
    if (!exact(v, ['bundle', 'proof'])) fail('bundle', 'a notice carries exactly {bundle, proof}');
    // A chain and nothing else, as chainOf sends it.
    const bundle = v.bundle;
    if (!exact(bundle, BUNDLE_KEYS) || !Array.isArray(bundle.rotations) || ![bundle.bindings, bundle.attestations, bundle.issuers].every((x) => Array.isArray(x) && x.length === 0)) {
      fail('bundle', 'a notice carries a chain only: genesis and rotations');
    }
    // No more rotations than a relay admits in a bundle (R15), refused before any check. The cap is
    // on what this notice carries: counted with what the store held, a thief's fork filled it and
    // the owner's recovery was refused.
    if (bundle.rotations.length > MAX_ROTATIONS) fail('bundle', `${bundle.rotations.length} rotations, more than ${MAX_ROTATIONS}`);
    // Every rotation is a signature check here and again in store.admit. Notices have no replay
    // protection, so one that brings nothing new (a replay, a resend, a prefix of the chain held)
    // is skipped before any check: merging it would change nothing.
    const held = new Set(c.rotations.map(canonicalize)), fresh = bundle.rotations.filter((x) => !held.has(canonicalize(x))), e = this.#entry(st, c.did);
    if (fresh.length === 0) {
      // Sent again: the writer has not heard that this agent holds its rotation (#next). A bundle
      // says so (its frame's `known`), at most every RESYNC, so a relay replaying notices gets one
      // bundle an hour at most, as RESYNC_CHECKS do.
      if (now - (e.prekeys_iat ?? 0) >= RESYNC) e.prekeys_resend = true;
      return [];
    }
    const id = hex(sha256(utf8ToBytes(canonicalize(v))).subarray(0, 16));
    const refused = (e.notices_refused ?? []).find(([x]) => x === id);
    if (refused) fail(refused[1], `refused before (${refused[1]}): not checked again`);
    const recent = (e.notice_checks ?? []).filter((x) => x > now - RESYNC);
    if (recent.length >= NOTICE_CHECKS && !recovers(c, bundle, fresh)) {
      fail('notice_rate', `${recent.length} notices of this contact checked within ${RESYNC} s, the most: dropped unchecked (one bringing its owner's recovery is checked whatever the count)`);
    }
    e.notice_checks = [...recent, now];
    // A refusal from here on is remembered, so the state is saved with it and the count: the
    // dropped notice is counted here, as #drop counts the others.
    try { return this.#mergeNotice({ now, me, store, st }, c, K, v, fresh); } catch (err) {
      if (!(err instanceof MsgError) || INTERNAL.has(err.check)) throw err;
      e.notices_refused = [...(e.notices_refused ?? []), [id, err.check]].slice(-REFUSED_NOTICES);
      st.dropped[err.check] = (st.dropped[err.check] ?? 0) + 1;
      return [{ type: 'dropped', check: err.check, detail: err.message }];
    }
  }

  // The checks of a notice #onContactNotice lets through, and the merge.
  #mergeNotice({ now, me, store, st }, c, K, v, fresh) {
    const bundle = v.bundle;
    let r;
    try { r = verify(bundle, now); } catch (e) { fail('bundle', `REJECT: ${e.message}`); }
    // Bundles are public: a contact could send another contact's. Only its own chain is merged,
    // and store.admit refuses one that starts anywhere but its original DID (original_did).
    if (!r.chain.includes(c.did)) fail('notice_chain', 'the bundle is not the chain of the contact that sent it');
    // Signed by the key the chain ends at, for this pairing (the header's "contact notice"): a chain
    // ending at a genesis whose key the sender does not hold is refused before the store sees it.
    // Unverified until the signature check: name the check, never echo the claimed DID.
    const p = v.proof;
    if (!exact(p, ['body', 'sig']) || typeof p.sig !== 'string' || !exact(p.body, ['v', 'typ', 'did', 'pair']) || p.body.v !== V || p.body.typ !== TYP_NOTICE) {
      fail('notice_sig', `the proof is not {body: {v: "${V}", typ: "${TYP_NOTICE}", did, pair}, sig}`);
    }
    if (p.body.did !== r.did || p.body.pair !== pairId(K)) fail('notice_sig', 'the proof names another DID than the chain ends at, or another pairing');
    if (!verifySig(keyOf(bundle, bundle.rotations, r.did), p.body, p.sig)) fail('notice_sig', 'the proof does not verify under the key the chain ends at');
    const before = structuredClone(c);
    // A mark stays with the record through a merge (admit writes it afresh); a new pairing clears it.
    const a = store.admit(bundle, r, null, { relay: c.relay, pair_key: c.pair_key, ...(c.re_pair && { re_pair: c.re_pair }) }, now);
    // admit writes every rotation either side held. The store keeps only those followed(); a
    // merged chain too long to keep puts the record back as it was. Held rotations come first, so
    // on an edge both hold, the one this store followed before stays. store.mjs has no verb for
    // this: the record is rewritten as #unpair rewrites one.
    const merged = store.load().s.contacts[c.did];
    let kept;
    try { kept = followed(bundle.genesis, [...before.rotations, ...fresh], merged.chain, now); } catch (e) {
      store.s.contacts[c.did] = before;
      store.save();
      throw e;
    }
    merged.rotations = kept;
    // A recovery this store had not followed: the key it superseded, and the files a thief copied
    // with it, held K. Burned here too (the header's "After a recovery").
    const held = new Set(before.rotations.map(canonicalize));
    const recovered = kept.some((x) => x.body.reason === 'recovery' && !held.has(canonicalize(x)));
    if (recovered) merged.re_pair ??= 'contact_recovery';
    store.save();
    const overruled = recovered ? this.#overrule(st, now, merged, kept, before.chain) : [];
    if (a.current_did === c.current_did) return [];
    // The contact's old key, and perhaps its state with the prekeys we listed, may be a thief's:
    // list fresh ones only. retire() keeps the old secrets until they expire, for epochs begun.
    const s = this.#restore(st, store, me, c.did);
    if (s) { s.in.prekeys.retire(now); this.#persist(st, s); }
    this.#entry(st, c.did).prekeys_resend = true;
    return [this.#note(st, now, { type: 'rotated', did: c.did, name: c.name, current_did: a.current_did, ...(recovered && { re_pair: merged.re_pair, overruled }) })];
  }

  // A recovery of contact c was merged (kept: the rotation followed on each edge of c.chain). The
  // DIDs it overrules: those of the chain up to the last recovery's node, and those of the chain
  // held before that it left. Messages of c's still waiting for inbox() signed by one of them are
  // taken out and noted refused (the header's "Recovery beats key"). → the DIDs overruled.
  #overrule(st, now, c, kept, before) {
    const last = kept.findLastIndex((x) => x.body.reason === 'recovery'), honest = new Set(c.chain.slice(last + 1));
    const overruled = [...new Set([...c.chain, ...before])].filter((d) => !honest.has(d));
    const out = st.inbox.filter((m) => m.from === c.did && !honest.has(m.current_did));
    if (out.length === 0) return overruled;
    st.inbox = st.inbox.filter((m) => !out.includes(m));
    for (const m of out) {
      this.#note(st, now, { type: 'refused', from: c.did, name: c.name, current_did: m.current_did, iat: m.iat, code: 're_pair',
        detail: `signed by ${m.current_did}, a key ${c.name}'s recovery overruled: maybe the thief's, not delivered` });
    }
    return overruled;
  }

  // Alice: an answer to one of her codes. checkAnswer runs sigelo-pair's checks in its order and
  // spends the code; the reply goes once her mailbox for this week is claimed (`needs`), so the
  // contact's first message cannot reach an unclaimed topic.
  // The store's writes are held until the state, with the session, the reply and its undo, is
  // saved (#with): saved first, the store kept the contact and spent the code while a crash or a
  // full disk lost the reply, and the relay's next delivery of the answer was dropped as
  // challenge_unknown: no reply ever went, and she held a contact that never heard of her (or, on
  // a re-key, a K he never derived). Now the code stays unspent until both are saved, and the
  // delivery runs again; a reply the state kept from such a run (it names this code's reply
  // topic) is put back first, as its undo says, so its K never goes out.
  #onAnswer(ctx, t, bytes) {
    const { now, me, store, st } = ctx;
    store.hold();
    const found = Object.entries(store.load().s.invites).find(([, x]) => inviteKeys(hexToBytes(x.secret)).answer_topic === t) ?? fail('challenge_unknown', 'no pending invite reads this topic');
    const [nonce, p] = found, keys = inviteKeys(hexToBytes(p.secret));
    for (const e of st.pending.filter((x) => x.control === 'reply' && x.topic === keys.reply_topic && x.undo)) this.#restorePeer(st, e);
    st.pending = st.pending.filter((x) => !(x.control === 'reply' && x.topic === keys.reply_topic));
    let res, ct = null, before;
    try {
      const answer = unseal(KIND.invite_answer, keys.key, t, bytes);
      // checkAnswer spends the code its proof names; this topic is this code's alone.
      if (typeof answer?.proof?.body?.nonce === 'string' && answer.proof.body.nonce !== nonce) fail('challenge_unknown', 'the answer names another code than the one whose topic it came on');
      before = structuredClone(store.load().s.contacts);
      res = checkAnswer(answer, store, now, (pk) => { const k = kemEncapsulate(pk); ct = k.ct; return k.shared; });
    } catch (e) {
      // Single use, whatever the outcome (plan §3 "Invite code"): acknowledging this delivery
      // kills the topic at the relay, so no other answer can come. Written now: the state is not
      // saved after a refusal. A write that fails is this process failing: not acknowledged.
      try { store.take('invites', nonce, now); } catch {}
      store.commit();
      throw e;
    }
    const c = store.lookup(res.did), K = hexToBytes(res.pair_key);
    // What checkAnswer replaced, put back if the reply cannot reach the answerer (#unpair).
    const undo = { contact: before[c.did] ?? null, peer: st.peers[c.did] ?? null };
    const s = session({ me: { did: me.did, current_did: me.current_did, secret: me.secret }, peer: c, K });
    const prekeys = s.in.prekeys.issue({ current_did: me.current_did, secret: me.secret }, s.pair, now);
    const reply = buildReply({ answer_id: res.answer_id, identity: { secret: me.secret, genesis: me.genesis }, bundle: chainOf(me.bundle), kem_ct: ct, prekeys });
    const frame = seal(KIND.invite_reply, keys.key, keys.reply_topic, reply);
    const entry = { relay: p.relay, topic: keys.reply_topic, kind: KIND.invite_reply, control: 'reply', peer: c.did, undo,
      needs: [topic(K, c.did, me.did, isoWeek(now))], exp: p.exp };
    if (frame.length > INVITE_BYTES) {
      return [this.#unpair(ctx, entry, { code: 'too_large', detail: `the reply is ${frame.length} bytes, more than an invite topic holds (${INVITE_BYTES}): this agent's chain is too long` })];
    }
    st.peers[c.did] = { session: dumpSession(s), announced: me.current_did, known: me.current_did, outbox: st.peers[c.did]?.outbox ?? [], prekeys_resend: false, prekeys_iat: now };
    this.#queue(st, { ...entry, bytes: frame });
    this.#routes = new Map();
    return [this.#note(st, now, { type: 'paired', did: c.did, name: c.name, current_did: c.current_did, rekeyed: res.rekeyed, fingerprint: wordsOf(res.pair_key) })];
  }

  // Alice: her reply will never reach the answerer (refused, too large, or its code expired while
  // it waited). What checkAnswer stored is put back as it was, so she keeps no contact that does
  // not know her, and the next inbox() says why. The store has no verb for this: the record is
  // restored as checkAnswer found it.
  #unpair({ now, store, st }, e, { code, detail }) {
    const name = store.lookup(e.peer)?.name ?? null;
    store.load();
    if (e.undo.contact) store.s.contacts[e.peer] = e.undo.contact; else delete store.s.contacts[e.peer];
    store.save();
    this.#restorePeer(st, e);
    this.#routes = new Map();
    return this.#note(st, now, { type: 'pairing_failed', did: e.peer, name, code, detail });
  }

  // The state's half of what a pending reply's pairing replaced (e.undo.peer), put back: the
  // contact's entry as it was, with what its outbox holds now.
  #restorePeer(st, e) {
    if (e.undo.peer) st.peers[e.peer] = { ...e.undo.peer, outbox: st.peers[e.peer]?.outbox ?? e.undo.peer.outbox };
    else delete st.peers[e.peer];
  }

  // Bob: the reply to his answer. His own prekeys go out as his first message (#next). Answers to
  // one code (accept run twice) share its secret and so its reply topic: the reply's proof names
  // the one it answers. This delivery kills the topic at the relay, so every answer waiting on it
  // is spent, whatever the outcome.
  // Alice holds him under the current DID his answer's chain ended at (store.addAccept `as`), not
  // the one he has now: he may have rotated, by choice or by a recovery, between the answer and
  // this reply. announced and known start at that DID, so #next sends his rotation notice before
  // any other frame when they differ. Set to his DID of now, the notice never went: Alice refused
  // his prekeys and every envelope (`from`), and kept trusting a key a recovery had left.
  // As in #onAnswer, the store's writes wait for the state (#with): saved first, he kept her as a
  // contact with no session, her prekeys lost, and the reply's next delivery was dropped. His
  // answer stays pending until both are saved; the delivery that runs again decapsulates the same
  // kem_ct to the same K.
  #onReply({ now, me, store, st }, t, bytes) {
    store.hold();
    const waiting = Object.entries(store.load().s.accepts).filter(([, x]) => inviteKeys(hexToBytes(x.secret)).reply_topic === t);
    if (waiting.length === 0) fail('challenge_unknown', 'no answer of this agent waits on this topic');
    const keys = inviteKeys(hexToBytes(waiting[0][1].secret)), spend = (except) => {
      for (const [x] of waiting) if (x !== except) { try { store.take('accepts', x, now); } catch {} }
    };
    let reply, res, id = waiting[0][0];
    try {
      reply = unseal(KIND.invite_reply, keys.key, t, bytes);
      // checkReply takes the pending answer its proof names; it must be one waiting on this topic.
      const named = reply?.proof?.body?.nonce;
      if (typeof named === 'string') {
        if (!waiting.some(([x]) => x === named)) fail('challenge_unknown', 'the reply names another answer than those whose topic it came on');
        id = named;
      }
      res = checkReply(reply, store, now, (kemCt, sk) => kemDecapsulate(kemCt, hexToBytes(sk)));
    } catch (e) {
      spend(null);
      store.commit();
      if (e instanceof MsgError) for (const [x] of waiting) this.#handshakes.set(x, { check: e.check, detail: e.message });
      throw e;
    }
    spend(id);
    // An entry written before `as` was kept: unknown, so the notice goes (#next `first`).
    const answered = waiting.find(([x]) => x === id)[1], held = answered.as ?? null;
    const c = renamed(store, store.lookup(res.did), answered);
    const s = session({ me: { did: me.did, current_did: me.current_did, secret: me.secret }, peer: c, K: hexToBytes(res.pair_key) });
    const events = [this.#note(st, now, { type: 'paired', did: c.did, name: c.name, current_did: c.current_did, rekeyed: res.rekeyed, fingerprint: wordsOf(res.pair_key) })];
    try { acceptPrekeys(s, reply.prekeys, now); } catch (e) {
      if (!(e instanceof MsgError)) throw e;
      events.push({ type: 'dropped', check: e.check, detail: `the reply's prekeys: ${e.message}` });
    }
    st.peers[c.did] = { session: dumpSession(s), announced: held, known: held, outbox: st.peers[c.did]?.outbox ?? [], prekeys_resend: false, prekeys_iat: 0 };
    for (const [x] of waiting) this.#handshakes.set(x, { contact: { name: c.name, did: c.did, current_did: c.current_did, fingerprint: wordsOf(res.pair_key) } });
    this.#routes = new Map();
    return events;
  }

  // ---- outgoing

  // The next frame to publish at this relay, saved in st.pending before it leaves: one queued
  // earlier whose topics are claimed, else per contact its rotation notice, its fresh prekeys,
  // then the outbox. Built one at a time, so a refused epoch start costs no later message.
  #next(ctx, link) {
    const { now, me, store, st } = ctx;
    // An answer or reply is worth nothing once its code has expired: the other side refuses it.
    // A reply that never left takes its half of the pairing with it.
    for (const p of st.pending) {
      if (p.control === 'reply' && p.undo && p.exp <= now) this.#emit(this.#unpair(ctx, p, { code: 'code_expired', detail: 'the reply did not reach the relay before the code expired' }));
    }
    st.pending = st.pending.filter((p) => p.exp === undefined || p.exp > now);
    // Nothing goes to a contact whose mailbox nobody held at this round's last publish to it
    // (no_reader): it would be refused alike. Its frames wait for the next round, its messages
    // unsealed in its outbox, so no epoch is begun (and no prekey spent) for nothing.
    const absent = (did) => did !== undefined && link.absent.has(did);
    const queued = st.pending.find((p) => p.relay === link.relay && (p.control === 'reply' || !absent(p.peer)) && (p.needs ?? []).every((t) => link.subscribed.has(t)));
    if (queued) return queued;
    const relay = link.relay;
    for (const c of this.#liveContacts(store, relay)) {
      const e = st.peers[c.did];
      if (!e) continue;
      if (absent(c.did)) {
        const detail = noReader(c.name);
        for (const item of e.outbox) this.#results.set(item.id, { code: null, queued: detail });
        // Said once while it lasts (a CLI agent reads it in inbox()).
        if (e.outbox.length > 0 && e.waiting !== detail) { e.waiting = detail; this.#emit(this.#note(st, now, { type: 'waiting', did: c.did, name: c.name, detail })); }
        continue;
      }
      const K = hexToBytes(c.pair_key), t = topic(K, me.did, c.did, isoWeek(now));
      const s = this.#restore(st, store, me, c.did), missing = prekeysMissing(s, now);
      // Our bundle when due, when the contact asked for it (want), when one is owed for an epoch of
      // the contact's that could not begin here (resync, RESYNC after the last such), or, at most
      // once a day while messages wait for want of the contact's, to ask for that (the header's
      // "Prekeys").
      const ask = missing !== null && e.outbox.length > 0 && now - (e.asked ?? 0) >= DAY;
      const resync = e.renew === true || (e.resync_due === true && now - (e.resync_at ?? 0) >= RESYNC);
      const told = e.known_due === true && now - (e.prekeys_iat ?? 0) >= RESYNC;
      // Under a burned K (re_pair) the notice alone goes: no bundle, no message.
      const bundle = !c.re_pair && (e.prekeys_resend || s.in.prekeys.due(now, me) || ask || resync || told);
      // The rotation notice: after this agent's own rotation (announced), and again, at most every
      // RESYNC, while the contact has not said it holds the current DID (known): before a frame
      // signed by the current key goes (a bundle, an envelope), or when the contact's frame named
      // another DID. Sent once, a notice the relay expired before the contact read it (away longer
      // than its retention) left every later envelope failing `from` there and every bundle
      // `prekeys`, acknowledged and lost, and a recovery's notice lost left the thief's key current.
      const first = e.announced !== me.current_did;
      const again = !first && (e.known ?? me.did) !== me.current_did && now - (e.noticed ?? 0) >= RESYNC
        && (e.notice_asked === true || bundle || (e.outbox.length > 0 && missing === null));
      if (first || again) {
        // After this agent's own rotation its record of the contact's spent one-time prekeys
        // cannot be trusted: a copy of this state in a thief's hands may have spent some, and an
        // epoch on one fails prekey_reused. Until the contact's fresh bundle comes (it sends one
        // when it reads this notice), epochs begin on its last-resort key, which may be reused.
        if (first && s.out.prekeys) { for (const k of s.out.prekeys.keys) s.out.used.add(k.id); this.#persist(st, s); }
        const proof = { v: V, typ: TYP_NOTICE, did: me.current_did, pair: pairId(K) };
        e.announced = me.current_did;
        e.noticed = now;
        e.notice_asked = false;
        return this.#queue(st, { relay, topic: t, bytes: seal(KIND_NOTICE, noticeKey(K, me.did, c.did), t, { bundle: chainOf(me.bundle), proof: { body: proof, sig: sign(me.secret, proof) } }),
          kind: KIND_NOTICE, peer: c.did, control: 'notice' });
      }
      if (c.re_pair) {
        // Queued before the mark: refused here, unsealed. Noted too: the send that queued it has
        // exited, and its agent was told it goes at a later connection.
        for (const item of e.outbox.splice(0)) {
          this.#results.set(item.id, { code: 're_pair', detail: rePairWhy(c), local: true });
          this.#emit(this.#note(st, now, { type: 'refused', id: item.id, peer: c.did, name: c.name, code: 're_pair', detail: rePairWhy(c) }));
        }
        continue;
      }
      if (bundle) {
        // The contact refuses a bundle no newer than the one it holds (envelope.mjs acceptPrekeys),
        // so two issued within one second get iat one apart (checkPrekeys allows SKEW ahead).
        // known: the contact's current DID as this agent holds it, so the contact learns whether
        // its rotation notice reached us.
        const iat = Math.max(now, (e.prekeys_iat ?? 0) + 1);
        if (resync) s.in.prekeys.retireOneTime(now);
        const frame = seal(KIND_PREKEYS, prekeysKey(K, me.did, c.did), t, { prekeys: s.in.prekeys.issue(me, s.pair, iat), want: missing !== null, known: c.current_did });
        this.#persist(st, s);
        // Every bundle names the contact's current DID as held here (known): what known_due owed.
        e.prekeys_resend = false;
        e.known_due = false;
        e.prekeys_iat = iat;
        if (resync) { e.renew = false; e.resync_due = false; e.resync_at = iat; }
        if (missing !== null) e.asked = now;
        return this.#queue(st, { relay, topic: t, bytes: frame, kind: KIND_PREKEYS, peer: c.did, control: 'prekeys' });
      }
      // This agent's operator hints, once per pairing and set of operators (#onOperator).
      const mine = this.#mine(me, now), ops = mine.operators, hinted = opKey(mine, ops);
      if (ops.length > 0 && e.op_hinted !== hinted) {
        e.op_hinted = hinted;
        e.outbox.unshift({ id: randomId(), label: OPERATOR_LABEL, content: { hints: [...ops].sort().map((d) => operatorHint(K, 'hint', me.did, d)) } });
      }
      while (e.outbox.length > 0) {
        const item = e.outbox[0];
        try {
          const m = send(s, { label: item.label, content: item.spool ? this.#spooled(item.id) : item.content }, now);
          e.outbox.shift();
          if (e.waiting === noReader(c.name)) e.waiting = null;
          this.#persist(st, s);
          // item: put back in the outbox if the relay says no_reader (#refused). Plaintext at rest
          // only as long as the outbox already kept it, until the PUBACK.
          return this.#queue(st, { id: item.id, relay, topic: m.topic, bytes: m.bytes, kind: KIND.message, n: m.n, peer: c.did, item });
        } catch (err) {
          if (!(err instanceof MsgError)) throw err;
          if (err.check === 'prekeys') {
            // No epoch can begin until the contact's fresh bundle comes, asked for above: the
            // messages stay queued, said once per reason (a CLI agent reads it in inbox()).
            const detail = `messages to ${c.name} wait for its fresh prekeys (${err.message}); asked for, at most once a day: they go once it answers`;
            if (e.waiting !== err.message) { e.waiting = err.message; this.#emit(this.#note(st, now, { type: 'waiting', did: c.did, name: c.name, detail })); }
            for (const x of e.outbox) this.#results.set(x.id, { code: null, queued: detail });
            break;
          }
          // Refused here, before sending (message_too_large, revoked): never reported as the relay's word.
          e.outbox.shift();
          this.#results.set(item.id, { code: err.check, detail: err.message, local: true });
        }
      }
    }
    return null;
  }

  // A publish the relay acknowledged but refused ($sigelo/notice). → true when the frame stays
  // pending, to go again next round.
  #refused(ctx, e, r) {
    const { me, store, st } = ctx;
    // The relay holds no proof of work from this identity (it forgot it with an idle account): the
    // frame stays pending and goes after a login with a proof (#flush closes this connection).
    if (r.code === 'pow') { (st.relays[e.relay] ??= { proven: false, claims: {} }).proven = false; return true; }
    if (e.control === 'reply') {
      if (REPLY_RETRY.has(r.code)) return true;
      // Before this, a refused reply left the inviter with a contact that never heard of her.
      if (e.undo) this.#emit(this.#unpair(ctx, e, { code: r.code, detail: `the relay refused the reply (${relaySays(r.detail)})` }));
      return false;
    }
    const p = e.peer && st.peers[e.peer];
    if (!p) return false;
    // A notice the relay refused goes again next round (#next, `again`); its prekeys were marked
    // used when it was first queued.
    if (e.control === 'notice') { p.noticed = 0; p.notice_asked = true; }
    if (e.control === 'prekeys') p.prekeys_resend = true;
    // The epoch's first envelope stored nothing: the next message begins a new epoch, and the
    // one-time prekey goes back to the pool (envelope.mjs restartEpoch), so a run of refusals spends
    // none of the contact's keys.
    if (e.kind === KIND.message && e.n === 0) {
      const s = this.#restore(st, store, me, e.peer);
      if (s) { restartEpoch(s, unb64(e.bytes)); this.#persist(st, s); }
    }
    // Nobody holds the contact's mailbox: the message goes back to the front of its outbox, to be
    // sealed again for the week it then goes in (the header's "Mailboxes"). Sealed bytes kept for
    // later could name a week whose mailbox the reader never claims again. An entry written by an
    // earlier version has no item: refused, as it was.
    if (e.kind === KIND.message && r.code === 'no_reader' && e.item) p.outbox.unshift(e.item);
    return false;
  }

  #nameOf(did) { try { return this.#read(({ store }) => store.lookup(did)?.name) ?? 'the contact'; } catch { return 'the contact'; } }

  async #throttle(link) {
    for (;;) {
      const t = Date.now();
      link.tokens = Math.min(RATE.burst, link.tokens + ((t - link.at) / 1000) * RATE.perSecond);
      link.at = t;
      if (link.tokens >= 1) { link.tokens -= 1; return; }
      await sleep(Math.ceil(((1 - link.tokens) / RATE.perSecond) * 1000));
    }
  }

  // One publish in flight per connection, so a notice that arrives before its PUBACK is its refusal:
  // the relay writes a refusal's notice before the PUBACK (relay/mailbox.mjs). A notice naming
  // another packet id (`id`) is not this publish's: a late one taken for it misread the next
  // message as refused (its epoch restarted, its prekey put back, its contact marked absent).
  async #publish(link, t, bytes) {
    link.collect = [];
    try {
      const id = await link.request('PUBACK', (cb) => link.client.publish(t, Buffer.from(bytes), { qos: 1 }, (err, packet) => (err ? cb(new MsgError('connect', err.message)) : cb(null, packet?.messageId))));
      const mine = (n) => PUBLISH_CODES.has(n.code) && (n.id === undefined || n.id === id);
      for (const n of link.collect) if (!mine(n)) this.#emit({ type: 'notice', relay: link.relay, code: n.code, detail: n.detail });
      return link.collect.find(mine) ?? null;
    } finally { link.collect = null; }
  }

  async #flush(link) {
    try { await this.#flushing(link); } finally { try { this.#locked(({ st }) => this.#sweepSpool(st)); } catch {} }
  }

  async #flushing(link) {
    for (;;) {
      if (!link.up) return;
      const e = this.#locked((ctx) => this.#next(ctx, link));
      if (!e) return;
      await this.#throttle(link);
      let r;
      try { r = await this.#publish(link, e.topic, unb64(e.bytes)); } catch (err) {
        // Still pending: published again at the next connection; a duplicate fails `replay` there.
        this.#emit({ type: 'error', relay: link.relay, check: err.check ?? 'publish', detail: err.message });
        return;
      }
      this.#locked((ctx) => { if (!(r && this.#refused(ctx, e, r))) ctx.st.pending = ctx.st.pending.filter((p) => p.id !== e.id); });
      if (r?.code === 'pow') { link.pow = true; link.closing = true; link.client.end(true); return; }   // log in again, with the proof (#connect, #closed)
      if (r?.code === 'no_reader' && e.peer !== undefined && e.control !== 'reply') link.absent.add(e.peer);
      // A message the relay had no reader for is back in its outbox (#refused): queued, not refused.
      const back = r?.code === 'no_reader' && e.kind === KIND.message && e.item !== undefined;
      if (e.control === undefined || e.control === 'answer') this.#results.set(e.id, back ? { code: null, queued: noReader(this.#nameOf(e.peer)) } : r ?? { code: null });   // what a verb waits for
      this.#emit(back ? { type: 'queued', id: e.id, peer: e.peer, code: r.code, detail: r.detail }
        : r ? { type: 'refused', id: e.id, peer: e.peer, control: e.control, code: r.code, detail: r.detail } : { type: 'sent', id: e.id, peer: e.peer, control: e.control });
      // A refusal stops this round: what follows would be refused alike (a quota, the rate brake),
      // and a control frame would be queued again at once. The next round retries. A mailbox
      // nobody holds stops only what goes to that contact (absent, #next).
      if (r && r.code !== 'no_reader') return;
    }
  }

  async #subscribe(link, items) {
    const reasons = new Set(), now = this.clock();
    let rated = null;
    for (let i = 0; i < items.length; i += MAX_TOPICS) {
      // The relay's brake refused a topic: every later one would be refused alike, and each
      // refusal is a strike (500 in a minute close the connection). They wait for the next round.
      if (rated) {
        for (const x of items.slice(i)) { link.refused.set(x.topic, now); this.#refusedTopics.set(x.topic, rated); }
        reasons.add(rated);
        break;
      }
      const chunk = items.slice(i, i + MAX_TOPICS);
      link.collect = [];
      let granted, notes;
      try {
        granted = await link.request('SUBACK', (cb) => link.client.subscribe(chunk.map((x) => x.topic), { qos: 1 }, (err, _subs, packet) =>
          (packet?.granted ? cb(null, packet.granted) : cb(new MsgError('connect', err?.message ?? 'no SUBACK')))));
        notes = link.collect;
      } finally { link.collect = null; }
      // One reason for every topic this packet had refused: the notices do not name their topic.
      const why = notes.find((n) => SUBSCRIBE_CODES.has(n.code)) ?? { code: 'subscribe', detail: 'refused by the relay' };
      for (const n of notes) if (!SUBSCRIBE_CODES.has(n.code)) this.#emit({ type: 'notice', relay: link.relay, ...n });
      chunk.forEach((x, j) => {
        if (granted[j] === 1) { link.subscribed.add(x.topic); this.#claimed.add(x.topic); this.#refusedTopics.delete(x.topic); return; }
        link.refused.set(x.topic, now);
        this.#refusedTopics.set(x.topic, why);
        reasons.add(why);
      });
      rated = notes.find((n) => n.code === 'rate') ?? null;
    }
    const pow = [...reasons].some((r) => r.code === 'pow');
    this.#locked(({ st }) => {
      const r = (st.relays[link.relay] ??= { proven: false, claims: {} });
      for (const x of items) if (x.peer && link.subscribed.has(x.topic)) r.claims[x.topic] = { peer: x.peer, until: x.until };
      // The relay has no proof of work from this identity (it never had one, or forgot it).
      if (pow) r.proven = false;
    });
    // Log in again, with the proof (#connect, #closed).
    if (pow) { link.pow = true; link.closing = true; link.client.end(true); return; }
    for (const r of reasons) this.#emit({ type: 'notice', relay: link.relay, ...r });
  }

  // UNSUBSCRIBE gives a claim up, and what is queued on it. A refused one ("rate") stays claimed:
  // it is tried again next round.
  async #unsubscribe(link, topics) {
    let refused = false;
    for (let i = 0; i < topics.length; i += MAX_TOPICS) {
      link.collect = [];
      try {
        await link.request('UNSUBACK', (cb) => link.client.unsubscribe(topics.slice(i, i + MAX_TOPICS), (err) => cb(err && new MsgError('connect', err.message))));
        refused ||= link.collect.some((n) => n.code === 'rate');
      } finally { link.collect = null; }
      if (refused) break;   // the rest would be refused alike, each a strike (#subscribe)
    }
    if (refused) return;
    this.#locked(({ st }) => { const claims = st.relays[link.relay]?.claims ?? {}; for (const t of topics) delete claims[t]; });
    for (const t of topics) link.subscribed.delete(t);
  }

  // One round at a relay: claim what is wanted, give up what has expired or was forgotten, then
  // publish. Claims come first: a reply or a first message must find the other side's topic held.
  async #refresh(relay) {
    const link = this.#links.get(relay);
    if (!link?.up) return;
    const { want, stale } = this.#read(({ now, me, store, st }) => {
      const live = (d) => { const c = store.lookup(d); return Boolean(c && !c.revoked); };
      return { want: this.#want({ now, me, store }, relay), stale: Object.entries(st.relays[relay]?.claims ?? {}).filter(([, x]) => x.until < now || !live(x.peer)).map(([t]) => t) };
    });
    const now = this.clock(), refusedLately = (t) => link.refused.has(t) && now - link.refused.get(t) < ASK_AGAIN;
    const fresh = want.filter((w) => !link.subscribed.has(w.topic) && !refusedLately(w.topic));
    if (fresh.length > 0) await this.#subscribe(link, fresh);
    if (!link.up) return;
    // UNSUBSCRIBE deletes what is queued on the topic (relay/db.mjs release). Only once deliveries
    // have stopped: a relay keeping messages longer than this agent thinks (a Pro reader run with
    // the free tier's retention) has then delivered them. #session ends with such a round.
    if (stale.length > 0 && link.quiet) await this.#unsubscribe(link, stale);
    await this.#flush(link);
  }

  // Work runs one item at a time, after the delivery that queued it is acknowledged: a SUBACK or
  // PUBACK it waits for is handled only once the packet before it is.
  #later(fn) {
    this.#busy++;
    this.#work = this.#work.then(fn).catch((e) => this.#emit({ type: 'error', check: e.check ?? 'internal', detail: e.message }))
      .finally(() => { this.#busy--; this.#lastWork = Date.now(); });
  }
  async #drain() { while (this.#busy > 0) await this.#work; }
  // A round for this relay, unless one is already queued and not yet begun: a burst of deliveries
  // costs one round, not one each.
  #refreshSoon(relay) {
    if (this.#soon.has(relay)) return;
    this.#soon.add(relay);
    this.#later(() => { this.#soon.delete(relay); return this.#refresh(relay); });
  }

  // Until queued work is done and nothing has arrived for QUIET ms (and `until()` holds), or max ms.
  async #idle({ max = DRAIN, until = null } = {}) {
    const end = Date.now() + max;
    for (;;) {
      await this.#drain();
      const last = Math.max(this.#lastWork, ...[...this.#links.values()].map((l) => l.lastIn));
      if (Date.now() - last >= QUIET && (!until || until())) return;
      if (Date.now() >= end) return;
      await sleep(50);
    }
  }

  // ---- connections

  async #credentials(relay, ep) {
    const { me, proven } = this.#read(({ me, st }) => ({ me, proven: st.relays[relay]?.proven === true }));
    const powMax = relay === this.relay ? POW_MAX : POW_MAX_OTHER;
    const r = await http(`${ep.http}/challenge?did=${encodeURIComponent(me.current_did)}`);
    this.#clockFrom(relay, r);
    if (r.status === 429) refuse('rate', `the relay ${relay} turned the login away: too many logins from this network (${relaySays(r.body?.error ?? r.body?.detail)}): ${retryIn(r, 'a minute')}, then try again`, r);
    // Any other status is no answer about this agent (nginx says 502 while the relay restarts):
    // `connect`, retried. `challenge`, which no retry fixes, is a 200 that is not this relay's
    // challenge for this agent.
    if (r.status !== 200) refuse('connect', `${relay}: ${statusWhy(r, 'GET /challenge')}`, r);
    const ch = r.body?.challenge;
    if (!exact(ch, ['v', 'typ', 'did', 'relay', 'nonce']) || ch.v !== LOGIN_V || ch.typ !== TYP_LOGIN || typeof ch.nonce !== 'string' || ch.nonce.length > 128) {
      fail('challenge', `GET /challenge did not answer a login body {v: "${LOGIN_V}", typ: "${TYP_LOGIN}", did, relay, nonce}`);
    }
    if (ch.did !== me.current_did) fail('challenge', 'the login body names another DID');
    // relay is the relay's own name: a login for any other would let whoever answered here log in
    // as this agent there (relay-plan §3 "Login").
    if (ch.relay !== relay) fail('challenge', `relay ${JSON.stringify(ch.relay)} is not this relay's name, ${relay}`);
    // Signed as built here, never as received; its typ is one no challenge signer produces (a SPEC
    // §5.2 challenge for this relay, got by a world from sign-challenge, logs in nobody).
    const body = { v: LOGIN_V, typ: TYP_LOGIN, did: me.current_did, relay, nonce: ch.nonce }, sig = sign(me.secret, body);
    if (!verifySig(me.genesis.key, body, sig)) fail('identity', 'this agent\'s secret does not match its current genesis key');
    if (canonicalize(body) !== canonicalize(ch)) fail('challenge', 'not the login body this agent signs');
    let pow;
    if (!proven) {
      const bits = r.body.pow_bits;
      if (!Number.isSafeInteger(bits) || bits < 0 || bits > powMax) {
        // No retry asks less of this client: permanent for this relay (#retry, accept).
        const e = new MsgError('pow', `the relay asks ${JSON.stringify(bits)} bits of proof of work; this client spends at most ${powMax} at ${relay === this.relay ? 'its own relay' : 'a relay other than its own (SIGELO_RELAY)'}: try again later`);
        e.permanent = true;
        throw e;
      }
      // A search of 0 bits costs nothing and is not counted.
      if (bits > 0) this.#locked(({ now, st }) => {
        const at = (st.relays[relay] ??= { proven: false, claims: {} }), recent = (at.searches ?? []).filter((t) => t > now - DAY);
        if (recent.length >= POW_SEARCHES) {
          // Permanent like the bits above: no backoff loop; the hourly round asks again (#retry).
          const e = new MsgError('pow', `${recent.length} proof-of-work searches at ${relay} within 24 hours, the most this client spends: the next may begin after ${new Date((recent[0] + DAY) * 1000).toISOString()}`);
          e.permanent = true;
          throw e;
        }
        at.searches = [...recent, now];
      });
      const t0 = Date.now();
      if (bits > 0) this.#emit({ type: 'pow', relay, bits });
      pow = await solvePow(relay, me.did, ch.nonce, bits, t0 + POW_MS) ?? fail('pow', `no ${bits}-bit proof of work found within the challenge's 5 minutes on this machine: try again, or later (the relay raises it under load)`);
      if (bits > 0) this.#emit({ type: 'pow_done', relay, bits, ms: Date.now() - t0 });
    }
    const password = canonicalize({ v: LOGIN_V, nonce: ch.nonce, sig, bundle: loginBundle(me.bundle, relay), ...(pow !== undefined && { pow }) });
    return { username: me.current_did, clientId: clientIdOf(me.did), password, pow };
  }

  // How long this agent's own relay keeps a message on the free tier (relay.json, plan §11), when
  // the constructor was not told: asked once, beside the first login's challenge. Any failure (no
  // such file, a relay on loopback, a value out of range) keeps RETENTION_DAYS. Before the first
  // claim, so the weeks claimed behind (#weeks) follow it.
  async #relayInfo(ep) {
    this.#ask = false;
    try {
      const r = await http(`${ep.http}/relay.json`);
      this.#clockFrom(this.relay, r);
      const n = r.status === 200 ? retentionOf(r.body) : null;
      if (n !== null) this.retention = n * DAY;
    } catch {}
  }

  get retentionDays() { return this.retention / DAY; }

  // The relay's clock less this agent's (this.clock), in seconds, from an answer r of relay: its
  // Date header (whole seconds, so +0.5) taken as of the middle of the round trip.
  #clockFrom(relay, r) {
    if (r?.date == null) return;
    const now = this.clock();
    this.#clocks.set(relay, { offset: Math.round((r.date + 500 - r.rtt / 2) / 1000 - now), checked: now });
  }

  /** { relay, offset, checked } as last measured at relay (a login, relay.json, a short code), or null. offset: seconds, relay minus local. */
  clockOffset(relay = this.relay) {
    const c = this.#clocks.get(relay);
    return c ? { relay, ...c } : null;
  }

  /** Measures the offset now at this agent's own relay (GET /relay.json). → clockOffset(); throws as a relay that does not answer does. */
  async checkClock() {
    this.#clockFrom(this.relay, await http(`${endpointOf(this.relay, this.endpoints).http}/relay.json`));
    return this.clockOffset();
  }

  async #dial(relay) {
    const ep = endpointOf(relay, this.endpoints), link = new Link(relay, relay === this.relay);
    const info = link.own && this.#ask ? this.#relayInfo(ep) : null;
    const creds = await this.#credentials(relay, ep);
    await info;
    // A cut connection is this client's own refusal: no POST /check may rename it.
    try { await mqttConnect(ep.mqtt, creds, link, (packet) => this.#onPacket(link, packet)); } catch (e) { throw link.cut ?? await named(ep, creds, e); }
    // A close right after CONNACK (a cut in the same read) reached no listener of this connection.
    if (!link.client.connected) throw link.cut ?? new MsgError('connect', 'the relay closed the connection');
    // Deliveries are counted from here (quiet), not from before the login: a proof-of-work search
    // of seconds would read as a drained queue, and give up stale claims before what they hold came.
    link.since = Date.now();
    if (creds.pow !== undefined) this.#locked(({ st }) => { (st.relays[relay] ??= { proven: false, claims: {} }).proven = true; });
    link.client.on('error', () => {});   // a close follows
    link.client.on('close', () => this.#closed(link));
    this.#links.set(relay, link);
    await link.request('SUBACK', (cb) => link.client.subscribe(NOTICE, { qos: 0 }, (err) => cb(err && new MsgError('connect', err.message))));
    this.#emit({ type: 'connected', relay });
    return link;
  }

  async #connect(relay) {
    this.#connecting.add(relay);
    try {
      for (let attempt = 0; ; attempt++) {
        const link = await this.#dial(relay);
        this.#refreshSoon(relay);
        await this.#drain();
        if (link.up) return link;
        if (link.cut) throw link.cut;
        if (link.pow && attempt === 0) continue;   // the relay asked for proof of work: once more, with it
        fail(link.pow ? 'pow' : 'connect', link.pow ? 'the relay refused the proof of work' : 'the relay closed the connection');
      }
    } finally { this.#connecting.delete(relay); }
  }

  #closed(link) {
    link.abort?.(new MsgError('connect', 'the connection to the relay closed'));
    if (this.#links.get(link.relay) === link) this.#links.delete(link.relay);
    this.#emit({ type: 'disconnected', relay: link.relay });
    if (Date.now() - link.since >= STABLE_MS) this.#attempts.delete(link.relay);
    if (!this.#started || this.#connecting.has(link.relay) || (link.closing && !link.pow)) return;
    if (link.cut?.permanent) {
      this.#emit({ type: 'error', relay: link.relay, check: link.cut.check, detail: link.cut.message });
      this.#abandon(link.relay, link.cut);
    } else this.#retry(link.relay);
  }

  // Exponential backoff with jitter: first, 2 × first, … up to most.
  #retry(relay, delay) {
    if (this.#timers.has(relay)) return;
    const n = (this.#attempts.get(relay) ?? 0) + 1, [first, most] = this.backoff;
    this.#attempts.set(relay, n);
    const wait = delay ?? Math.min(most, first * 2 ** (n - 1)) * (0.5 + Math.random() / 2);
    this.#timers.set(relay, setTimeout(async () => {
      this.#timers.delete(relay);
      if (!this.#started || this.#links.get(relay)?.up || this.#connecting.has(relay)) return;
      try {
        const link = await this.#connect(relay);
        this.#powFails.delete(relay);
        if (!this.#started) await this.#hangUp(link);   // stop() came while this connected
      } catch (e) {
        this.#emit({ type: 'error', relay, check: e.check ?? 'connect', detail: e.message });
        if (e.check === 'pow') this.#powFails.set(relay, (this.#powFails.get(relay) ?? 0) + 1);
        // A refusal no retry can fix, or proof of work failing twice (each try may cost POW_MS of
        // CPU), or POW_SEARCHES spent: no backoff loop here. The hourly round tries again while a
        // contact, a code or an answer is at that relay; #abandon withdraws the answers a
        // stranger's code sent there.
        if (PERMANENT.has(e.check) || e.permanent || this.#powFails.get(relay) >= 2) this.#abandon(relay, e);
        else this.#retry(relay);
      }
    }, wait));
  }

  // A relay other than this agent's own refuses it for good: the answers still waiting to go to it
  // are withdrawn, so no later round dials, for them, a host that a stranger's code named. An
  // answer the relay already holds stays: the inviter may pair and reply, and its secret is what
  // reads the reply, at a later round while the code lasts. Nothing is withdrawn at this agent's
  // own relay, nor for this agent's own bundle (`identity`): neither is a stranger's doing.
  #abandon(relay, e) {
    if (e.check === 'identity' || relay === this.relay) return;
    try {
      this.#locked(({ now, store, st }) => {
        const waiting = new Set(st.pending.filter((x) => x.relay === relay && x.control === 'answer').map((x) => x.topic));
        for (const [id, p] of Object.entries(store.load().s.accepts)) {
          if (p.relay !== relay || !waiting.has(inviteKeys(hexToBytes(p.secret)).answer_topic)) continue;
          store.take('accepts', id, now);
          this.#emit(this.#note(st, now, { type: 'pairing_failed', did: p.code_did, name: p.name, code: e.check ?? 'connect', detail: `the code's relay refused this agent: ${e.message}` }));
        }
        st.pending = st.pending.filter((x) => !(x.relay === relay && x.control === 'answer'));
      });
    } catch {}
  }

  async #hangUp(link) {
    link.closing = true;
    if (link.client?.connected) {
      // DISCONNECT, then the socket closes; a relay that never answers is cut off after ACK_MS.
      await new Promise((resolve) => {
        const timer = setTimeout(() => { link.client.end(true); resolve(); }, ACK_MS);
        link.client.end(false, {}, () => { clearTimeout(timer); resolve(); });
      });
    } else link.client?.end(true);
    if (this.#links.get(link.relay) === link) this.#links.delete(link.relay);
  }

  // Connects (or refreshes) each relay, waits for the round to settle, and hangs up again unless
  // started.
  async #session(relays, idle = {}) {
    const opened = [];
    this.#locked((ctx) => this.#expireKeys(ctx));
    try {
      for (const r of relays) {
        if (this.#links.get(r)?.up) this.#refreshSoon(r);
        else opened.push(await this.#connect(r));
      }
      await this.#idle(idle);
      // One more round now that deliveries have stopped: claims past their time are given up
      // only then (#refresh), and a frame that waited for a claim goes.
      for (const r of relays) if (this.#links.get(r)?.up) this.#refreshSoon(r);
      await this.#drain();
      // A connection cut after connecting fails the session as a cut while connecting does, so
      // the verb withdraws what it would have (accept) or reports it (inbox).
      const cut = opened.find((l) => l.cut)?.cut;
      if (cut) throw cut;
    } finally {
      if (!this.#started) for (const l of opened) if (this.#links.get(l.relay) === l) await this.#hangUp(l);
    }
  }

  // ---- the verbs

  // short: the long code is parked at the relay (POST /park, relay/park.mjs) under a short code
  // (short.mjs) for SHORT_TTL seconds, one fetch; refused, the invite is withdrawn as when its topic
  // is. A login of its own: the relay checks that the parked code is this agent's.
  async invite({ name, ttl, short = false } = {}) {
    const code = this.#locked(({ now, me, store }) => {
      const code = makeInvite({ did: me.current_did, relay: this.relay, now, ...(ttl !== undefined && { ttl }) });
      store.addInvite(code, name ?? `invite-${code.nonce.slice(1, 9)}`, now);
      return code;
    });
    // The answer topic is claimed before the code leaves: the relay drops what nobody reads.
    const t = inviteKeys(code.secret).answer_topic;
    try {
      await this.#session([code.relay]);
      if (!this.#claimed.has(t)) {
        const r = this.#refusedTopics.get(t);
        fail(r?.code ?? 'subscribe', `the relay did not let this agent claim the invite's topic${r ? ` (${relaySays(r.detail)})` : ''}`);
      }
      if (!short) return { code: code.text, did: code.did, relay: code.relay, exp: code.exp };
      const s = makeShort(), exp = Math.min(checkNow(this.clock()) + SHORT_TTL, code.exp), ep = endpointOf(code.relay, this.endpoints);
      const creds = await this.#credentials(code.relay, ep);
      const r = await http(`${ep.http}/park`, { method: 'POST', body: JSON.stringify({ username: creds.username, client_id: creds.clientId, password: creds.password, code_hash: codeHash(s), invite: code.text, exp }) });
      const check = typeof r.body?.check === 'string' ? r.body.check : null;
      if (r.status === 429) refuse('rate', `the relay ${code.relay} parks no more short codes from this network for now (${relaySays(r.body?.detail)}): ${retryIn(r, 'up to an hour')}, or use the long code (invite --long)`, r);
      if ((r.status === 404 || r.status === 405) && check === null) refuse('park', `the relay ${code.relay} takes no short codes: use the long code (invite --long)`, r);
      if (r.status !== 200) refuse('connect', `${code.relay}: ${statusWhy(r, 'POST /park')}`, r);
      // exp is this machine's clock: one far off the relay's is refused (relay/park.mjs PARK_SKEW).
      const clock = typeof r.body?.detail === 'string' && r.body.detail.startsWith('exp:') ? ': this machine\'s clock may be off (date -u), or use the long code (invite --long)' : '';
      if (r.body?.ok !== true) refuse(PARK_CHECKS.has(check) ? check : 'park', `the relay refused the short code (${relaySays(`${check}: ${r.body?.detail}`)})${clock}`, r);
      // The relay keeps the code until its own exp (park.mjs: at most SHORT_TTL by its clock), not
      // this machine's: that is the one shown. This machine's only when the relay names none.
      const held = Number.isSafeInteger(r.body.exp) && r.body.exp > 0 ? r.body.exp : exp;
      return { code: code.text, did: code.did, relay: code.relay, exp: code.exp, short: formatShort(s), short_exp: held };
    } catch (e) {
      try { this.#locked(({ store }) => store.cancelInvite(code.nonce)); } catch {}
      throw e;
    }
  }

  // The long code parked under a short one, at this agent's own relay (a short code names none):
  // GET /park/<code hash>, which the relay answers once. Whatever it answers is a code to parse
  // like any other (accept); the four words show whether the pairing is the inviter's.
  async unpark(text) {
    const shown = formatShort(normaliseShort(text)), ep = endpointOf(this.relay, this.endpoints);
    const r = await http(`${ep.http}/park/${codeHash(text)}`);
    if (r.status === 429) refuse('rate', `the relay ${this.relay} looks up no more short codes from this network for now (${relaySays(r.body?.detail)}): ${retryIn(r, 'up to 10 minutes')}, or ask for the long code (invite --long)`, r);
    if (r.status === 404 && r.body?.check === 'park_unknown') {
      refuse('park_unknown', `short code ${shown}: no invite waits under it at ${this.relay}. It expired (a short code lives 10 minutes), was used already (once only), or is mistyped; ask the inviter for a new one. If the inviter's agent uses another relay than ${this.relay} (SIGELO_RELAY), ask for the long code (invite --long)`, r);
    }
    if (r.status === 404 || r.status === 405) refuse('park', `the relay ${this.relay} takes no short codes: ask the inviter for the long code (invite --long)`, r);
    if (r.status !== 200) refuse('connect', `${this.relay}: ${statusWhy(r, 'GET /park')}`, r);
    if (r.body?.ok !== true || typeof r.body.invite !== 'string') refuse('connect', `${this.relay}: GET /park answered 200 without a parked code: try again later; SIGELO_DEBUG=1 shows the answer`, r);
    return r.body.invite;
  }

  async accept(text, opts = {}) {
    // Short or long by the input's shape, before either parser runs (short.mjs codeKind).
    const how = codeKind(text) === 'short' ? 'parked' : 'long';
    if (how !== 'parked') return this.#answer(text, how, opts);
    const long = await this.unpark(text);
    try { return await this.#answer(long, how, opts); } catch (e) { throw keepLong(e, long); }
  }

  async #answer(text, how, { name, wait = 10, tier } = {}) {
    if (tier !== undefined && !TIERS.includes(tier)) fail('tier', `a tier is ${TIERS.join(', ')}; not ${JSON.stringify(tier)}`);
    const { code, id, entry } = this.#locked(({ now, me, store, st }) => {
      const code = readCode(text, now, how);
      // This agent's own relay, and those its operator configured, are the operator's choice.
      if (code.relay !== this.relay && !Object.hasOwn(this.endpoints ?? {}, code.relay) && !publicRelay(code.relay)) {
        fail('code_relay', `the code names ${code.relay}, an address or a local name, not a public relay: allow it in SIGELO_RELAY_ENDPOINTS if it is yours`);
      }
      const k = kemKey();
      try {
        const answer = buildAnswer({ code, identity: { secret: me.secret, genesis: me.genesis }, bundle: chainOf(me.bundle), kem_pk: k.pk, prekeys: null });
        const keys = inviteKeys(code.secret), frame = seal(KIND.invite_answer, keys.key, keys.answer_topic, answer);
        // Checked before anything is stored: the relay would refuse it (quota_storage).
        if (frame.length > INVITE_BYTES) fail('too_large', `the answer is ${frame.length} bytes, more than an invite topic holds (${INVITE_BYTES}): this agent's chain is too long`);
        const id = answerId(answer);
        // Unnamed: the code's DID's first digits ("z5esAbCd"), as operators shorten a DID. Named, the
        // name also replaces a known contact's on a re-pair (#onReply).
        store.addAccept(code, id, name ?? code.did.slice('did:sigelo:'.length, 'did:sigelo:'.length + 8), now, hex(k.secretKey), me.current_did, name !== undefined, tier ?? null);
        const entry = this.#queue(st, { relay: code.relay, topic: keys.answer_topic, bytes: frame, kind: KIND.invite_answer, control: 'answer', needs: [keys.reply_topic], exp: code.exp });
        return { code, id, entry: entry.id };
      } finally { k.secretKey.fill(0); }
    });
    // Refused: the answer and the pending entry go, so no later connection sends or waits for them.
    const drop = (check, why) => {
      this.#locked(({ now, store, st }) => { st.pending = st.pending.filter((p) => p.id !== entry); store.take('accepts', id, now); });
      fail(check, why);
    };
    // Done early too once the reply topic or the answer is refused (a code answered before:
    // mailbox_taken), not after the whole wait.
    const reply = inviteKeys(code.secret).reply_topic;
    // And once the code expires (#lapse): the answer is dead, so --wait does not run out first.
    const settled = () => this.#handshakes.has(id) || this.#refusedTopics.has(reply) || Boolean(this.#results.get(entry)?.code) || this.clock() >= code.exp;
    try { await this.#session([code.relay], { max: wait * 1000, until: settled }); } catch (e) {
      // A relay other than this agent's own that refuses it for good would be dialled again at
      // every connection, until the code expires, for an answer it never takes: and a stranger's
      // code names it. Withdrawn only while it waits to go: an answer the relay holds keeps its
      // secret for the reply (#abandon).
      const forGood = code.relay !== this.relay && ((PERMANENT.has(e.check) && e.check !== 'identity') || e.permanent);
      const left = this.#locked(({ now, store, st }) => {
        if (!Object.hasOwn(store.load().s.accepts, id)) return 'withdrawn';
        if (!st.pending.some((p) => p.id === entry)) return 'delivered';
        if (!forGood) return 'queued';
        st.pending = st.pending.filter((p) => p.id !== entry);
        store.take('accepts', id, now);
        return 'withdrawn';
      });
      const why = { withdrawn: 'the answer is withdrawn', queued: 'the answer stays queued: it goes at the next connection', delivered: 'the relay holds the answer: the reply is read at a later connection' }[left];
      const err = new MsgError(e.check ?? 'connect', `${reason(e)} (${why})`, { cause: e, http: e.http });
      if (left !== 'withdrawn') err.kept = true;
      throw err;
    }
    const h = this.#handshakes.get(id), sent = this.#results.get(entry);
    this.#handshakes.delete(id); this.#results.delete(entry);
    if (h?.check) fail(h.check, h.detail);
    if (h) return { status: 'connected', contact: h.contact };
    if (this.#refusedTopics.has(reply)) {
      const r = this.#refusedTopics.get(reply);
      // The reply topic is the code's: held by another identity, someone answered the code first.
      drop(r.code, r.code === 'mailbox_taken' ? `this code was answered already, by another agent (a code works once): ask the inviter for a new one (${relaySays(r.detail)})`
        : `the relay did not let this agent claim the reply topic (${relaySays(r.detail)})`);
    }
    if (sent?.code) drop(sent.code, `the relay refused the answer (${relaySays(sent.detail)})`);
    // The code expired during the wait: #lapse emitted pairing_failed (onEvent); the refusal says
    // it here, so the next inbox does not say it again. No long code to keep (keepLong): it is dead.
    const lapsed = this.#locked(({ now, store, st }) => {
      if (now < code.exp) return null;
      st.pending = st.pending.filter((p) => p.id !== entry); store.take('accepts', id, now);
      const at = new Date(code.exp * 1000).toISOString().replace('.000', '');
      const i = st.events.findIndex((e) => e.type === 'pairing_failed' && e.code === 'code_expired' && e.did === code.did && e.detail?.includes(at));
      return i >= 0 ? st.events.splice(i, 1)[0].detail : `the code expired at ${at} before the inviter's agent replied: ask the inviter for a new code`;
    });
    if (lapsed) throw Object.assign(new MsgError('code_expired', lapsed), { lapsed: true });
    if (!sent) return { status: 'pending', did: code.did, relay: code.relay, detail: 'the answer has not reached the relay yet: it goes at the next connection' };
    return { status: 'waiting', did: code.did, relay: code.relay, detail: 'answer delivered; the pairing completes when the inviter\'s agent next connects' };
  }

  // An invite this agent made and nobody has answered, withdrawn: code, its long code (invite's
  // `code`). Its answer topic is given up at the next round; a short code parked for it leads to
  // nothing. → { cancelled: true, name }.
  async cancelInvite(code) {
    const { relay, name } = this.#locked(({ now, store }) => {
      const c = readCode(code, now), p = store.load().s.invites[c.nonce];
      store.cancelInvite(c.nonce);
      return { relay: c.relay, name: p.name };
    });
    this.#routes = new Map();
    if (this.#links.get(relay)?.up) this.#refreshSoon(relay);
    return { cancelled: true, name };
  }

  /** The owner renames a contact (a name or any DID of its chain; store.mjs rename) → { did, name }. */
  rename(who, name) { return this.#locked(({ store }) => store.rename(who, name)); }

  contacts() {
    return this.#read(({ now, store, st }) => {
      const s = store.load().s;
      return {
        contacts: Object.values(s.contacts).map((c) => {
          const e = st.peers[c.did], pair = c.revoked || !c.pair_key ? null : pairId(hexToBytes(c.pair_key));
          return { name: c.name, did: c.did, current_did: c.current_did, chain: c.chain, revoked: c.revoked, relay: c.relay, queued: e?.outbox.length ?? 0,
            re_pair: c.re_pair ?? null, fingerprint: c.revoked ? null : wordsOf(c.pair_key), pair, tier: store.tierOf(c, now), tier_by: c.tier_by ?? null,
            prekeys: pair !== null && theirPrekeys(c, e?.session, pair, now), waiting: e?.waiting ?? null };
        }),
        invites: Object.values(s.invites).filter((p) => p.exp > now).map((p) => ({ name: p.name, exp: p.exp, relay: p.relay })),
        answers: Object.values(s.accepts).filter((p) => p.exp > now).map((p) => ({ name: p.name, did: p.code_did, exp: p.exp, relay: p.relay })),
        // Pairings that failed since the last inbox, which takes them as events.
        failed: st.events.filter((e) => e.type === 'pairing_failed').map(({ name, did, code, detail, at }) => ({ name, did, code, detail, at })),
      };
    });
  }

  async send(to, content, { label = '', local = false } = {}) {
    const [r] = await this.sendAll(to, [content], { label, local });
    if (r.status === 'refused') fail(r.code, `refused (${r.detail})`);
    return r;
  }

  // Several messages to one contact in one session: one login, where `send` costs one each (the
  // relay allows 30 logins a minute per network). sent: the relay accepted it, and holds it for
  // the contact's claim on the topic; queued: it goes at the next connection.
  async sendAll(to, contents, { label = '', local = false } = {}) { return this.#sendAll(to, contents, label, false, local); }

  // spool: every content after the first waits on disk (#spool), as a file's chunks do. local: queued
  // only, for the started carrier of this identity in another process (inbox's local, for sending).
  async #sendAll(to, contents, label, spool, local = false) {
    if (typeof label !== 'string') fail('body', 'label must be a string');
    if (label === LABEL_PREKEYS || label === OPERATOR_LABEL) fail('body', `the label ${JSON.stringify(label)} is the carrier's own`);
    if (!Array.isArray(contents) || contents.length === 0) fail('body', 'at least one message');
    for (const content of contents) {
      if (content === undefined) fail('body', 'content is required');
      try { canonicalize({ label, content }); } catch (e) { fail('body', `content is not canonical JSON (no floats): ${e.message}`); }
    }
    // An answer of ours to `to`'s code waits for its reply (accept said `waiting`): the reply may be
    // at the relay now. One session reads it first, so `send` right after `accept` pairs (or, to a
    // contact already, re-pairs) and goes under the key the reply brings.
    const answered = this.#read(({ now, store }) => [...new Set(Object.values(store.load().s.accepts)
      .filter((p) => p.exp > now && (p.name === to || p.code_did === to)).map((p) => p.relay))]);
    if (answered.length > 0 && !local) {
      try { await this.#session(answered); } catch {}
      this.#routes = new Map();
      this.#read(({ now, store }) => {
        const s = store.load().s;
        if (!Object.values(s.contacts).some((c) => !c.revoked && c.pair_key && (c.name === to || c.chain.includes(to)))
          && Object.values(s.accepts).some((p) => p.exp > now && (p.name === to || p.code_did === to))) {
          fail('not_paired', `${JSON.stringify(to)} is not paired yet: your answer to its code waits for the inviter's agent to connect and reply; send again once inbox reports "paired"`);
        }
      });
    }
    const { ids, c } = this.#locked(({ store, st }) => {
      const c = this.#resolve(store, to), outbox = this.#entry(st, c.did).outbox;
      const ids = contents.map((content, i) => {
        const id = randomId();
        if (spool && i > 0) { this.#spool(id, content); outbox.push({ id, label, spool: true }); } else outbox.push({ id, label, content });
        return id;
      });
      return { ids, c };
    });
    if (local) return ids.map((id) => ({ status: 'queued', id, to: c.did, name: c.name, detail: 'kept for the process that holds this identity\'s relay session: it sends it' }));
    try { await this.#session([c.relay]); } catch (e) {
      throw new MsgError(e.check ?? 'connect', `${reason(e)} (${ids.length === 1 ? 'the message stays' : `the ${ids.length} messages stay`} queued for ${c.name}: they go at the next connection)`, { cause: e, http: e.http });
    }
    return ids.map((id) => {
      const r = this.#results.get(id);
      this.#results.delete(id);
      // detail: the carrier's own words when it refused the message itself, else the relay's, quoted.
      if (r?.code) return { status: 'refused', id, to: c.did, name: c.name, code: r.code, detail: r.local ? r.detail : relaySays(r.detail) };
      if (!r || r.queued) return { status: 'queued', id, to: c.did, name: c.name, detail: r?.queued ?? 'waiting for the relay\'s acknowledgement: it goes at the next connection' };
      return { status: 'sent', id, to: c.did, name: c.name };
    });
  }

  // A file to a contact (file.mjs): its manifest and chunks in one sendAll, so one login. Read whole
  // first (at most MAX_FILE); this identity's own files (key, contacts, state, files received) are
  // refused, so a confused or misled agent cannot send its key. A refusal of any part throws as
  // send does: the contact gets no file, and what came of it there goes at its retention.
  async sendFile(to, path, { local = false } = {}) {
    if (typeof path !== 'string' || path === '') fail('file', 'a file path is required');
    let real, bytes;
    try {
      real = realpathSync(path);
      const s = statSync(real);
      if (!s.isFile()) fail('file', `${path} is not a regular file`);
      if (s.size > MAX_FILE) fail('file_too_large', `${path} is ${s.size} bytes, at most ${MAX_FILE} (8 MiB) a file`);
    } catch (e) {
      if (e instanceof MsgError) throw e;
      fail('file', `cannot read ${path}: ${e.code === 'ENOENT' ? 'no such file' : e.code ?? e.message}`, { cause: e });
    }
    // Beside the identity: its own files (x.*) and any profile's (*.local.*, sigelo-agent's pattern).
    const own = resolve(this.statePath.replace(/(\.carrier)?\.json$/, '')), files = (() => { try { return realpathSync(this.filesDir); } catch { return this.filesDir; } })();
    let ownDir;
    try { ownDir = realpathSync(dirname(own)); } catch { ownDir = dirname(own); }
    const leaf = basename(real);
    if (real.startsWith(files + sep) || (dirname(real) === ownDir && (leaf.startsWith(`${basename(own)}.`) || leaf.includes('.local.')))) {
      fail('file', `${path} is one of this agent's identity files (key, contacts, state, files received): not sent`);
    }
    try { bytes = readFileSync(real); } catch (e) { fail('file', `cannot read ${path}: ${e.code ?? e.message}`, { cause: e }); }
    if (bytes.length > MAX_FILE) fail('file_too_large', `${path} is ${bytes.length} bytes, at most ${MAX_FILE} (8 MiB) a file`);
    const { manifest, chunks } = splitFile(bytes, basename(real));
    const results = await this.#sendAll(to, [manifest, ...chunks], FILE_LABEL, true, local);
    const refused = results.find((x) => x.status === 'refused'), queued = results.find((x) => x.status === 'queued');
    if (refused) fail(refused.code, `refused (${refused.detail}): ${manifest.name} did not go whole; send it again once that is settled`);
    const { id, name, size, sha256: sum, chunks: n } = manifest;
    return { status: queued ? 'queued' : 'sent', to: results[0].to, name: results[0].name, file: { id, name, size, sha256: sum, chunks: n },
      ...(queued && { detail: queued.detail }) };
  }

  // tiers: only messages from contacts of these tiers are taken (and waited for); the rest stay for a
  // later inbox. Events are all taken. local: no session: what the state file holds, waited for by
  // reading it again, for a reader beside a started carrier of the same identity (a watcher), which
  // a session here would disconnect.
  async inbox({ wait = 0, tiers, local = false, paired = false } = {}) {
    const want = tiers === undefined ? null : new Set(tiers);
    if (want && ![...want].every((t) => TIERS.includes(t))) fail('tier', `tiers: some of ${TIERS.join(', ')}`);
    const picks = (store, now) => { const t = want && store.tiers(now); return (m) => !want || want.has(t.get(m.from) ?? 'friend'); };
    const ready = () => this.#read(({ now, store, st }) => st.inbox.some(picks(store, now)) || st.events.some((e) => e.type === 'pairing_failed' || (paired && e.type === 'paired')));
    let offline = null;
    if (local) {
      for (const end = Date.now() + wait * 1000; Date.now() < end && !ready();) await sleep(250);
    } else {
      // With nothing in use anywhere, this agent's own relay: an operator with no contacts logs in by
      // `inbox` before uploading its licence (relay/site/pro.md step 2), and proves its work there.
      const inUse = this.#relaysInUse(), relays = inUse.length > 0 ? inUse : [this.relay];
      try {
        await this.#session(relays, wait > 0 ? { max: wait * 1000, until: ready } : {});
      } catch (e) { this.lastError = e; offline = e instanceof MsgError ? e.message : `connect: ${e.message}`; }
    }
    return this.#locked(({ now, store, st }) => {
      this.#sweepFiles(st, now);
      const pick = picks(store, now), messages = st.inbox.filter(pick);
      const out = { messages, events: st.events, dropped: st.dropped, ...(offline && { offline }) };
      st.inbox = st.inbox.filter((m) => !pick(m)); st.events = []; st.dropped = {};
      return out;
    });
  }

  peek() {
    return this.#read(({ now, store, st }) => { const t = store.tiers(now); return st.inbox.map((m) => ({ ...m, tier: t.get(m.from) ?? 'friend' })); });
  }

  take(pick) {
    if (typeof pick !== 'function') throw new TypeError('take: a function (message, tier) → boolean');
    return this.#locked(({ now, store, st }) => {
      const t = store.tiers(now), out = [], keep = [];
      for (const m of st.inbox) (pick(m, t.get(m.from) ?? 'friend') ? out : keep).push(m);
      st.inbox = keep;
      return out;
    });
  }

  setTier(who, tier) { return this.#locked(({ now, store }) => store.setTier(who, tier, now)); }

  // A contact's full bundle, from wherever it came (the UI reads its local agents' files): verified
  // here; → { did, tier }, or null when it is no contact's.
  observe(bundle) {
    return this.#locked(({ now, store }) => {
      let r;
      try { r = verify(bundle, now); } catch (e) { fail('bundle', `REJECT: ${e.message}`); }
      const c = store.lookup(r.chain[0]);
      if (!c || c.revoked || c.did !== r.chain[0]) return null;
      return { did: c.did, tier: store.observe(c.did, r, now) };
    });
  }

  async forget(did) {
    const c = this.#locked(({ store, st }) => {
      const c = store.revoke(did);
      delete st.peers[c.did];
      st.pending = st.pending.filter((p) => p.peer !== c.did);
      this.#sweepSpool(st);
      return c;
    });
    this.#routes = new Map();
    // Revoked here whatever the relay says; offline: its mailboxes are given up at a later round.
    let offline = null;
    try { await this.#session([c.relay]); } catch (e) { this.lastError = e; offline = e instanceof MsgError ? e.message : `connect: ${e.message}`; }
    const released = this.#read(({ st }) => !Object.values(st.relays[c.relay]?.claims ?? {}).some((x) => x.peer === c.did));
    return { name: c.name, did: c.did, revoked: true, released, ...(offline && { offline }) };
  }

  // ---- staying connected

  async start() {
    if (this.#started) return;
    this.#started = true;
    for (const r of this.#relaysInUse()) this.#retry(r, 0);
    this.#tick = setInterval(() => this.#round(), this.tick);
    this.#tick.unref?.();
  }

  #round() {
    this.#later(() => this.#locked((ctx) => this.#expireKeys(ctx)));
    for (const l of this.#links.values()) l.absent.clear();   // an absent contact may be back: try once more
    for (const r of this.#relaysInUse()) {
      if (this.#links.get(r)?.up) this.#refreshSoon(r);
      else if (!this.#timers.has(r) && !this.#connecting.has(r)) this.#retry(r, 0);
    }
  }

  /** One round now (claims for a new week, queued messages), then wait as `inbox` does. */
  async sync({ wait = 0 } = {}) {
    if (this.#started) { this.#round(); await this.#idle({ max: Math.max(DRAIN, wait * 1000) }); return; }
    await this.#session(this.#relaysInUse(), { max: Math.max(DRAIN, wait * 1000) });
  }

  async stop() {
    this.#started = false;
    clearInterval(this.#tick);
    for (const t of this.#timers.values()) clearTimeout(t);
    this.#timers.clear();
    await this.#drain();
    for (const link of [...this.#links.values()]) await this.#hangUp(link);
  }
}
