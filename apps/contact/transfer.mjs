// SPDX-License-Identifier: MIT
// Big files agent to agent (design/transfer.md, apps/agent/TRANSFER.md): the pure part, no I/O.
// The relay carries only the introduction, four small messages labelled TRANSFER_LABEL inside the
// pairing's end-to-end envelopes; the bytes go over a direct WebRTC data channel (sigelo-transfer,
// werift) or a one-shot Tor onion stream, both driven by transfer-node.mjs. Here: the messages and
// their checks, the frames on the channel, the chunk bitmap, the two ends of the chunk protocol
// over an abstract channel, and the order the paths are tried in.
//
// The messages (content of a TRANSFER_LABEL message; id: 32 hex digits, one per file offered):
//   manifest  sender → receiver   {typ, id, name, size, sha256 (the file), chunk, chunks, list (SHA-256 of the chunk hashes), exp}
//   offer     receiver → sender   {typ, id, attempt, sdp (null: no direct path from this side), tor: {serve, connect}, via?: "tor"}
//   answer    sender → receiver   {typ, id, attempt, sdp, tor}
//   onion     the side that serves {typ, id, attempt, onion (56 base32), port, auth (x25519 client key, base64, or null), token (64 hex)}
//   end       either side          {typ, id, reason, attempt?}   reason one of REASONS
// The receiver offers because it pulls. Offer and answer ride signed envelopes naming id and attempt,
// so the two identities authenticate the DTLS fingerprints and the onion address: the relay cannot sit
// in the middle. Data channel label: `sigelo-transfer/0 <id> <attempt>`; any other is closed.
//
// The frames (binary, at most FRAME bytes each; on a Tor stream each behind a u32 BE length):
//   LIST   sender    [1][u32 first index][32-byte chunk hashes…]   checked whole against the manifest's list
//   WANT   receiver  [2][u32 from][u16 n]                          at most OUTSTANDING chunks asked and not yet written
//   DATA   sender    [3][u32 index][u32 offset][bytes]             a chunk in frames of DATA_MAX (17 for 1 MiB)
//   END    either    [4][u8 reason]                                done once the receiver read the file back
//   TOKEN  connector [5][32 bytes]                                 the first frame on a Tor stream, else it is closed
// Back-pressure: the receiver asks again only after writing to disk; the sender stops above HIGH
// buffered and goes on below LOW. A chunk whose SHA-256 is not the list's is asked once more, then
// the transfer ends chunk_hash. Nothing is written before the receiver's operator said yes.
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { fail } from './kdf.mjs';

export const TRANSFER_LABEL = 'sigelo-transfer/0';
export const CHUNK = 1 << 20, MAX_SIZE = 16 * 2 ** 30, MAX_CHUNKS = MAX_SIZE / CHUNK;
export const FRAME = 65536, DATA_HEAD = 9, DATA_MAX = FRAME - DATA_HEAD, HASHES_PER_FRAME = Math.floor((FRAME - 5) / 32);
export const OUTSTANDING = 8, HIGH = 4 * CHUNK, LOW = CHUNK, RETRIES = 1;
// Timings (design §3): a manifest lives 7 days; candidates gathered 3 s; an offer waits 10 minutes
// for its answer, then ICE has 30 s.
export const DAY = 86400, MANIFEST_TTL = 7 * DAY, GATHER_MS = 3000, ANSWER_WAIT = 600, ICE_MS = 30_000;
// Manifests waiting for a yes: so many per contact and in all; more get `end busy`.
export const WAIT_CONTACT = 8, WAIT_ALL = 64;
// The accept rule's default (design §10.2, decided 2026-11-13): files up to 25 MB land without a question
// from own agents and contacts and from friends whose words were compared.
export const AUTO_MB = 25;
export const REASONS = ['done', 'declined', 'cancelled', 'no_path', 'try_tor', 'chunk_hash', 'file_changed', 'busy'];
export const TYPS = ['manifest', 'offer', 'answer', 'onion', 'end'];
export const T = { LIST: 1, WANT: 2, DATA: 3, END: 4, TOKEN: 5 };
export const NAME_MAX_IN = 1024, SDP_MAX = 16384, ATTEMPT_MAX = 1000;

const ID = /^[0-9a-f]{32}$/, HEX64 = /^[0-9a-f]{64}$/, ONION = /^[a-z2-7]{56}$/, B64KEY = /^[A-Za-z0-9+/]{43}=$/;
const isObject = (x) => typeof x === 'object' && x !== null && !Array.isArray(x);
const int = (n, lo, hi) => Number.isSafeInteger(n) && n >= lo && n <= hi;
const hex = (b) => bytesToHex(b);
/** A transfer id: 16 random bytes as hex. */
export const newId = (rng = randomBytes) => hex(rng(16));
/** How many chunks a file of n bytes goes in. */
export const chunksOf = (n) => Math.ceil(n / CHUNK);
/** The length of chunk i of a file of size bytes. */
export const chunkLength = (size, i) => Math.min(CHUNK, size - i * CHUNK);
/** The manifest's list: SHA-256 over the chunk hashes, in order (hashes: 32 bytes each, concatenated). */
export const listOf = (hashes, h = sha256) => hex(h(hashes));
export const sha256Hex = (b) => hex(sha256(b));

// ---------------------------------------------------------------- the messages

/** A manifest for a file whose chunk hashes are known. → the message content. */
export function manifest({ id = newId(), name, size, sha256: whole, hashes, now, h = sha256 }) {
  if (!int(size, 0, MAX_SIZE)) fail('transfer_too_large', `${size} bytes: at most ${MAX_SIZE} (16 GiB) a file`);
  if (hashes.length !== chunksOf(size) * 32) throw new TypeError('hashes: 32 bytes per chunk');
  return { typ: 'manifest', id, name, size, sha256: whole, chunk: CHUNK, chunks: chunksOf(size), list: listOf(hashes, h), exp: now + MANIFEST_TTL };
}

const SHAPES = {
  manifest: ['name', 'size', 'sha256', 'chunk', 'chunks', 'list', 'exp'],
  offer: ['attempt', 'sdp', 'tor'],
  answer: ['attempt', 'sdp', 'tor'],
  onion: ['attempt', 'onion', 'port', 'auth', 'token'],
  end: ['reason'],
};
const MAY = { offer: ['via'], end: ['attempt'] };
/** A TRANSFER_LABEL message's content, checked for shape (transfer_message, transfer_too_large). → it. */
export function checkMessage(x) {
  const bad = (why) => fail('transfer_message', `not a ${TRANSFER_LABEL} message: ${why}`);
  if (!isObject(x) || !TYPS.includes(x.typ)) bad('typ');
  if (typeof x.id !== 'string' || !ID.test(x.id)) bad('id: 32 lowercase hex digits');
  const need = SHAPES[x.typ], may = MAY[x.typ] ?? [];
  for (const k of need) if (!Object.hasOwn(x, k)) bad(`${x.typ} needs ${k}`);
  for (const k of Object.keys(x)) if (k !== 'typ' && k !== 'id' && !need.includes(k) && !may.includes(k)) bad(`${x.typ} has no ${k}`);
  if (Object.hasOwn(x, 'attempt') && !int(x.attempt, 1, ATTEMPT_MAX)) bad(`attempt: 1 to ${ATTEMPT_MAX}`);
  switch (x.typ) {
    case 'manifest':
      if (typeof x.name !== 'string' || x.name.length === 0 || x.name.length > NAME_MAX_IN) bad(`name: 1 to ${NAME_MAX_IN} characters`);
      if (!int(x.size, 0, Number.MAX_SAFE_INTEGER)) bad('size: whole bytes');
      if (x.size > MAX_SIZE) fail('transfer_too_large', `the manifest says ${x.size} bytes, at most ${MAX_SIZE} (16 GiB) a file`);
      if (typeof x.sha256 !== 'string' || !HEX64.test(x.sha256) || typeof x.list !== 'string' || !HEX64.test(x.list)) bad('sha256 and list: 64 lowercase hex digits');
      if (x.chunk !== CHUNK) bad(`chunk: ${CHUNK}`);
      if (x.chunks !== chunksOf(x.size)) bad(`chunks: ${x.size} bytes go in ${chunksOf(x.size)}`);
      if (!int(x.exp, 0, Number.MAX_SAFE_INTEGER)) bad('exp: unix seconds');
      break;
    case 'offer': case 'answer':
      if (x.sdp !== null && (typeof x.sdp !== 'string' || x.sdp.length === 0 || x.sdp.length > SDP_MAX)) bad(`sdp: null or 1 to ${SDP_MAX} characters`);
      if (!isObject(x.tor) || Object.keys(x.tor).length !== 2 || typeof x.tor.serve !== 'boolean' || typeof x.tor.connect !== 'boolean') bad('tor: {serve, connect}, both true or false');
      if (Object.hasOwn(x, 'via') && x.via !== 'tor') bad('via: "tor"');
      break;
    case 'onion':
      if (typeof x.onion !== 'string' || !ONION.test(x.onion)) bad('onion: 56 base32 characters, no .onion');
      if (!int(x.port, 1, 65535)) bad('port: 1 to 65535');
      if (x.auth !== null && (typeof x.auth !== 'string' || !B64KEY.test(x.auth))) bad('auth: null or a base64 x25519 key');
      if (typeof x.token !== 'string' || !HEX64.test(x.token)) bad('token: 64 lowercase hex digits');
      break;
    case 'end':
      if (!REASONS.includes(x.reason)) bad(`reason: ${REASONS.join(', ')}`);
      break;
  }
  return x;
}

/** The data channel's label for an attempt. */
export const channelLabel = (id, attempt) => `${TRANSFER_LABEL} ${id} ${attempt}`;

// ---------------------------------------------------------------- the frames

const u32 = (b, o) => ((b[o] << 24) >>> 0) + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3];
const put32 = (b, o, n) => { b[o] = n >>> 24; b[o + 1] = (n >>> 16) & 255; b[o + 2] = (n >>> 8) & 255; b[o + 3] = n & 255; };
export const frames = {
  list(first, hashes) { const f = new Uint8Array(5 + hashes.length); f[0] = T.LIST; put32(f, 1, first); f.set(hashes, 5); return f; },
  want(from, n) { const f = new Uint8Array(7); f[0] = T.WANT; put32(f, 1, from); f[5] = n >>> 8; f[6] = n & 255; return f; },
  data(index, offset, bytes) { const f = new Uint8Array(DATA_HEAD + bytes.length); f[0] = T.DATA; put32(f, 1, index); put32(f, 5, offset); f.set(bytes, DATA_HEAD); return f; },
  end(reason) { const f = new Uint8Array(2); f[0] = T.END; f[1] = Math.max(0, REASONS.indexOf(reason)); return f; },
  token(t) { const f = new Uint8Array(33); f[0] = T.TOKEN; f.set(t, 1); return f; },
};
/** A frame as received, checked for shape (transfer_frame). → { type, … }. */
export function readFrame(f) {
  const bad = (why) => fail('transfer_frame', why);
  if (!(f instanceof Uint8Array) || f.length < 2 || f.length > FRAME) bad('a frame is 2 to 65,536 bytes');
  switch (f[0]) {
    case T.LIST:
      if (f.length < 5 + 32 || (f.length - 5) % 32 !== 0) bad('LIST: a first index and whole hashes');
      return { type: T.LIST, first: u32(f, 1), hashes: f.subarray(5) };
    case T.WANT:
      if (f.length !== 7) bad('WANT: 7 bytes');
      return { type: T.WANT, from: u32(f, 1), n: (f[5] << 8) + f[6] };
    case T.DATA:
      if (f.length <= DATA_HEAD) bad('DATA: a header and bytes');
      return { type: T.DATA, index: u32(f, 1), offset: u32(f, 5), bytes: f.subarray(DATA_HEAD) };
    case T.END:
      if (f.length !== 2 || f[1] >= REASONS.length) bad('END: a reason');
      return { type: T.END, reason: REASONS[f[1]] };
    case T.TOKEN:
      if (f.length !== 33) bad('TOKEN: 32 bytes');
      return { type: T.TOKEN, token: f.subarray(1) };
    default: return bad(`frame type ${f[0]}`);
  }
}
/** Length-prefixed frames on a byte stream (Tor): push(bytes) → the whole frames received so far. */
export function deframer(max = FRAME) {
  let buf = new Uint8Array(0);
  return (bytes) => {
    buf = buf.length ? concatBytes(buf, bytes) : bytes;
    const out = [];
    while (buf.length >= 4) {
      const n = u32(buf, 0);
      if (n < 2 || n > max) fail('transfer_frame', `a stream frame of ${n} bytes`);
      if (buf.length < 4 + n) break;
      out.push(buf.slice(4, 4 + n));
      buf = buf.subarray(4 + n);
    }
    return out;
  };
}
/** A frame for a byte stream: its u32 BE length, then the frame. */
export const enframe = (f) => { const b = new Uint8Array(4 + f.length); put32(b, 0, f.length); b.set(f, 4); return b; };

// ---------------------------------------------------------------- the chunk bitmap (<id>.have)

export class Have {
  constructor(chunks, bytes) {
    this.chunks = chunks;
    this.bits = bytes ? Uint8Array.from(bytes) : new Uint8Array(Math.ceil(chunks / 8));
    if (this.bits.length !== Math.ceil(chunks / 8)) fail('transfer_have', `a bitmap of ${this.bits.length} bytes for ${chunks} chunks`);
  }
  has(i) { return (this.bits[i >> 3] & (1 << (i & 7))) !== 0; }
  set(i) { this.bits[i >> 3] |= 1 << (i & 7); }
  count() { let n = 0; for (let i = 0; i < this.chunks; i++) if (this.has(i)) n++; return n; }
  done() { return this.count() === this.chunks; }
  /** Bytes held, of a file of size bytes. */
  bytes(size) { let n = 0; for (let i = 0; i < this.chunks; i++) if (this.has(i)) n += chunkLength(size, i); return n; }
}

// ---------------------------------------------------------------- the two ends
//
// channel: { send(frame), buffered() → bytes not yet on the wire, close(), on(event, fn) } with the
// events 'frame' (a Uint8Array), 'low' (buffered fell below LOW) and 'close'. Both ends end once:
// onEnd(reason, { remote }) — remote: the other side said it.

/** The sender's end: the list first, then the chunks the receiver asks for, read in place (read(i) → bytes). */
export class Serve {
  constructor({ m, hashes, read, channel, onEnd, onProgress = () => {} }) {
    Object.assign(this, { m, hashes, read, ch: channel, onEnd, onProgress });
    this.queue = []; this.busy = false; this.ended = false; this.sent = 0;
    channel.on('frame', (f) => this.#frame(f));
    channel.on('low', () => this.#pump());
    channel.on('close', () => this.#end('cancelled', true, true));
  }
  start() {
    for (let i = 0; i < this.m.chunks; i += HASHES_PER_FRAME) this.#send(frames.list(i, this.hashes.subarray(i * 32, Math.min(this.m.chunks, i + HASHES_PER_FRAME) * 32)));
  }
  #frame(f) {
    if (this.ended) return;
    let x;
    try { x = readFrame(f); } catch { return this.#end('cancelled'); }
    if (x.type === T.END) return this.#end(x.reason, true);
    if (x.type !== T.WANT || x.n < 1 || x.n > OUTSTANDING || x.from + x.n > this.m.chunks || this.queue.length + x.n > 4 * OUTSTANDING) return this.#end('cancelled');
    for (let i = x.from; i < x.from + x.n; i++) this.queue.push(i);
    void this.#pump();
  }
  async #pump() {
    if (this.busy || this.ended) return;
    this.busy = true;
    try {
      while (!this.ended && this.queue.length && this.ch.buffered() < HIGH) {
        const i = this.queue.shift();
        let bytes;
        try { bytes = await this.read(i); } catch (e) { this.#end(e?.check === 'file_changed' ? 'file_changed' : 'cancelled'); return; }
        if (this.ended) return;
        for (let o = 0; o < bytes.length; o += DATA_MAX) if (!this.#send(frames.data(i, o, bytes.subarray(o, o + DATA_MAX)))) return;
        this.sent += bytes.length;
        this.onProgress(this.sent);
      }
    } finally { this.busy = false; }
  }
  // A channel that went away while sending: the end, as if it had closed.
  #send(f) { try { this.ch.send(f); return true; } catch { this.#end('cancelled', true, true); return false; } }
  /** Stop: the other side is told reason (unless it said it, or the channel went). */
  #end(reason, remote = false, gone = false) {
    if (this.ended) return;
    this.ended = true;
    if (!remote && !gone) { try { this.ch.send(frames.end(reason)); } catch {} }
    this.onEnd(reason, { remote: remote && !gone, gone });
  }
  stop(reason = 'cancelled') { this.#end(reason); }
}

/**
 * The receiver's end: checks the list, asks for what `have` lacks, at most OUTSTANDING chunks asked
 * and not yet written, checks each chunk's SHA-256 and writes it (write(i, bytes); flush() before the
 * bits are set: a bit means checked and on disk). A bad chunk is asked once more, then chunk_hash.
 * When every bit is set, onEnd('complete'): the caller reads the file back, then finish('done') or
 * finish('chunk_hash'). hashes: the list from an earlier attempt (a resume), else it comes first.
 */
export class Pull {
  constructor({ m, have, hashes = null, write, flush, channel, onEnd, onProgress = () => {}, onList = () => {}, h = sha256, flushEach = OUTSTANDING }) {
    Object.assign(this, { m, have, write, flush, ch: channel, onEnd, onProgress, onList, h, flushEach: Math.max(1, Math.min(OUTSTANDING, flushEach)) });
    this.hashes = hashes ?? (m.chunks === 0 ? new Uint8Array(0) : null);
    this.listGot = 0; this.listBuf = this.hashes ? null : new Uint8Array(m.chunks * 32);
    this.out = new Map(); this.writingSet = new Set(); this.unflushed = []; this.again = []; this.next = 0;
    this.tries = new Map(); this.ended = false; this.writing = Promise.resolve();
    channel.on('frame', (f) => this.#frame(f));
    channel.on('close', () => this.#end('cancelled', true, true));
  }
  start() {
    if (this.m.chunks === 0 && listOf(new Uint8Array(0), this.h) !== this.m.list) return this.#end('chunk_hash');
    if (this.hashes) this.#ask();
  }
  #frame(f) {
    if (this.ended) return;
    let x;
    try { x = readFrame(f); } catch { return this.#end('cancelled'); }
    if (x.type === T.END) return this.#end(x.reason, true);
    if (x.type === T.LIST) return this.#list(x);
    if (x.type !== T.DATA || !this.hashes) return this.#end('cancelled');
    const p = this.out.get(x.index);
    if (!p || x.offset !== p.got || p.got + x.bytes.length > p.len) return this.#end('cancelled');
    p.buf.set(x.bytes, p.got);
    p.got += x.bytes.length;
    if (p.got === p.len) this.#chunk(x.index, p.buf);
  }
  #list(x) {
    if (this.listBuf === null) return;   // known already (a resume): the sender sends it again
    const n = x.hashes.length / 32;
    if (x.first !== this.listGot || x.first + n > this.m.chunks) return this.#end('cancelled');
    this.listBuf.set(x.hashes, x.first * 32);
    this.listGot += n;
    if (this.listGot < this.m.chunks) return;
    if (listOf(this.listBuf, this.h) !== this.m.list) return this.#end('chunk_hash');
    this.hashes = this.listBuf; this.listBuf = null;
    this.onList(this.hashes);
    this.#ask();
  }
  #chunk(i, buf) {
    this.out.delete(i);
    if (!same(this.h(buf), this.hashes.subarray(i * 32, i * 32 + 32))) {
      const t = (this.tries.get(i) ?? 0) + 1;
      this.tries.set(i, t);
      if (t > RETRIES) return this.#end('chunk_hash');
      this.again.push(i);
      return this.#ask();
    }
    // Written in order of arrival; its slot is free once it is on disk (the back-pressure).
    this.writingSet.add(i);
    this.writing = this.writing.then(async () => {
      if (this.ended) return;
      await this.write(i, buf);
      this.writingSet.delete(i);
      this.unflushed.push(i);
      this.onProgress(buf.length);
      if (this.unflushed.length >= this.flushEach || (this.out.size === 0 && this.writingSet.size === 0)) await this.#flush();
      this.#ask();
    }).catch((e) => { this.error = e; this.#end('cancelled'); });
  }
  async #flush() {
    if (!this.unflushed.length) return;
    const now = this.unflushed.splice(0);
    await this.flush();
    for (const i of now) this.have.set(i);
  }
  #ask() {
    if (this.ended || !this.hashes) return;
    const wanted = [], busy = () => this.out.size + this.writingSet.size + wanted.length;
    while (this.again.length && busy() < OUTSTANDING) wanted.push(this.again.shift());
    while (this.next < this.m.chunks && busy() < OUTSTANDING) {
      const i = this.next++;
      if (!this.have.has(i)) wanted.push(i);
    }
    // Runs of consecutive chunks, one WANT each.
    wanted.sort((a, b) => a - b);
    for (let k = 0; k < wanted.length;) {
      let n = 1;
      while (k + n < wanted.length && wanted[k + n] === wanted[k] + n) n++;
      for (let j = 0; j < n; j++) { const len = chunkLength(this.m.size, wanted[k + j]); this.out.set(wanted[k + j], { len, got: 0, buf: new Uint8Array(len) }); }
      try { this.ch.send(frames.want(wanted[k], n)); } catch { return this.#end('cancelled', true, true); }
      k += n;
    }
    if (busy() === 0 && this.next >= this.m.chunks && this.again.length === 0) {
      this.writing = this.writing.then(() => this.#flush()).then(() => {
        if (!this.ended && this.have.done()) { this.ended = true; this.onEnd('complete', { remote: false }); }
      });
    }
  }
  #end(reason, remote = false, gone = false) {
    if (this.ended) return;
    this.ended = true;
    if (!remote && !gone) { try { this.ch.send(frames.end(reason)); } catch {} }
    // What was checked and written is kept (a resume asks only for the rest).
    void this.writing.then(() => this.#flush()).catch(() => {}).finally(() => this.onEnd(reason, { remote: remote && !gone, gone }));
  }
  /** After 'complete': the file read back; done or chunk_hash goes to the sender. */
  finish(reason) { try { this.ch.send(frames.end(reason)); } catch {} }
  stop(reason = 'cancelled') { this.#end(reason); }
}
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// ---------------------------------------------------------------- the paths

/**
 * The order the paths are tried in (design §2, §9): free, direct then Tor; Pro by its setting, fast
 * (direct, TURN, Tor) or private (Tor, direct, TURN). via tor: Tor only (the address stays hidden).
 * TURN is T4: until it exists it is left out. direct: allowed with this contact and possible here;
 * tor: both sides can (one serves, the other connects). → ['direct', 'tor'], …
 */
export function pathOrder({ pro = false, prefer = 'fast', via = 'auto', direct = true, tor = false, turn = false }) {
  if (via === 'tor') return tor ? ['tor'] : [];
  const order = pro && prefer === 'private' ? ['tor', 'direct', 'turn'] : pro ? ['direct', 'turn', 'tor'] : ['direct', 'tor'];
  return order.filter((p) => (p === 'direct' ? direct : p === 'tor' ? tor : turn && pro));
}
/**
 * The accept rule (design §10.2): → 'auto' (lands without a question) or 'ask'. trust: 'own' (own agents and
 * contacts), 'compared' (a friend whose four words were compared) or 'other' (not compared, a public-code
 * joiner, quiet: always asked); limitMb: the contact's own size (0: always ask), null for defaultMb; MB are
 * 10^6 bytes; direct: may this contact see the addresses already (else the human is asked first).
 */
export function acceptRule({ size, trust, limitMb = null, defaultMb = AUTO_MB, direct = true }) {
  if (trust !== 'own' && trust !== 'compared') return 'ask';
  const mb = limitMb ?? defaultMb;
  if (!(Number.isFinite(mb) && mb > 0) || !(size <= mb * 1e6)) return 'ask';
  return direct === true ? 'auto' : 'ask';
}
/** Who serves the onion: the sender if it can, else the receiver; null when no pair of the two works. */
export function torRoles(sender, receiver) {
  if (sender?.serve && receiver?.connect) return 'sender';
  if (receiver?.serve && sender?.connect) return 'receiver';
  return null;
}
/** The free refusal (design §5), for a contact's name. */
export const noPath = (name) => `No direct path to ${name} from these two networks, and no Tor. Up to 8 MiB: send-file. Tor on both sides, or Pro, carries larger files.`;

export { hexToBytes, bytesToHex };
