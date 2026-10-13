// SPDX-License-Identifier: MIT
// The contact store of sigelo-invite/0: one JSON file per identity. Contacts are keyed by the
// peer's ORIGINAL DID with every rotation seen, as accept/node/sigelo-pair.mjs keeps pairings, so
// a rotation keeps the contact and a recovery still beats a thief (SPEC §7.1).
//   { v, self, invites: { nonce: { secret, exp, name, peer, relay } },
//              accepts: { answer id: { secret, code_did, exp, name, relay, kem_sk, as } },
//              contacts: { original DID: { name, did, current_did, current_key, revoked, chain, rotations, relay, pair_key } } }
// invites: codes this owner handed out, keyed by inviteNonce(code bytes); peer: the original DID of
// the contact a re-key code is for, null on a new contact's code. accepts: codes this owner
// answered, keyed by answerId(answer). The file holds one-time secrets, Bob's one-time key and
// pairing keys, so it is written 0600. Two simultaneous writers still need the integrator's lock.
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { canonicalize, verify } from 'sigelo';
import { SKEW, TTL_MAX, V, attempt, checkTime, fail, hex, keyOf } from './invite.mjs';

export class Contacts {
  /** self: the owner's ORIGINAL DID. A store belongs to one identity; K is derived from it. */
  constructor(path, self) {
    if (typeof self !== 'string' || !self.startsWith('did:sigelo:z')) throw new TypeError('Contacts: self must be the owner\'s original DID');
    this.path = path; this.self = self; this.load();
  }

  // Every operation re-reads the file: another process (the owner's revoke) may have written it.
  // Not while writes are held (hold): the change in memory is the one to keep.
  load() {
    if (this.held) return this;
    this.s = existsSync(this.path) ? JSON.parse(readFileSync(this.path, 'utf8')) : { v: V, self: this.self, invites: {}, accepts: {}, contacts: {} };
    if (this.s.v !== V || this.s.self !== this.self) fail('store', `${this.path} is not the ${V} store of ${this.self}`);
    return this;
  }

  // A fresh temporary name each time, created exclusively: a leftover or planted "<path>.tmp" (a
  // wider mode, a symlink) is never written through. As adapters/moadim/sigelo-agent.ts save().
  save() {
    if (this.held) { this.dirty = true; return; }
    const tmp = join(dirname(this.path), `.${basename(this.path)}.${randomBytes(8).toString('hex')}.tmp`);
    writeFileSync(tmp, JSON.stringify(this.s, null, 2), { mode: 0o600, flag: 'wx' });
    renameSync(tmp, this.path);
  }

  // The carrier (carrier.mjs #onAnswer, #onReply) saves its own state file first and this file
  // after it: two renames are never one step, and in this order a crash or a full disk between
  // them leaves the code or answer unspent here, so the relay's next delivery of the message runs
  // the handshake again. Saved first, this file kept a contact the state had no session or reply
  // for, and the delivery, its code spent, was then dropped: a pairing half made, for good. While
  // held, save() only marks the change and load() keeps what is in memory; the caller holds the
  // lock both files are written under, so nobody else writes meanwhile. commit() writes it.
  hold() { this.held = true; return this; }
  commit() {
    const dirty = this.dirty === true;
    this.held = false; this.dirty = false;
    if (dirty) this.save();
  }

  // Expired invites and answers go, with the one-time secret and kem_sk they hold, whenever an
  // entry is added or taken, as sigelo-pair's issue() drops expired challenges. Returns how many.
  #purge(now) {
    let n = 0;
    for (const k of ['invites', 'accepts']) for (const [nonce, p] of Object.entries(this.s[k])) if (p.exp <= now) { delete this.s[k][nonce]; n++; }
    return n;
  }

  // max: TTL_MAX for the owner's own codes. The code does not say when it was made, so on the
  // answering side a 7-day code read on a clock a little behind gets SKEW more.
  #add(kind, nonce, entry, now, max) {
    checkTime(now);
    if (entry.name !== null && typeof entry.name !== 'string') fail('name', 'a string, or null for a known contact only');
    if (!Number.isSafeInteger(entry.exp) || entry.exp <= now || entry.exp - now > max) fail('ttl', `the code must expire within ${max} seconds`);
    this.load(); this.#purge(now);
    this.s[kind][nonce] = entry; this.save();
    return nonce;
  }

  /**
   * Alice, after makeInvite. name: the new contact's name, and peer null. A re-key code has name
   * null and peer = a DID of the known contact it is for: an answer from anyone else fails
   * challenge_did, as sigelo-pair pins its challenge to one DID.
   */
  addInvite(code, name, now, peer = null) {
    let pin = null;
    if (name === null) {
      const c = this.lookup(peer) ?? fail('not_contact', `a re-key code names the contact it is for; ${JSON.stringify(peer)} is not one`);
      if (c.revoked) fail('revoked', `${c.did} was revoked by this owner`);
      pin = c.did;
    } else if (peer !== null) fail('name', 'a new contact\'s code is for whoever holds it: no peer');
    return this.#add('invites', code.nonce, { secret: hex(code.secret), exp: code.exp, name, peer: pin, relay: code.relay }, now, TTL_MAX);
  }

  /**
   * Bob, after buildAnswer: code = parseInvite(...), id = answerId(answer), name as in addInvite
   * (null: the code's DID must be a known contact; admit checks). kem_sk: the one-time secret key
   * behind his kem_pk, opaque here (M2), handed back to agree() when the reply comes. It lives
   * exactly as long as the pending answer: first reply, revoke, or expiry (at the next add or take).
   * as: the current DID his answer's chain ends at, which the inviter files him under; he may
   * rotate before the reply comes, and must then tell her (the carrier's rotation notice).
   */
  addAccept(code, id, name, now, kem_sk = null, as = null) {
    return this.#add('accepts', id, { secret: hex(code.secret), code_did: code.did, exp: code.exp, name, relay: code.relay, kem_sk, as }, now, TTL_MAX + SKEW);
  }

  /** Single use: the entry is deleted, and the file saved, before any check runs on the message naming it. */
  take(kind, nonce, now) {
    checkTime(now);
    this.load();
    const p = typeof nonce === 'string' && Object.hasOwn(this.s[kind], nonce) ? { ...this.s[kind][nonce], nonce } : null;
    if (p) delete this.s[kind][nonce];
    if (this.#purge(now) || p) this.save();
    return p;
  }

  /** The owner withdraws a code not yet answered (nonce = code.nonce). */
  cancelInvite(nonce) {
    if (typeof nonce !== 'string' || !Object.hasOwn(this.load().s.invites, nonce)) fail('challenge_unknown', 'no pending invite with this nonce');
    delete this.s.invites[nonce]; this.save();
  }

  // Every contact whose chain shares a DID with `chain`. admit lets at most one exist.
  #holders(chain) { return Object.values(this.load().s.contacts).filter((c) => c.chain.some((d) => chain.includes(d))); }

  /** The contact whose chain holds did. Two would be a file written by something else: refused, not a guess. */
  lookup(did) {
    const found = this.#holders([did]);
    if (found.length > 1) fail('original_did', `${found.length} contacts hold ${did}: ${found.map((c) => c.did).join(', ')}`);
    return found[0] ?? null;
  }

  /** Local and final for this store: the pairing key goes, and pending codes to or from the contact die with it. */
  revoke(did) {
    const c = this.lookup(did) ?? fail('not_contact', `${did} is not a contact`);
    c.revoked = true; c.pair_key = null;
    for (const [n, p] of Object.entries(this.s.accepts)) if (c.chain.includes(p.code_did)) delete this.s.accepts[n];
    for (const [n, p] of Object.entries(this.s.invites)) if (p.peer === c.did) delete this.s.invites[n];
    this.save(); return c;
  }

  /**
   * sigelo-pair's last checks, in its order and under its names: revoked, not_contact, then every
   * rotation this store has seen is merged in and §7.3 picks again (bundle, stale_chain): a peer
   * cannot hide a rotation, so a recovery seen once keeps beating the thief. Then original_did
   * (own), and revoked once more, just before writing. r: verify(bundle) already checked by the caller.
   *
   * The old record is found through ANY DID the chains share, not by r.chain[0] alone: whoever
   * holds a key in a chain can put a throwaway genesis in front of it (a voluntary rotation from
   * the throwaway into the real genesis, carrying its recovery commitment, which is public).
   * Looked up by the first DID, that prefix would dodge the revocation and the merge. A peer keeps
   * one original DID per store, so a chain that reaches a contact from another start is refused.
   */
  admit(bundle, r, name, fields, now) {
    const held = this.#holders(r.chain), gone = held.find((c) => c.revoked);
    if (gone) fail('revoked', `${gone.did} was revoked by this owner`);
    if (held.length > 1) fail('original_did', `the chain runs through ${held.length} contacts: ${held.map((c) => c.did).join(', ')}`);
    const old = held[0];
    if (!old && name === null) fail('not_contact', `${r.chain[0]} is not a contact; this code was for a known contact only`);
    let rotations = bundle.rotations;
    if (old) {
      const claimed = r.did, seen = new Set(rotations.map(canonicalize));
      rotations = [...rotations, ...old.rotations.filter((x) => !seen.has(canonicalize(x)))];
      r = attempt('bundle', () => verify({ ...bundle, rotations }, now));
      if (r.did !== claimed) fail('stale_chain', `the rotations already seen resolve to ${r.did}, not ${claimed}`);
      if (r.chain[0] !== old.did) fail('original_did', `the chain starts at ${r.chain[0]}; this store knows the peer from ${old.did}`);
    }
    const heldNow = this.#holders(r.chain);
    if (heldNow.some((c) => c.revoked)) fail('revoked', `${r.chain[0]} was revoked during this pairing`);
    if (heldNow.some((c) => c.did !== old?.did)) fail('original_did', `another contact took ${r.chain[0]}'s chain during this pairing`);
    const c = { name: old?.name ?? name, did: r.chain[0], current_did: r.did, current_key: keyOf(bundle, rotations, r.did), revoked: false, chain: r.chain, rotations, ...fields };
    this.s.contacts[c.did] = c; this.save();
    return { did: c.did, current_did: c.current_did, current_key: c.current_key, attestations: r.attestations, rejected: r.rejected, rekeyed: Boolean(old) };
  }
}
