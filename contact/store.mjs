// SPDX-License-Identifier: MIT
// The contact store of sigelo-invite/0: one JSON file per identity. Contacts are keyed by the
// peer's ORIGINAL DID with every rotation seen, as accept/node/sigelo-pair.mjs keeps pairings, so
// a rotation keeps the contact and a recovery still beats a thief (SPEC §7.1).
//   { v, self, invites: { nonce: { secret, exp, name, peer, relay } },
//              accepts: { answer id: { secret, code_did, exp, name, relay, kem_sk, as, named?, tier? } },
//              contacts: { original DID: { name, did, current_did, current_key, revoked, chain, rotations, relay, pair_key, re_pair?,
//                                          tier, tier_by, operator_exp?, link? } },
//              preset?: { original DID: tier } }
// invites: codes this owner handed out, keyed by inviteNonce(code bytes); peer: the original DID of
// the contact a re-key code is for, null on a new contact's code. accepts: codes this owner
// answered, keyed by answerId(answer). re_pair: "own_recovery" or "contact_recovery" once a recovery
// burned pair_key (carrier.mjs, "After a recovery"); a new pairing writes the record without it.
// Tiers (TIERS): tier, what the owner's tools do with the contact's messages: "own" (the owner's
// own agents: pushed in full), "friend" (a notice, the content pulled), "quiet" (nothing, pulled).
// tier_by "owner": chosen (setTier, accept --tier) and kept; "auto": computed, as tierOf does, on
// every write. Own is automatic while the contact carries an unexpired operator attestation
// (OPERATOR_CTX) from a DID of `mine` (this identity's chain, or an operator attesting this
// identity: operator_exp, from observe), or is one of those operators, or another writer set tier
// "own" without tier_by. Else friend. The attestation is the mark of an own agent (an enrolled
// worker included, enrol.mjs): no flag beside it. A re-pair,
// a merge and a rename keep all of it. Ours (oursOf) is that mark alone, whatever the tier: an own
// agent the owner set to friend or quiet is ours and low trust. preset: the owner's tier for a DID
// not yet a contact (an agent enrolled before it pairs), filed by the admit that makes it one.
// link (link.mjs, sigelo-link/1): {id, purpose, linked_by, expires, tier, prior?}, the operator's
// introduction this contact came with (prior: {tier, tier_by}, the pairing was there before: an end
// restores them instead of forgetting). Kept by a re-pair, a merge and a rename; gone with revoke. A
// link never writes operator_exp, so never ours; while it lasts a contact that is not ours cannot be
// set own (link_tier).
// The file holds one-time secrets, Bob's one-time key and
// pairing keys, so it is written 0600. Two simultaneous writers still need the integrator's lock.
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { files as nodeFiles } from './platform-node.mjs';
import { canonicalize, verify } from 'sigelo';
import { SKEW, TTL_MAX, V, attempt, checkTime, fail, hex, keyOf } from './invite.mjs';

export const TIERS = ['own', 'friend', 'quiet'];
// UTF-8 as readFileSync(…, 'utf8') reads it: a byte order mark is kept (JSON.parse refuses it).
const UTF8 = new TextDecoder('utf-8', { ignoreBOM: true });
export const OPERATOR_CTX = 'sigelo-relay/operator';
// The longest name rename() gives a contact, in characters.
export const NAME_MAX = 64;
// What a record keeps of its tier through admit (a re-pair, a merged notice).
const TIER_KEYS = ['tier', 'tier_by', 'operator_exp', 'link'];

export class Contacts {
  /**
   * self: the owner's ORIGINAL DID. A store belongs to one identity; K is derived from it.
   * mine: () → { chain, operators }: this identity's DIDs and those of the operators attesting it
   * (the carrier's, from its bundle), for tiers; without it nobody is own by attestation.
   */
  // files: the platform's (platform-node.mjs files, by default): the file is read and written by name.
  constructor(path, self, { mine, files = nodeFiles } = {}) {
    if (typeof self !== 'string' || !self.startsWith('did:sigelo:z')) throw new TypeError('Contacts: self must be the owner\'s original DID');
    this.path = path; this.self = self; this.mine = mine ?? null; this.files = files; this.load();
  }

  // ---- tiers (the header)

  #auto(c, now) {
    if ((c.operator_exp ?? 0) > now) return 'own';
    const ops = this.mine?.().operators ?? [];
    return c.chain.some((d) => ops.includes(d)) ? 'own' : 'friend';
  }

  /** The tier of record c now: the owner's choice, another writer's own, else computed. */
  tierOf(c, now) {
    if (c.tier_by === 'owner' && TIERS.includes(c.tier)) return c.tier;
    if (c.tier_by === undefined && c.tier === 'own') return 'own';
    return this.#auto(c, now);
  }

  // c.tier written for readers of the file (the UI's), unless chosen or set by another writer.
  #settle(c, now) {
    if ((c.tier_by === 'owner' && TIERS.includes(c.tier)) || (c.tier_by === undefined && c.tier === 'own')) return;
    c.tier = this.#auto(c, now); c.tier_by = 'auto';
  }

  /** Ours: marked by an operator attestation of mine (or one of my operators), the tier aside. */
  oursOf(c, now) { return this.#auto(c, now) === 'own'; }

  /** original DID → tier, every contact, one read. */
  tiers(now) {
    return new Map(Object.values(this.load().s.contacts).map((c) => [c.did, this.tierOf(c, now)]));
  }

  // A live contact by name or any DID of its chain, for the owner's verbs.
  #find(who) {
    if (typeof who !== 'string' || who === '') fail('not_contact', 'name a contact, by name or DID');
    this.load();
    let c = who.startsWith('did:') ? this.lookup(who) : null;
    if (!c) {
      const named = Object.values(this.s.contacts).filter((x) => !x.revoked && x.name === who);
      if (named.length > 1) fail('name', `${named.length} contacts are called ${JSON.stringify(who)}: use the DID`);
      c = named[0] ?? fail('not_contact', `${JSON.stringify(who)} is not a contact`);
    }
    if (c.revoked) fail('revoked', `${c.did} was revoked by this owner`);
    return c;
  }

  /** The owner's choice for a contact (a name or any DID of its chain): kept until changed. */
  setTier(who, tier, now) {
    if (!TIERS.includes(tier)) fail('tier', `a tier is ${TIERS.join(', ')}; not ${JSON.stringify(tier)}`);
    const c = this.#find(who);
    if (tier === 'own' && c.link && !this.oursOf(c, now)) fail('link_tier', `${c.name} came by link ${c.link.id} and is not yours by key: a link never makes a contact own (unlink it first)`);
    c.tier = tier; c.tier_by = 'owner';
    this.save();
    return { did: c.did, name: c.name, tier: this.tierOf(c, now), ours: this.oursOf(c, now) };
  }

  /**
   * The link record of a contact (who: a name or any DID of its chain), link.mjs's: an object
   * {id, purpose, linked_by, expires, tier, prior?}, or null to drop it (prior: its tier and tier_by
   * restored). Another link already there: link_exists. → the contact's { did, name, link }.
   */
  setLink(who, link, now) {
    const c = this.#find(who);
    if (link === null) {
      const p = c.link?.prior;
      if (p) { if (p.tier_by === undefined) { delete c.tier; delete c.tier_by; } else { c.tier = p.tier; c.tier_by = p.tier_by; } this.#settle(c, now); }
      delete c.link;
    } else {
      if (typeof link !== 'object' || typeof link.id !== 'string' || typeof link.linked_by !== 'string') fail('link_message', 'a link record is {id, purpose, linked_by, expires, tier}');
      if (c.link && (c.link.id !== link.id || c.link.linked_by !== link.linked_by)) fail('link_exists', `${c.name} is linked already (${c.link.id}: ${c.link.purpose})`);
      c.link = link;
    }
    this.save();
    return { did: c.did, name: c.name, link: c.link ?? null };
  }

  /**
   * The owner's tier for an original DID: set now on the contact holding it, else kept (preset)
   * for the admit that makes it a contact. → { did, tier, preset }.
   */
  presetTier(did, tier, now) {
    if (!TIERS.includes(tier)) fail('tier', `a tier is ${TIERS.join(', ')}; not ${JSON.stringify(tier)}`);
    if (typeof did !== 'string' || !did.startsWith('did:sigelo:z')) fail('not_contact', 'presetTier: an original DID');
    const c = this.load().lookup(did);
    if (c && !c.revoked) return { ...this.setTier(c.did, tier, now), preset: false };
    (this.s.preset ??= {})[did] = tier;
    this.save();
    return { did, tier, preset: true };
  }

  /**
   * The owner's name for a contact (who: a name or any DID of its chain): 1 to NAME_MAX characters,
   * trimmed, no control characters, and no other live contact's (name_taken: a name two contacts
   * share is refused by every verb that takes a name). Kept through a re-pair. → { did, name }.
   */
  rename(who, name) {
    if (typeof name !== 'string' || name.trim() === '' || [...name.trim()].length > NAME_MAX || /[\u0000-\u001f\u007f-\u009f]/.test(name)) {
      fail('name', `a name is 1 to ${NAME_MAX} characters, no control characters`);
    }
    const c = this.#find(who), to = name.trim();
    if (Object.values(this.s.contacts).some((x) => !x.revoked && x.did !== c.did && x.name === to)) fail('name_taken', `another contact is called ${JSON.stringify(to)}`);
    c.name = to;
    this.save();
    return { did: c.did, name: to };
  }

  // The last expiry of the operator attestations from a DID of mine() in r (verify's), or 0.
  #attested(r, now) {
    const m = this.mine?.(), by = new Set([...(m?.chain ?? []), ...(m?.operators ?? [])]);
    let exp = 0;
    for (const [iss, bodies] of Object.entries(r.attestations ?? {})) {
      if (by.has(iss)) for (const b of bodies) if (b.ctx === OPERATOR_CTX && b.exp > now && b.exp > exp) exp = b.exp;
    }
    return exp;
  }

  /**
   * The contact's bundle seen (r: verify of it, by the caller): its unexpired operator
   * attestations from a DID of mine() make it own until the last expires. → its tier.
   */
  observe(did, r, now) {
    const c = this.lookup(did) ?? fail('not_contact', `${did} is not a contact`);
    if (!r.chain.includes(c.did)) fail('original_did', `the bundle is not ${c.did}'s chain`);
    // Ending anywhere else, the chain may rotate into a third party's public genesis (a rotation is
    // signed by the key it leaves) and bring that party's attestations (THREAT-MODEL §2.12).
    if (r.did !== c.current_did) fail('current_did', `the bundle ends at ${r.did}; this store holds ${c.did} at ${c.current_did}`);
    const exp = this.#attested(r, now);
    if (exp > (c.operator_exp ?? 0)) { c.operator_exp = exp; this.#settle(c, now); this.save(); }
    return this.tierOf(c, now);
  }

  // Every operation re-reads the file: another process (the owner's revoke) may have written it.
  // Not while writes are held (hold): the change in memory is the one to keep.
  load() {
    if (this.held) return this;
    const raw = this.files.read(this.path);
    this.s = raw !== null ? JSON.parse(UTF8.decode(raw)) : { v: V, self: this.self, invites: {}, accepts: {}, contacts: {} };
    if (this.s.v !== V || this.s.self !== this.self) fail('store', `${this.path} is not the ${V} store of ${this.self}`);
    return this;
  }

  // A fresh temporary name each time, created exclusively: a leftover or planted "<path>.tmp" (a
  // wider mode, a symlink) is never written through. As adapters/moadim/sigelo-agent.ts save().
  save() {
    if (this.held) { this.dirty = true; return; }
    this.files.write(this.path, utf8ToBytes(JSON.stringify(this.s, null, 2)));
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
  // An expired answer is a pairing that never completed: kept, without its secrets, for lapsed().
  #purge(now) {
    let n = 0;
    for (const k of ['invites', 'accepts']) {
      for (const [nonce, p] of Object.entries(this.s[k])) {
        if (p.exp > now) continue;
        if (k === 'accepts') (this.gone ??= []).push({ id: nonce, code_did: p.code_did, name: p.name, exp: p.exp, relay: p.relay });
        delete this.s[k][nonce]; n++;
      }
    }
    return n;
  }

  /** The answers that expired unanswered, purged now or at an add or take since the last call: once each. */
  lapsed(now) {
    checkTime(now);
    this.load();
    if (this.#purge(now)) this.save();
    const g = this.gone ?? [];
    this.gone = [];
    return g;
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
   * named: he chose the name (accept --name), so a re-pair renames the known contact (the carrier).
   * tier: he chose the tier (accept --tier): the contact is filed with it (invite.mjs checkReply).
   */
  addAccept(code, id, name, now, kem_sk = null, as = null, named = false, tier = null) {
    if (tier !== null && !TIERS.includes(tier)) fail('tier', `a tier is ${TIERS.join(', ')}; not ${JSON.stringify(tier)}`);
    return this.#add('accepts', id, { secret: hex(code.secret), code_did: code.did, exp: code.exp, name, relay: code.relay, kem_sk, as, ...(named && { named: true }), ...(tier && { tier }) }, now, TTL_MAX + SKEW);
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
    c.revoked = true; c.pair_key = null; delete c.link;
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
    const kept = old ? Object.fromEntries(TIER_KEYS.filter((k) => Object.hasOwn(old, k)).map((k) => [k, old[k]])) : {};
    const pre = !old && TIERS.includes(this.s.preset?.[r.chain[0]]) ? { tier: this.s.preset[r.chain[0]], tier_by: 'owner' } : {};
    if (this.s.preset) delete this.s.preset[r.chain[0]];
    const c = { name: old?.name ?? name, did: r.chain[0], current_did: r.did, current_key: keyOf(bundle, rotations, r.did), revoked: false, chain: r.chain, rotations, ...kept, ...pre, ...fields };
    if (fields.tier !== undefined && !TIERS.includes(fields.tier)) fail('tier', `a tier is ${TIERS.join(', ')}`);
    this.s.contacts[c.did] = c;
    // Attestations the bundle carried (none at a pairing today: chains only), then the tier.
    const exp = this.#attested(r, now);
    if (exp > (c.operator_exp ?? 0)) c.operator_exp = exp;
    this.#settle(c, now);
    this.save();
    return { did: c.did, current_did: c.current_did, current_key: c.current_key, attestations: r.attestations, rejected: r.rejected, rekeyed: Boolean(old) };
  }
}
