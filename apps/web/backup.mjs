// SPDX-License-Identifier: MIT
// The backup file of a profile that holds its own identity (sigelo-backup/0; ROADMAP "encrypted backup and restore of
// contacts and chats"): the profile as this phone holds it, encrypted under the words password, so a restore on a new
// phone is the same device: the same keys, the same pairings, nothing paired again. The crypto is the words password's
// (apps/contact/words-lock.mjs lockBytes: PBKDF2-SHA256 with ITERATIONS rounds and a 16-byte salt, HKDF, AES-256-GCM),
// under its own label, the header bound as the AAD.
//
//   makeBackup(p, password, o)          → { bytes, name, did }   o: { profile: { id, name }, kept (words.mjs openKept's
//                                        check done by the caller), iterations, now }
//   readHeader(bytes)                   → the plaintext header; another version or kind refused backup_version
//   openBackup(bytes, password, gate)   → the contents; a wrong password: words_password after the gate's delay
//   restoreBackup(p, bytes, password, o) → { did, original, name, words }   o: { dids (the originals this phone holds:
//                                        one there refused backup_exists), gate, commit (after the checks, before the first
//                                        write: the shell's mode) }; the network held until it is all sealed
//   fileName(name, now)                 sigelo-<name>-<yyyy-mm-dd>.sbk
//
// The file: one JSON object. Header (plain, bound as AAD): { v: "sigelo-backup/0", did (current), created (ISO date),
// kdf: "PBKDF2-SHA256", iter }; then salt, iv, ct (base64). Inside ct, JSON: { v, profile: { name, original, words },
// identity (the identity file), keeper (K_j's file, or null), words (the kept words' blob, already under the words
// password, or null), files: { name: base64 } } with every file of the profile's storage (contacts with their pairing
// keys, the carrier's sessions, history, groups, links, pictures, the page's data and settings, the seat notes) but the
// sealed ones (re-sealed here under this phone's key) and the transfers in progress (their bytes are in the old phone's
// shell). Not in it: the relay's queue (it waits at the relay for whichever phone logs in), the lock's settings (the
// shell's), this phone's look. At the first start after a restore every session starts afresh (carrier.mjs freshEpochs,
// retire), as after a snapshot moved the seat: the pairing keys stay, the ratchets of an older copy are never reused.
import { did as didOf, parseBytes } from 'sigelo';
import { ITERATIONS, KDF, gate as pageGate, lockBytes, openBytes, wordsMeta } from './vendor/contact/words-lock.mjs';
import { didWords } from './vendor/contact/short.mjs';
import { holdNetwork, loadSealed, saveSealed } from './platform-web.mjs';
import { b64, unb64 } from './platform-android.mjs';

export const V = 'sigelo-backup/0', EXT = '.sbk', FRESH = 'app/backup-restored.json';
const SEALED = /\.(sealed|keystore)$/, SKIP = [/^app\/me\.local\.transfers\.json$/, /^app\/me\.local\.files\/\.transfer\//];
const te = new TextEncoder(), td = new TextDecoder();
const refuse = (status, check, message) => { throw Object.assign(new Error(message), { status, check }); };
const headOf = (s) => (s.rotations ?? []).at(-1)?.next_genesis ?? s.genesis;
const header = (h) => te.encode(JSON.stringify({ v: h.v, did: h.did, created: h.created, kdf: h.kdf, iter: h.iter }));
const wordsOf = (did) => { try { return didWords(did); } catch { return null; } };

/** The file's name: sigelo-<the profile's name, lowercase letters and digits>-<date>.sbk. */
export function fileName(name, now = Date.now()) {
  const slug = String(name ?? '').toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24) || 'profile';
  return `sigelo-${slug}-${new Date(now).toISOString().slice(0, 10)}${EXT}`;
}

/** Every file of the profile's storage that goes into the backup: not the sealed ones, not the transfers in progress. */
export function filesOf(files) {
  const out = {}, walk = (dir) => {
    for (const n of files.list(dir)) {
      const path = dir === '' ? n : `${dir}/${n}`, b = files.read(path);
      if (b !== null && !SEALED.test(path) && !SKIP.some((r) => r.test(path))) out[path] = b64(b);
      if (b === null || files.list(path).length) walk(path);
    }
  };
  // The platform's list(dir) names what is under dir/; the top level by its known roots.
  for (const top of ['app']) walk(top);
  return out;
}

/** The profile as a backup file, encrypted under the password (the caller checked it against the kept words, if any). */
export async function makeBackup(p, password, { profile = {}, iterations = ITERATIONS, now = Date.now() } = {}) {
  const id = await loadSealed(p, 'identity');
  if (id === null) refuse(409, 'backup_none', 'Nothing to back up: this profile holds no identity on this phone.');
  let keeper = null, words = null, plain = null;
  try {
    const s = parseBytes(id), original = didOf(s.genesis), did = didOf(headOf(s));
    keeper = await loadSealed(p, 'keeper');
    words = await loadSealed(p, 'words');
    const body = { v: V, profile: { name: profile.name ?? null, original, words: wordsOf(original) }, identity: td.decode(id),
      keeper: keeper === null ? null : td.decode(keeper), words: words === null ? null : td.decode(words), files: filesOf(p.files) };
    plain = te.encode(JSON.stringify(body));
    const h = { v: V, did, created: new Date(now).toISOString(), kdf: KDF, iter: iterations };
    const x = await lockBytes(V, plain, password, { iterations, aad: header(h) });
    const bytes = te.encode(JSON.stringify({ ...h, salt: b64(x.salt), iv: b64(x.iv), ct: b64(x.ct) }));
    return { bytes, name: fileName(profile.name ?? profile.id, now), did };
  } finally { id.fill(0); keeper?.fill(0); words?.fill(0); plain?.fill(0); }
}

/** The plaintext header, checked: { v, did, created, kdf, iter, salt, iv, ct } (bytes for the last three). */
export function readHeader(bytes) {
  let o;
  try { o = JSON.parse(td.decode(bytes)); } catch { refuse(400, 'backup_file', 'Not a sigelo backup file.'); }
  if (typeof o?.v !== 'string' || !/^sigelo-backup\//.test(o.v)) refuse(400, 'backup_file', 'Not a sigelo backup file.');
  if (o.v !== V) refuse(400, 'backup_version', `A backup of another version (${o.v}): this app reads ${V}. Update the app, then try again.`);
  if (o.kdf !== KDF || !Number.isSafeInteger(o.iter) || o.iter < 1000 || typeof o.did !== 'string' || typeof o.created !== 'string') refuse(400, 'backup_file', 'The backup file is damaged.');
  try { return { ...o, salt: unb64(o.salt), iv: unb64(o.iv), ct: unb64(o.ct) }; } catch { return refuse(400, 'backup_file', 'The backup file is damaged.'); }
}

/** The contents, the password checked through the page's gate (a wrong one: words_password after its delay). */
export async function openBackup(bytes, password, gate = pageGate) {
  const h = readHeader(bytes);
  let plain;
  try { plain = (await gate.run(() => openBytes(V, h, password, header(h)))).plain; } catch (e) { throw Object.assign(e, { status: e.status ?? 403 }); }
  let body;
  try { body = JSON.parse(td.decode(plain)); } catch { refuse(400, 'backup_file', 'The backup file is damaged.'); } finally { plain.fill(0); }
  if (body?.v !== V || typeof body.identity !== 'string' || typeof body.files !== 'object' || body.files === null) refuse(400, 'backup_file', 'The backup file is damaged.');
  const s = parseBytes(te.encode(body.identity));
  if (typeof s?.secret !== 'string' || didOf(headOf(s)) !== h.did || didOf(s.genesis) !== body.profile?.original) refuse(400, 'backup_file', 'The backup file is damaged: its identity is not the one it names.');
  return { header: h, body, original: didOf(s.genesis) };
}

/**
 * The backup into this profile (its first run: no identity here yet): every file written, the identity, the keeper and
 * the kept words sealed under this phone's key, the network held from the first write to the last commit. dids: the
 * original DIDs of this phone's other profiles; the same identity twice on one phone is refused (backup_exists).
 */
export async function restoreBackup(p, bytes, password, { dids = [], gate = pageGate, now = Date.now(), commit = async () => {} } = {}) {
  const { header: h, body, original } = await openBackup(bytes, password, gate);
  if (dids.includes(original)) refuse(409, 'backup_exists', 'This identity is already a profile on this phone: use that one, or remove it first.');
  if (['identity.sealed', 'identity.keystore'].some((n) => p.files.read(n) !== null)) refuse(409, 'backup_here', 'This profile holds an identity already: add a new profile to restore into.');
  if (body.words != null) wordsMeta(te.encode(body.words));
  await commit();
  const release = holdNetwork();
  const id = te.encode(body.identity), keeper = body.keeper == null ? null : te.encode(body.keeper), words = body.words == null ? null : te.encode(body.words);
  try {
    for (const [name, v] of Object.entries(body.files)) {
      if (typeof v !== 'string' || !name.startsWith('app/') || name.split('/').includes('..') || SEALED.test(name)) refuse(400, 'backup_file', `The backup file is damaged (${name}).`);
      p.files.write(name, unb64(v));
    }
    p.files.write(FRESH, te.encode(JSON.stringify({ restored: Math.floor(now / 1000), created: h.created })));
    await saveSealed(p, 'identity', id, undefined, { full: true });
    if (keeper) await saveSealed(p, 'keeper', keeper, undefined, { full: true });
    if (words) await saveSealed(p, 'words', words, undefined, { full: true });
    await p.flush();
  } finally { id.fill(0); keeper?.fill(0); words?.fill(0); release(); }
  return { did: h.did, original, name: body.profile?.name ?? null, words: body.profile?.words ?? wordsOf(original), created: h.created };
}

/** At a start after a restore (FRESH there): every session afresh, the pairing keys kept; then the mark gone. */
export async function freshAfterRestore(p, carrier) {
  if (p.files.read(FRESH) === null) return null;
  const n = carrier.freshEpochs({ retire: true }).length;
  p.files.remove(FRESH);
  await p.flush();
  return n;
}
