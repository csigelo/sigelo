// SPDX-License-Identifier: MIT
// The self-contained app's start (app.mjs calls it with the page's globals; test-shell.mjs with fakes).
// Profiles first (profiles.mjs, design/profiles.md P1): the registry (migrated from a single-profile
// install at the first start), the dropped profiles erased, then the active one: at a start with more
// than one, the picker (welcome.mjs pickProfile) and the lock. Then that profile alone: its platform
// (platform-web.mjs, the Android app's platform-android.mjs), its identity (sealed in its storage), the
// router (router.mjs), or the remote form (shell.mjs) for a computer's page. No identity yet: its first
// run (welcome.mjs, the work in setup.mjs): create, restore from the 25 words, connect to an agent
// elsewhere; an import of a device file under Advanced. Then a reload.
//
//   const app = boot(env)   env: { shell (SigeloShell) | null, target? (where its port arrives), box (the first run's element), main (ui.js's),
//                           mqtt, indexedDB?, storage (localStorage), session (sessionStorage), reload(), seal? }
//   app.local               what ui.js reads as globalThis.sigeloLocal: { call, onChange, mode, share, unlock, secure, profiles, computers, words }
//   app.ready               → the backend (rejects while there is none: the first run, the connect view)
//
// local.profiles (ui.js Me → Profiles): list() → { active, limit, profiles }; use(id) the switch: the lock
// once (the shell's unlock), the active id kept, a reload; rename(id, name); add() a new profile, its
// first run (the lock too: it leaves the profile open now); remove(id, { name, words }) a words profile
// needs words: true ("I have the 25 words") and its name typed, a remote one its name, one not set up
// yet nothing; then the lock, the drop, the wipe (the active one: after the reload). Refusals throw an
// Error with { check, status }. A words profile whose words are kept behind a password (words.mjs) needs
// that password too ({ password }).
// local.words (ui.js Me → Security): words.mjs wordsApi over the active profile; local.secure(on): FLAG_SECURE.
// local.computers (ui.js Me → Computers, a remote profile in the Android app; design/profiles.md P2): list() → { active,
// limit, computers, profile }; use(id) the switch (the lock once, a reload), add() the pairing screens after a reload,
// forget(id) its control key gone here (the lock), → { revoke }: what to run on the computer, which keeps it until then.
import { parseBytes } from 'sigelo';
import { loadIdentity, memoryFiles, openDb, webPlatform } from './platform-web.mjs';
import { androidPlatform, connectBridge, keystoreSealer, profileBridge } from './platform-android.mjs';
import { makeRouter } from './router.mjs';
import { addComputerView, remoteBackend, wipeIfAsked } from './shell.mjs';
import { LIMIT as COMPUTERS_MAX, REVOKE, openComputers } from './computers.mjs';
import { keeperOf, seatOf } from './seed.mjs';
import { firstRun, pickProfile } from './welcome.mjs';
import { setupApi } from './setup.mjs';
import { LIMIT, dbName, deleteDb, openRegistry, prefixed, runWipes } from './profiles.mjs';
import { guard, wordsApi } from './words.mjs';

const SETTINGS = 'app/settings.json', PICKED = 'sigelo-picked', FROM = 'sigelo-from';
const refuse = (status, check, message) => { throw Object.assign(new Error(message), { status, check }); };

export function boot({ shell = null, target, box = null, main = null, mqtt, indexedDB = globalThis.indexedDB, storage = globalThis.localStorage, session = null, reload, seal = './vendor/icon.svg', pow, locks } = {}) {
  let router = null, raw = null, bridge = null, prof = null, own = null, regOk, regNo, profOk;   // own: the active profile's platform, once it holds an identity
  const profP = new Promise((y) => { profOk = y; });
  const regP = new Promise((y, n) => { regOk = y; regNo = n; });
  regP.catch(() => {});
  const sess = { get: (k) => { try { return session?.getItem(k) ?? null; } catch { return null; } }, set: (k, v) => { try { session?.setItem(k, v); } catch {} } };
  const extra = { ...(indexedDB && { indexedDB }), ...(pow && { pow }), ...(locks && { locks }) };

  /** p1 before profiles: an identity sealed in `sigelo` → words; the shell's form remote → remote; else nothing yet. */
  async function migrate() {
    if (raw?.info.mode === 'remote') return { kind: 'remote' };
    const db = await openDb(indexedDB, dbName('p1')), f = (await memoryFiles(db)).files;
    const has = ['identity.keystore', 'identity.sealed'].some((n) => f.read(n) !== null);
    try { db.close?.(); } catch {}
    return { kind: has ? 'words' : null };
  }
  const stopNow = async () => { try { await router?.stop?.(); } catch {} };
  /** What this profile's page says of itself (GET /api/me): its original DID and four words, kept in the list. */
  const learn = (kind) => {
    void Promise.resolve(router.call('GET', '/api/me')).then(async (r) => {
      if (r?.status === 200) await (await regP).set(prof.id, { kind, did: r.body.original ?? r.body.did, words: r.body.words ?? null });
    }).catch(() => {});
  };
  const hideMain = (on) => { if (main) main.hidden = on; };

  const ready = (async () => {
    if (shell) { raw = await connectBridge({ shell, ...(target && { target }) }); await wipeIfAsked(raw, { indexedDB, storage }); }
    let reg;
    try { reg = await openRegistry({ indexedDB, migrate }); } catch (e) { regNo(e); throw e; }
    regOk(reg);
    await runWipes(reg, { indexedDB, storage, bridge: raw });
    if (!reg.active()) await reg.add();
    // More than one: the picker, then the lock (at a start the shell's own lock was just confirmed: not asked twice).
    if (reg.list().length > 1 && sess.get(PICKED) !== reg.active().id) {
      hideMain(true);
      for (;;) {
        const id = await pickProfile(box, { profiles: reg.list(), active: reg.active().id, seal });
        try { await raw?.unlock(); await reg.use(id); break; } catch {}
      }
      if (box) box.hidden = true;
      hideMain(false);
    }
    prof = reg.active();
    profOk(prof);
    sess.set(PICKED, prof.id);
    bridge = raw && profileBridge(raw, prof.id);
    const store = prefixed(storage, prof.id), name = dbName(prof.id);
    if (bridge && prof.kind === 'remote') {
      // Its computer in use (computers.mjs); none yet, one being added, or one that does not open: the pairing screens.
      const o = { storage: store, mqtt, name, expect: prof.did, ...extra };
      try { router = await remoteBackend(bridge, o); } catch (e) {
        if (e.check === 'connect') { hideMain(true); addComputerView(box, bridge, { ...o, reload, seal, broken: e.broken ? e : null }); }
        throw e;
      }
      learn('remote');
      return router;
    }
    const platform = bridge ? await androidPlatform({ bridge, mqtt, name, ...extra }) : await webPlatform({ mqtt, name, ...extra });
    const id = await loadIdentity(platform);
    if (id === null) {
      setup(platform, store, name, reg);
      refuse(403, 'identity', 'This app holds no identity yet.');
    }
    const s = platform.files.read(SETTINGS), settings = s === null ? {} : JSON.parse(new TextDecoder().decode(s));
    const identity = parseBytes(id);
    own = platform;
    router = makeRouter({ platform, identity: () => identity, mode: settings.mode ?? { kind: 'safe' }, seat: seatOf(platform, () => identity), keeper: keeperOf(platform),
      words: { guard: (password) => guard(platform, password) } });
    await router.start();
    globalThis.addEventListener?.('pagehide', () => { void router.stop(); });
    learn('words');
    return router;
  })();
  ready.catch(() => {});

  // ---- no identity yet: the first run, alone on the screen (ui.js's page hidden until there is one)
  function setup(platform, store, name, reg) {
    if (!box) return;
    hideMain(true);
    const others = reg.list().some((p) => p.id !== prof.id);
    const leave = others ? { label: 'Back to my profiles', run: () => profiles.remove(prof.id, {}).catch(() => {}) } : undefined;
    firstRun(box, setupApi(platform, { bridge, mqtt, storage: store, reload, profile: { name, kind: (k) => reg.set(prof.id, { kind: k }), leave } }));
  }

  /** fn(profile id's store of kept words): the active one's platform, else its database opened (its keystore aliases) and closed again. */
  async function withProfile(id, fn) {
    if (id === prof?.id && own) return fn(own);
    const db = await openDb(indexedDB, dbName(id)), f = await memoryFiles(db);
    try { return await fn({ files: f.files, flush: f.flush, db, ...(raw && { sealer: keystoreSealer(profileBridge(raw, id)) }) }); } finally { try { db.close?.(); } catch {} }
  }

  const profiles = Object.freeze({
    list: async () => (await regP).full(),
    /** The switch: the lock once, the active id kept, a reload (the new profile starts; its keys within the lock's window). */
    async use(id) {
      const reg = await regP;
      if (!reg.byId(id)) refuse(404, 'profile', `no profile ${JSON.stringify(id)}`);
      if (id === reg.active()?.id) return { active: id };
      await raw?.unlock();
      await reg.use(id);
      sess.set(PICKED, id);
      await stopNow();
      reload();
      return { active: id, reload: true };
    },
    async rename(id, name) { const reg = await regP; await reg.rename(id, name); return reg.full(); },
    /** A new profile and its first run (the three choices); at the limit, refused profile_limit. */
    async add() {
      const reg = await regP, from = reg.active()?.id ?? null;
      if (reg.list().length >= LIMIT) refuse(400, 'profile_limit', `At most ${LIMIT} profiles on this phone: remove one first.`);
      await raw?.unlock();
      const p = await reg.add();
      sess.set(PICKED, p.id);
      if (from) sess.set(FROM, from);
      await stopNow();
      reload();
      return { active: p.id, reload: true };
    },
    async remove(id, { name, words, password } = {}) {
      const reg = await regP, p = reg.byId(id) ?? refuse(404, 'profile', `no profile ${JSON.stringify(id)}`);
      if (p.kind === 'words' && words !== true) refuse(400, 'profile_words', 'Tick "I have the 25 words": only they bring this identity back.');
      if (p.kind !== null && String(name ?? '').trim() !== p.name) refuse(400, 'profile_name', `Type the profile's name, ${p.name}, to remove it.`);
      const active = reg.active()?.id === id;
      if (p.kind !== null) await raw?.unlock();
      // Its words kept behind a password (words.mjs): that password too.
      if (p.kind === 'words') await withProfile(id, (q) => guard(q, password));
      await reg.drop(id);
      // An added profile left before its first run: back to the one it was added from (the lock was asked at add).
      const from = sess.get(FROM);
      if (active && p.kind === null && from && reg.byId(from)) await reg.use(from);
      if (!active) { await runWipes(reg, { indexedDB, storage, bridge: raw }); return reg.full(); }
      if (reg.active()) sess.set(PICKED, reg.active().id);
      await stopNow();
      reload();
      return { reload: true };
    },
  });

  // ---- Me → Computers (design/profiles.md P2): a remote profile's computers, the one in use marked
  const computersOf = async () => {
    const p = await profP;
    if (p.kind !== 'remote' || !raw) refuse(409, 'not_remote', 'This profile holds an identity here, not computers.');
    return openComputers(prefixed(storage, p.id));
  };
  const computers = Object.freeze({
    async list() { const c = await computersOf(), p = (await regP).byId(prof.id) ?? prof; return { ...c.full(), profile: { id: p.id, name: p.name, did: p.did, words: p.words } }; },
    /** The switch: the lock once, that computer in use, a reload (its page). */
    async use(id) {
      const c = await computersOf();
      if (!c.byId(id)) refuse(404, 'computer', `no computer ${JSON.stringify(id)}`);
      if (id === c.active()?.id && !c.adding) return { active: id };
      await raw.unlock();
      c.use(id);
      await stopNow();
      reload();
      return { active: id, reload: true };
    },
    /** The pairing screens (code or scan) after a reload; Cancel there returns to the one in use. */
    async add() {
      const c = await computersOf();
      if (c.list().length >= COMPUTERS_MAX) refuse(400, 'computer_limit', `At most ${COMPUTERS_MAX} computers in a profile: forget one first.`);
      await raw.unlock();
      c.setAdding(true);
      await stopNow();
      reload();
      return { reload: true };
    },
    /** Its control key gone from this phone (the lock first); the computer keeps the control until revoked there (revoke). */
    async forget(id) {
      const c = await computersOf();
      if (!c.byId(id)) refuse(404, 'computer', `no computer ${JSON.stringify(id)}`);
      await raw.unlock();
      const r = c.forget(id, dbName(prof.id));
      // One shape on both paths: the list as it is now, the reminder, whether the page reloads.
      if (r.active) { await stopNow(); reload(); return { ...c.full(), revoke: REVOKE, reload: true }; }
      for (const db of c.wipes()) if (await deleteDb(indexedDB, db)) c.wiped(db);
      return { ...c.full(), revoke: REVOKE, reload: false };
    },
  });

  const local = Object.freeze({
    async call(method, path, body) {
      let r;
      try { r = await ready; } catch (e) { return { status: e.status ?? 503, body: { error: { check: e.check ?? 'start', message: e.message } } }; }
      return r.call(method, path, body);
    },
    onChange(fn) { ready.then((r) => r.onChange(fn), () => {}); },
    mode: () => router?.mode() ?? null,
    // A ready-to-send message through the Android share sheet; without the shell, ui.js copies it.
    async share(text) { if (!raw) throw new Error('no share sheet'); await raw.share(text); },
    // The screen lock before a screen that shows or spends the identity (ui.js GUARDED); a page has none.
    async unlock() { if (raw) await raw.unlock(); },
    // FLAG_SECURE while the kept words are on the screen (ui.js Me → Security → Show my 25 words).
    async secure(on) { if (raw) await raw.secure(on); },
    profiles,
    computers,
    words: wordsApi(() => own, { unlock: async () => { if (raw) await raw.unlock(); }, withProfile }),
  });
  return { ready, local, registry: regP };
}
