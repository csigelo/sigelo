// SPDX-License-Identifier: MIT
// The Android app's remote form (design/apps.md §8, design/profiles.md P2), for boot.mjs: a remote
// profile drives its computers' `sigelo-agent ui --remote`, holding no account key, one computer at a
// time (the one in use, computers.mjs; switch, add, forget from Me → Computers):
//   LAN:    SIGELO:UI:, every call sealed here (sigelo-remote/0, remote-client.mjs) and carried by the
//           shell's HTTP, the text sealed under an AndroidKeyStore key (its blob naming the computer).
//   relay:  SIGELO:CTL: (design/apps.md §6.3): a control identity per computer, made here (a random key,
//           sealed as an identity is, never attested), paired with the operator by the code and four words
//           checked on the computer; calls are sigelo-device/1 requests (apps/contact/control.mjs), the state comes
//           pushed (events), so the page's 2 s poll reads it here and sends nothing.
// Pairing (code or scan: welcome.mjs's connect screens) refuses a computer whose page is another identity
// than the profile's operator, other_operator, before anything of it is kept; a computer whose page changes
// to another identity later is refused the same way at its first GET /api/me.
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { canonicalize } from 'sigelo';
import { parseControl, remoteClient } from './vendor/remote-client.mjs';
import { Carrier, DEFAULT_RELAY, pathsFor } from './vendor/contact/carrier.mjs';
import { makeControl, newControlIdentity, readControlText } from './vendor/contact/control.mjs';
import { androidPlatform, b64, bridgeFetch, computerBridge, unb64 } from './platform-android.mjs';
import { loadIdentity, saveIdentity } from './platform-web.mjs';
import { LIMIT, computerDb, controlKey, openComputers, otherOperator, relayKey } from './computers.mjs';
import { firstRun, scanner } from './welcome.mjs';

const CONTROL_FILE = 'app/control.local.json';
const stop = (check, message) => Object.assign(new Error(message), { status: 403, check });
let jsQR = null;   // the QR decoder, when this build has it (the import map's /qr-decode.mjs)
if (globalThis.document) import('/qr-decode.mjs').then((m) => { jsQR = m.jsQR; }, () => {});
/** deleteDatabase to its end: true once deleted, false if it stays blocked (an open connection) past ms. */
const deleteDb = (indexedDB, name, ms = 5000) => new Promise((ok) => {
  const r = indexedDB.deleteDatabase(name), t = setTimeout(() => ok(false), ms);
  r.onsuccess = () => { clearTimeout(t); ok(true); };
  r.onerror = () => { clearTimeout(t); ok(false); };
});

/** After a switch the shell asks the page to clear what it kept (IndexedDB, localStorage), once. */
export async function wipeIfAsked(bridge, { indexedDB = globalThis.indexedDB, storage = globalThis.localStorage } = {}) {
  if (!bridge.info.wipe) return false;
  await new Promise((ok) => { const r = indexedDB.deleteDatabase('sigelo'); r.onsuccess = r.onerror = r.onblocked = () => ok(); });
  try { storage.clear(); } catch {}
  await bridge.request('wiped');
  return true;
}

const bundleOf = (s) => ({ v: 'sigelo/0', typ: 'bundle', genesis: s.genesis, rotations: [], bindings: [], attestations: [], issuers: [] });
const hexBytes = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
/** The control's carrier on the shell's platform: its own identity, the operator's relay. */
function controlCarrier(platform, idf, relay, options, onEvent) {
  return new Carrier({ identity: () => ({ secret: hexBytes(idf.secret), bundle: bundleOf(idf) }), ...pathsFor(CONTROL_FILE), ...(relay && { relay }), ...options, onEvent, platform });
}

/**
 * Over the relay, a computer's first time: a control identity made for computer cid and sealed (in its own
 * database, its blob naming it), the SIGELO:CTL: code accepted with it. A computer serving another operator
 * than expect: its contact forgotten, its database deleted, refused other_operator. → { words, operator,
 * original, relay }: the four words the computer must confirm. o: { mqtt, storage, indexedDB, pow, options, name, cid, expect }.
 */
export async function pairRelay(bridge, text, { mqtt, storage = globalThis.localStorage, indexedDB, pow, options = {}, name = 'sigelo', cid = 'c1', expect = null } = {}) {
  const t = readControlText(text), db = computerDb(name, cid);
  const platform = await androidPlatform({ bridge: computerBridge(bridge, cid), mqtt, ...(indexedDB && { indexedDB }), ...(pow && { pow }), name: db });
  const idf = newControlIdentity();
  await saveIdentity(platform, new TextEncoder().encode(JSON.stringify(idf)), undefined, { full: false });
  const car = controlCarrier(platform, idf, t.relay, options);
  let refused = null, out = null;
  try {
    const r = await car.accept(t.code, { name: 'computer', wait: 20, ...(t.relay && { relay: t.relay }) });
    if (!r.contact) throw Object.assign(new Error(`the computer did not answer (${r.status}): is sigelo-agent ui --remote --relay still running, its code under 10 minutes old?`), { check: 'remote' });
    const c = car.contacts().contacts.find((x) => x.did === r.contact.did), chain = c?.chain?.length ? c.chain : [r.contact.did];
    refused = otherOperator(expect, chain);
    if (refused) {
      refused.message += ' On the computer, answer no to its four words.';
      try { await car.forget(r.contact.did); } catch {}
    } else {
      storage.setItem(relayKey(cid), JSON.stringify({ operator: r.contact.did, relay: t.relay }));
      await platform.flush();
      out = { words: c?.fingerprint ?? null, operator: r.contact.did, original: chain[0], relay: t.relay ?? car.relay ?? DEFAULT_RELAY };
    }
  } finally { await car.stop(); }
  if (refused) { try { platform.db?.close?.(); } catch {} await deleteDb(indexedDB ?? globalThis.indexedDB, db, 2000); throw refused; }
  return out;
}

/** Over the relay: the backend, its carrier started on computer cid's control identity; GET /api/state from the pushed events. */
async function relayBackend(bridge, kept, { mqtt, indexedDB, pow, options = {}, timeout, name, cid }) {
  const platform = await androidPlatform({ bridge: computerBridge(bridge, cid), mqtt, ...(indexedDB && { indexedDB }), ...(pow && { pow }), name: computerDb(name, cid) });
  const raw = await loadIdentity(platform);
  if (raw === null) throw Object.assign(stop('connect', 'This app\'s control key for this computer is gone: forget it (Me → Computers) and pair again.'), { broken: true });
  const idf = JSON.parse(new TextDecoder().decode(raw)), ctl = makeControl({ operator: kept.operator, ...(timeout && { timeout }) });
  const car = controlCarrier(platform, idf, kept.relay, options, (e) => ctl.onEvent(e));
  await car.start();
  ctl.attach(car);
  globalThis.addEventListener?.('pagehide', () => { ctl.stop(); void car.stop(); });
  return {
    call: (method, path, body) => ctl.call(method, path, body),
    onChange: (fn) => ctl.onChange(fn),
    mode: () => ({ kind: 'remote', via: 'relay' }),
    carrier: car, stop: async () => { ctl.stop(); await car.stop(); },
  };
}

const lanDeps = (bridge) => ({ xchacha20poly1305, canonicalize, fetch: bridgeFetch(bridge), randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)) });
/** On the LAN: the backend over the computer's sealed text. */
async function lanBackend(bridge, kept, cid) {
  let text;
  try { text = new TextDecoder().decode(await computerBridge(bridge, cid).open(unb64(kept), { kind: 'control' })); } catch (e) {
    throw Object.assign(stop('connect', `This computer's text kept here does not open (${e.message}): forget it (Me → Computers) and pair it again.`), { broken: true });
  }
  const client = await remoteClient(text, { deps: lanDeps(bridge) }), where = `${client.host}:${client.port}`;
  return {
    async call(method, path, body) {
      try { return await client.call(method, path, body); } catch (e) {
        const message = e.status === 403 ? `The computer at ${where} refused this phone's text (revoked there, or another page): forget it (Me → Computers) and pair it again.`
          : e.status ? `The computer at ${where} answered HTTP ${e.status}.`
            : `No answer from ${where}: is \`sigelo-agent ui --remote\` running there, on this network?`;
        return { status: e.status === 403 ? 403 : 502, body: { error: { check: 'remote', message } } };
      }
    },
    onChange() {},   // the page polls /api/state, as over HTTP
    mode: () => ({ kind: 'remote', via: 'lan' }),
  };
}

/**
 * Its answers while its page is the operator's: the first GET /api/me 200 compared with the profile's (expect,
 * else another computer's); another identity → every call refused other_operator. Else it is learned (did, last used).
 */
function guarded(be, list, cid, expect) {
  let refused = null, learned = false;
  const want = () => expect ?? list.list().find((x) => x.id !== cid && x.did)?.did ?? null;
  return {
    ...be, cid,
    async call(method, path, body) {
      if (refused) return { status: 409, body: { error: { check: 'other_operator', message: refused.message } } };
      const r = await be.call(method, path, body);
      if (!learned && method === 'GET' && String(path).split('?')[0] === '/api/me' && r.status === 200) {
        const did = r.body?.original ?? r.body?.did;
        refused = otherOperator(want(), did);
        if (refused) return { status: 409, body: { error: { check: 'other_operator', message: refused.message } } };
        learned = true;
        list.learn(cid, { did });
      }
      return r;
    },
  };
}

/**
 * The remote form: the backend ui.js calls ({ call, onChange, mode, cid }) for the computer in use, or a refusal
 * check 'connect' (none yet, one being added: boot.mjs shows the pairing; broken: its material does not open).
 * Databases of forgotten computers are deleted first. o: { storage (the profile's), name (its database), expect (its operator), … }
 */
export async function remoteBackend(bridge, { storage = globalThis.localStorage, mqtt, indexedDB, pow, options, timeout, name = 'sigelo', expect = null } = {}) {
  const list = openComputers(storage);
  for (const db of list.wipes()) if (await deleteDb(indexedDB ?? globalThis.indexedDB, db)) list.wiped(db);
  const cur = list.active();
  if (!cur || list.adding) throw stop('connect', 'Connect to a computer.');
  if (cur.via === 'relay') {
    let kept = null;
    try { kept = JSON.parse(storage.getItem(relayKey(cur.id)) ?? 'null'); } catch {}
    if (!kept?.operator) throw Object.assign(stop('connect', 'This computer\'s pairing is not kept here: forget it (Me → Computers) and pair again.'), { broken: true });
    return guarded(await relayBackend(bridge, kept, { mqtt, indexedDB, pow, options, timeout, name, cid: cur.id }), list, cur.id, expect);
  }
  const kept = storage.getItem(controlKey(cur.id));
  if (kept === null) throw Object.assign(stop('connect', 'This computer\'s text is not kept here: forget it (Me → Computers) and pair it again.'), { broken: true });
  return guarded(await lanBackend(bridge, kept, cur.id), list, cur.id, expect);
}

/**
 * A computer's SIGELO:UI: text on the LAN, for computer cid: checked with one sealed call (its page another
 * identity than expect: refused other_operator, nothing kept), then kept sealed for the next start. → { did, where }.
 */
export async function connectLan(bridge, text, { storage = globalThis.localStorage, cid = 'c1', expect = null } = {}) {
  // base45 has spaces: never trimmed at the end, cut at the 60 characters of 40 bytes.
  const t = /SIGELO:UI:\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}:[0-9A-Z $%*+\-./:]{60}/.exec(text)?.[0] ?? text;
  let c;
  try { c = parseControl(t); } catch { throw new Error(t.startsWith('SIGELO:') ? 'This is not a computer\'s page (SIGELO:UI: or SIGELO:CTL:).' : 'Not a SIGELO:UI: or SIGELO:CTL: text.'); }
  let r;
  try { r = await (await remoteClient(t, { deps: lanDeps(bridge) })).call('GET', '/api/me'); } catch (e) {
    throw new Error(e.status === 403 ? 'The computer refused this text (revoked, or another computer\'s).' : `No answer: is sigelo-agent ui --remote running there, on this network? (${e.message})`);
  }
  if (r.status !== 200) throw new Error(r.body?.error?.message ?? `HTTP ${r.status}`);
  const did = r.body.original ?? r.body.did, no = otherOperator(expect, did);
  if (no) throw no;
  storage.setItem(controlKey(cid), b64(await computerBridge(bridge, cid).seal(new TextEncoder().encode(t), { kind: 'control' })));
  return { did, where: `${c.host}:${c.port}` };
}

/**
 * A computer paired now, by code or scan (SIGELO:CTL: over the relay, SIGELO:UI: on the LAN), under the
 * profile's next computer id, made the one in use. → { words } over the relay (compare, then open), { opened: true }
 * on the LAN. other_operator (expect: the profile's operator, else its computers') refused, nothing kept.
 * o: { storage, mqtt, name (the profile's database), expect, indexedDB, pow, options }.
 */
export async function pairComputer(bridge, text, { storage = globalThis.localStorage, expect = null, ...o } = {}) {
  const list = openComputers(storage), cid = list.nextId(), want = expect ?? list.operator();
  if (list.list().length >= LIMIT) throw Object.assign(new Error(`At most ${LIMIT} computers in a profile: forget one first.`), { check: 'computer_limit' });
  if (/^\s*SIGELO:CTL:/i.test(text)) {
    const r = await pairRelay(bridge, text.trim(), { ...o, storage, cid, expect: want });
    list.add({ via: 'relay', did: r.original, where: r.relay });
    return { words: r.words };
  }
  const r = await connectLan(bridge, text, { storage, cid, expect: want });
  list.add({ via: 'lan', did: r.did, where: r.where });
  return { opened: true };
}

/**
 * The pairing screens (welcome.mjs's connect: the code, or a SIGELO:UI: / SIGELO:CTL: text pasted or scanned)
 * for a remote profile with no computer yet, or one being added (Cancel back to the one in use); or, when the
 * one in use does not open (broken), that said with Forget it. o: { storage, mqtt, name, expect, reload, broken, … }.
 */
export function addComputerView(box, bridge, { storage = globalThis.localStorage, reload, broken = null, seal = './vendor/icon.svg', ...o } = {}) {
  if (!box) return null;
  const list = openComputers(storage);
  const api = {
    seal,
    scan: (onText) => scanner(onText, jsQR),
    async connect(text) {
      const r = await pairComputer(bridge, text, { storage, ...o });
      if (r.opened) reload();
      return r;
    },
    async open() { reload(); },
    async done() { reload(); },
    ...(list.list().length && { cancel: { label: list.adding ? 'Cancel' : 'Back to my computers', run: () => { list.setAdding(false); reload(); } } }),
  };
  const fr = firstRun(box, api, { show: false });
  if (!broken) { fr.connect(); return fr; }
  const cur = list.active(), forget = fr.button('Forget it', null, true), add = fr.button('Pair another');
  const s = fr.screen({ title: cur?.name ?? 'This computer', back: false, lead: broken.message, primary: forget, secondary: add });
  forget.onclick = () => { if (cur) list.forget(cur.id, o.name); reload(); };
  add.onclick = () => { list.setAdding(true); fr.connect(); };
  void s;
  return fr;
}
