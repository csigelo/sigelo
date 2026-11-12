#!/usr/bin/env -S gjs -m
// SPDX-License-Identifier: MIT
// sigelo on a Linux phone (design/apps.md §7): a GTK 4 + libadwaita window around a WebKitGTK 6.0 view
// of the page of `sigelo-agent ui` (apps/agent/UI-API.md), in one of two forms:
//   this phone:  spawns `sigelo-agent ui --app [--identity <file>]` (no shell, stdin a pipe: the page
//                stops when this app does), reads the URL and token from its stdout, shows that page.
//   a computer:  the page's files from sigelo-app://app/ and every call sealed here to the computer's
//                `ui --remote` (sigelo-remote/0, remote-client.mjs) over Soup. The phone holds no
//                account key: only the control's text (an id and a 32-byte key for that computer),
//                kept in the keyring (libsecret), else for this run only. The page never sees it.
//   over the relay: a SIGELO:CTL: code: `sigelo-agent control pair <text>` makes this phone's control
//                identity (a random key, ~/.config/sigelo/control.local.json, 0600) and pairs it; the
//                four words are compared with the computer's; then `sigelo-agent control ui --app`
//                serves the computer's page here, every call a request over the relay (design/apps.md §6.3).
//   restore from seed (design/apps-seed.md): the 25 words from the start page go once, on stdin, to
//                `sigelo-agent keeper --from-words --keychain` (the key and K_1 sealed in the keyring before
//                anything is written; never argv, never a file); then `device seat init` (this phone takes the
//                seat) or, when another device keeps it, a standby: this phone's page does not start until
//                "Take the seat here" (seat init here; the other device must be stopped or lost).
//   create (pass A10a): `keeper --new-words` draws 25 words and their wallet's address; the start page shows
//                them once (no Back, copy on stagenet only); three typed back are checked here, then the words
//                go once on stdin to `keeper --from-words --keychain --made-here` (birth today), and the seat init.
// Start page (web/start.html): pick a form, or scan/paste a computer's SIGELO:UI: or SIGELO:CTL: text.
// This phone's form shows the relay new codes name (the page's setting, relay.sigelo.ai pre-filled): changed
// there, it is set through the page's own POST /api/settings once the page runs; SIGELO_RELAY still wins.
// Profiles (design/profiles.md P1): several identities, each its own files: p1 the files of before (me.local.json,
// the keyring text, control.local.json, the standby mark), profile <id> me.<id>.local.json beside it (its keeper
// beside it, wrapped in the keyring under its original DID as any identity), control.<id>.local.json, the
// keyring text under kind "sigelo-remote/0 <id>", standby.<id>; the list in profiles.json beside the identity
// files (0600, no secret). Only the active profile's page runs (`ui --app --identity <its file>`, its verbs with
// SIGELO_HUMAN and SIGELO_CONTROL naming its files). At a start with more than one: the picker (start page).
// The Profiles sheet (the profile chip) and Settings → Profiles (ui.js) ask the bridge too: from the start page, ui.html and this phone's own page, the
// profile operations only. No app lock here: the session's login is the lock (design/apps.md §5).
// Computers (design/profiles.md P2): a remote profile keeps a list of computers in its registry entry
// (computers: {active, next, adding, list: [{id, name, via, did, words, where, paired, last_used}]}), each paired
// once; the one in use is opened. Per computer: the LAN text in the keyring under kind "sigelo-remote/0[ <id>]
// <computer>" and the attribute computer (c1: the item of before, no computer attribute), the relay control in
// control[.<id>].<computer>.local.json (c1: the file of before). All of a profile's computers serve its operator:
// another identity's page is refused other_operator at pairing (LAN: its GET /api/me; relay: control pair --operator).
// Me → Connect → Computers (ui.js) asks the bridge: computers, computer-use, computer-add, computer-forget.
// Notifications (design/ux1/build.md, pass 6): the page asks the bridge `notify` {tag, title, text} (the sender's, group's or
// agent's name and a generic line, never a message's text) or {tag, cancel: true}; a tap opens the page there (sigeloOpen).
// Raised only while the app runs: no background service.
// Headless checks (apps/gtk/test-gtk.mjs): SIGELO_APP_TEST=remote|self|relay|restore|create|profiles|computers|words|notify, no window.
// The words password (design/apps-seed.md §8): optional after a create or a restore; the words encrypted in the page,
// kept in the keyring (words-keep, words-get, words-drop, words-status); the same password guards profile-remove and take.
import GLib from 'gi://GLib';
import Gio from 'gi://Gio';
import Soup from 'gi://Soup?version=3.0';
import System from 'system';
import { canonicalize } from './lib/jcs.js';
import { xchacha20poly1305 } from './lib/noble-ciphers/chacha.js';
import { parseControl, remoteClient } from './lib/remote-client.mjs';

const ID = 'io.sigelo.App';
const HERE = GLib.path_get_dirname(GLib.filename_from_uri(import.meta.url)[0]);
const WEB = GLib.build_filenamev([HERE, 'web']);
const dec = new TextDecoder(), enc = new TextEncoder();

// gjs has no atob/btoa nor crypto.getRandomValues: remote-client.mjs and noble use them.
globalThis.btoa ??= (s) => GLib.base64_encode(Uint8Array.from(s, (c) => c.charCodeAt(0)));
globalThis.atob ??= (s) => String.fromCharCode(...GLib.base64_decode(s + '='.repeat((4 - s.length % 4) % 4)));   // GLib wants the padding
const urandom = Gio.File.new_for_path('/dev/urandom');
function randomBytes(n) {
  const st = urandom.read(null), b = st.read_bytes(n, null).toArray(); st.close(null);
  if (b.length !== n) throw new Error('short read from /dev/urandom');
  return b;
}
globalThis.crypto ??= { getRandomValues: (a) => { a.set(randomBytes(a.length)); return a; } };

// ---- HTTP (Soup 3) in the shape remote-client.mjs wants from fetch
const session = new Soup.Session({ timeout: 20 });
function soupFetch(url, { method = 'GET', headers = {}, body } = {}) {
  const msg = Soup.Message.new(method, url);
  for (const [k, v] of Object.entries(headers)) if (k.toLowerCase() !== 'content-type') msg.get_request_headers().append(k, v);
  if (body !== undefined) msg.set_request_body_from_bytes(headers['Content-Type'] ?? 'application/json', new GLib.Bytes(enc.encode(body)));
  return new Promise((ok, no) => session.send_and_read_async(msg, GLib.PRIORITY_DEFAULT, null, (s, res) => {
    try { const text = dec.decode(s.send_and_read_finish(res).toArray()); ok({ status: msg.get_status(), text: async () => text }); } catch (e) { no(e); }
  }));
}
const DEPS = { xchacha20poly1305, canonicalize, fetch: soupFetch, randomBytes };
const args = System.programArgs, at = args.indexOf('--identity'), identity = at >= 0 ? args[at + 1] ?? null : null;   // p1's file; else ui's default

// ---- remote: the control's text in the keyring
let Secret = null;
try { Secret = (await import('gi://Secret?version=1')).default; } catch {}
const SCHEMA = Secret && Secret.Schema.new(`${ID}.Control`, Secret.SchemaFlags.NONE, { kind: Secret.SchemaAttributeType.STRING, computer: Secret.SchemaAttributeType.STRING });
// p1's first computer's item as before profiles; profile <id>'s under its own kind; a computer other than a profile's
// first under its own kind and the attribute computer. A lookup matches every item holding the attributes given, so
// the kind alone is exact: no item of another computer or profile has it.
const attrOf = (id, cid) => {
  const kind = `${id === 'p1' ? 'sigelo-remote/0' : `sigelo-remote/0 ${id}`}${cid === 'c1' ? '' : ` ${cid}`}`;
  return cid === 'c1' ? { kind } : { kind, computer: cid };
};
// The headless checks (SIGELO_APP_TEST): the same matching, in memory, never the session's keyring.
const memKeyring = GLib.getenv('SIGELO_APP_TEST') ? new Map() : null;
const matches = (item, attrs) => Object.entries(attrs).every(([k, v]) => item[k] === v);
const keyring = {
  get(id, cid) {
    if (memKeyring) return [...memKeyring.entries()].find(([a]) => matches(JSON.parse(a), attrOf(id, cid)))?.[1] ?? null;
    try { return Secret?.password_lookup_sync(SCHEMA, attrOf(id, cid), null) ?? null; } catch { return null; }
  },
  set(t, id, cid) {
    if (memKeyring) { memKeyring.set(JSON.stringify(attrOf(id, cid)), t); return true; }
    try { return Secret?.password_store_sync(SCHEMA, attrOf(id, cid), Secret.COLLECTION_DEFAULT, 'sigelo: control of a computer', t, null) ?? false; } catch { return false; }
  },
  clear(id, cid) {
    if (memKeyring) { for (const a of [...memKeyring.keys()]) if (matches(JSON.parse(a), attrOf(id, cid))) memKeyring.delete(a); return; }
    try { Secret?.password_clear_sync(SCHEMA, attrOf(id, cid), null); } catch {}
  },
  /** The kinds held (the headless checks only). */
  held: () => (memKeyring ? [...memKeyring.keys()].map((a) => JSON.parse(a)) : null),
};

let client = null;   // the remote client while connected
/** The control's text out of what was scanned or pasted: base45 has spaces, so never trimmed, cut at 60 (40 bytes). */
const controlText = (t) => /SIGELO:UI:\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}:[0-9A-Z $%*+\-./:]{60}/.exec(String(t ?? ''))?.[0] ?? String(t ?? '');
async function connect(text) {
  let c;
  text = controlText(text);
  try { parseControl(text); c = await remoteClient(text, { deps: DEPS }); } catch (e) { return { ok: false, message: `Not a computer's text: ${e.message}` }; }
  const r = await call(c, 'GET', '/api/me');
  if (r.status !== 200) return { ok: false, message: r.body?.error?.message ?? `HTTP ${r.status}` };
  client = c;
  return { ok: true, did: r.body.did, original: r.body.original ?? r.body.did, words: r.body.words ?? null, where: `${c.host}:${c.port}` };
}
/** A refusal of a computer serving another operator than the profile's (its own, else another computer's), or null. */
function otherOperator(did, cid = null, words = null) {
  const p = byId(activeId()), mine = comps().list.find((x) => x.id !== cid && x.did)?.did ?? null, want = p?.did ?? mine;
  if (!want || !did || did === want) return null;
  return no('other_operator', `This computer's page is another identity (${words ?? did}), not this profile's${p?.words ? ` (${p.words})` : ''}: all the computers of a profile serve one operator. Add it in a profile of its own (tap the profile name at the top, then Add).`);
}
/** One sealed call → {status, body}; transport failures as a status and an error body. */
async function call(c, method, path, body) {
  try { return await c.call(method, path, body); } catch (e) {
    if (GLib.getenv("SIGELO_APP_DEBUG")) printerr(e, e.stack);
    const where = `${c.host}:${c.port}`;
    const message = e.status === 403 ? `The computer at ${where} refused this phone's text (revoked there, or another page): scan its text again.`
      : e.status ? `The computer at ${where} answered HTTP ${e.status}.`
        : `No answer from ${where}: is \`sigelo-agent ui --remote\` running there, on this network?`;
    return { status: e.status === 403 ? 403 : 502, body: { error: { check: 'remote', message } } };
  }
}

// ---- this phone: `sigelo-agent ui --app`
function agentArgv() {
  const env = GLib.getenv('SIGELO_AGENT');
  if (env) return env.trim().startsWith('[') ? JSON.parse(env) : [env];
  try { return JSON.parse(dec.decode(GLib.file_get_contents(GLib.build_filenamev([HERE, 'agent.json']))[1])); } catch { return ['sigelo-agent']; }
}
/** A launcher whose children see the active profile's files: SIGELO_HUMAN (keeper, device), SIGELO_CONTROL (its computer in use's control, or `control`). */
function launcher(flags, control = controlPath()) {
  const l = new Gio.SubprocessLauncher({ flags });
  l.setenv('SIGELO_HUMAN', identityPath(), true);
  l.setenv('SIGELO_CONTROL', control, true);
  return l;
}
const readLine = (st) => new Promise((ok) => st.read_line_async(GLib.PRIORITY_DEFAULT, null, (s, r) => {
  try { const [line] = s.read_line_finish_utf8(r); ok(line); } catch { ok(null); }
}));
let child = null;
/** → {ok, url} or {ok: false, message}: the page's URL (with its token) from the child's first stdout line. */
async function startSelf(identity, verb = ['ui', '--app', ...(identity ? ['--identity', identity] : [])]) {
  stopSelf();
  const argv = [...agentArgv(), ...verb];
  let p;
  try { p = launcher(Gio.SubprocessFlags.STDIN_PIPE | Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE).spawnv(argv); } catch (e) {
    return { ok: false, message: `Cannot start ${argv[0]}: ${e.message}. Install sigelo-agent, or run install.sh from a checkout.` };
  }
  child = p;
  const out = Gio.DataInputStream.new(p.get_stdout_pipe()), err = Gio.DataInputStream.new(p.get_stderr_pipe());
  const errs = [];
  (async () => { for (let l; (l = await readLine(err)) !== null;) errs.push(l); })();
  const line = await readLine(out);
  const m = line && /^http:\/\/127\.0\.0\.1:(\d+)\/#t=[0-9a-f]{32}$/.exec(line);
  if (m) return { ok: true, url: line, port: Number(m[1]) };
  await new Promise((ok) => p.wait_async(null, () => ok()));
  child = null;
  return { ok: false, message: errs.filter(Boolean).join('\n').slice(-1500) || `sigelo-agent ui ended (exit ${p.get_exit_status()})` };
}
/** sigelo-agent once, to its end → {status, out, err}. input: its stdin (the 25 words, never argv). */
async function runAgent(args, input = null, control = controlPath()) {
  let p;
  try { p = launcher(Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE | (input === null ? 0 : Gio.SubprocessFlags.STDIN_PIPE), control).spawnv([...agentArgv(), ...args]); } catch (e) { return { status: -1, out: '', err: e.message }; }
  const [out, err] = await new Promise((ok) => p.communicate_utf8_async(input, null, (s, r) => { try { const [, o, e] = s.communicate_utf8_finish(r); ok([o ?? '', e ?? '']); } catch (e) { ok(['', String(e.message)]); } }));
  return { status: p.get_exit_status(), out, err };
}
const lastLine = (r, what) => ((r.err.trim().split('\n').at(-1) ?? '').replace(/^sigelo-agent: /, '') || `${what} ended (exit ${r.status})`).replace(/"[^"\n]*"/g, '"…"');

// ---- restore from seed: the standby mark (another device keeps the seat), this app's own
const standbyPath = (id = activeId()) => GLib.build_filenamev([GLib.get_user_config_dir(), 'sigelo-app', id === 'p1' ? 'standby' : `standby.${id}`]);
const standbyName = () => { try { return dec.decode(GLib.file_get_contents(standbyPath())[1]).trim() || null; } catch { return null; } };
function setStandby(name) {
  if (name === null) { try { Gio.File.new_for_path(standbyPath()).delete(null); } catch {} return; }
  GLib.mkdir_with_parents(GLib.path_get_dirname(standbyPath()), 0o700);
  GLib.file_set_contents(standbyPath(), name);
}
/** The words to keeper --from-words --keychain on stdin; then the seat here (seat init) or a standby → {ok, seat, message}. */
async function restore({ words, name, height, net, elsewhere, made = false }) {
  if (typeof words !== 'string' || typeof name !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,19}$/.test(name)) return { ok: false, message: 'Name for this device: lowercase letters, digits, _ and -, at most 20.' };
  if (net !== 'mainnet' && net !== 'stagenet') return { ok: false, message: 'Network: mainnet or stagenet.' };
  const h = String(height ?? '').trim(), birth = h === '' ? ['--restore-height', '0'] : /^\d+$/.test(h) ? ['--restore-height', h] : ['--restore-date', h];
  const r = await runAgent(['keeper', '--from-words', '--keychain', '--net', net, ...birth, ...(made ? ['--made-here'] : [])], words);
  if (r.status !== 0) return { ok: false, message: lastLine(r, 'sigelo-agent keeper') };
  if (elsewhere === true) { setStandby(name); return { ok: true, seat: 'elsewhere' }; }
  const s = await runAgent(['device', 'seat', 'init', '--name', name]);
  return s.status === 0 ? { ok: true, seat: 'here' } : { ok: true, seat: 'pending', message: `not taken yet (${lastLine(s, 'device seat init')}): run sigelo-agent device seat init --name ${name} when online` };
}
// ---- create a new identity (pass A10a): `keeper --new-words` draws the words (newRoot's draw) and their
// wallet's address; the start page shows them once; three typed back are checked HERE (the page never
// decides); then the same words go once, on stdin, to keeper --from-words --keychain --made-here, the
// wallet's birth today, and the seat here. The words live in this process until then, never in a file.
let fresh = null;   // { words: [25], net, vault, asked: [3 positions] | null, passed }
const sameWord = (typed, word) => { const t = String(typed ?? '').trim().toLowerCase(); return t === word || (t.length === 3 && t === word.slice(0, 3)); };
/** New words for the review screen → {ok, words, vault, net}. */
async function newWords(net) {
  fresh = null;
  if (net !== 'mainnet' && net !== 'stagenet') return { ok: false, message: 'Network: mainnet or stagenet.' };
  const r = await runAgent(['keeper', '--new-words', '--net', net]);
  let j = null;
  try { j = JSON.parse(r.out); } catch {}
  if (r.status !== 0 || typeof j?.words !== 'string' || j.words.split(' ').length !== 25) return { ok: false, message: lastLine(r, 'sigelo-agent keeper --new-words') };
  fresh = { words: j.words.split(' '), net, vault: j.vault, asked: null, passed: false };
  return { ok: true, words: [...fresh.words], vault: fresh.vault, net };
}
/** Three positions (1 to 25) drawn here from /dev/urandom → {ok, asked}. */
function quiz() {
  if (fresh === null) return { ok: false, message: 'No new words: start again.' };
  const at = new Set();
  while (at.size < 3) { const b = randomBytes(1)[0]; if (b < 250) at.add((b % 25) + 1); }
  fresh.asked = [...at].sort((a, b) => a - b); fresh.passed = false;
  return { ok: true, asked: [...fresh.asked] };
}
/** The three words typed back; right → the identity made (restore with made), the words dropped → {ok, wrong?, seat}. */
async function create({ answers, name }) {
  if (fresh === null || fresh.asked === null) return { ok: false, message: 'No words asked: start again.' };
  const wrong = Array.isArray(answers) && answers.length === 3 ? fresh.asked.filter((p, i) => !sameWord(answers[i], fresh.words[p - 1])) : [...fresh.asked];
  fresh.asked = null;
  if (wrong.length) return { ok: false, wrong };
  const words = fresh.words.join(' '), today = new Date().toISOString().slice(0, 10), net = fresh.net;
  const r = await restore({ words, name, height: today, net, elsewhere: false, made: true });
  if (r.ok) fresh = null;   // kept on a failure before keeper wrote anything (a bad name): the page may try again
  return r;
}
const discard = () => { fresh = null; return { ok: true }; };

/** This phone's page refused while a standby (it would log in as you beside the seat), else null. */
const standbyRefusal = () => (standbyName() === null ? null
  : { ok: false, standby: true, message: 'Another device holds your seat: this phone does not log in as you. Take the seat here (Restore from seed), only if that device is stopped or lost.' });
/** Standby → the seat here: device seat init (no list on this phone: it becomes the seat's). */
async function take(proof) {
  const name = standbyName();
  if (name === null) return { ok: false, message: 'This phone is not a standby.' };
  const g = wordsGuard(activeId(), proof);   // the words password, when the words are kept
  if (g !== null && g !== true) return g;
  const s = await runAgent(['device', 'seat', 'init', '--name', name]);
  if (s.status !== 0) return { ok: false, message: lastLine(s, 'device seat init') };
  setStandby(null);
  return { ok: true, seat: 'here' };
}
/** p1's identity file, as ui picks it: --identity, else $SIGELO_HUMAN, else <config>/sigelo/me.local.json. */
const baseIdentity = () => identity ?? GLib.getenv('SIGELO_HUMAN') ?? GLib.build_filenamev([GLib.get_user_config_dir(), 'sigelo', 'me.local.json']);
/** The active profile's identity file: p1's, else me.<id>.local.json beside it. */
const identityPath = (id = activeId()) => (id === 'p1' ? baseIdentity() : GLib.build_filenamev([GLib.path_get_dirname(baseIdentity()), `me.${id}.local.json`]));
// Over the relay: this phone's control (sigelo-agent-control.ts), its file where sigelo-agent keeps it; profile <id>'s beside it.
const baseControl = () => GLib.getenv('SIGELO_CONTROL') ?? GLib.build_filenamev([GLib.get_home_dir(), '.config', 'sigelo', 'control.local.json']);
// Computer <cid> of a profile (P2): c1 the file of before, another control.<cid>.local.json (p1) or control.<id>.<cid>.local.json.
const controlPath = (id = activeId(), cid = activeComputer(id)) => {
  const stem = `control${id === 'p1' ? '' : `.${id}`}${cid === 'c1' ? '' : `.${cid}`}`;
  return id === 'p1' && cid === 'c1' ? baseControl() : GLib.build_filenamev([GLib.path_get_dirname(baseControl()), `${stem}.local.json`]);
};
/** A paired control only: a pairing that failed leaves a control key with no operator, which is no computer kept. */
const hasRelayControl = (id, cid = 'c1') => { try { return typeof JSON.parse(dec.decode(GLib.file_get_contents(controlPath(id, cid))[1])).operator === 'string'; } catch { return false; } };
/** A SIGELO:CTL: text paired with a new control identity at `control` → {ok, words, operator, original} or {ok: false, check?, message}. operator: the profile's (control pair --operator). */
async function pairRelay(text, control = controlPath(), operator = null) {
  const t = String(text ?? '').trim();
  if (!/^SIGELO:CTL:/i.test(t)) return { ok: false, message: 'Not a SIGELO:CTL: text.' };
  const r = await runAgent(['control', 'pair', t, '--force', ...(operator ? ['--operator', operator] : [])], null, control);
  if (r.status !== 0) {
    const last = (r.err.trim().split('\n').at(-1) ?? '').replace(/^sigelo-agent: /, '').replace(/^control pair: /, '');
    return { ok: false, ...(/^other_operator: /.test(last) && { check: 'other_operator' }), message: last.replace(/^other_operator: /, '') || `sigelo-agent control pair ended (exit ${r.status})` };
  }
  try { const j = JSON.parse(r.out); return { ok: true, words: j.words, operator: j.operator, original: j.original ?? j.operator }; } catch { return { ok: false, message: r.out.slice(0, 300) }; }
}
/** The page's relay setting (POST /api/settings, apps/contact/page.mjs) on this phone's page → {status, body}. */
async function setRelay(port, url, relay) {
  const token = /#t=(\w+)/.exec(url)[1], origin = `http://127.0.0.1:${port}`;
  const r = await soupFetch(`${origin}/api/settings`, { method: 'POST', headers: { 'X-Sigelo-Token': token, Origin: origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ relay }) });
  return { status: r.status, body: JSON.parse(await r.text()) };
}
function stopSelf() {
  if (!child) return null;
  const c = child;
  try { child.get_stdin_pipe().close(null); } catch {}
  try { child.send_signal(15); } catch {}
  child = null;
  return new Promise((ok) => c.wait_async(null, () => ok()));
}

// ---- profiles (design/profiles.md P1): the list in profiles.json, the active one's files (above), the operations
const LIMIT = 8, NAME_MAX = 24, PROFILE_ID = /^p[1-9]\d{0,2}$/, V = 'sigelo-profiles/0';
const NAME_BAD = new RegExp('[\\u0000-\\u001f\\u007f-\\u009f\\u061c\\u200e\\u200f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069]');
const registryPath = () => GLib.build_filenamev([GLib.path_get_dirname(baseIdentity()), 'profiles.json']);
const exists = (f) => GLib.file_test(f, GLib.FileTest.EXISTS);
let reg = null, picked = false, addedFrom = null;
function saveRegistry() {
  const f = registryPath();
  GLib.mkdir_with_parents(GLib.path_get_dirname(f), 0o700);
  Gio.File.new_for_path(f).replace_contents(enc.encode(JSON.stringify(reg, null, 1)), null, false, Gio.FileCreateFlags.PRIVATE | Gio.FileCreateFlags.REPLACE_DESTINATION, null);
}
/** The list; none yet: p1 = what this phone held before profiles (an identity: words; a computer kept: remote; nothing: not set up), left where it is. */
function registry() {
  if (reg) return reg;
  try { const r = JSON.parse(dec.decode(GLib.file_get_contents(registryPath())[1])); if (r?.v === V && Array.isArray(r.profiles)) reg = r; } catch {}
  if (!reg) {
    reg = { v: V, active: 'p1', next: 2, profiles: [{ id: 'p1', name: 'Profile 1', kind: kindOnDisk('p1'), did: null, words: null, created: Math.floor(Date.now() / 1000) }] };
    saveRegistry();
  }
  return reg;
}
function activeId() { return registry().active ?? 'p1'; }
/** What a profile holds by its files: an identity file (words), a computer kept (remote), else nothing (null). */
function kindOnDisk(id) { return exists(identityPath(id)) ? 'words' : keyring.get(id, 'c1') !== null || hasRelayControl(id, 'c1') ? 'remote' : null; }
const byId = (id) => registry().profiles.find((p) => p.id === id) ?? null;
const listed = () => ({ ok: true, active: registry().active, limit: LIMIT, picked, profiles: registry().profiles.map((p) => ({ ...p })) });
const no = (check, message) => ({ ok: false, check, message });
/** What the active profile's page said of itself (GET /api/me): kind, original DID, four words. */
function learn(fields) {
  const p = byId(activeId());
  if (!p) return;
  let changed = false;
  for (const [k, v] of Object.entries(fields)) if (['kind', 'did', 'words'].includes(k) && v !== undefined && p[k] !== v) { p[k] = v; changed = true; }
  if (changed) saveRegistry();
}
async function learnPage(port, url, kind) {
  try {
    const token = /#t=(\w+)/.exec(url)[1], r = await soupFetch(`http://127.0.0.1:${port}/api/me`, { headers: { 'X-Sigelo-Token': token } }), b = JSON.parse(await r.text());
    if (r.status === 200) learn({ kind, did: b.original ?? b.did, words: b.words ?? null });
    if (r.status === 200 && kind === 'remote') learnComputer(activeComputer(), { did: b.original ?? b.did, words: b.words ?? null });
  } catch {}
}
/** The original DID a words profile's identity file is wrapped under (its keyring item's account), or null (a plain file). */
const accountOf = (id) => { try { const s = JSON.parse(dec.decode(GLib.file_get_contents(identityPath(id))[1])).secret; return typeof s?.account === 'string' ? s.account : null; } catch { return null; } };
function removeTree(f) {
  const g = Gio.File.new_for_path(f);
  if (GLib.file_test(f, GLib.FileTest.IS_DIR) && !GLib.file_test(f, GLib.FileTest.IS_SYMLINK)) {
    const it = g.enumerate_children('standard::name', Gio.FileQueryInfoFlags.NOFOLLOW_SYMLINKS, null);
    for (let i; (i = it.next_file(null)) !== null;) removeTree(GLib.build_filenamev([f, i.get_name()]));
  }
  try { g.delete(null); } catch {}
}
/**
 * A profile's files erased: its identity file and every file beside it named after it (<stem>.*: keeper, page
 * data, history, carrier state, contacts, devices, seat), its keyring items (the identity's, unless another profile's
 * file is wrapped under the same DID; its computer's text), this phone's device file of it in the agents' directory,
 * its relay control (control forget), its standby mark.
 */
async function wipeProfile(id) {
  const file = identityPath(id), dir = GLib.path_get_dirname(file), stem = GLib.path_get_basename(file).replace(/\.json$/, '');
  const others = registry().profiles.filter((p) => p.id !== id).map((p) => GLib.path_get_basename(identityPath(p.id)).replace(/\.json$/, ''));
  const acct = accountOf(id), shared = acct !== null && registry().profiles.some((p) => p.id !== id && accountOf(p.id) === acct);
  const clearItem = async (a) => {
    if (!/^[A-Za-z0-9:._-]{1,200}$/.test(a)) return;
    try { await new Promise((ok) => Gio.Subprocess.new(['secret-tool', 'clear', 'service', 'sigelo', 'account', a], Gio.SubprocessFlags.STDERR_SILENCE).wait_async(null, () => ok())); } catch {}
  };
  if (acct !== null && !shared) await clearItem(acct);
  // This phone as a device of that identity (device seat init: worker i, FULL, its file in the agents' directory,
  // sigelo.<name>.local.json, wrapped under the worker's DID): its key is this profile's too, so it goes with it.
  let roster = {};
  try { roster = JSON.parse(dec.decode(GLib.file_get_contents(GLib.build_filenamev([dir, `${stem}.keeper.json`]))[1])).workers ?? {}; } catch {}
  const mine = new Set(Object.values(roster).filter((w) => w?.placed === 'device' && w.via === 'here' && typeof w.original === 'string').map((w) => w.original));
  const agents = GLib.path_get_dirname(GLib.getenv('SIGELO_IDENTITY') ?? GLib.build_filenamev([GLib.get_user_config_dir(), 'moadim', 'sigelo.local.json']));
  if (mine.size && GLib.file_test(agents, GLib.FileTest.IS_DIR)) {
    const it = Gio.File.new_for_path(agents).enumerate_children('standard::name', Gio.FileQueryInfoFlags.NOFOLLOW_SYMLINKS, null), names = [];
    for (let i; (i = it.next_file(null)) !== null;) names.push(i.get_name());
    for (const n of names.filter((x) => /^sigelo\.[a-z0-9][a-z0-9_-]{0,63}\.local\.json$/.test(x))) {
      let a = null;
      try { a = JSON.parse(dec.decode(GLib.file_get_contents(GLib.build_filenamev([agents, n]))[1])).secret?.account ?? null; } catch {}
      if (!mine.has(a)) continue;
      const base = n.replace(/\.json$/, '');
      for (const m of names) if (m === n || m.startsWith(`${base}.`)) removeTree(GLib.build_filenamev([agents, m]));
      await clearItem(a);
    }
  }
  // Its computers (P2), each one's control: the first's (the files of before) and every other one listed.
  for (const cid of new Set(['c1', ...(byId(id)?.computers?.list ?? []).map((x) => x.id)])) await dropComputer(id, cid);
  keptWords.clear(id);
  removeTree(standbyPath(id));
  if (GLib.file_test(dir, GLib.FileTest.IS_DIR)) {
    const it = Gio.File.new_for_path(dir).enumerate_children('standard::name', Gio.FileQueryInfoFlags.NOFOLLOW_SYMLINKS, null), names = [];
    for (let i; (i = it.next_file(null)) !== null;) names.push(i.get_name());
    for (const n of names) {
      if (n !== `${stem}.json` && !n.startsWith(`${stem}.`)) continue;
      if (others.some((o) => o !== stem && n.startsWith(`${o}.`)) || n === 'profiles.json') continue;   // another profile's (p1 named me.json, say)
      removeTree(GLib.build_filenamev([dir, n]));
    }
  }
}
// ---- the words password (design/apps-seed.md §8): the 25 words, encrypted in the page under a key made from the
// password (apps/contact/words-lock.mjs: PBKDF2-SHA256, WebKit's WebCrypto; never here), kept as one keyring item per
// profile ({kind: sigelo-words/0, file: its identity file}): {blob, check}. The check (HKDF of the password's key)
// stays here: a guarded op (words-keep over kept words, words-drop, profile-remove, take) carries the page's proof,
// which only a page that opened the words under the password has. words-get hands out the blob, never the check.
const WSCHEMA = Secret && Secret.Schema.new(`${ID}.Words`, Secret.SchemaFlags.NONE, { kind: Secret.SchemaAttributeType.STRING, file: Secret.SchemaAttributeType.STRING });
const wordsAttr = (id = activeId()) => ({ kind: 'sigelo-words/0', file: identityPath(id) });
// The headless checks (SIGELO_APP_TEST) keep the item in a file under $HOME instead: never the session's real keyring.
const fakeRing = GLib.getenv('SIGELO_APP_TEST') ? (a) => GLib.build_filenamev([GLib.get_home_dir(), '.fake-words', GLib.compute_checksum_for_string(GLib.ChecksumType.SHA256, JSON.stringify(a), -1)]) : null;
const ring = {
  lookup: (a) => (fakeRing ? (exists(fakeRing(a)) ? dec.decode(GLib.file_get_contents(fakeRing(a))[1]) : null) : Secret?.password_lookup_sync(WSCHEMA, a, null) ?? null),
  store(a, t) {
    if (!fakeRing) return Secret?.password_store_sync(WSCHEMA, a, Secret.COLLECTION_DEFAULT, 'sigelo: your 25 words, encrypted under your words password', t, null) ?? false;
    GLib.mkdir_with_parents(GLib.path_get_dirname(fakeRing(a)), 0o700); GLib.file_set_contents(fakeRing(a), t); return true;
  },
  clear: (a) => { if (fakeRing) { try { Gio.File.new_for_path(fakeRing(a)).delete(null); } catch {} } else Secret?.password_clear_sync(WSCHEMA, a, null); },
};
const keptWords = {
  get(id) { try { const t = ring.lookup(wordsAttr(id)); const o = t === null ? null : JSON.parse(t); return typeof o?.blob === 'string' && /^[0-9a-f]{64}$/.test(o.check) ? o : null; } catch { return null; } },
  set(o) { try { return ring.store(wordsAttr(), JSON.stringify(o)); } catch { return false; } },
  clear(id) { try { ring.clear(wordsAttr(id)); } catch {} },
};
/** The proof the page sent against the kept check: null when none is kept (the guards of before), else a refusal or true. */
function wordsGuard(id, proof) {
  const k = keptWords.get(id);
  if (k === null) return null;
  if (typeof proof !== 'string' || proof === '') return no('words_password_needed', 'Type your words password.');
  let d = proof.length ^ k.check.length;
  for (let i = 0; i < k.check.length; i++) d |= k.check.charCodeAt(i) ^ (proof.charCodeAt(i) || 0);
  return d === 0 ? true : no('words_password', 'Wrong password.');
}
/** An identity of this profile's own words (its keeper file beside it, as keeper --from-words writes it). */
const fromWords = (id = activeId()) => exists(identityPath(id).replace(/\.json$/, '.keeper.json'));
const wordsOps = {
  status({ id }) {
    if (id !== undefined) return byId(String(id)) ? { ok: true, here: false, kept: keptWords.get(String(id)) !== null } : no('profile', `no profile ${JSON.stringify(id)}`);
    return { ok: true, here: fromWords(), kept: keptWords.get() !== null, keyring: Secret !== null, iterations: 1000000 };
  },
  get({ id }) {
    const k = keptWords.get(id === undefined ? activeId() : String(id));
    return k === null ? no('words_none', 'No words are kept on this phone.') : { ok: true, blob: k.blob };
  },
  keep({ blob, check, proof }) {
    if (Secret === null && !fakeRing) return no('words_keyring', 'No keyring on this phone: the words cannot be kept.');
    if (!fromWords()) return no('words_none', 'This profile holds no identity from 25 words.');
    let o = null;
    try { o = JSON.parse(dec.decode(GLib.base64_decode(String(blob)))); } catch {}
    if (o?.v !== 'sigelo-words/0' || typeof check !== 'string' || !/^[0-9a-f]{64}$/.test(check)) return no('words_blob', 'Not the words as the page encrypts them.');
    const g = wordsGuard(activeId(), proof);
    if (g !== null && g !== true) return g;
    return keptWords.set({ blob: String(blob), check }) ? { ok: true, kept: true } : no('words_keyring', 'The keyring did not keep the words.');
  },
  drop({ proof }) {
    const g = wordsGuard(activeId(), proof);
    if (g === null) return no('words_none', 'No words are kept on this phone.');
    if (g !== true) return g;
    keptWords.clear();
    return { ok: true, kept: false };
  },
};
// ---- computers (design/profiles.md P2): a remote profile's list, in its registry entry
const COMPUTERS_MAX = 8, CID = /^c[1-9]\d{0,2}$/;
/** The profile's computers; none listed yet: today's one computer (relay or LAN, whichever is kept) becomes c1, left where it is. */
function comps(id = activeId()) {
  const p = byId(id);
  if (!p) return { active: null, next: 1, adding: false, list: [] };
  if (!p.computers || !Array.isArray(p.computers.list)) {
    const via = hasRelayControl(id, 'c1') ? 'relay' : keyring.get(id, 'c1') !== null ? 'lan' : null;
    let op = null;
    if (via === 'relay') try { op = JSON.parse(dec.decode(GLib.file_get_contents(controlPath(id, 'c1'))[1])).operator ?? null; } catch {}
    p.computers = { active: via ? 'c1' : null, next: via ? 2 : 1, adding: false, list: via ? [{ id: 'c1', name: 'Computer 1', via, did: op, words: null, where: null, paired: null, last_used: null }] : [] };
    saveRegistry();
  }
  return p.computers;
}
function activeComputer(id = activeId()) { return comps(id).active ?? 'c1'; }
const computerNow = () => comps().list.find((x) => x.id === comps().active) ?? null;
/** A computer paired now, made the one in use (its control material already kept under its id). */
function addComputer({ via, did = null, words = null, where = null }) {
  const c = comps(), id = `c${c.next}`, t = Math.floor(Date.now() / 1000);
  c.list.push({ id, name: `Computer ${c.next}`, via, did, words, where, paired: t, last_used: t });
  c.next += 1; c.active = id; c.adding = false;
  saveRegistry();
  return id;
}
/** What its page said (GET /api/me) and that it was used now. */
function learnComputer(cid, { did, words } = {}) {
  const x = comps().list.find((y) => y.id === cid);
  if (!x) return;
  if (typeof did === 'string') x.did = did;
  if (typeof words === 'string') x.words = words;
  x.last_used = Math.floor(Date.now() / 1000);
  saveRegistry();
}
/** Its control material gone from this phone: the keyring text, the relay control (control forget: its key and files). */
async function dropComputer(id, cid) {
  keyring.clear(id, cid);
  const f = controlPath(id, cid);
  if (exists(f)) { await runAgent(['control', 'forget'], null, f); removeTree(f); }
}
const REVOKE = 'sigelo-agent ui --revoke-control <name>';
const computersListed = () => { const c = comps(), p = byId(activeId()); return { ok: true, kind: p?.kind ?? null, active: c.active, limit: COMPUTERS_MAX, adding: c.adding === true, computers: c.list.map((x) => ({ ...x })), profile: { id: p?.id, name: p?.name, did: p?.did ?? null, words: p?.words ?? null } }; };
/** The computer operations (the bridge's computers, computer-*): {ok, …, reload?}; reload: the start page opens the one in use (or the pairing). */
const computerOps = {
  list() { return byId(activeId())?.kind === 'words' ? no('not_remote', 'This profile holds an identity here, not computers.') : computersListed(); },
  async use(id) {
    const c = comps();
    if (!c.list.some((x) => x.id === id)) return no('computer', `no computer ${JSON.stringify(id)}`);
    if (id === c.active && !c.adding) return computersListed();
    await stopSelf(); client = null;
    c.active = id; c.adding = false; saveRegistry();
    return { ...computersListed(), reload: true };
  },
  async add() {
    const c = comps();
    if (c.list.length >= COMPUTERS_MAX) return no('computer_limit', `At most ${COMPUTERS_MAX} computers in a profile: forget one first.`);
    await stopSelf(); client = null;
    c.adding = true; saveRegistry();
    return { ...computersListed(), reload: true };
  },
  cancel() { const c = comps(); c.adding = false; saveRegistry(); return { ...computersListed(), reload: true }; },
  async forget(id) {
    const c = comps(), x = c.list.find((y) => y.id === id);
    if (!x) return no('computer', `no computer ${JSON.stringify(id)}`);
    const active = c.active === id;
    if (active) { await stopSelf(); client = null; }
    await dropComputer(activeId(), id);
    c.list = c.list.filter((y) => y.id !== id);
    if (active) c.active = c.list[0]?.id ?? null;
    saveRegistry();
    return { ...computersListed(), revoke: REVOKE, reload: active };
  },
  /** SIGELO:UI: on the LAN → a new computer (other_operator refused, nothing kept) → {ok, did, …}. */
  async pairLan(text) {
    const c = comps();
    if (c.list.length >= COMPUTERS_MAX) return no('computer_limit', `At most ${COMPUTERS_MAX} computers in a profile: forget one first.`);
    const r = await connect(text);
    if (!r.ok) return r;
    const refused = otherOperator(r.original, null, r.words);
    if (refused) { client = null; return refused; }
    const cid = `c${c.next}`, kept = keyring.set(controlText(text), activeId(), cid);
    addComputer({ via: 'lan', did: r.original, words: r.words, where: r.where });
    learn({ kind: 'remote', did: r.original, words: r.words });
    return { ...r, kept, computer: cid };
  },
  /** SIGELO:CTL: over the relay → a new computer's control paired (control pair --operator the profile's) → {ok, words}. */
  async pairRelay(text) {
    const c = comps();
    if (c.list.length >= COMPUTERS_MAX) return no('computer_limit', `At most ${COMPUTERS_MAX} computers in a profile: forget one first.`);
    const cid = `c${c.next}`, p = byId(activeId()), want = p?.did ?? c.list.find((x) => x.did)?.did ?? null;
    const r = await pairRelay(text, controlPath(activeId(), cid), want);
    if (!r.ok) return r;
    const host = /^SIGELO:CTL:[0-9A-Z-]+:([A-Z0-9.-]+)$/i.exec(String(text).trim())?.[1]?.toLowerCase() ?? 'relay.sigelo.ai';
    addComputer({ via: 'relay', did: r.original, where: host });
    learn({ kind: 'remote' });
    return { ...r, computer: cid };
  },
  /** The one in use on the LAN, opened (its page's identity checked as at pairing) → {ok, …}. */
  async openLan() {
    const cur = computerNow();
    if (!cur) return { ok: false, message: 'No computer kept.' };
    const t = keyring.get(activeId(), cur.id);
    if (t === null) return { ok: false, message: `${cur.name}'s text is not kept here (no keyring answered when it was paired): forget it and pair it again.` };
    const r = await connect(t);
    if (!r.ok) return r;
    const refused = otherOperator(r.original, cur.id, r.words);
    if (refused) { client = null; return refused; }
    learnComputer(cur.id, { did: r.original, words: r.words });
    learn({ kind: 'remote', did: r.original, words: r.words });
    return r;
  },
};

const cleanName = (v) => { const t = typeof v === 'string' ? v.trim() : ''; return t === '' || [...t].length > NAME_MAX || NAME_BAD.test(t) ? null : t; };
/** The profile operations (the bridge's profiles, profile-*): {ok, …, reload?}; reload: the start page opens the active one. */
const profileOps = {
  list: () => listed(),
  async use(id) {
    if (!byId(id)) return no('profile', `no profile ${JSON.stringify(id)}`);
    picked = true;
    if (id === activeId()) return { ...listed(), reload: true };
    await stopSelf(); client = null;
    registry().active = id; saveRegistry();
    return { ...listed(), reload: true };
  },
  rename(id, name) {
    const p = byId(id), n = cleanName(name);
    if (!p) return no('profile', `no profile ${JSON.stringify(id)}`);
    if (n === null) return no('profile_name', `A name of 1 to ${NAME_MAX} characters.`);
    p.name = n; saveRegistry();
    return listed();
  },
  async add() {
    const r = registry();
    if (r.profiles.length >= LIMIT) return no('profile_limit', `At most ${LIMIT} profiles on this phone: remove one first.`);
    await stopSelf(); client = null;
    const n = r.next, p = { id: `p${n}`, name: `Profile ${n}`, kind: null, did: null, words: null, created: Math.floor(Date.now() / 1000) };
    addedFrom = r.active; r.next = n + 1; r.profiles.push(p); r.active = p.id; picked = true;
    saveRegistry();
    return { ...listed(), reload: true };
  },
  async remove(id, { name, words, proof } = {}) {
    const p = byId(id);
    if (!p) return no('profile', `no profile ${JSON.stringify(id)}`);
    // Not set up by the list, but files there (a first run that went further than the list knows): asked as what they are.
    if (p.kind === null && kindOnDisk(id) !== null) { p.kind = kindOnDisk(id); saveRegistry(); }
    if (p.kind === 'words' && words !== true) return no('profile_words', 'Tick "I have the 25 words": only they bring this identity back.');
    if (p.kind !== null && String(name ?? '').trim() !== p.name) return no('profile_name', `Type the profile's name, ${p.name}, to remove it.`);
    // Its words kept behind a password: the page's proof of that password too.
    const g = p.kind === 'words' ? wordsGuard(id, proof) : null;
    if (g !== null && g !== true) return g;
    const active = id === activeId();
    if (active) { await stopSelf(); client = null; }
    await wipeProfile(id);
    const r = registry();
    r.profiles = r.profiles.filter((x) => x.id !== id);
    if (active) r.active = p.kind === null && addedFrom && byId(addedFrom) ? addedFrom : r.profiles[0]?.id ?? null;
    if (r.active === null) { const n = r.next; r.next = n + 1; r.profiles.push({ id: `p${n}`, name: `Profile ${n}`, kind: null, did: null, words: null, created: Math.floor(Date.now() / 1000) }); r.active = `p${n}`; }
    saveRegistry();
    return { ...listed(), reload: active };
  },
};

// ---- the bridge's rule: which page may ask what
// The start page: all but call and notify; ui.html (a computer's page): call, the profile operations and notify; this phone's
// own page (the local ui, or control ui over the relay): the profile operations (the Profiles sheet, Settings → Profiles,
// the words' among them: Settings → Backup and recovery) and notify.
const PROFILE_OPS = new Set(['profiles', 'profile-use', 'profile-rename', 'profile-add', 'profile-remove', 'computers', 'computer-use', 'computer-add', 'computer-forget', 'words-status', 'words-get', 'words-keep', 'words-drop']);
function bridgeAllows(uri, op, selfOrigin) {
  const page = PROFILE_OPS.has(op) || op === 'notify';
  if (uri.startsWith('sigelo-app://app/start.html')) return op !== 'call' && op !== 'notify';
  if (uri.startsWith('sigelo-app://app/ui.html')) return op === 'call' || page;
  return selfOrigin !== null && uri.startsWith(selfOrigin) && page;
}

// ---- notifications: the name only (Decided: a new message or a payment request; never the text)
const NOTE_TAG = /^(chat|group|pay):[A-Za-z0-9:._-]{1,200}$/, NOTE_KEYS = new Set(['op', 'tag', 'title', 'text', 'cancel']);
const noteLine = (s, min) => typeof s === 'string' && s.length >= min && s.length <= 100 && !/[\p{Cc}\p{Cf}\u2028\u2029]/u.test(s);
const noted = new Set();   // sent, not withdrawn: withdrawn when the app stops (a tap after that would find no app)
/** {tag, title, text} → a Gio.Notification to sink.send(tag, n, what); {tag, cancel: true} → sink.withdraw(tag). */
function notify(m, sink) {
  const no = { ok: false, check: 'notify', message: 'Not a notification.' };
  if (m === null || typeof m !== 'object' || Object.keys(m).some((k) => !NOTE_KEYS.has(k)) || typeof m.tag !== 'string' || !NOTE_TAG.test(m.tag)) return no;
  if (m.cancel !== undefined) {
    if (m.cancel !== true || m.title !== undefined || m.text !== undefined) return no;
    sink.withdraw(m.tag); noted.delete(m.tag);
    return { ok: true };
  }
  if (!noteLine(m.title, 1) || !noteLine(m.text ?? '', 0)) return no;
  const n = new Gio.Notification();
  n.set_title(m.title);
  if (m.text) n.set_body(m.text);
  n.set_priority(Gio.NotificationPriority.NORMAL);
  n.set_default_action_and_target('app.open', new GLib.Variant('s', m.tag));
  sink.send(m.tag, n, { title: m.title, body: m.text ?? '', priority: 'normal', action: 'app.open', target: m.tag });
  noted.add(m.tag);
  return { ok: true };
}
/** The page's open, for a tag checked again: a JSON string literal, nothing else of it reaches the script. */
const openScript = (tag) => (typeof tag === 'string' && NOTE_TAG.test(tag) ? `globalThis.sigeloOpen?.(${JSON.stringify(tag)})` : null);
/** app.open (a notification tapped): present the window, then the page opens the tag (run: the script into the page). */
function openAction(present, run) {
  const a = new Gio.SimpleAction({ name: 'open', parameter_type: new GLib.VariantType('s') });
  a.connect('activate', (_a, v) => { present(); const s = openScript(v?.unpack()); if (s) run(s); });
  return a;
}

// ---- headless checks
const TEST = GLib.getenv('SIGELO_APP_TEST');
if (TEST) {
  let out;
  if (TEST === 'remote') {
    const r = await connect(GLib.getenv('SIGELO_APP_CONTROL') ?? '');
    out = r.ok ? { ...r, state: (await call(client, 'GET', '/api/state')).status, links: (await call(client, 'GET', '/api/links')).status, scope: (await call(client, 'POST', '/api/forget', { contact: 'did:sigelo:zNope' })).status,
      devices: (await call(client, 'GET', '/api/devices')).status } : r;
  } else if (TEST === 'relay') {
    const p = await pairRelay(GLib.getenv('SIGELO_APP_CONTROL') ?? '');
    if (p.ok) {
      // The computer confirms the words (the test does it there) before the page asks anything.
      const go = GLib.getenv('SIGELO_APP_WAIT');
      if (go) { print(JSON.stringify({ paired: p.words })); while (!GLib.file_test(go, GLib.FileTest.EXISTS)) await new Promise((r) => GLib.timeout_add(GLib.PRIORITY_DEFAULT, 100, () => { r(); return GLib.SOURCE_REMOVE; })); }
      const r = await startSelf(null, ['control', 'ui', '--app']);
      if (r.ok) {
        const token = /#t=(\w+)/.exec(r.url)[1], c = child;
        const get = async (path) => { const x = await soupFetch(`http://127.0.0.1:${r.port}${path}`, { headers: { 'X-Sigelo-Token': token } }); return { status: x.status, body: JSON.parse(await x.text()) }; };
        const me = await get('/api/me'), st = await get('/api/state'), st2 = await get('/api/state');
        stopSelf();
        await new Promise((ok) => c.wait_async(null, () => ok()));
        out = { ok: true, words: p.words, kept: hasRelayControl(), me: me.status, did: me.body.did, state: st.status, again: st2.status, exited: c.get_if_exited() };
      } else out = { ...r, words: p.words };
    } else out = p;
  } else if (TEST === 'restore') {
    // The words from the test's environment here only; the start page hands them over the bridge.
    out = await restore({ words: GLib.getenv('SIGELO_APP_WORDS') ?? '', name: 'gphone', height: GLib.getenv('SIGELO_APP_HEIGHT') ?? '', net: 'stagenet', elsewhere: GLib.getenv('SIGELO_APP_ELSEWHERE') === '1' });
    out.standby = standbyName();
    out.refused = standbyRefusal()?.standby === true;
    if (GLib.getenv('SIGELO_APP_TAKE') === '1') out.take = await take();
  } else if (TEST === 'words') {
    // The words password's keyring side (the page encrypts; here the blob and its check from the test, made by words-lock.mjs).
    const blob = GLib.getenv('SIGELO_APP_BLOB') ?? '', check = GLib.getenv('SIGELO_APP_CHECK') ?? '', bad = 'f'.repeat(64);
    const before = wordsOps.status({});
    out = { before: [before.here, before.kept, before.keyring] };
    out.noIdentity = wordsOps.keep({ blob, check }).check;
    const r = await restore({ words: GLib.getenv('SIGELO_APP_WORDS') ?? '', name: 'gphone', height: '', net: 'stagenet', elsewhere: GLib.getenv('SIGELO_APP_ELSEWHERE') === '1' });
    if (r.ok) learn({ kind: 'words' });
    const st = wordsOps.status({});
    out.restored = [r.ok, st.here, st.kept];
    out.junk = wordsOps.keep({ blob: GLib.base64_encode(enc.encode('{"v":"x"}')), check }).check;
    out.kept = wordsOps.keep({ blob, check }).ok;
    out.get = wordsOps.get({}).blob === blob && wordsOps.get({ id: 'p1' }).blob === blob;
    out.status = [wordsOps.status({}).kept, wordsOps.status({ id: 'p1' }).kept, wordsOps.status({ id: 'p9' }).check];
    out.overwrite = [wordsOps.keep({ blob, check: bad }).check, wordsOps.keep({ blob, check: bad, proof: bad }).check, keptWords.get()?.check === check];
    out.drop = [wordsOps.drop({}).check, wordsOps.drop({ proof: bad }).check];
    out.take = (await take(bad)).check ?? null;
    out.remove = [(await profileOps.remove('p1', { name: 'Profile 1', words: true })).check, (await profileOps.remove('p1', { name: 'Profile 1', words: true, proof: bad })).check];
    out.dropped = [wordsOps.drop({ proof: check }).ok, keptWords.get() === null, wordsOps.get({}).check];
    out.again = wordsOps.keep({ blob, check }).ok;
    const rm = await profileOps.remove('p1', { name: 'Profile 1', words: true, proof: check });
    out.removed = [rm.ok, keptWords.get('p1') === null, exists(identityPath('p1'))];
    keptWords.clear('p1');
  } else if (TEST === 'create') {
    // The create flow as the start page drives it; the answers are read from the words in this process only.
    const n = await newWords('stagenet');
    out = { new: n.ok, count: n.words?.length ?? 0, vault: n.vault ?? null };
    if (n.ok) {
      const q1 = quiz(), bad = await create({ answers: q1.asked.map((p, i) => (i !== 1 ? fresh.words[p - 1] : fresh.words[p % 25] === fresh.words[p - 1] ? 'zzz' : fresh.words[p % 25])), name: 'gphone' });
      out.wrong = bad.wrong ?? null;
      out.unasked = (await create({ answers: ['a', 'b', 'c'], name: 'gphone' })).ok;
      const q2 = quiz(), good = await create({ answers: q2.asked.map((p) => fresh.words[p - 1].toUpperCase()), name: 'gphone' });
      out = { ...out, ...good, kept: fresh !== null, again: (await create({ answers: ['a', 'b', 'c'], name: 'gphone' })).ok };
    }
  } else if (TEST === 'profiles') {
    // p1 restored (the install before profiles), the list migrated; p2 added and restored into its own files; its page;
    // rename; the limit; a switch back; p2 removed (its files and keyring item gone, p1's kept). Words from the environment.
    const files = (d = GLib.path_get_dirname(baseIdentity())) => { const it = Gio.File.new_for_path(d).enumerate_children('standard::name', 0, null), n = []; for (let i; (i = it.next_file(null)) !== null;) n.push(i.get_name()); return n.sort(); };
    reg = null;
    const r1 = await restore({ words: GLib.getenv('SIGELO_APP_WORDS') ?? '', name: 'gphone', height: '', net: 'stagenet', elsewhere: false });
    removeTree(registryPath()); reg = null;   // the list as an install before profiles had it: none
    out = { p1restored: r1.ok, migrated: listed().profiles.map((p) => `${p.id}:${p.name}:${p.kind}`) };
    const a = await profileOps.add();
    out.added = { active: a.active, ids: a.profiles.map((p) => p.id), identity: identityPath(), control: controlPath(), standby: standbyPath(), attr: attrOf(activeId(), activeComputer()).kind };
    const r2 = await restore({ words: GLib.getenv('SIGELO_APP_WORDS2') ?? '', name: 'gtab', height: '', net: 'stagenet', elsewhere: false });
    if (r2.ok) learn({ kind: 'words' });
    const s2 = await startSelf(identityPath());
    if (s2.ok) { await learnPage(s2.port, s2.url, 'words'); await stopSelf(); }
    // This phone as p2's device (device seat init places it in the agents' directory; offline here it may not get so
    // far): planted as seat init writes it when it is not there, a worker of p2's keeper, its file wrapped under its DID.
    {
      const ag = GLib.build_filenamev([GLib.get_user_config_dir(), 'moadim']), f = GLib.build_filenamev([ag, 'sigelo.gtab.local.json']), kf = identityPath('p2').replace(/\.json$/, '.keeper.json');
      if (!exists(f)) {
        const k = JSON.parse(dec.decode(GLib.file_get_contents(kf)[1])), w = 'did:sigelo:zGtabWorker1111111111111111111111111111111111';
        k.workers['0'] = { name: 'gtab', original: w, did: w, placed: 'device', via: 'here', rank: 'full' };
        GLib.file_set_contents(kf, JSON.stringify(k));
        GLib.mkdir_with_parents(ag, 0o700); GLib.file_set_contents(f, JSON.stringify({ secret: { provider: 'keychain', account: w } }));
        await new Promise((ok) => { const c = Gio.Subprocess.new(['secret-tool', 'store', '--label=x', 'service', 'sigelo', 'account', w], Gio.SubprocessFlags.STDIN_PIPE); c.communicate_utf8_async('k', null, () => ok()); });
      }
    }
    out.p2 = { restored: r2.ok, page: s2.ok, message: s2.message ?? null, ...byId('p2'), account: accountOf('p2'), p1account: accountOf('p1'), files: files(), agents: files(GLib.build_filenamev([GLib.get_user_config_dir(), 'moadim'])) };
    out.rename = [profileOps.rename('p2', '  Work ').ok, profileOps.rename('p2', '').check, profileOps.rename('p2', 'x'.repeat(25)).check, byId('p2').name];
    for (let i = 0; i < 6; i++) await profileOps.add();
    const ninth = await profileOps.add();
    out.limit = { count: registry().profiles.length, ninth: ninth.check ?? null };
    for (const p of registry().profiles.filter((x) => x.kind === null)) await profileOps.remove(p.id, {});
    const back = await profileOps.use('p1');
    out.switched = { active: back.active, identity: identityPath(), reload: back.reload, picked };
    out.refused = [(await profileOps.remove('p2', { name: 'Work' })).check, (await profileOps.remove('p2', { name: 'work', words: true })).check];
    const rm = await profileOps.remove('p2', { name: 'Work', words: true });
    out.removed = { ok: rm.ok, reload: rm.reload, ids: rm.profiles.map((p) => p.id), files: files(), agents: files(GLib.build_filenamev([GLib.get_user_config_dir(), 'moadim'])), active: activeId() };
    out.registryMode = Gio.File.new_for_path(registryPath()).query_info('unix::mode', 0, null).get_attribute_uint32('unix::mode') & 0o777;
  } else if (TEST === 'computers') {
    // P2, two parts. LAN (SIGELO_APP_CONTROLS: [a computer of the operator, a second of the same, one of another]): p1 as before
    // P2 (one computer, its text under the kind of before) migrated as c1; add; the second paired as c2 (its own item); the
    // third refused other_operator; Cancel; switch; forget c2; the profile removed (every computer's item gone).
    // Relay (SIGELO_APP_CODES: [a code of the operator, a code of another]): c1 over the relay, the other refused, forget.
    const lans = JSON.parse(GLib.getenv('SIGELO_APP_CONTROLS') ?? 'null'), codes = JSON.parse(GLib.getenv('SIGELO_APP_CODES') ?? 'null');
    out = {};
    if (lans) {
      const [a1, a2, o] = lans;
      removeTree(registryPath()); reg = null;
      keyring.set(controlText(a1), 'p1', 'c1');
      out.migrated = { kind: byId('p1').kind, computers: comps().list.map((x) => `${x.id}:${x.via}`), active: comps().active, items: keyring.held() };
      const r1 = await computerOps.openLan();
      out.c1 = { ok: r1.ok, did: r1.original, learned: comps().list[0].did, profile: byId('p1').did, used: comps().list[0].last_used > 0 };
      const ad = await computerOps.add();
      out.adding = { reload: ad.reload, adding: comps().adding };
      const r2 = await computerOps.pairLan(a2);
      out.c2 = { ok: r2.ok, computer: r2.computer, active: comps().active, adding: comps().adding, same: r2.original === r1.original, items: keyring.held(), c1: keyring.get('p1', 'c1') === controlText(a1), c2: keyring.get('p1', 'c2') === controlText(a2) };
      await computerOps.add();
      const r3 = await computerOps.pairLan(o);
      out.other = { ok: r3.ok, check: r3.check ?? null, message: r3.message ?? null, count: comps().list.length, items: keyring.held().length, next: comps().next, client: client === null };
      const cn = computerOps.cancel();
      const u = await computerOps.use('c1'), r4 = await computerOps.openLan();
      out.switched = { cancel: cn.adding, active: comps().active, ok: r4.ok, reload: u.reload, unknown: (await computerOps.use('c9')).check };
      const f = await computerOps.forget('c2');
      out.forgot = { revoke: f.revoke, ids: comps().list.map((x) => x.id), c2: keyring.get('p1', 'c2'), c1: keyring.get('p1', 'c1') !== null, reload: f.reload };
      out.listed = computerOps.list();
      await computerOps.add(); await computerOps.pairLan(a2);
      out.beforeWipe = keyring.held().length;
      const rm = await profileOps.remove('p1', { name: 'Profile 1' });
      out.wiped = { ok: rm.ok, items: keyring.held().length, profiles: rm.profiles?.map((p) => `${p.id}:${p.kind}`) };
    }
    if (codes) {
      const [same, other] = codes;
      removeTree(registryPath()); reg = null;
      const p1 = await computerOps.pairRelay(same);
      out.relay = { ok: p1.ok, message: p1.message ?? null, computer: p1.computer, file: exists(controlPath('p1', 'c1')), list: comps().list.map((x) => `${x.id}:${x.via}:${x.where}`), did: comps().list[0]?.did ?? null };
      learn({ did: comps().list[0]?.did });
      await computerOps.add();
      const p2 = await computerOps.pairRelay(other);
      out.relayOther = { ok: p2.ok, check: p2.check ?? null, message: p2.message ?? null, file: exists(controlPath('p1', 'c2')), count: comps().list.length };
      computerOps.cancel();
      const f = await computerOps.forget('c1');
      out.relayForgot = { file: exists(controlPath('p1', 'c1')), count: comps().list.length, active: comps().active, revoke: f.revoke };
    }
  } else if (TEST === 'notify') {
    // The notify op as the page asks it (SIGELO_APP_NOTES: the messages), recorded instead of sent (no notification server);
    // the bridge's rule for it; then app.open activated as a tap does, its script run here against a recording sigeloOpen.
    const sent = [], gone = [], opened = [], ran = [];
    let presented = 0;
    const sink = { send: (id, n, what) => sent.push({ id, notification: n instanceof Gio.Notification, ...what }), withdraw: (id) => gone.push(id) };
    out = { results: JSON.parse(GLib.getenv('SIGELO_APP_NOTES') ?? '[]').map((m) => notify(m, sink)), sent, gone, pending: [...noted] };
    const so = 'http://127.0.0.1:5000/';
    out.allows = ['sigelo-app://app/ui.html', `${so}#t=x`, 'sigelo-app://app/start.html', 'http://127.0.0.1:5001/'].map((u) => bridgeAllows(u, 'notify', so));
    globalThis.sigeloOpen = (tag) => opened.push(tag);
    const a = openAction(() => { presented++; }, (s) => { ran.push(s); (0, eval)(s); });
    for (const t of JSON.parse(GLib.getenv('SIGELO_APP_TAPS') ?? '[]')) a.activate(new GLib.Variant('s', t));
    out = { ...out, presented, opened, ran, param: a.get_parameter_type()?.dup_string() ?? null };
  } else if (TEST === 'self') {
    const r = await startSelf(GLib.getenv('SIGELO_APP_IDENTITY'));
    if (r.ok) {
      const token = /#t=(\w+)/.exec(r.url)[1], p = child;
      const me = await soupFetch(`http://127.0.0.1:${r.port}/api/me`, { headers: { 'X-Sigelo-Token': token } });
      const devices = await soupFetch(`http://127.0.0.1:${r.port}/api/devices`, { headers: { 'X-Sigelo-Token': token } });
      const qr = await soupFetch(`http://127.0.0.1:${r.port}/qr-decode.mjs`);
      const relay = GLib.getenv('SIGELO_APP_RELAY') ? await setRelay(r.port, r.url, GLib.getenv('SIGELO_APP_RELAY')) : null;
      stopSelf();
      await new Promise((ok) => p.wait_async(null, () => ok()));
      out = { ok: true, me: me.status, devices: devices.status, devices_list: JSON.parse(await devices.text()).devices?.length ?? null, decoder: qr.status, exited: p.get_if_exited(), code: p.get_exit_status(),
        ...(relay && { relay: relay.status, setting: relay.body.relay ?? relay.body.error?.message }) };
    } else out = r;
  }
  print(JSON.stringify(out));
  System.exit(0);
}

// ---- the window
const { default: Gtk } = await import('gi://Gtk?version=4.0');
const { default: Adw } = await import('gi://Adw?version=1');
const { default: WebKit } = await import('gi://WebKit?version=6.0');
const { default: JSC } = await import('gi://JavaScriptCore?version=6.0');

const TYPES = { html: 'text/html', js: 'text/javascript', mjs: 'text/javascript', css: 'text/css', svg: 'image/svg+xml', json: 'application/json' };
// sigelo-app://app/<file>: the files of web/ by name, nothing else (no directories, no dot files).
function serve(req) {
  const name = req.get_path().replace(/^\//, ''), ext = /\.([a-z]+)$/.exec(name)?.[1];
  const file = GLib.build_filenamev([WEB, name]);
  if (req.get_uri().split('/')[2] !== 'app' || !/^[a-z0-9][a-z0-9-]*\.[a-z]+$/.test(name) || !TYPES[ext] || !GLib.file_test(file, GLib.FileTest.IS_REGULAR)) {
    req.finish_error(new GLib.Error(Gio.IOErrorEnum, Gio.IOErrorEnum.NOT_FOUND, 'not found'));
    return;
  }
  const bytes = GLib.file_get_contents(file)[1];
  const res = WebKit.URISchemeResponse.new(Gio.MemoryInputStream.new_from_bytes(new GLib.Bytes(bytes)), bytes.length);
  res.set_content_type(TYPES[ext]);
  const h = new Soup.MessageHeaders(Soup.MessageHeadersType.RESPONSE);
  h.append('Content-Security-Policy', `default-src 'self'; script-src 'self'${ext === 'html' ? inlineHashes(dec.decode(bytes)) : ''}; img-src 'self' blob: data:; media-src 'self' blob: mediastream:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`);
  h.append('Cache-Control', 'no-store');
  res.set_http_headers(h);
  req.finish_with_response(res);
}
/** The import map is the one inline script start.html has: allowed by its hash, nothing else inline. */
function inlineHashes(html) {
  return [...html.matchAll(/<script type="importmap">([\s\S]*?)<\/script>/g)].map(([, s]) => {
    const hex = GLib.compute_checksum_for_string(GLib.ChecksumType.SHA256, s, -1);
    return ` 'sha256-${GLib.base64_encode(Uint8Array.from(hex.match(/../g), (x) => parseInt(x, 16)))}'`;
  }).join('');
}

// One instance (a second start presents the first): a notification's tap reaches the app by its name on the session bus.
const app = new Adw.Application({ application_id: ID, flags: Gio.ApplicationFlags.DEFAULT_FLAGS ?? Gio.ApplicationFlags.FLAGS_NONE });
let shown = null;

app.connect('activate', () => {
  if (shown) { shown.present(); return; }
  const DEV = GLib.getenv('SIGELO_APP_DEVTOOLS') === '1';   // the inspector, and the page's console on stdout
  const ctx = new WebKit.WebContext();
  ctx.register_uri_scheme('sigelo-app', serve);
  const sm = ctx.get_security_manager();
  sm.register_uri_scheme_as_secure('sigelo-app');
  sm.register_uri_scheme_as_cors_enabled('sigelo-app');
  const ucm = new WebKit.UserContentManager();
  ucm.register_script_message_handler_with_reply('sigelo', null);
  const settings = new WebKit.Settings({ enable_media_stream: true, enable_developer_extras: DEV, enable_write_console_messages_to_stdout: DEV, media_playback_requires_user_gesture: false, enable_back_forward_navigation_gestures: false });
  const view = new WebKit.WebView({ web_context: ctx, user_content_manager: ucm, settings, vexpand: true, hexpand: true });
  let selfOrigin = null;   // http://127.0.0.1:<port>/ while this phone's page runs
  const ours = (uri) => uri.startsWith('sigelo-app://app/') || (selfOrigin !== null && uri.startsWith(selfOrigin));
  const startPage = (why) => { stopSelf(); selfOrigin = null; client = null; view.load_uri(`sigelo-app://app/start.html${why ? '#' + encodeURIComponent(why) : ''}`); };

  // The bridge: pages of sigelo-app://app/ and this phone's own page (bridgeAllows).
  const sink = { send: (id, n) => app.send_notification(id, n), withdraw: (id) => app.withdraw_notification(id) };
  const reopen = (r) => { if (r?.ok && r.reload) GLib.idle_add(GLib.PRIORITY_DEFAULT, () => { startPage(); return GLib.SOURCE_REMOVE; }); return r; };
  const ops = {
    async self({ relay }) {
      const no = standbyRefusal();
      if (no) return no;
      const r = await startSelf(identityPath());
      if (!r.ok) return r;
      void learnPage(r.port, r.url, 'words');
      if (typeof relay === 'string') {
        const s = await setRelay(r.port, r.url, relay);
        if (s.status !== 200) { stopSelf(); return { ok: false, message: s.body?.error?.message ?? `relay: HTTP ${s.status}` }; }
      }
      selfOrigin = `http://127.0.0.1:${r.port}/`;
      GLib.idle_add(GLib.PRIORITY_DEFAULT, () => { view.load_uri(r.url); return GLib.SOURCE_REMOVE; });
      return { ok: true };
    },
    // Pairing a computer (the first, or one added): on the LAN opened at once; over the relay the words, then relay.
    async connect({ text }) {
      const r = await computerOps.pairLan(text);
      if (!r.ok) return r;
      GLib.idle_add(GLib.PRIORITY_DEFAULT, () => { view.load_uri('sigelo-app://app/ui.html'); return GLib.SOURCE_REMOVE; });
      return r;
    },
    async pair({ text }) { return computerOps.pairRelay(text); },
    async relay() {
      const r = await startSelf(null, ['control', 'ui', '--app']);
      if (!r.ok) return r;
      void learnPage(r.port, r.url, 'remote');
      selfOrigin = `http://127.0.0.1:${r.port}/`;
      GLib.idle_add(GLib.PRIORITY_DEFAULT, () => { view.load_uri(r.url); return GLib.SOURCE_REMOVE; });
      return { ok: true };
    },
    async saved() {
      if (byId(activeId())?.kind === null && kindOnDisk(activeId()) !== null) learn({ kind: kindOnDisk(activeId()) });
      const c = comps(), remote = byId(activeId())?.kind === 'remote';
      return { identity: GLib.file_test(identityPath(), GLib.FileTest.IS_REGULAR), text: computerNow() !== null && !c.adding, remote, adding: remote && (c.adding === true || !c.list.length), computers: c.list.length, keyring: Secret !== null, standby: standbyName() !== null };
    },
    async restore(o) { const r = await restore({ words: o.words, name: o.name, height: o.height, net: o.net, elsewhere: o.elsewhere }); if (r.ok) learn({ kind: 'words' }); return r; },
    async newwords({ net }) { return newWords(net); },
    async quiz() { return quiz(); },
    async create({ answers, name }) { const r = await create({ answers, name }); if (r.ok) learn({ kind: 'words' }); return r; },
    async discard() { return discard(); },
    async take({ proof }) { return take(proof); },
    // After the words were pasted: the clipboard (and the primary selection) emptied.
    async clipclear() { try { view.get_clipboard().set_content(null); view.get_primary_clipboard().set_content(null); } catch {} return { ok: true }; },
    // The computer in use: over the relay its control's page, on the LAN its sealed calls.
    async resume() {
      const cur = computerNow();
      if (!cur) return { ok: false, message: 'No computer kept.' };
      if (cur.via === 'relay') return ops.relay();
      const r = await computerOps.openLan();
      if (r.ok) GLib.idle_add(GLib.PRIORITY_DEFAULT, () => { view.load_uri('sigelo-app://app/ui.html'); return GLib.SOURCE_REMOVE; });
      return r;
    },
    async forget() { const cur = computerNow(); if (cur) await computerOps.forget(cur.id); return { ok: true, revoke: REVOKE }; },
    // Computers (P2): Me → Connect → Computers, and the start page's pairing (Cancel).
    async computers() { return computerOps.list(); },
    async 'computer-use'({ id }) { return reopen(await computerOps.use(String(id))); },
    async 'computer-add'() { return reopen(await computerOps.add()); },
    async 'computer-add-cancel'() { return reopen(computerOps.cancel()); },
    async 'computer-forget'({ id }) { return reopen(await computerOps.forget(String(id))); },
    // Profiles: after a switch, an add, or the active one removed, the start page opens the active profile.
    async profiles() { return profileOps.list(); },
    async 'profile-use'({ id }) { return reopen(await profileOps.use(String(id))); },
    async 'profile-rename'({ id, name }) { return profileOps.rename(String(id), name); },
    async 'profile-add'() { return reopen(await profileOps.add()); },
    async 'profile-remove'({ id, name, words, proof }) { return reopen(await profileOps.remove(String(id), { name, words: words === true, proof })); },
    // The words password (Me → Security, the offer after a create or a restore, the guards above).
    async 'words-status'(m) { return wordsOps.status(m); },
    async 'words-get'(m) { return wordsOps.get(m); },
    async 'words-keep'(m) { return wordsOps.keep(m); },
    async 'words-drop'(m) { return wordsOps.drop(m); },
    // A new message or a payment request: the name only (notify above checks it).
    async notify(m) { return notify(m, sink); },
    async call({ method, path, body }) {
      if (client === null) return { status: 403, body: { error: { check: 'remote', message: 'Not connected to a computer.' } } };
      return call(client, String(method), String(path), body);
    },
  };
  ucm.connect('script-message-with-reply-received::sigelo', (_m, value, reply) => {
    const uri = view.get_uri() ?? '';
    let msg = null;
    try { msg = JSON.parse(value.to_json(0)); } catch {}
    const op = msg?.op, allowed = bridgeAllows(uri, op, selfOrigin);
    const p = allowed && Object.hasOwn(ops, op) ? ops[op](msg) : Promise.resolve({ ok: false, message: 'refused' });
    p.catch((e) => ({ ok: false, message: String(e?.message ?? e) }))
      .then((r) => reply.return_value(JSC.Value.new_from_json(value.get_context(), JSON.stringify(r ?? null))));
    return true;
  });

  // Navigation: our pages only; a link elsewhere opens in the browser, never here.
  view.connect('decide-policy', (_v, d, type) => {
    if (type === WebKit.PolicyDecisionType.RESPONSE) return false;
    const uri = d.get_navigation_action().get_request().get_uri();
    if (type === WebKit.PolicyDecisionType.NAVIGATION_ACTION && ours(uri)) { d.use(); return true; }
    d.ignore();
    if (/^https?:\/\//.test(uri) && !ours(uri)) new Gtk.UriLauncher({ uri }).launch(win, null, null);
    return true;
  });
  // Camera for scanning only (the start page, this phone's Devices view); never the microphone, nothing else.
  view.connect('permission-request', (_v, req) => {
    const camera = req instanceof WebKit.UserMediaPermissionRequest && req.is_for_video_device && !req.is_for_audio_device, uri = view.get_uri() ?? '';
    if (camera && (uri.startsWith('sigelo-app://app/start.html') || (selfOrigin !== null && uri.startsWith(selfOrigin)))) req.allow(); else req.deny();
    return true;
  });
  view.connect('load-failed', (_v, _e, uri, err) => { if (selfOrigin !== null && uri.startsWith(selfOrigin)) startPage(`This phone's page stopped: ${err.message}`); return false; });

  const menu = new Gio.Menu();
  menu.append('Start page', 'app.start');
  menu.append('Forget this computer', 'app.forget');
  const header = new Adw.HeaderBar({ title_widget: new Adw.WindowTitle({ title: 'sigelo' }) });
  header.pack_end(new Gtk.MenuButton({ icon_name: 'open-menu-symbolic', menu_model: menu, tooltip_text: 'Menu' }));
  const tv = new Adw.ToolbarView({ content: view });
  tv.add_top_bar(header);
  const win = new Adw.ApplicationWindow({ application: app, title: 'sigelo', default_width: 420, default_height: 820, content: tv });
  const action = (name, fn) => { const a = new Gio.SimpleAction({ name }); a.connect('activate', fn); app.add_action(a); };
  action('start', () => startPage());
  action('forget', () => {
    const cur = computerNow();
    if (!cur) { startPage('No computer in use.'); return; }
    void computerOps.forget(cur.id).then(() => startPage(`This phone no longer keeps ${cur.name}'s control key. Revoke it there too: ${REVOKE}.`));
  });
  // A notification tapped: the window, then the page (ours only) opens that chat, group or request.
  app.add_action(openAction(() => win.present(), (s) => {
    if (!ours(view.get_uri() ?? '')) return;
    view.evaluate_javascript(s, -1, null, null, null, (v, res) => { try { v.evaluate_javascript_finish(res); } catch {} });
  }));
  win.connect('close-request', () => { stopSelf(); shown = null; return false; });
  shown = win;
  startPage();
  win.present();
});
app.connect('shutdown', () => { stopSelf(); for (const id of noted) app.withdraw_notification(id); noted.clear(); });
await app.runAsync([System.programInvocationName]);   // async: promises and imports keep running
