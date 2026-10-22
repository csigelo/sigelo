#!/usr/bin/env -S gjs -m
// SPDX-License-Identifier: MIT
// sigelo on a Linux phone (design/apps.md §7): a GTK 4 + libadwaita window around a WebKitGTK 6.0 view
// of the page of `sigelo-agent ui` (adapters/moadim/UI-API.md), in one of two forms:
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
// Start page (web/start.html): pick a form, or scan/paste a computer's SIGELO:UI: or SIGELO:CTL: text.
// Headless checks (apps/gtk/test-gtk.mjs): SIGELO_APP_TEST=remote|self, no window.
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

// ---- remote: the control's text in the keyring
let Secret = null;
try { Secret = (await import('gi://Secret?version=1')).default; } catch {}
const SCHEMA = Secret && Secret.Schema.new(`${ID}.Control`, Secret.SchemaFlags.NONE, { kind: Secret.SchemaAttributeType.STRING });
const ATTR = { kind: 'sigelo-remote/0' };
const keyring = {
  get() { try { return Secret?.password_lookup_sync(SCHEMA, ATTR, null) ?? null; } catch { return null; } },
  set(t) { try { return Secret?.password_store_sync(SCHEMA, ATTR, Secret.COLLECTION_DEFAULT, 'sigelo: control of a computer', t, null) ?? false; } catch { return false; } },
  clear() { try { Secret?.password_clear_sync(SCHEMA, ATTR, null); } catch {} },
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
  return { ok: true, did: r.body.did, where: `${c.host}:${c.port}` };
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
const readLine = (st) => new Promise((ok) => st.read_line_async(GLib.PRIORITY_DEFAULT, null, (s, r) => {
  try { const [line] = s.read_line_finish_utf8(r); ok(line); } catch { ok(null); }
}));
let child = null;
/** → {ok, url} or {ok: false, message}: the page's URL (with its token) from the child's first stdout line. */
async function startSelf(identity, verb = ['ui', '--app', ...(identity ? ['--identity', identity] : [])]) {
  stopSelf();
  const argv = [...agentArgv(), ...verb];
  let p;
  try { p = Gio.Subprocess.new(argv, Gio.SubprocessFlags.STDIN_PIPE | Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE); } catch (e) {
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
/** sigelo-agent once, to its end → {status, out, err}. */
async function runAgent(args) {
  let p;
  try { p = Gio.Subprocess.new([...agentArgv(), ...args], Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE); } catch (e) { return { status: -1, out: '', err: e.message }; }
  const [out, err] = await new Promise((ok) => p.communicate_utf8_async(null, null, (s, r) => { try { const [, o, e] = s.communicate_utf8_finish(r); ok([o ?? '', e ?? '']); } catch (e) { ok(['', String(e.message)]); } }));
  return { status: p.get_exit_status(), out, err };
}
// Over the relay: this phone's control (sigelo-agent-control.ts), its file where sigelo-agent keeps it.
const controlPath = () => GLib.getenv('SIGELO_CONTROL') ?? GLib.build_filenamev([GLib.get_home_dir(), '.config', 'sigelo', 'control.local.json']);
const hasRelayControl = () => GLib.file_test(controlPath(), GLib.FileTest.IS_REGULAR);
/** A SIGELO:CTL: text paired with a new control identity → {ok, words} or {ok: false, message}. */
async function pairRelay(text) {
  const t = String(text ?? '').trim();
  if (!/^SIGELO:CTL:/i.test(t)) return { ok: false, message: 'Not a SIGELO:CTL: text.' };
  const r = await runAgent(['control', 'pair', t, '--force']);
  if (r.status !== 0) return { ok: false, message: (r.err.trim().split('\n').at(-1) ?? '').replace(/^sigelo-agent: /, '') || `sigelo-agent control pair ended (exit ${r.status})` };
  try { const j = JSON.parse(r.out); return { ok: true, words: j.words, operator: j.operator }; } catch { return { ok: false, message: r.out.slice(0, 300) }; }
}
function stopSelf() {
  if (!child) return;
  try { child.get_stdin_pipe().close(null); } catch {}
  try { child.send_signal(15); } catch {}
  child = null;
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
  } else if (TEST === 'self') {
    const r = await startSelf(GLib.getenv('SIGELO_APP_IDENTITY'));
    if (r.ok) {
      const token = /#t=(\w+)/.exec(r.url)[1], p = child;
      const me = await soupFetch(`http://127.0.0.1:${r.port}/api/me`, { headers: { 'X-Sigelo-Token': token } });
      const devices = await soupFetch(`http://127.0.0.1:${r.port}/api/devices`, { headers: { 'X-Sigelo-Token': token } });
      const qr = await soupFetch(`http://127.0.0.1:${r.port}/qr-decode.mjs`);
      stopSelf();
      await new Promise((ok) => p.wait_async(null, () => ok()));
      out = { ok: true, me: me.status, devices: devices.status, devices_list: JSON.parse(await devices.text()).devices?.length ?? null, decoder: qr.status, exited: p.get_if_exited(), code: p.get_exit_status() };
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

const TYPES = { html: 'text/html', js: 'text/javascript', mjs: 'text/javascript', css: 'text/css', svg: 'image/svg+xml' };
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

const app = new Adw.Application({ application_id: ID, flags: Gio.ApplicationFlags.NON_UNIQUE });
const args = System.programArgs, at = args.indexOf('--identity'), identity = at >= 0 ? args[at + 1] ?? null : null;   // else ui's default

app.connect('activate', () => {
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

  // The bridge: only pages of sigelo-app://app/ may use it; ui.html only for `call`.
  const ops = {
    async self() {
      const r = await startSelf(identity);
      if (!r.ok) return r;
      selfOrigin = `http://127.0.0.1:${r.port}/`;
      GLib.idle_add(GLib.PRIORITY_DEFAULT, () => { view.load_uri(r.url); return GLib.SOURCE_REMOVE; });
      return { ok: true };
    },
    async connect({ text }) {
      const r = await connect(text);
      if (!r.ok) return r;
      const kept = keyring.set(controlText(text));
      GLib.idle_add(GLib.PRIORITY_DEFAULT, () => { view.load_uri('sigelo-app://app/ui.html'); return GLib.SOURCE_REMOVE; });
      return { ...r, kept };
    },
    async pair({ text }) { return pairRelay(text); },
    async relay() {
      const r = await startSelf(null, ['control', 'ui', '--app']);
      if (!r.ok) return r;
      selfOrigin = `http://127.0.0.1:${r.port}/`;
      GLib.idle_add(GLib.PRIORITY_DEFAULT, () => { view.load_uri(r.url); return GLib.SOURCE_REMOVE; });
      return { ok: true };
    },
    async saved() { return { text: keyring.get() !== null || hasRelayControl(), keyring: Secret !== null }; },
    async resume() {
      if (hasRelayControl()) return ops.relay();
      const t = keyring.get(); return t === null ? { ok: false, message: 'No computer kept.' } : ops.connect({ text: t });
    },
    async forget() { keyring.clear(); if (hasRelayControl()) await runAgent(['control', 'forget']); return { ok: true }; },
    async call({ method, path, body }) {
      if (client === null) return { status: 403, body: { error: { check: 'remote', message: 'Not connected to a computer.' } } };
      return call(client, String(method), String(path), body);
    },
  };
  ucm.connect('script-message-with-reply-received::sigelo', (_m, value, reply) => {
    const uri = view.get_uri() ?? '';
    let msg = null;
    try { msg = JSON.parse(value.to_json(0)); } catch {}
    const op = msg?.op, allowed = uri.startsWith('sigelo-app://app/start.html') ? op !== 'call' : uri.startsWith('sigelo-app://app/ui.html') && op === 'call';
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
  menu.append('Forget the computer', 'app.forget');
  const header = new Adw.HeaderBar({ title_widget: new Adw.WindowTitle({ title: 'sigelo' }) });
  header.pack_end(new Gtk.MenuButton({ icon_name: 'open-menu-symbolic', menu_model: menu, tooltip_text: 'Menu' }));
  const tv = new Adw.ToolbarView({ content: view });
  tv.add_top_bar(header);
  const win = new Adw.ApplicationWindow({ application: app, title: 'sigelo', default_width: 420, default_height: 820, content: tv });
  const action = (name, fn) => { const a = new Gio.SimpleAction({ name }); a.connect('activate', fn); app.add_action(a); };
  action('start', () => startPage());
  action('forget', () => { keyring.clear(); if (hasRelayControl()) void runAgent(['control', 'forget']); startPage('This phone no longer keeps the computer\'s text. Revoke it there too: sigelo-agent ui --revoke-control <name>.'); });
  win.connect('close-request', () => { stopSelf(); return false; });
  startPage();
  win.present();
});
app.connect('shutdown', () => stopSelf());
await app.runAsync([System.programInvocationName]);   // async: promises and imports keep running
