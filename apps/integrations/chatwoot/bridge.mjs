// SPDX-License-Identifier: MIT
// sigelo-chatwoot: a sigelo identity as a Chatwoot API inbox; each allowed contact one Chatwoot contact and conversation.
// In: the files `sigelo-agent watch --spool <dir>` writes → incoming messages (Application API).
// Out: Chatwoot's signed `message_created` webhook (an agent's reply) → `sigelo-agent send <did> - --re <id>`.
// No sigelo key here: the watcher is the only relay process; this reads its spool and runs its CLI.
import { spawn } from 'node:child_process';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';

const KEEP_S = 30 * 86400;            // the carrier knows a message id 30 days; so long here
const SKEW_S = 300;                   // a webhook signed more than 5 minutes off: refused (Chatwoot's advice)
const BODY_MAX = 1 << 20;
export const BACKOFF = { first: 2000, max: 300000 };
const TAG = 'sigelo:';                // source_id of every message the bridge posts

export class ChatwootError extends Error {
  constructor(status, what, body) { super(`chatwoot ${what}: HTTP ${status} ${String(body).slice(0, 200)}`); this.status = status; }
}

/** The contact's name in a spool item: `name` for a message, `contact` for a file (its `name` is the file's). */
const nameOf = (item) => { const n = item.type === 'file' ? item.contact : item.name ?? item.contact; return typeof n === 'string' ? n : undefined; };

/** message_type as a word: the webhook sends 'outgoing', the REST messages list 1 (Chatwoot 4.20.1). */
const TYPES = ['incoming', 'outgoing', 'activity', 'template'];
export const kindOf = (t) => (typeof t === 'number' || (typeof t === 'string' && /^\d$/.test(t)) ? TYPES[Number(t)] : t);

/** The map file beside the identity: <identity minus .json>.chatwoot.json. */
export const mapPathOf = (identity) => `${identity.replace(/\.json$/, '')}.chatwoot.json`;

export class Bridge {
  /**
   * o: { base, account, inbox, token, secret, allow: [name|did], identity, spool, send?, fetch?, now?, log? }
   * send(did, text, re) → Promise<{ ok, detail }>: default runs `sigelo-agent send` (o.cli, default 'sigelo-agent').
   */
  constructor(o) {
    for (const k of ['base', 'account', 'inbox', 'token', 'secret', 'identity', 'spool']) if (o[k] === undefined || o[k] === '') throw new Error(`config: ${k} is missing`);
    this.o = o;
    this.base = o.base.replace(/\/+$/, '');
    this.allow = new Set(o.allow ?? []);
    this.fetch = o.fetch ?? globalThis.fetch;
    this.now = o.now ?? (() => Date.now());
    this.log = o.log ?? ((l) => process.stderr.write(`sigelo-chatwoot: ${l}\n`));
    this.send = o.send ?? ((did, text, re) => cliSend(o.cli ?? 'sigelo-agent', o.identity, did, text, re));
    this.mapPath = o.map ?? mapPathOf(o.identity);
    this.state = this.#load();
    this.queue = Promise.resolve();     // webhooks one at a time, in order
    this.told = new Set();              // spool files left for the operator, said once
  }

  // ---- state: whole or nothing, 0600 ----
  #load() {
    let s;
    try { s = JSON.parse(readFileSync(this.mapPath, 'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw new Error(`${this.mapPath}: ${e.message}`); }
    return { contacts: {}, convs: {}, in: {}, out: {}, ...s };
  }
  save() {
    const t = this.now() / 1000;
    for (const k of ['in', 'out']) for (const [id, v] of Object.entries(this.state[k])) if (t - v.at > KEEP_S) delete this.state[k][id];
    const tmp = `${this.mapPath}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.state) + '\n', { mode: 0o600 });
    renameSync(tmp, this.mapPath);
  }
  allowed(item) { return [item.from, nameOf(item)].some((x) => typeof x === 'string' && this.allow.has(x)); }

  // ---- Chatwoot Application API ----
  async api(method, path, body, what) {
    const headers = { api_access_token: this.o.token, authorization: `Bearer ${this.o.token}` };
    let b = body;
    if (body !== undefined && !(body instanceof FormData)) { headers['content-type'] = 'application/json'; b = JSON.stringify(body); }
    const r = await this.fetch(`${this.base}/api/v1/accounts/${this.o.account}${path}`, { method, headers, body: b, signal: AbortSignal.timeout(30000) });
    const text = await r.text();
    if (!r.ok) throw new ChatwootError(r.status, what, text);
    try { return text === '' ? {} : JSON.parse(text); } catch { throw new ChatwootError(r.status, what, 'not JSON'); }
  }

  /** The contact and its conversation for a DID: from the map, else made (and kept). */
  async conversationOf(did, name) {
    const c = Object.hasOwn(this.state.contacts, did) ? this.state.contacts[did] : (this.state.contacts[did] = {});
    c.name = name;                      // the allowlist may name it; a reply checks it again
    if (c.contact === undefined) {
      let r;
      try { r = await this.api('POST', '/contacts', { inbox_id: this.o.inbox, name, identifier: did }, 'create contact'); } catch (e) {
        if (e.status !== 422) throw e;   // taken: made before this map (a lost map file); found by identifier
        const s = await this.api('GET', `/contacts/search?q=${encodeURIComponent(did)}`, undefined, 'search contact');
        const hit = (s.payload ?? []).find((x) => x.identifier === did);
        if (!hit) throw e;
        r = { payload: { contact: hit } };
      }
      const p = r.payload ?? r, contact = p.contact ?? p;
      c.contact = contact.id;
      c.source_id = p.contact_inbox?.source_id ?? (contact.contact_inboxes ?? []).find((x) => Number(x.inbox?.id) === Number(this.o.inbox))?.source_id;
      this.save();
    }
    if (c.source_id === undefined) {
      const r = await this.api('POST', `/contacts/${c.contact}/contact_inboxes`, { inbox_id: this.o.inbox }, 'create contact inbox');
      c.source_id = r.source_id;
      this.save();
    }
    if (c.conversation === undefined) {
      const r = await this.api('POST', '/conversations', { source_id: c.source_id, inbox_id: this.o.inbox, contact_id: c.contact, status: 'open' }, 'create conversation');
      c.conversation = r.id;
      this.state.convs[String(r.id)] = did;
      this.save();
    }
    return c;
  }

  // ---- in: one spool file ----
  /** → 'posted' | 'done' (posted before) | 'left' (not ours to take); throws on a Chatwoot failure (retried). */
  async inbound(file) {
    let item;
    try { item = JSON.parse(readFileSync(file, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return 'left'; throw e; }
    const id = item.id;
    if (typeof id !== 'string' || id.includes('.') || item.group !== undefined || typeof item.from !== 'string' || !item.from.startsWith('did:sigelo:')) return this.#left(file, 'a group message or not a message');
    if (!this.allowed(item)) return this.#left(file, `${nameOf(item) ?? item.from} is not on the allowlist`);
    const rec = Object.hasOwn(this.state.in, id) ? this.state.in[id] : undefined;
    if (rec?.state === 'done') { rmSync(file, { force: true }); return 'done'; }
    const c = await this.conversationOf(item.from, nameOf(item) ?? item.from);
    if (rec?.state === 'pending') {
      // A post that may have landed before a crash: look for it before posting again.
      const l = await this.api('GET', `/conversations/${c.conversation}/messages`, undefined, 'list messages');
      const hit = (l.payload ?? []).find((m) => m.source_id === TAG + id && kindOf(m.message_type) === 'incoming');
      if (hit) return this.#done(file, id, hit.id, item, c);
    }
    this.state.in[id] = { state: 'pending', at: this.now() / 1000 };
    this.save();
    let m;
    try { m = await this.#post(c, item); } catch (e) {
      if (e.status === 404) { delete this.state.convs[String(c.conversation)]; delete c.conversation; this.save(); }  // gone: a new one next time
      throw e;
    }
    return this.#done(file, id, m.id, item, c);
  }
  #left(file, why) {
    if (!this.told.has(file)) { this.told.add(file); this.log(`${basename(file)} left for the operator: ${why}`); }
    return 'left';
  }
  #done(file, id, cw, item, c) {
    this.state.in[id] = { state: 'done', cw, at: this.now() / 1000 };
    if (item.type !== 'file' && typeof item.content === 'string') c.last_in = id;   // a text: what a reply quotes
    this.save();
    rmSync(file, { force: true });
    return 'posted';
  }
  async #post(c, item) {
    const path = `/conversations/${c.conversation}/messages`, source_id = TAG + item.id;
    if (item.type === 'file') {
      let bytes = null;
      try { bytes = readFileSync(item.path); } catch {}
      if (bytes === null) return this.api('POST', path, { content: `[file ${item.name} (${item.size} bytes) not on disk here]`, message_type: 'incoming', private: false, source_id }, 'create message');
      const f = new FormData();
      f.append('content', String(item.name ?? 'file'));
      f.append('message_type', 'incoming');
      f.append('private', 'false');
      f.append('source_id', source_id);
      f.append('attachments[]', new Blob([bytes]), String(item.name ?? 'file'));
      return this.api('POST', path, f, 'create message');
    }
    const content = typeof item.content === 'string' ? item.content : JSON.stringify(item.content);
    return this.api('POST', path, { content, message_type: 'incoming', private: false, source_id }, 'create message');
  }

  /** Every spool file once, oldest first. → { posted, left, failed } (failed: the first error, then stops). */
  async pollOnce() {
    const r = { posted: 0, left: 0, failed: null };
    let names;
    try { names = readdirSync(this.o.spool).filter((n) => /^[^.]+(\.[^.]+)?\.json$/.test(n)); } catch (e) { if (e.code === 'ENOENT') return r; throw e; }
    for (const n of names.sort()) {
      try { const x = await this.inbound(join(this.o.spool, n)); if (x === 'left') r.left++; else r.posted++; } catch (e) { r.failed = e; break; }
    }
    return r;
  }

  /** Replies marked but not known sent (a crash between the mark and send): a private note each, never sent again. */
  async unsure() {
    for (const [k, v] of Object.entries(this.state.out)) {
      if (v.state !== 'sending') continue;
      try { await this.api('POST', `/conversations/${v.conv}/messages`, { content: 'sigelo: the bridge stopped while sending the reply above; it may not have gone. Send it again if needed.', message_type: 'outgoing', private: true }, 'note'); }
      catch (e) { this.log(e.message); continue; }
      v.state = 'unknown';
      this.save();
      this.log(`reply ${k}: may not have been sent (noted in the conversation)`);
    }
  }

  /** Poll until stopped; a failure waits 2 s, doubling to 5 min; success resets. → stop() */
  run(every = 2000) {
    let wait = 0, timer = null, stopped = false;
    let first = true;
    const tick = async () => {
      if (first) { first = false; await this.unsure(); }
      const r = await this.pollOnce().catch((e) => ({ failed: e }));
      if (stopped) return;
      if (r.failed) { wait = Math.min(wait ? wait * 2 : BACKOFF.first, BACKOFF.max); this.log(`${r.failed.message}; again in ${wait / 1000} s`); }
      else wait = 0;
      timer = setTimeout(tick, wait || every);
    };
    void tick();
    return () => { stopped = true; clearTimeout(timer); };
  }

  // ---- out: the webhook ----
  /** A Chatwoot signature check (the webhooks guide): sha256=HMAC-SHA256(secret, `${ts}.${raw}`), ts within 5 min. */
  signed(raw, ts, sig) {
    if (typeof ts !== 'string' || !/^\d{1,12}$/.test(ts) || typeof sig !== 'string') return false;
    if (Math.abs(this.now() / 1000 - Number(ts)) > SKEW_S) return false;
    const want = Buffer.from('sha256=' + createHmac('sha256', this.o.secret).update(`${ts}.`).update(raw).digest('hex'));
    const got = Buffer.from(sig);
    return got.length === want.length && timingSafeEqual(got, want);
  }

  /** A verified webhook body → what was done (a word, for the log and tests). */
  async outbound(ev) {
    if (ev?.event !== 'message_created') return 'ignored: event';
    if (kindOf(ev.message_type) !== 'outgoing') return 'ignored: not outgoing';
    if (ev.private === true) return 'ignored: private note';
    if (typeof ev.source_id === 'string' && ev.source_id.startsWith(TAG)) return 'ignored: ours';
    if (ev.inbox?.id !== undefined && Number(ev.inbox.id) !== Number(this.o.inbox)) return 'ignored: another inbox';
    const conv = ev.conversation?.display_id ?? ev.conversation?.id;
    const did = conv !== undefined && Object.hasOwn(this.state.convs, String(conv)) ? this.state.convs[String(conv)] : undefined;
    if (did === undefined) return 'ignored: not a bridged conversation';
    const key = String(ev.id);
    if (ev.id === undefined || Object.hasOwn(this.state.out, key)) return 'duplicate';
    this.state.out[key] = { state: 'sending', at: this.now() / 1000, conv };
    this.save();
    const note = (t) => this.api('POST', `/conversations/${conv}/messages`, { content: t, message_type: 'outgoing', private: true }, 'note').catch((e) => this.log(e.message));
    if (!this.allowed({ from: did, name: this.state.contacts[did]?.name })) {
      this.state.out[key].state = 'refused'; this.save();
      await note('sigelo: not sent, this contact is no longer bridged.');
      return 'refused: not allowed';
    }
    if (Array.isArray(ev.attachments) && ev.attachments.length > 0) await note('sigelo: attachments are not sent; the text is.');
    const text = typeof ev.content === 'string' ? ev.content : '';
    if (text.trim() === '') { this.state.out[key].state = 'sent'; this.save(); return 'nothing to send'; }
    const c = this.state.contacts[did];
    let r = await this.send(did, text, c?.last_in);
    if (!r.ok && c?.last_in) r = await this.send(did, text, undefined);   // the quoted message gone from the log: unquoted
    this.state.out[key].state = r.ok ? 'sent' : 'refused';
    this.save();
    if (!r.ok) { await note(`sigelo: not sent: ${String(r.detail).slice(0, 300)}`); return 'refused: send'; }
    return 'sent';
  }

  /** node:http handler for POST <path>. */
  handler(path) {
    return (req, res) => {
      const end = (code, t) => { res.writeHead(code, { 'content-type': 'text/plain' }); res.end(`${t}\n`); };
      if (req.method !== 'POST' || req.url !== path) return end(404, 'not found');
      const parts = []; let n = 0, big = false;
      req.on('data', (d) => {
        if (big) return;
        n += d.length;
        if (n <= BODY_MAX) return void parts.push(d);
        big = true;                    // answered now, the rest not read
        res.on('finish', () => req.socket.destroy());
        res.writeHead(413, { 'content-type': 'text/plain', connection: 'close' }); res.end('too large\n');
      });
      req.on('error', () => {});
      req.on('end', () => {
        if (big) return;
        const raw = Buffer.concat(parts);
        if (!this.signed(raw, req.headers['x-chatwoot-timestamp'], req.headers['x-chatwoot-signature'])) return end(401, 'bad signature');
        let ev;
        try { ev = JSON.parse(raw.toString('utf8')); } catch { return end(400, 'not JSON'); }
        this.queue = this.queue.then(() => this.outbound(ev)).then((w) => { this.log(`webhook ${ev.id ?? '?'}: ${w}`); end(200, w); },
          (e) => { this.log(`webhook ${ev.id ?? '?'}: ${e.message}`); end(500, 'failed'); });
      });
    };
  }
}

/** `sigelo-agent send <did> - [--re <id>] --identity <file>`, the text on stdin. → { ok, detail } */
export function cliSend(cli, identity, did, text, re) {
  const args = ['send', did, '-', ...(re ? ['--re', re] : []), '--identity', identity];
  return new Promise((done) => {
    const p = spawn(cli, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let err = '';
    p.stderr.on('data', (d) => { err += d; });
    p.stdout.resume();
    p.on('error', (e) => done({ ok: false, detail: e.message }));
    p.on('close', (code) => done({ ok: code === 0, detail: err.trim().split('\n').pop() ?? `exit ${code}` }));
    p.stdin.end(text);
  });
}
