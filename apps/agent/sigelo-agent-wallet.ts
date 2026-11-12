// SPDX-License-Identifier: MIT
/**
 * The Wallet of the computer's page (UI-API.md "Wallet", design/ux1/notes.md "Decided": wallet sync, price opt-in).
 *
 * Which wallet: a `monero-wallet-rpc` on this computer, the "wallet service" (Settings → Wallet): the wallet-rpc of a
 * keeper this host registered (its policy.json `wallet`: loopback URL and digest login, sigelo-agent-spend.ts reads it),
 * or another loopback wallet-rpc given by hand. One ACCOUNT of it is the person's: never one a keeper agent or delegate is
 * pinned to (apps/keeper: agents are accounts), chosen in Settings or made there (`create_account`). Nothing here holds a
 * key: the wallet-rpc does, as the keeper's does. The vault (the 25 words' own wallet) is never loaded (MONERO.md §2).
 * The self-contained app has none of this (apps/contact/page.mjs answers `where: "none"`).
 *
 * Off (`settings.wallet` false, the default): no route here calls a wallet, a node or a price source.
 *
 * Sync (Decided 2026-11-11): reading the state IS the sync the page starts when the Wallet tab or a balance is shown. The
 * wallet's height (`get_height`) against the node's (`/get_height` of the node in use: Settings → Monero node, else the
 * keeper's first daemon): `synced` (within a block), `syncing` (N blocks behind, ≈ 2 min each, the progress since this
 * sync began), `node` (the node does not answer, or the wallet has not moved for 3 minutes while behind), `wallet` (the
 * wallet-rpc does not answer). A wallet not of a keeper is also asked to `refresh` while behind (at most once a minute); a
 * keeper's wallet-rpc refreshes itself, and a page-made rescan would hold the keeper's payments behind it. The balance is
 * always the wallet's own (`get_balance` of the account), with `current` false and `at` the last time it was in sync when
 * it is not: the page greys it, "as of …". Send refuses until synced (`409 wallet_unsynced`).
 *
 * Send: built with `do_not_relay` (the fee priced, nothing sent), reviewed, then relayed by its id (10 minutes); the note
 * kept with the transaction (`set_tx_notes`); a payment to a contact told in their chat ("Paid you …"), that message
 * marked as the payment in this page's chat. Prices (opt-in, Settings → Wallet): one public source, CoinGecko's simple
 * price (no key), asked by this server for every currency at once, kept 10 minutes; it learns this computer asked.
 */
import { randomBytes, createHash } from 'node:crypto';
import { Agent as HttpAgent, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { decodeAddress } from 'sigelo/dist/monero.js';
import * as spend from './sigelo-agent-spend.ts';

type Json = Record<string, unknown>;
const plain = (x: unknown): x is Json => typeof x === 'object' && x !== null && !Array.isArray(x);
const refuse = (status: number, check: string, message: string): never => { throw Object.assign(new Error(message), { check, status }); };
const ATOMIC = /^(0|[1-9][0-9]*)$/, MAX_ATOMIC = 9007199254740991n, BLOCK_S = 120;
export const CURRENCIES = ['EUR', 'USD', 'GBP', 'CHF', 'RON', 'JPY', 'CAD', 'AUD', 'SEK', 'NOK', 'DKK', 'PLN', 'CZK', 'HUF', 'BRL', 'INR'];
export const PRICE_SOURCE = 'CoinGecko';
const PRICE_URL = 'https://api.coingecko.com/api/v3/simple/price';
const PRICE_TTL = 600, REVIEW_TTL = 600, STUCK_S = 180, CACHE_MS = 4000;

/** What the page keeps of the wallet in `.ui.json` `wallet`. */
export interface WalletData {
  service?: { keeper?: string; url?: string; login?: string; account: number };
  node?: string; nodes?: string[]; synced_at?: number; last?: { total: string; unlocked: string; at: number };
  /** Mine, by txid: to whom, the note, and the chat message that told them (its `at`, which never changes). */
  payments?: Record<string, { contact: string | null; note: string; at: number; msg_at: number | null; amount: string }>;
  payees?: Record<string, string>;
}

// ---- wallet-rpc (HTTP digest, as apps/keeper/service.ts walletRpc) and a node's height
const md5 = (s: string): string => createHash('md5').update(s, 'utf8').digest('hex');
function digest(challenge: string, login: string, uri: string): string {
  const field = (k: string): string => new RegExp(`${k}="?([^",]*)"?`).exec(challenge)?.[1] ?? '';
  const i = login.indexOf(':'), [user, pass] = [login.slice(0, i), login.slice(i + 1)];
  const [realm, nonce, opaque] = [field('realm'), field('nonce'), field('opaque')], [nc, cnonce] = ['00000001', randomBytes(8).toString('hex')];
  const response = md5([md5(`${user}:${realm}:${pass}`), nonce, nc, cnonce, 'auth', md5(`POST:${uri}`)].join(':'));
  return `Digest username="${user}", realm="${realm}", nonce="${nonce}", uri="${uri}", qop=auth, nc=${nc}, cnonce="${cnonce}", response="${response}", algorithm=MD5${opaque === '' ? '' : `, opaque="${opaque}"`}`;
}
/** One JSON-RPC call to a wallet-rpc; its error thrown with the wallet's words, `unreachable` when nothing answers. */
export async function rpc(url: string, login: string | undefined, method: string, params: unknown, timeoutMs = 15000): Promise<Json> {
  const uri = new URL(url).pathname, body = JSON.stringify({ jsonrpc: '2.0', id: '0', method, params });
  const headers: Record<string, string> = { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(body)) };
  const agent = new HttpAgent({ keepAlive: true, maxSockets: 1 });   // the digest nonce lives on its connection
  const send = (): Promise<{ status: number; challenge: string; text: string }> => new Promise((ok, no) => {
    const r = httpRequest(url, { method: 'POST', headers, agent }, (res) => {
      let t = ''; res.setEncoding('utf8'); res.on('data', (c) => { t += String(c); });
      res.on('end', () => { clearTimeout(timer); ok({ status: res.statusCode ?? 0, challenge: [res.headers['www-authenticate'] ?? ''].flat().join(', '), text: t }); });
      res.on('error', no);
    });
    const timer = setTimeout(() => r.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })), timeoutMs);
    r.on('error', (e) => { clearTimeout(timer); no(e); });
    r.end(body);
  });
  let res;
  try {
    try { res = await send(); } catch (e) { throw Object.assign(new Error(`the wallet service at ${url} doesn't answer (${(e as { code?: string }).code ?? 'no answer'})`), { check: 'wallet_unreachable', status: 409 }); }
    if (res.status === 401 && login) {
      headers['Authorization'] = digest(res.challenge, login, uri);
      try { res = await send(); } catch (e) { throw Object.assign(new Error(`the wallet service at ${url} doesn't answer (${(e as { code?: string }).code ?? 'no answer'})`), { check: 'wallet_unreachable', status: 409 }); }
    }
  } finally { agent.destroy(); }
  if (res.status === 401) refuse(409, 'wallet_login', 'The wallet service wants a login this page doesn\'t have: set it in Settings → Wallet → Wallet service.');
  let out: { result?: unknown; error?: { code: number; message: string } };
  try { out = JSON.parse(res.text) as typeof out; } catch { return refuse(409, 'wallet', `The wallet service answered something that isn't JSON (HTTP ${res.status}).`); }
  if (out.error) refuse(409, 'wallet', `The wallet says: ${out.error.message}`);
  if (!plain(out.result)) refuse(409, 'wallet', 'The wallet service gave no answer.');
  return out.result as Json;
}
/** A node's height (monerod `/get_height`): http or https, never a .onion (no proxy here). */
export function nodeHeight(node: string, timeoutMs = 6000): Promise<number> {
  const url = /^https?:\/\//.test(node) ? node : `http://${node}`;
  return new Promise((ok, no) => {
    let u: URL;
    try { u = new URL('/get_height', url); } catch { no(new Error('not a node address')); return; }
    if (u.hostname.endsWith('.onion')) { no(new Error('an onion node needs a proxy this page does not have')); return; }
    const r = (u.protocol === 'https:' ? httpsRequest : httpRequest)(u, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': '2' } }, (res) => {
      let t = ''; res.setEncoding('utf8'); res.on('data', (c) => { t += String(c); });
      res.on('end', () => { clearTimeout(timer); try { const h = (JSON.parse(t) as Json)['height']; if (Number.isSafeInteger(h) && (h as number) > 0) ok(h as number); else no(new Error('no height')); } catch { no(new Error('not a node')); } });
    });
    const timer = setTimeout(() => r.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })), timeoutMs);
    r.on('error', (e) => { clearTimeout(timer); no(e); });
    r.end('{}');
  });
}
const goodNode = (s: unknown): s is string => typeof s === 'string' && s.length <= 255 && /^(https?:\/\/)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):\d{1,5}\/?$/.test(s.trim());
const atomicIn = (v: unknown, what: string): bigint => {
  if (typeof v !== 'string' || !ATOMIC.test(v) || BigInt(v) === 0n || BigInt(v) > MAX_ATOMIC) return refuse(400, 'body', `${what}: an amount above 0 in atomic units, as a decimal string`);
  return BigInt(v);
};
const xmr = (a: bigint): string => { const f = (a % 10n ** 12n).toString().padStart(12, '0').replace(/0+$/, ''); return `${a / 10n ** 12n}${f ? '.' + f : ''}`; };
const short = (a: string): string => `${a.slice(0, 4)}…${a.slice(-4)}`;
const NOTE = /^[^\u0000-\u001f\u007f-\u009f]{0,100}$/;

export interface WalletHooks {
  data(): WalletData; save(): void; on(): boolean; prices(): { on: boolean; currency: string };
  /** A payment told in a contact's chat: the message's history record (its `at`), or null when it did not go. */
  tell(contact: string, text: string): Promise<{ at: number } | null>;
  contactName(did: string): string | null;
  now?(): number; priceUrl?: string;
}

export function makeWallet(h: WalletHooks): { routes: Record<string, (b: Json, q: URLSearchParams) => unknown>; paymentOf(contact: string, at: number): Json | null } {
  const now = h.now ?? ((): number => Math.floor(Date.now() / 1000));
  const W = (): WalletData => h.data();
  // ---- the service: which wallet-rpc, which account
  type Svc = { kind: 'keeper' | 'rpc'; keeper: string | null; url: string; login: string | undefined; net: string | null; account: number | null; held: Map<number, string>; daemons: string[] };
  const keepersNow = (): spend.KeeperHere[] => { const f = spend.findKeepers(); return f.state === 'here' ? f.keepers : []; };
  /** The accounts a keeper's agents and delegates are pinned to (never the person's). */
  const heldBy = (k: spend.KeeperHere): Map<number, string> => {
    const m = new Map<number, string>();
    for (const [name, a] of Object.entries(k.policy['agents'] as Record<string, Json>)) if (Number.isSafeInteger(a['account'])) m.set(a['account'] as number, name);
    for (const { entry: e } of k.log) if (e['kind'] === 'delegate' && Number.isSafeInteger(e['account'])) m.set(e['account'] as number, String(e['name']));
    return m;
  };
  const keeperSvc = (k: spend.KeeperHere, account: number | null): Svc => {
    const w = plain(k.policy['wallet']) ? k.policy['wallet'] as Json : {};
    const daemons = Array.isArray(k.install['daemons']) ? (k.install['daemons'] as unknown[]).filter((d): d is string => typeof d === 'string') : [];
    return { kind: 'keeper', keeper: k.id, url: String(w['rpc'] ?? ''), login: typeof w['login'] === 'string' ? w['login'] : undefined, net: k.net, account, held: heldBy(k), daemons };
  };
  function service(): Svc | { why: string; detail?: string } {
    const s = W().service;
    if (s?.url !== undefined) return { kind: 'rpc', keeper: null, url: s.url, login: s.login, net: null, account: s.account, held: new Map(), daemons: [] };
    const found = spend.findKeepers();
    if (found.state === 'unreadable') return { why: 'unreadable', detail: found.detail };
    const ks = found.state === 'here' ? found.keepers : [];
    if (s?.keeper !== undefined) {
      const k = ks.find((x) => x.id === s.keeper);
      return k ? keeperSvc(k, s.account) : { why: 'keeper_gone', detail: s.keeper };
    }
    if (ks.length === 0) return { why: 'no_service' };
    // Not chosen yet: the first keeper's wallet, account 0 when no agent holds it.
    const k = ks[0]!, sv = keeperSvc(k, null);
    return sv.held.has(0) ? { why: 'no_account', detail: k.id } : { ...sv, account: 0 };
  }
  const call = (sv: Svc, method: string, params: unknown, ms?: number): Promise<Json> => rpc(sv.url, sv.login, method, params, ms);
  const nodeOf = (sv: Svc): string | null => W().node ?? sv.daemons[0] ?? W().nodes?.[0] ?? null;

  // ---- sync: read now, at most every CACHE_MS
  const S = { key: '', at: 0, start: null as number | null, moved: { h: -1, t: 0 }, refreshAt: 0, refreshing: false, view: null as Json | null };
  async function read(force = false): Promise<Json> {
    if (!h.on()) return { on: false };
    const sv = service();
    if ('why' in sv) return { on: true, where: 'here', ready: false, why: sv.why, ...(sv.detail !== undefined && { detail: sv.detail }) };
    if (sv.account === null) return { on: true, where: 'here', ready: false, why: 'no_account' };
    if (sv.held.has(sv.account)) return { on: true, where: 'here', ready: false, why: 'account_held', detail: sv.held.get(sv.account) };
    const key = `${sv.url} ${sv.account}`, t = now();
    if (!force && S.view && S.key === key && Date.now() - S.at < CACHE_MS) return S.view;
    if (S.key !== key) Object.assign(S, { key, start: null, moved: { h: -1, t: 0 } });
    const d = W(), node = nodeOf(sv), base = { on: true, where: 'here', ready: true, service: { kind: sv.kind, keeper: sv.keeper, url: sv.url, account: sv.account }, node };
    let height: number, bal: Json;
    try { height = Number((await call(sv, 'get_height', {}, 8000))['height']); bal = await call(sv, 'get_balance', { account_index: sv.account }, 8000); } catch (e) {
      const view = { ...base, net: sv.net, sync: { state: 'wallet', detail: (e as Error).message, synced_at: d.synced_at ?? null, checked_at: t }, balance: d.last ? { ...d.last, current: false } : null, payees: d.payees ?? {} };
      Object.assign(S, { at: Date.now(), view }); return view;
    }
    let net = sv.net;
    if (net === null) { try { net = decodeAddress(String((await call(sv, 'get_address', { account_index: sv.account, address_index: [0] }, 8000))['address'])).net; } catch { net = null; } }
    let chain: number | null = null, nodeErr: string | null = null;
    if (node === null) nodeErr = 'no node set';
    else { try { chain = await nodeHeight(node); } catch (e) { nodeErr = (e as Error).message; } }
    if (height !== S.moved.h) S.moved = { h: height, t };
    let state: string, behind = 0;
    if (chain === null) state = 'node';
    else {
      behind = Math.max(0, chain - height);
      if (behind <= 1) { state = 'synced'; S.start = null; if (!d.synced_at || t - d.synced_at >= 60) { d.synced_at = t; h.save(); } else d.synced_at = t; }
      else {
        state = t - S.moved.t > STUCK_S ? 'node' : 'syncing';
        if (S.start === null || S.start > height) S.start = height;
        // A wallet of its own (not a keeper's) is asked to catch up; a keeper's refreshes itself.
        if (sv.kind === 'rpc' && !S.refreshing && Date.now() - S.refreshAt > 60000) {
          S.refreshing = true; S.refreshAt = Date.now();
          void call(sv, 'refresh', {}, 3600000).catch(() => {}).finally(() => { S.refreshing = false; });
        }
      }
    }
    const total = String(bal['balance'] ?? '0'), unlocked = String(bal['unlocked_balance'] ?? '0');
    if (state === 'synced') { d.last = { total, unlocked, at: t }; }
    const progress = state === 'syncing' && chain !== null && S.start !== null && chain > S.start ? Math.min(0.99, (height - S.start) / (chain - S.start)) : null;
    const view = { ...base, net, sync: { state, height, chain, behind, behind_s: behind * BLOCK_S, progress, synced_at: d.synced_at ?? null, checked_at: t, ...(nodeErr !== null && { detail: nodeErr }) },
      balance: { total, unlocked, blocks_to_unlock: Number(bal['blocks_to_unlock'] ?? 0), at: state === 'synced' ? t : d.synced_at ?? null, current: state === 'synced' }, payees: d.payees ?? {} };
    Object.assign(S, { at: Date.now(), view });
    return view;
  }
  async function ready(): Promise<Svc> {
    if (!h.on()) refuse(409, 'wallet_off', 'Wallet is off for this profile: turn it on in Settings → Wallet.');
    const sv = service();
    if ('why' in sv || sv.account === null) return refuse(409, 'wallet_setup', 'Choose your wallet in Settings → Wallet → Wallet service.');
    if (sv.held.has(sv.account)) refuse(409, 'wallet_setup', `Account ${sv.account} is ${sv.held.get(sv.account)}'s allowance: choose your own in Settings → Wallet → Wallet service.`);
    return sv;
  }

  // ---- send: review (built, not relayed), then send by id
  const reviews = new Map<string, { exp: number; sv: string; account: number; metas: string[]; to: string; contact: string | null; agent: string | null; note: string; amount: string; fee: string }>();
  async function target(b: Json, net: string | null): Promise<{ addr: string; contact: string | null; agent: string | null }> {
    const to = plain(b['to']) ? b['to'] as Json : refuse(400, 'body', 'to: {addr}, {contact, addr} or {agent, keeper}');
    if (typeof to['agent'] === 'string') {
      const k = keepersNow().find((x) => x.id === to['keeper']) ?? refuse(404, 'keeper_unknown', 'That keeper isn\'t on this computer.');
      const a = (k.policy['agents'] as Record<string, Json>)[to['agent'] as string] ?? refuse(404, 'keeper_agent', `No agent ${JSON.stringify(to['agent'])} in that keeper.`);
      const ks = keeperSvc(k, null), r = await call(ks, 'get_address', { account_index: a['account'], address_index: [0] });
      return { addr: String(r['address']), contact: null, agent: to['agent'] as string };
    }
    const addr = typeof to['addr'] === 'string' ? to['addr'].trim() : refuse(400, 'body', 'to.addr: a Monero address');
    let d;
    try { d = decodeAddress(addr); } catch { return refuse(400, 'address', 'This isn\'t a Monero address. Paste or scan the whole address.'); }
    if (net !== null && d.net !== net) refuse(400, 'address', `This is a ${d.net} address; your wallet is on ${net}.`);
    if (d.kind === 'integrated') refuse(400, 'address', 'Integrated addresses are not sent to: ask for a standard address or a subaddress.');
    const contact = typeof to['contact'] === 'string' ? to['contact'] : null;
    return { addr, contact, agent: null };
  }
  const review = async (b: Json): Promise<Json> => {
    const sv = await ready(), v = await read(true), sync = v['sync'] as Json;
    if (sync['state'] !== 'synced') refuse(409, 'wallet_unsynced', 'Your wallet isn\'t up to date yet: Send works once it is synced.');
    const net = (v['net'] as string | null) ?? null, t = await target(b, net);
    const note = typeof b['note'] === 'string' ? b['note'].trim() : '';
    if (!NOTE.test(note)) refuse(400, 'body', 'note: at most 100 characters, no control characters');
    let metas: string[], amount: bigint, fee: bigint;
    if (b['amount'] === 'all') {
      const r = await call(sv, 'sweep_all', { address: t.addr, account_index: sv.account, do_not_relay: true, get_tx_metadata: true }, 180000);
      metas = (r['tx_metadata_list'] as unknown[] ?? []).map(String);
      amount = (r['amount_list'] as unknown[] ?? []).reduce<bigint>((s, x) => s + BigInt(String(x)), 0n);
      fee = (r['fee_list'] as unknown[] ?? []).reduce<bigint>((s, x) => s + BigInt(String(x)), 0n);
      if (metas.length === 0) refuse(409, 'wallet_funds', 'There is nothing spendable to send yet.');
    } else {
      amount = atomicIn(b['amount'], 'amount');
      const r = await call(sv, 'transfer', { destinations: [{ address: t.addr, amount: Number(amount) }], account_index: sv.account, priority: 0, do_not_relay: true, get_tx_metadata: true }, 180000);
      metas = [String(r['tx_metadata'] ?? '')]; fee = BigInt(String(r['fee'] ?? '0'));
      if (!metas[0]) refuse(409, 'wallet', 'The wallet built no transaction.');
    }
    const id = randomBytes(12).toString('hex'), exp = now() + REVIEW_TTL;
    for (const [k, r] of reviews) if (r.exp <= now()) reviews.delete(k);
    reviews.set(id, { exp, sv: S.key, account: sv.account!, metas, to: t.addr, contact: t.contact, agent: t.agent, note, amount: String(amount), fee: String(fee) });
    return { id, exp, to: t.addr, contact: t.contact, agent: t.agent, amount: String(amount), fee: String(fee), total: String(amount + fee), note, all: b['amount'] === 'all' };
  };
  const send = async (b: Json): Promise<Json> => {
    const sv = await ready(), r = reviews.get(String(b['id']));
    if (!r || r.exp <= now() || r.sv !== `${sv.url} ${sv.account}`) return refuse(409, 'review_gone', 'This review ran out: review the payment again.');
    reviews.delete(String(b['id']));
    const txids: string[] = [];
    for (const m of r.metas) {
      try { txids.push(String((await call(sv, 'relay_tx', { hex: m }, 60000))['tx_hash'])); } catch (e) {
        if (txids.length === 0) throw e;
        break;
      }
    }
    if (r.note) { try { await call(sv, 'set_tx_notes', { txids, notes: txids.map(() => r.note) }); } catch {} }
    try { await call(sv, 'store', {}, 60000); } catch {}
    const d = W(), at = now();
    d.payments ??= {};
    let msgAt: number | null = null;
    if (r.contact) {
      (d.payees ??= {})[r.contact] = r.to;
      const told = await h.tell(r.contact, `Paid you ${xmr(BigInt(r.amount))} XMR${r.note ? `: ${r.note}` : ''}. Transaction ${short(txids[0]!)}.`).catch(() => null);
      msgAt = told?.at ?? null;
    }
    for (const tx of txids) d.payments[tx] = { contact: r.contact, note: r.note, at, msg_at: msgAt, amount: r.amount };
    h.save(); S.at = 0;
    return { sent: true, txids, amount: r.amount, fee: r.fee, to: r.to, contact: r.contact, agent: r.agent, note: r.note, told: msgAt !== null };
  };

  // ---- history
  const statusOf = (t: Json): string => {
    const ty = t['type'];
    if (ty === 'failed') return 'failed';
    if (ty === 'pool' || ty === 'pending') return 'pending';
    return t['locked'] === true || (Number(t['confirmations'] ?? 10) < 10) ? 'confirming' : 'confirmed';
  };
  const entryOf = (t: Json, labels: Map<number, string>): Json => {
    const txid = String(t['txid'] ?? ''), p = W().payments?.[txid], dir = t['type'] === 'in' || (t['type'] === 'pool' && !Array.isArray(t['destinations'])) ? 'in' : 'out';
    const minor = plain(t['subaddr_index']) ? Number(t['subaddr_index']['minor']) : null;
    const dest = Array.isArray(t['destinations']) && plain(t['destinations'][0]) ? String((t['destinations'][0] as Json)['address'] ?? '') : null;
    return { txid, dir, amount: String(t['amount'] ?? '0'), fee: String(t['fee'] ?? '0'), at: Number(t['timestamp'] ?? 0) || null, height: Number(t['height'] ?? 0) || null,
      confirmations: Number.isSafeInteger(t['confirmations']) ? t['confirmations'] : null, status: statusOf(t), address: dir === 'in' ? String(t['address'] ?? '') : dest,
      note: String(t['note'] || p?.note || (dir === 'in' && minor !== null ? labels.get(minor) ?? '' : '')), contact: p?.contact ?? null, contact_name: p?.contact ? h.contactName(p.contact) : null };
  };
  const labelsOf = async (sv: Svc): Promise<Map<number, string>> => {
    const m = new Map<number, string>();
    try { for (const x of (await call(sv, 'get_address', { account_index: sv.account }))['addresses'] as Json[] ?? []) if (plain(x) && typeof x['label'] === 'string') m.set(Number(x['address_index']), x['label']); } catch {}
    return m;
  };
  const history = async (q: URLSearchParams): Promise<Json> => {
    const sv = await ready(), n = Math.min(200, Math.max(1, Number(q.get('n') ?? 50) || 50));
    const r = await call(sv, 'get_transfers', { in: true, out: true, pending: true, failed: true, pool: true, account_index: sv.account });
    const labels = await labelsOf(sv), all: Json[] = [];
    for (const k of ['pool', 'pending', 'in', 'out', 'failed']) for (const t of (Array.isArray(r[k]) ? r[k] as unknown[] : [])) if (plain(t)) all.push(entryOf({ ...t, type: t['type'] ?? k }, labels));
    const atOf = (x: Json): number => (typeof x['at'] === 'number' ? x['at'] : Infinity);   // not yet in a block: first
    all.sort((a, b) => atOf(b) - atOf(a));
    return { entries: all.slice(0, n) };
  };
  const tx = async (q: URLSearchParams): Promise<Json> => {
    const sv = await ready(), txid = q.get('txid') ?? '';
    if (!/^[0-9a-f]{64}$/.test(txid)) refuse(400, 'body', 'txid: 64 hex digits');
    const r = await call(sv, 'get_transfer_by_txid', { txid, account_index: sv.account });
    const t = plain(r['transfer']) ? r['transfer'] : refuse(404, 'tx_unknown', 'That payment isn\'t in this wallet.');
    return { ...entryOf(t, await labelsOf(sv)), suggested: Number(t['suggested_confirmations_threshold'] ?? 10), double_spend: t['double_spend_seen'] === true };
  };

  // ---- prices (opt-in): one fetch for every currency, kept PRICE_TTL; this server asks, never the page
  const P = { rates: null as Record<string, number> | null, at: 0, inflight: null as Promise<void> | null, error: null as string | null };
  const fetchRates = async (): Promise<void> => {
    const url = `${h.priceUrl ?? process.env['SIGELO_PRICE_URL'] ?? PRICE_URL}?ids=monero&vs_currencies=${CURRENCIES.map((c) => c.toLowerCase()).join(',')}`;
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(10000), headers: { Accept: 'application/json' } });
      const j = await r.json() as Json, m = plain(j['monero']) ? j['monero'] as Json : null;
      if (!r.ok || !m) throw new Error(`HTTP ${r.status}`);
      const rates: Record<string, number> = {};
      for (const c of CURRENCIES) { const v = m[c.toLowerCase()]; if (typeof v === 'number' && Number.isFinite(v) && v > 0) rates[c] = v; }
      P.rates = rates; P.at = now(); P.error = null;
    } catch (e) { P.error = (e as Error).message; }
  };
  const price = async (): Promise<Json> => {
    const p = h.prices();
    if (!h.on() || !p.on) return { on: false, currency: p.currency };
    if (!P.rates || now() - P.at >= PRICE_TTL) { P.inflight ??= fetchRates().finally(() => { P.inflight = null; }); await P.inflight; }
    const rate = P.rates?.[p.currency] ?? null;
    return { on: true, currency: p.currency, rate, at: P.rates ? P.at : null, source: PRICE_SOURCE, stale: P.error !== null && P.rates !== null, ...(rate === null && { error: P.error ?? 'no price for this currency' }) };
  };

  // ---- Settings → Wallet: the service, the node
  const services = async (): Promise<Json> => {
    const found = spend.findKeepers(), ks = found.state === 'here' ? found.keepers : [], cur = W().service ?? null;
    const out: Json[] = [];
    for (const k of ks) {
      const sv = keeperSvc(k, null);
      let accounts: Json[] = [], error: string | null = null;
      try {
        const r = await call(sv, 'get_accounts', {}, 8000);
        accounts = (Array.isArray(r['subaddress_accounts']) ? r['subaddress_accounts'] as Json[] : []).map((a) => ({ index: Number(a['account_index']), label: String(a['label'] ?? ''), balance: String(a['balance'] ?? '0'), held: sv.held.get(Number(a['account_index'])) ?? null }));
      } catch (e) { error = (e as Error).message; }
      out.push({ keeper: k.id, url: sv.url, net: k.net, accounts, error });
    }
    const chosen = service();
    return { current: 'why' in chosen ? null : { kind: chosen.kind, keeper: chosen.keeper, url: chosen.url, account: chosen.account, chosen: cur !== null },
      why: 'why' in chosen ? chosen.why : null, keepers: out, unreadable: found.state === 'unreadable' ? found.detail : null, rpc: cur?.url ? { url: cur.url, login: cur.login !== undefined } : null };
  };
  const setService = async (b: Json): Promise<Json> => {
    const d = W();
    if (typeof b['keeper'] === 'string') {
      const k = keepersNow().find((x) => x.id === b['keeper']) ?? refuse(404, 'keeper_unknown', 'That keeper isn\'t on this computer.');
      const sv = keeperSvc(k, null);
      let account: number;
      if (b['new_account'] === true) account = Number((await call(sv, 'create_account', { label: 'me' }))['account_index']);
      else if (Number.isSafeInteger(b['account']) && (b['account'] as number) >= 0) account = b['account'] as number;
      else return refuse(400, 'body', 'account: an account index, or new_account: true');
      if (sv.held.has(account)) refuse(409, 'account_held', `Account ${account} is ${sv.held.get(account)}'s allowance: an agent's money, not yours.`);
      d.service = { keeper: k.id, account };
    } else if (typeof b['url'] === 'string') {
      let u: URL;
      try { u = new URL(b['url']); } catch { return refuse(400, 'body', 'url: the wallet-rpc address, like http://127.0.0.1:18083/json_rpc'); }
      if (u.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname)) refuse(400, 'wallet_url', 'Only a wallet-rpc on this computer (127.0.0.1): its login goes in the clear.');
      const login = typeof b['login'] === 'string' && b['login'] !== '' ? b['login'] : undefined;
      if (login !== undefined && !login.includes(':')) refuse(400, 'body', 'login: user:password, as --rpc-login');
      const account = Number.isSafeInteger(b['account']) ? b['account'] as number : 0;
      await rpc(u.href.endsWith('json_rpc') ? u.href : new URL('/json_rpc', u).href, login, 'get_height', {}, 8000);
      d.service = { url: u.href.endsWith('json_rpc') ? u.href : new URL('/json_rpc', u).href, ...(login !== undefined && { login }), account };
    } else if (b['default'] === true) delete d.service;
    else refuse(400, 'body', '{keeper, account | new_account}, {url, login?, account?} or {default: true}');
    delete d.last; delete d.synced_at; S.at = 0; S.key = '';
    h.save();
    return services();
  };
  const nodes = async (): Promise<Json> => {
    const sv = service(), list = [...new Set([...('why' in sv ? [] : sv.daemons), ...(W().nodes ?? [])])], inUse = 'why' in sv ? W().node ?? null : nodeOf(sv);
    const rows = await Promise.all(list.map(async (u) => { const t0 = Date.now(); try { const ht = await nodeHeight(u); return { url: u, ok: true, height: ht, ms: Date.now() - t0 }; } catch (e) { return { url: u, ok: false, height: null, ms: null, detail: (e as Error).message }; } }));
    const top = Math.max(0, ...rows.map((r) => r.height ?? 0));
    return { in_use: inUse, nodes: rows.map((r) => ({ ...r, in_use: r.url === inUse, behind: r.height !== null && top > 0 ? top - r.height : null, from: 'why' in sv || !sv.daemons.includes(r.url) ? 'added' : 'keeper' })) };
  };
  const setNode = async (b: Json): Promise<Json> => {
    const d = W(), sv = service();
    if (b['remove'] !== undefined) { d.nodes = (d.nodes ?? []).filter((x) => x !== b['remove']); if (d.node === b['remove']) delete d.node; h.save(); return nodes(); }
    const u = typeof b['add'] === 'string' ? b['add'] : typeof b['use'] === 'string' ? b['use'] : refuse(400, 'body', '{use}, {add} or {remove}: a node as host:port');
    if (!goodNode(u)) refuse(400, 'node', 'A node is host:port, like node.example.org:18089');
    const node = u.trim().replace(/\/$/, '');
    try { await nodeHeight(node); } catch (e) { refuse(409, 'node_down', `That node doesn't answer (${(e as Error).message}): check the address, or try another.`); }
    if (b['add'] !== undefined) { d.nodes = [...new Set([...(d.nodes ?? []), node])]; h.save(); return nodes(); }
    if (!('why' in sv)) await call(sv, 'set_daemon', { address: node, trusted: false, ...(node.startsWith('https://') && { ssl_support: 'enabled' }) }, 15000);
    d.node = node; d.nodes = [...new Set([...(d.nodes ?? []), node])]; S.at = 0; S.start = null; h.save();
    return nodes();
  };

  /** A chat message of mine that told a payment: its payment (by the contact and the message's `at`). */
  const paymentOf = (contact: string, at: number): Json | null => {
    for (const [txid, p] of Object.entries(W().payments ?? {})) if (p.contact === contact && p.msg_at === at) return { txid, amount: p.amount, note: p.note };
    return null;
  };
  return { paymentOf, routes: {
    'GET /api/wallet': () => read(false),
    'POST /api/wallet/sync': () => read(true),
    'POST /api/wallet/receive': async (b) => {
      const sv = await ready(), note = typeof b['note'] === 'string' ? b['note'].trim() : '';
      if (!NOTE.test(note)) refuse(400, 'body', 'note: at most 100 characters, no control characters');
      const r = await call(sv, 'create_address', { account_index: sv.account, label: note });
      return { address: String(r['address']), index: Number(r['address_index']), account: sv.account };
    },
    'POST /api/wallet/label': async (b) => {
      const sv = await ready(), note = typeof b['note'] === 'string' ? b['note'].trim() : '';
      if (!NOTE.test(note) || !Number.isSafeInteger(b['index'])) refuse(400, 'body', '{index, note}: the address index and at most 100 characters');
      await call(sv, 'label_address', { index: { major: sv.account, minor: b['index'] }, label: note });
      return { index: b['index'], note };
    },
    'POST /api/wallet/review': (b) => review(b),
    'POST /api/wallet/send': (b) => send(b),
    'GET /api/wallet/history': (_b, q) => history(q),
    'GET /api/wallet/tx': (_b, q) => tx(q),
    'GET /api/wallet/services': () => (h.on() ? services() : refuse(409, 'wallet_off', 'Wallet is off for this profile.')),
    'POST /api/wallet/service': (b) => (h.on() ? setService(b) : refuse(409, 'wallet_off', 'Wallet is off for this profile.')),
    'GET /api/wallet/nodes': () => (h.on() ? nodes() : refuse(409, 'wallet_off', 'Wallet is off for this profile.')),
    'POST /api/wallet/node': (b) => (h.on() ? setNode(b) : refuse(409, 'wallet_off', 'Wallet is off for this profile.')),
    'GET /api/price': () => price(),
  } };
}
