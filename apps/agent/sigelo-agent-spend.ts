// SPDX-License-Identifier: MIT
/**
 * The keeper settings and the payment requests of the page (UI-API.md "Keeper"): what `sigelo-spend`
 * (apps/keeper) keeps on this computer, read and written for the agents' pages of `sigelo-agent ui`.
 *
 * Where: the keepers this host registered (`SIGELO_SPEND_REGISTRY`, else
 * `$XDG_CONFIG_HOME/sigelo-spend/keepers.json`, the file apps/keeper/licence.ts writes), each a directory
 * with `policy.json`, `install.json`, `identity.json` and `spend.log`. Nothing else is looked for: no
 * keeper registered is `none`; one whose files this user cannot read (the two-user layout) is
 * `unreadable`. The self-contained app has no keeper (apps/contact/page.mjs answers `elsewhere`).
 *
 * Read: per agent its caps (`per_tx_max`, `per_period_max`, `period_seconds`, `rate_per_minute`,
 * `approval_above`, `max_delegates`), its allowlist, and what it spent in the period (spend.log, counted
 * as the keeper counts it: an intent's amount + fee, once per transaction); the keeper's `approvers`;
 * the payment requests waiting (`pending` lines the keeper signed, not approved, not spent, not expired).
 *
 * Write: only those fields of one agent, and the approvers list, each checked as apps/keeper/policy.ts
 * checks it, everything else in the file kept as it is; written whole, 0600, through a temporary file.
 * A running keeper re-reads the file on its next request (apps/keeper/README.md "What a running keeper
 * re-reads", 0.1.15); one installed before that takes it at its next start: `featuresOf()` tells which by
 * the frozen copy it runs, the answer says so, and `restart()` restarts a systemd user unit.
 *
 * Approve: the request's body signed by the human's own key (an approver's: its current DID must be in
 * `approvers`) and posted to the keeper's own `POST /approve`, which checks everything again; the agent's
 * next run of the same pay pays it once. Refuse: the same body with typ "spend-refusal" posted to the
 * keeper's `POST /refuse` with the reason (a keeper-signed `refused` line: the agent's same pay is
 * REFUSED until exp); a keeper without that route, or one that refuses it, leaves it kept on this side
 * only. Either way the page tells the agent in its chat (sigelo-agent-ui.ts).
 *
 * Seen: the addresses the keeper paid, was asked to pay or was invoiced for (spend.log), newest first,
 * offered under "Who it may pay" beside the contacts.
 *
 * Signed (design/agent-wallet-page.md, Owner 2026-11-14): a keeper that takes `POST /policy` and lists this
 * identity in `owners` gets every change as a `policy-change` signed by this identity, which it checks and
 * logs; the file write stays for a keeper from before, or one not running. Its `POST /agents`, signed the same
 * way, gives each agent's address (i, 0), balance and incoming money. `relayPolicy` carries a change another
 * device signed (a phone with its own identity) to the keeper untouched: this side cannot alter it.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { did as didOf, structure, verify, verifySig, type Bundle, type Genesis } from 'sigelo';
import { decodeAddress } from 'sigelo/dist/monero.js';

const ATOMIC = /^(0|[1-9][0-9]*)$/, MAX_ATOMIC = 9007199254740991n;
const DID = /^did:sigelo:z[1-9A-HJ-NP-Za-km-z]+$/, NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const PERIODS = new Set([3600, 86400, 7 * 86400, 30 * 86400]);
type Json = Record<string, unknown>;
const plain = (x: unknown): x is Json => typeof x === 'object' && x !== null && !Array.isArray(x);
const fail = (status: number, check: string, message: string): never => { throw Object.assign(new Error(message), { check, status }); };

export const registryPath = (env: Record<string, string | undefined> = process.env): string => env['SIGELO_SPEND_REGISTRY'] ||
  join(env['XDG_CONFIG_HOME'] || join(homedir(), '.config'), 'sigelo-spend', 'keepers.json');

/** A keeper of this host, read: its files as JSON (policy kept raw, to be written back as it was). */
export interface KeeperHere {
  id: string; dir: string; policyPath: string; did: string; key: string; net: string; port: number | null;
  install: Json; policy: Json; log: { entry: Json; sig: string }[];
}
export type Found = { state: 'here'; keepers: KeeperHere[] } | { state: 'none' } | { state: 'unreadable'; detail: string };

/** The keepers registered on this host, their files read now. */
export function findKeepers(env: Record<string, string | undefined> = process.env): Found {
  const reg = registryPath(env);
  if (!existsSync(reg)) return { state: 'none' };
  let dirs: string[];
  try {
    const raw = JSON.parse(readFileSync(reg, 'utf8')) as unknown;
    dirs = plain(raw) && Array.isArray(raw['keepers']) ? (raw['keepers'] as unknown[]).flatMap((k) => (plain(k) && typeof k['dir'] === 'string' ? [resolve(k['dir'])] : [])) : [];
  } catch (e) { return { state: 'unreadable', detail: `${reg}: ${(e as Error).message}` }; }
  dirs = dirs.filter((d) => existsSync(join(d, 'policy.json')));
  if (dirs.length === 0) return { state: 'none' };
  const keepers: KeeperHere[] = [];
  for (const dir of dirs) {
    try { keepers.push(readKeeperDir(dir)); } catch (e) {
      if (keepers.length === 0 && dir === dirs.at(-1)) return { state: 'unreadable', detail: (e as Error).message };
    }
  }
  return keepers.length ? { state: 'here', keepers } : { state: 'unreadable', detail: 'no keeper here could be read' };
}

const readJson = (file: string): Json => {
  const raw = JSON.parse(readFileSync(file, 'utf8')) as unknown;
  if (!plain(raw)) throw new Error(`${file}: not a JSON object`);
  return raw;
};
/** One keeper directory: its identity (the key its lines are signed with), its install, its policy, its log. */
export function readKeeperDir(dir: string, now = Math.floor(Date.now() / 1000)): KeeperHere {
  const policyPath = join(dir, 'policy.json');
  let policy: Json;
  try { policy = readJson(policyPath); } catch (e) {
    const code = (e as { code?: string }).code;
    throw new Error(code === 'EACCES' ? `the keeper at ${dir} runs under its own user: this user cannot read it` : `${policyPath}: ${(e as Error).message}`);
  }
  if (!plain(policy['agents'])) throw new Error(`${policyPath}: an older policy (buckets): set it there with sigelo-spend`);
  let install: Json = {};
  try { install = readJson(join(dir, 'install.json')); } catch {}
  // The keeper's DID and current key: identity.json (a bundle), verified.
  const b = readJson(join(dir, 'identity.json')) as unknown as Bundle;
  const r = verify(b, now);
  const head = (b.rotations ?? []).at(-1)?.next_genesis ?? b.genesis;
  const log: { entry: Json; sig: string }[] = [];
  const lp = join(dir, 'spend.log');
  if (existsSync(lp)) {
    for (const line of readFileSync(lp, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try { const x = JSON.parse(line) as unknown; if (plain(x) && plain(x['entry']) && typeof x['sig'] === 'string') log.push({ entry: x['entry'], sig: x['sig'] }); } catch {}
    }
  }
  const port = Number.isSafeInteger(install['port']) ? install['port'] as number : null;
  return { id: basename(dir), dir, policyPath, did: r.chain[0]!, key: head.key, net: String(policy['net'] ?? ''), port, install, policy, log };
}

// ---- reading
const agentOf = (e: Json): string => { const q = plain(e['request']) ? e['request'] : {}; return String(q['agent'] ?? q['bucket'] ?? ''); };
/** What each agent spent since `since`: an intent's amount + fee (relayed or not), once per transaction, as the keeper counts. */
function spent(k: KeeperHere, name: string, since: number): bigint {
  const open = new Map<string, number>();
  let t = 0n;
  for (const { entry: e } of k.log) {
    if (Object.hasOwn(e, 'kind') || e['status'] === 'approved' || e['status'] === 'pending' || e['status'] === 'refused') continue;
    const tx = String(e['txid'] ?? ''), n = open.get(tx) ?? 0;
    if ((e['status'] === 'relayed' || e['status'] === 'relay_failed') && n > 0) { open.set(tx, n - 1); continue; }
    if (e['status'] === 'intent') open.set(tx, n + 1);
    if (agentOf(e) !== name || !Number.isSafeInteger(e['ts']) || (e['ts'] as number) <= since) continue;
    try { t += BigInt(String(e['amount'])) + BigInt(String(e['fee'])); } catch {}
  }
  return t;
}
export interface Worker { worker: number; name: string; did: string; original: string; status: string; local: string | null }
/** The policy entry of each worker: by its DID (original or current), else, for an entry without one, by its name. */
function match(k: KeeperHere, ws: Worker[]): Map<string, Worker> {
  const out = new Map<string, Worker>(), agents = k.policy['agents'] as Record<string, Json>;
  for (const [name, a] of Object.entries(agents)) {
    const w = typeof a['did'] === 'string' ? ws.find((x) => x.original === a['did'] || x.did === a['did']) : ws.find((x) => x.name === name && x.status !== 'revoked');
    if (w) out.set(name, w);
  }
  return out;
}
const ruleView = (r: unknown): Json => {
  const x = plain(r) ? r : {};
  return typeof x['addr'] === 'string' ? { kind: 'addr', addr: x['addr'], label: x['label'] ?? null }
    : { kind: typeof x['did'] === 'string' ? 'did' : 'issuer', did: x['did'] ?? null, issuer: x['issuer'] ?? null, ctx: x['ctx'] ?? null };
};
/** The restart a cap needs: the keeper's systemd unit, and whether this page may run it (a user unit). */
export function restartOf(k: KeeperHere): { command: string; can: boolean } {
  const units = Array.isArray(k.install['units']) ? (k.install['units'] as unknown[]).filter((u): u is string => typeof u === 'string') : [];
  const unit = units.find((u) => /^sigelo-keeper-.*\.service$/.test(u));
  if (k.install['systemd'] === true && unit !== undefined) {
    const user = typeof k.install['unit_dir'] === 'string' && (k.install['unit_dir'] as string).includes(join('.config', 'systemd', 'user'));
    return { command: `systemctl${user ? ' --user' : ''} restart ${unit}`, can: user };
  }
  return { command: `stop and start sigelo-spend serve ${k.policyPath}${k.port !== null ? ` --port ${k.port}` : ''}`, can: false };
}
/**
 * What the keeper's frozen copy can do (apps/keeper/init.ts copies the package to `<dir>/app`, `install.json`
 * `app`): `live` it re-reads policy.json on its next request, `refuse` it takes POST /refuse (both 0.1.15).
 * null: not known (a keeper run by hand); the page then says both cases.
 */
export function featuresOf(k: KeeperHere): { live: boolean | null; refuse: boolean | null; policy: boolean | null } {
  const app = typeof k.install['app'] === 'string' ? k.install['app'] as string : null;
  if (app === null) return { live: null, refuse: null, policy: null };
  try {
    const src = readFileSync(join(dirname(app), 'service.js'), 'utf8');
    return { live: src.includes('now in use for'), refuse: src.includes("'POST /refuse'"), policy: src.includes("'POST /policy'") };
  } catch { return { live: null, refuse: null, policy: null }; }
}
/** The policy's `owners` (POST /policy), as DIDs. */
export const ownersOf = (k: KeeperHere): string[] => (Array.isArray(k.policy['owners']) ? (k.policy['owners'] as Json[]).map((o) => String(o['did'])) : []);
/** Is this identity one of the keeper's owners: its current DID or one of its chain (the keeper checks the same). */
export const isOwner = (k: KeeperHere, me: { did: string; chain?: string[] }): boolean => ownersOf(k).some((d) => d === me.did || (me.chain ?? []).includes(d));
/** The addresses this keeper paid, was asked to pay (pending, refused) or was invoiced for, newest first, once each. */
function seenOf(k: KeeperHere): Json[] {
  const by = new Map<string, Json>();
  for (const { entry: e } of k.log) {
    const q = plain(e['request']) ? e['request'] as Json : null, to = q && plain(q['to']) ? q['to'] as Json : null;
    if (!to || typeof to['addr'] !== 'string' || !Number.isSafeInteger(e['ts'])) continue;
    const addr = to['addr'] as string, was = by.get(addr);
    by.delete(addr);
    by.set(addr, { addr, agent: agentOf(e), purpose: String(q!['purpose'] ?? ''), did: typeof to['did'] === 'string' ? to['did'] : was?.['did'] ?? null,
      invoice: plain(to['invoice']) || was?.['invoice'] === true, paid: e['status'] === 'relayed' || was?.['paid'] === true, last: e['ts'] });
  }
  return [...by.values()].reverse().slice(0, 32);
}
/** The approval requests still open: signed by the keeper, not approved or spent, not expired, not refused here. */
function requests(k: KeeperHere, now: number, refused: Record<string, number>): Json[] {
  const used = new Set<string>(), open: Json[] = [];
  for (const { entry: e, sig } of k.log) {
    if (e['status'] === 'approved' && plain(e['approval']) && plain((e['approval'] as Json)['body']) && verifySig(k.key, e, sig)) used.add(String(((e['approval'] as Json)['body'] as Json)['nonce']));
    if (e['status'] === 'refused' && plain(e['refusal']) && plain((e['refusal'] as Json)['body']) && verifySig(k.key, e, sig)) used.add(String(((e['refusal'] as Json)['body'] as Json)['nonce']));
    if (e['status'] === 'intent' && plain(e['request']) && typeof (e['request'] as Json)['approval'] === 'string') used.add((e['request'] as Json)['approval'] as string);
  }
  for (const { entry: e, sig } of k.log) {
    const q = e['approval_request'];
    if (e['status'] !== 'pending' || !plain(q) || !verifySig(k.key, e, sig)) continue;
    const nonce = String(q['nonce']), exp = Number(q['exp']);
    if (used.has(nonce) || !(exp > now) || refused[`${k.id}/${nonce}`] !== undefined || q['keeper'] !== k.did) continue;
    open.push({ keeper: k.id, nonce, agent: agentOf(e), amount: String(q['amount']), to: String(q['to']), purpose: String(q['purpose'] ?? ''), ref: String(q['ref'] ?? ''), iat: Number(q['iat']), exp });
  }
  return open;
}
/** GET /api/keeper, `here`: every keeper, its agents (named by the worker they are), the requests waiting. */
export function view(found: Found, ws: Worker[], me: { did: string; chain?: string[] }, refused: Record<string, number>, now = Math.floor(Date.now() / 1000)): Json {
  if (found.state !== 'here') return found;
  const keepers: Json[] = [], agents: Json[] = [], reqs: Json[] = [];
  for (const k of found.keepers) {
    const m = match(k, ws), approvers = Array.isArray(k.policy['approvers']) ? (k.policy['approvers'] as Json[]).map((a) => String(a['did'])) : [];
    keepers.push({ id: k.id, did: k.did, net: k.net, port: k.port, approvers, me_approver: approvers.includes(me.did), me_owner: isOwner(k, me), restart: restartOf(k), ...featuresOf(k), seen: seenOf(k) });
    for (const [name, a] of Object.entries(k.policy['agents'] as Record<string, Json>)) {
      const w = m.get(name) ?? null, period = Number(a['period_seconds']), sp = spent(k, name, now - period);
      const cap = (() => { try { return BigInt(String(a['per_period_max'])); } catch { return 0n; } })();
      agents.push({ keeper: k.id, name, worker: w?.worker ?? null, did: a['did'] ?? null, account: a['account'], per_tx_max: a['per_tx_max'], per_period_max: a['per_period_max'],
        period_seconds: period, rate_per_minute: a['rate_per_minute'], approval_above: a['approval_above'] ?? null, max_delegates: a['max_delegates'] ?? 0,
        allow: Array.isArray(a['allow']) ? (a['allow'] as unknown[]).map(ruleView) : [], spent: String(sp), remaining: String(sp > cap ? 0n : cap - sp), window_start: now - period,
        paused: a['paused'] === true, address: null, incoming: [] });
    }
    for (const r of requests(k, now, refused)) reqs.push({ ...r, worker: m.get(String(r['agent']))?.worker ?? null });
  }
  return { state: 'here', keepers, agents, requests: reqs.sort((a, b) => Number(b['iat']) - Number(a['iat'])) };
}

// ---- writing
export function keeperBy(found: Found, id: unknown): KeeperHere {
  if (found.state === 'none') return fail(409, 'keeper_none', 'There is no keeper on this computer. Set this on the computer that runs the keeper.');
  if (found.state === 'unreadable') return fail(409, 'keeper_unreadable', `This page can't read the keeper here: ${found.detail}. Set it with sigelo-spend on that computer.`);
  const k = found.keepers.find((x) => x.id === id) ?? (id === undefined && found.keepers.length === 1 ? found.keepers[0] : undefined);
  return k ?? fail(404, 'keeper_unknown', `no keeper ${JSON.stringify(id)} on this computer`);
}
const atomic = (v: unknown, what: string): string => {
  if (typeof v !== 'string' || !ATOMIC.test(v) || BigInt(v) > MAX_ATOMIC) return fail(400, 'body', `${what}: an amount in atomic units, as a decimal string`);
  return v;
};
const int = (v: unknown, what: string, min: number, max: number): number => (Number.isSafeInteger(v) && (v as number) >= min && (v as number) <= max ? v as number : fail(400, 'body', `${what}: a whole number from ${min} to ${max}`));
function allowOf(v: unknown, net: string): Json[] {
  if (!Array.isArray(v) || v.length > 64) return fail(400, 'body', 'allow: a list of at most 64 rules');
  const out = v.map((r, i): Json => {
    if (!plain(r)) return fail(400, 'body', `allow[${i}]: a rule`);
    if (typeof r['addr'] === 'string') {
      for (const k of Object.keys(r)) if (k !== 'addr' && k !== 'label') fail(400, 'body', `allow[${i}]: an address rule is {addr, label?}`);
      let d;
      try { d = decodeAddress(r['addr']); } catch { return fail(400, 'allow_addr', 'This isn\'t a Monero address. Paste their whole address.'); }
      if (d.net !== net) fail(400, 'allow_addr', `This is a ${d.net} address; this keeper pays on ${net}.`);
      if (d.kind === 'integrated') fail(400, 'allow_addr', 'Integrated addresses are refused: ask them for their standard address or a subaddress.');
      if (r['label'] !== undefined && !(typeof r['label'] === 'string' && NAME.test(r['label']))) fail(400, 'body', `allow[${i}].label: 1 to 64 of A-Z a-z 0-9 . _ -`);
      return { addr: r['addr'], ...(r['label'] !== undefined && { label: r['label'] }) };
    }
    for (const k of Object.keys(r)) if (!['did', 'issuer', 'ctx'].includes(k)) fail(400, 'body', `allow[${i}]: a rule is {addr, label?} or {did?, issuer, ctx?}`);
    if (typeof r['issuer'] !== 'string' || r['issuer'] === '') fail(400, 'body', `allow[${i}]: {did?, issuer, ctx?} needs an issuer`);
    if (r['did'] !== undefined && (typeof r['did'] !== 'string' || r['did'] === '')) fail(400, 'body', `allow[${i}].did: a DID`);
    if (r['ctx'] !== undefined && typeof r['ctx'] !== 'string') fail(400, 'body', `allow[${i}].ctx: a string`);
    return { ...(r['did'] !== undefined && { did: r['did'] }), issuer: r['issuer'], ...(r['ctx'] !== undefined && { ctx: r['ctx'] }) };
  });
  const labels = out.flatMap((r) => (typeof r['label'] === 'string' ? [r['label']] : []));
  const dup = labels.find((l, i) => labels.indexOf(l) !== i);
  if (dup !== undefined) fail(400, 'allow_label', `Two addresses are named ${dup}: give one another name.`);
  return out;
}
/** The policy written back whole, 0600, through a temporary sibling (the keeper reads it at its next start). */
function save(k: KeeperHere): void {
  const tmp = join(dirname(k.policyPath), `.policy.json.${randomBytes(6).toString('hex')}.tmp`);
  let mode = 0o600;
  try { mode = statSync(k.policyPath).mode & 0o600; } catch {}
  writeFileSync(tmp, JSON.stringify(k.policy, null, 2) + '\n', { mode: mode || 0o600, flag: 'wx' });
  renameSync(tmp, k.policyPath);
}
const FIELDS = ['per_tx_max', 'per_period_max', 'period_seconds', 'rate_per_minute', 'approval_above', 'max_delegates', 'allow', 'paused'];
/**
 * POST /api/keeper/agent: one agent's settings, checked before any is kept. `approval_above` set needs
 * approvers and the agent's DID and genesis in the policy (the keeper names the agent in a request): an
 * agent of this machine (`genesis` given by the page's host) gets them written; another is refused.
 */
export function setAgent(k: KeeperHere, name: unknown, b: Json, genesisOf: (name: string) => Genesis | null, opts: { write?: boolean; owner?: string } = {}): Json {
  const agents = k.policy['agents'] as Record<string, Json>;
  if (typeof name !== 'string' || !Object.hasOwn(agents, name)) return fail(404, 'keeper_agent', `no agent ${JSON.stringify(name)} in this keeper's policy`);
  const a = { ...agents[name]! }, given = FIELDS.filter((f) => b[f] !== undefined);
  if (given.length === 0) fail(400, 'body', `one of ${FIELDS.join(', ')}`);
  if (b['per_tx_max'] !== undefined) a['per_tx_max'] = atomic(b['per_tx_max'], 'per_tx_max');
  if (b['per_period_max'] !== undefined) a['per_period_max'] = atomic(b['per_period_max'], 'per_period_max');
  if (b['period_seconds'] !== undefined) { const p = int(b['period_seconds'], 'period_seconds', 1, 366 * 86400); if (!PERIODS.has(p)) fail(400, 'body', 'period_seconds: an hour, a day, a week or 30 days'); a['period_seconds'] = p; }
  if (b['rate_per_minute'] !== undefined) a['rate_per_minute'] = int(b['rate_per_minute'], 'rate_per_minute', 1, 600);
  if (b['max_delegates'] !== undefined) a['max_delegates'] = int(b['max_delegates'], 'max_delegates', 0, 1000);
  if (b['allow'] !== undefined) a['allow'] = allowOf(b['allow'], k.net);
  if (b['paused'] !== undefined) {
    if (typeof b['paused'] !== 'boolean') fail(400, 'body', 'paused: true or false');
    // A keeper from before 0.1.16 refuses a policy with a field it does not know: it would stop at its next start.
    if (featuresOf(k).policy !== true && opts.write !== false) fail(409, 'keeper_old', 'This keeper is from before Pause: update it, or set its limits to 0 meanwhile.');
    if (b['paused']) a['paused'] = true; else delete a['paused'];
  }
  if (b['approval_above'] !== undefined) {
    if (b['approval_above'] === null) delete a['approval_above'];
    else {
      a['approval_above'] = atomic(b['approval_above'], 'approval_above');
      const approvers = Array.isArray(k.policy['approvers']) ? k.policy['approvers'] as unknown[] : [];
      if (approvers.length === 0) fail(409, 'keeper_approvers', 'Nobody could approve: add yourself as an approver first (Advanced).');
      if (typeof a['did'] !== 'string' || !plain(a['genesis'])) {
        const g = genesisOf(name);
        if (g === null) fail(409, 'keeper_did', `The keeper doesn't know ${name}'s identity yet, so it can't ask you. Add ${name}'s did and genesis to its entry in ${k.policyPath}.`);
        a['did'] = didOf(g); a['genesis'] = g;
      }
    }
  }
  if (BigInt(String(a['per_tx_max'])) > BigInt(String(a['per_period_max']))) fail(400, 'keeper_caps', 'One payment can\'t be more than the whole period allows.');
  if (typeof a['did'] === 'string' && Array.isArray(k.policy['approvers']) && (k.policy['approvers'] as Json[]).some((x) => x['did'] === a['did'])) fail(409, 'keeper_approvers', `${name} is an approver: an agent can't approve its own payments.`);
  if (opts.write === false) return { entry: a, identity: a['did'] !== agents[name]!['did'] || a['genesis'] !== agents[name]!['genesis'] };
  agents[name] = a;
  // The first save by this identity on a keeper that takes signed changes makes it an owner: whoever can write
  // this file is the authority already, and from then on its changes are signed and logged.
  if (opts.owner !== undefined && featuresOf(k).policy === true && !ownersOf(k).includes(opts.owner)) k.policy['owners'] = [...ownersOf(k).map((d) => ({ did: d })), { did: opts.owner }];
  save(k);
  return { saved: true, signed: false, keeper: k.id, agent: name, live: featuresOf(k).live, restart: restartOf(k), ...(Array.isArray(k.policy['owners']) && { owners: ownersOf(k) }) };
}

/** Who signs here: this identity's DIDs (current, chain) and its key over sigelo's signing input, with its bundle. */
export interface Signer { did: string; chain: string[]; sign(body: object): string; bundle: Bundle }
const hex16 = (): string => randomBytes(16).toString('hex');
/** A keeper-local signed object for this keeper (policychange.ts in apps/keeper), signed by `me`. */
const signedFor = (k: KeeperHere, me: Signer, rest: Json, now: number): Json => {
  const body = { v: 'sigelo/0', ...rest, keeper: k.did, net: k.net, nonce: hex16(), iat: now, exp: now + 300 };
  return { body, sig: me.sign(body), bundle: me.bundle };
};
/** The keeper's answer to a signed object, or a 409 naming the keeper's own code (`keeper_owner`, …). */
async function toKeeper(k: KeeperHere, path: string, env: unknown): Promise<Json> {
  if (k.port === null) return fail(409, 'keeper_offline', `The keeper's port isn't in ${join(k.dir, 'install.json')}: set it on that computer with sigelo-spend.`);
  let r;
  try { r = await post(k.port, path, env); } catch (e) {
    return fail(409, 'keeper_offline', `The keeper isn't answering on this computer (${(e as { code?: string }).code ?? 'no answer'}). Start it, then save again.`);
  }
  if (r.status === 404) fail(409, 'keeper_old', 'This keeper is from before signed changes: update it, or set its limits on this computer\'s page.');
  if (r.status !== 200) fail(409, `keeper_${String(r.body['code'] ?? 'refused')}`, String(r.body['error'] ?? `the keeper said ${r.status}`));
  return r.body;
}
/**
 * POST /api/keeper/agent: one agent's settings. A keeper that takes signed changes and lists this identity in
 * `owners` gets them as a `policy-change` signed here (checked and logged by the keeper, in use at once): the
 * same checks as the file write first, then only the fields given. Else, or when the keeper is not running,
 * or when the change needs the agent's did and genesis written (approval_above), the file as before.
 */
export async function saveAgent(k: KeeperHere, name: unknown, b: Json, genesisOf: (name: string) => Genesis | null, me: Signer, now = Math.floor(Date.now() / 1000)): Promise<Json> {
  const dry = setAgent({ ...k, policy: structuredClone(k.policy) }, name, b, genesisOf, { write: false }) as { entry: Json; identity: boolean };
  if (!isOwner(k, me) || featuresOf(k).policy === false || k.port === null || dry.identity) return setAgent(k, name, b, genesisOf, { owner: me.chain[0] ?? me.did });
  const set: Json = {};
  for (const f of FIELDS) if (b[f] !== undefined) set[f] = f === 'paused' ? b[f] : f === 'approval_above' && b[f] === null ? null : dry.entry[f];
  let r: Json;
  try { r = await toKeeper(k, '/policy', signedFor(k, me, { typ: 'policy-change', agent: name, set }, now)); } catch (e) {
    // Not running: the file, as a keeper before signed changes takes it (at its next request or start).
    if ((e as { check?: string }).check === 'keeper_offline' && b['paused'] === undefined) return { ...setAgent(k, name, b, genesisOf, { owner: me.chain[0] ?? me.did }), why: 'offline' };
    throw e;
  }
  return { saved: true, signed: true, keeper: k.id, agent: name, by: r['by'], policy: r['policy'], live: true, restart: restartOf(k) };
}
/** POST /api/keeper/policy: a change signed elsewhere (`{body, sig, bundle}`, a phone's), carried to the keeper as it is. */
export async function relayPolicy(k: KeeperHere, change: unknown): Promise<Json> {
  if (!plain(change) || !plain(change['body']) || typeof change['sig'] !== 'string' || !plain(change['bundle'])) return fail(400, 'body', 'change: {body, sig, bundle}, signed by the owner');
  if (change['body']['keeper'] !== k.did) fail(400, 'body', `change: for keeper ${String(change['body']['keeper'])}, this one is ${k.did}`);
  const r = await toKeeper(k, '/policy', change);
  return { saved: true, signed: true, relayed: true, keeper: k.id, agent: r['agent'], by: r['by'], policy: r['policy'], live: true };
}
/** The keeper's POST /agents, signed by `me` (an owner): per agent its address, balance and incoming money; null when it can't. */
export async function ownerView(k: KeeperHere, me: Signer, now = Math.floor(Date.now() / 1000)): Promise<Json | null> {
  if (!isOwner(k, me) || k.port === null || featuresOf(k).policy === false) return null;
  try { return await toKeeper(k, '/agents', signedFor(k, me, { typ: 'owner-view' }, now)); } catch { return null; }
}
/** GET /api/keeper's agents with what the keeper's owner view says (address, balance, unlocked, incoming, paused). */
export function mergeView(v: Json, k: KeeperHere, ov: Json): void {
  const rows = Array.isArray(ov['agents']) ? ov['agents'] as Json[] : [];
  for (const a of (v['agents'] as Json[]).filter((x) => x['keeper'] === k.id)) {
    const o = rows.find((x) => x['name'] === a['name']);
    if (!o) continue;
    Object.assign(a, { address: typeof o['address'] === 'string' ? o['address'] : null, paused: o['paused'] === true, incoming: Array.isArray(o['incoming']) ? o['incoming'] : [],
      ...(typeof o['balance'] === 'string' && { balance: o['balance'], unlocked_balance: o['unlocked_balance'] }) });
  }
}
/** POST /api/keeper/approvers: the keeper's approver DIDs (all its agents'), the whole list. */
export function setApprovers(k: KeeperHere, list: unknown): Json {
  if (!Array.isArray(list) || list.length > 32 || !list.every((d) => typeof d === 'string' && DID.test(d))) return fail(400, 'body', 'approvers: a list of did:sigelo:z… DIDs');
  const dids = [...new Set(list as string[])], agents = k.policy['agents'] as Record<string, Json>;
  const own = Object.entries(agents).find(([, a]) => dids.includes(a['did'] as string));
  if (own) fail(409, 'keeper_approvers', `${own[0]} is one of the agents: an agent can't approve its own payments.`);
  const asks = Object.entries(agents).find(([, a]) => a['approval_above'] !== undefined && a['approval_above'] !== null);
  if (dids.length === 0 && asks) fail(409, 'keeper_approvers', `${asks[0]} asks before paying more than a limit: with nobody to approve it, turn that off first.`);
  if (dids.length === 0) delete k.policy['approvers']; else k.policy['approvers'] = dids.map((d) => ({ did: d }));
  save(k);
  return { saved: true, keeper: k.id, approvers: dids, live: featuresOf(k).live, restart: restartOf(k) };
}

// ---- approving
const post = (port: number, path: string, body: unknown): Promise<{ status: number; body: Json }> => new Promise((ok, no) => {
  const text = JSON.stringify(body);
  const r = request({ host: '127.0.0.1', port, method: 'POST', path, timeout: 15000, headers: { Host: `127.0.0.1:${port}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) } }, (res) => {
    let b = ''; res.setEncoding('utf8'); res.on('data', (d: string) => { b += d; });
    res.on('end', () => { let j: Json = {}; try { const x = JSON.parse(b) as unknown; if (plain(x)) j = x; } catch {} ok({ status: res.statusCode ?? 0, body: j }); });
  });
  r.on('timeout', () => r.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
  r.on('error', no);
  r.end(text);
});
/**
 * POST /api/keeper/approve: the pending request `nonce`, as the keeper signed it, signed by the human
 * (`sign` over sigelo's signing input, the key of `bundle`'s head) and posted to the keeper's /approve.
 */
export async function approve(k: KeeperHere, nonce: unknown, me: { did: string; sign(body: object): string; bundle: Bundle }, now = Math.floor(Date.now() / 1000)): Promise<Json> {
  if (typeof nonce !== 'string' || !/^[0-9a-f]{32}$/.test(nonce)) return fail(400, 'body', 'nonce: the request\'s nonce (32 hex digits)');
  const open = requests(k, now, {}).find((r) => r['nonce'] === nonce);
  if (!open) return fail(404, 'keeper_request', 'This request isn\'t waiting any more: it was answered, paid or ran out.');
  const line = k.log.find(({ entry: e }) => e['status'] === 'pending' && plain(e['approval_request']) && (e['approval_request'] as Json)['nonce'] === nonce)!;
  const body = line.entry['approval_request'] as Json;
  const approvers = Array.isArray(k.policy['approvers']) ? (k.policy['approvers'] as Json[]).map((a) => a['did']) : [];
  if (!approvers.includes(me.did)) fail(409, 'keeper_not_approver', 'You aren\'t one of this keeper\'s approvers. Add yourself under Advanced, restart the keeper, then approve.');
  structure(me.bundle.genesis, 'genesis');
  if (k.port === null) fail(409, 'keeper_offline', `The keeper's port isn't in ${join(k.dir, 'install.json')}: approve on that computer with sigelo-spend.`);
  let r;
  try { r = await post(k.port!, '/approve', { body, sig: me.sign(body), bundle: me.bundle }); } catch (e) {
    return fail(409, 'keeper_offline', `The keeper isn't answering on this computer (${(e as { code?: string }).code ?? 'no answer'}). Start it, then approve again.`);
  }
  if (r.status !== 200) fail(409, `keeper_${String(r.body['code'] ?? 'refused')}`, String(r.body['error'] ?? `the keeper said ${r.status}`));
  return { approved: true, keeper: k.id, nonce, agent: open['agent'], amount: open['amount'], next: 'the agent pays it the next time it asks' };
}
/**
 * POST /api/keeper/refuse: the pending request `nonce` answered no. Its body with typ "spend-refusal", signed by the
 * human, and `reason`, posted to the keeper's /refuse: a keeper-signed `refused` line, and the agent's same pay is
 * REFUSED until exp. `logged: false` (with why) when the keeper has no such route, is not running, or refused it:
 * the request is then put away on this side only (the caller keeps it), as before 0.1.15.
 */
export async function refuseAt(k: KeeperHere, nonce: unknown, reason: string, me: { did: string; sign(body: object): string; bundle: Bundle }, now = Math.floor(Date.now() / 1000)): Promise<Json> {
  if (typeof nonce !== 'string' || !/^[0-9a-f]{32}$/.test(nonce)) return fail(400, 'body', 'nonce: the request\'s nonce (32 hex digits)');
  const open = requests(k, now, {}).find((r) => r['nonce'] === nonce);
  if (!open) return fail(404, 'keeper_request', 'This request isn\'t waiting any more: it was answered, paid or ran out.');
  const line = k.log.find(({ entry: e }) => e['status'] === 'pending' && plain(e['approval_request']) && (e['approval_request'] as Json)['nonce'] === nonce)!;
  const body = { ...(line.entry['approval_request'] as Json), typ: 'spend-refusal' };
  const base = { refused: true, keeper: k.id, nonce, agent: open['agent'], exp: open['exp'] };
  const approvers = Array.isArray(k.policy['approvers']) ? (k.policy['approvers'] as Json[]).map((a) => a['did']) : [];
  if (!approvers.includes(me.did)) return { ...base, logged: false, why: 'not_approver' };
  if (k.port === null || featuresOf(k).refuse === false) return { ...base, logged: false, why: k.port === null ? 'no_port' : 'old_keeper' };
  let r;
  try { r = await post(k.port, '/refuse', { body, sig: me.sign(body), bundle: me.bundle, ...(reason !== '' && { reason }) }); } catch { return { ...base, logged: false, why: 'offline' }; }
  if (r.status === 404) return { ...base, logged: false, why: 'old_keeper' };
  if (r.status !== 200) return { ...base, logged: false, why: String(r.body['code'] ?? 'refused'), detail: String(r.body['error'] ?? '') };
  return { ...base, logged: true };
}
/** POST /api/keeper/restart: the keeper's systemd user unit restarted (its new caps), else how to. */
export function restart(k: KeeperHere, run = (cmd: string, args: string[]) => spawnSync(cmd, args, { encoding: 'utf8', timeout: 20000 })): Json {
  const r = restartOf(k);
  if (!r.can) return fail(409, 'keeper_restart', `Restart it on that computer: ${r.command}`);
  const [cmd, ...args] = r.command.split(' ');
  const x = run(cmd!, args);
  if (x.status !== 0) fail(409, 'keeper_restart', `It didn't restart${x.error ? ` (${x.error.message})` : x.stderr ? ` (${String(x.stderr).trim().split('\n')[0]})` : ''}. Run it there: ${r.command}`);
  return { restarted: true, keeper: k.id };
}
