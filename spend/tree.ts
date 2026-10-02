// SPDX-License-Identifier: MIT
/**
 * sigelo-spend — the delegation tree (MONERO.md §4.3, §8 G5).
 *
 * Pure, like policy.ts: no I/O, no clock, no wallet. The tree is never stored anywhere but
 * in spend.log, as signed `delegate` and `revoke` lines; every start replays them on top of
 * the Owner's policy.json, whose agents are the roots. So policy.json stays the Owner's file,
 * and a restart rebuilds exactly the tree the log says was built.
 *
 * The one rule: a delegate can never exceed its delegator. Refused at creation (`planDelegate`)
 * and enforced again at every spend (`effective`): caps are the minimum along the ancestor
 * chain and `allow` keeps only rules every ancestor still covers, so an Owner who tightens a
 * root tightens its whole subtree without touching the log.
 */
import { did as didOf, structure, type Genesis } from 'sigelo';
import { parseAllow, plain, type Agent, type AllowRule, type Policy } from './policy.js';
import type { Net } from 'sigelo/dist/monero.js';

/** What a delegate may spend. `period_seconds` is not here: it is always the root's. */
export interface DelegateCaps { per_tx_max: string; per_period_max: string; rate_per_minute: number }
export interface DelegateEntry {
  kind: 'delegate'; ts: number; name: string; parent: string;
  /** Its Monero account, from `create_account`. Never reused, not even after revocation. */
  account: number;
  /** The account's (i, 0) address: where funding goes. */
  address: string;
  did: string; genesis: Genesis; token_hash: string;
  caps: DelegateCaps; allow: AllowRule[];
  /** How many delegates its own subtree may hold (see `reserved`). 0 by default (§9 decision 9). */
  max_delegates: number;
  /** Its own threshold (§4.1 step 8), or null for none of its own: it is clamped by its ancestors' anyway. */
  approval_above: string | null;
}
/** `by` is the agent that revoked it: a strict ancestor. Revoking a node revokes its subtree. */
export interface RevokeEntry { kind: 'revoke'; ts: number; name: string; by: string }
export type TreeEntry = DelegateEntry | RevokeEntry;
export interface Tree { delegates: Map<string, DelegateEntry>; revoked: Map<string, RevokeEntry> }
export type Roots = Record<string, Agent>;
export type Status = 'live' | 'revoked' | 'orphaned';

const ATOMIC = /^(0|[1-9][0-9]*)$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HASH = /^sha256:[0-9a-f]{64}$/;
const DELEGATE_FIELDS = ['kind', 'ts', 'name', 'parent', 'account', 'address', 'did', 'genesis', 'token_hash', 'caps', 'allow', 'max_delegates', 'approval_above'];
const intIn = (x: unknown, min: number): x is number => Number.isSafeInteger(x) && (x as number) >= min;
const min = (a: string, b: string): string => (BigInt(a) < BigInt(b) ? a : b);
/** The lower of two thresholds, `null` being "never" — above every number. */
const lowest = (a: string | null, b: string | null): string | null => (a === null ? b : b === null ? a : min(a, b));
const own = (o: object, k: string): boolean => Object.hasOwn(o, k);

/**
 * One log line's entry, if it is a tree line: `undefined` when it is not one (a spend line),
 * a thrown error naming the field when it claims to be one and is malformed. A malformed tree
 * line is fatal to the log, like a spend line whose debit is unknown: it decides who holds
 * a token.
 */
export function asTreeEntry(e: unknown, net: Net, at: string): TreeEntry | undefined {
  if (!plain(e) || !own(e, 'kind')) return undefined;
  const fail = (m: string): never => { throw new Error(`${at}: ${e['kind']} line: ${m}`); };
  if (!intIn(e['ts'], 0)) fail('ts is not a non-negative integer');
  if (typeof e['name'] !== 'string' || !NAME.test(e['name'])) fail('name is not 1..64 of [A-Za-z0-9._-]');
  if (e['kind'] === 'revoke') {
    if (Object.keys(e).sort().join() !== 'by,kind,name,ts') fail('fields are not exactly { kind, ts, name, by }');
    if (typeof e['by'] !== 'string' || !NAME.test(e['by'])) fail('by is not an agent name');
    return e as unknown as RevokeEntry;
  }
  if (e['kind'] !== 'delegate') return fail(`unknown kind ${JSON.stringify(e['kind'])}`);
  for (const k of Object.keys(e)) if (!DELEGATE_FIELDS.includes(k)) fail(`unknown field ${JSON.stringify(k)}`);
  for (const k of DELEGATE_FIELDS) if (!own(e, k)) fail(`missing ${k}`);
  if (typeof e['parent'] !== 'string' || !NAME.test(e['parent'])) fail('parent is not an agent name');
  if (!intIn(e['account'], 1)) fail('account is not an account index above 0');
  if (typeof e['address'] !== 'string') fail('address is not a string');
  if (typeof e['token_hash'] !== 'string' || !HASH.test(e['token_hash'])) fail('token_hash is not sha256:<64 hex>');
  try { structure(e['genesis'], 'genesis'); } catch (x) { fail(`genesis: ${x instanceof Error ? x.message : String(x)}`); }
  if (e['did'] !== didOf(e['genesis'])) fail('did is not the DID of genesis');
  const c = e['caps'];
  if (!plain(c) || Object.keys(c).sort().join() !== 'per_period_max,per_tx_max,rate_per_minute') fail('caps is not { per_tx_max, per_period_max, rate_per_minute }');
  const caps = c as Record<string, unknown>;
  if (typeof caps['per_tx_max'] !== 'string' || !ATOMIC.test(caps['per_tx_max']) || typeof caps['per_period_max'] !== 'string' || !ATOMIC.test(caps['per_period_max'])) fail('caps: an amount is not a decimal string of atomic units');
  if (!intIn(caps['rate_per_minute'], 1)) fail('caps.rate_per_minute is not a positive integer');
  if (!intIn(e['max_delegates'], 0)) fail('max_delegates is not a non-negative integer');
  if (e['approval_above'] !== null && !(typeof e['approval_above'] === 'string' && ATOMIC.test(e['approval_above']))) fail('approval_above is not null or a decimal string of atomic units');
  if (!Array.isArray(e['allow'])) fail('allow is not an array');
  parseAllow(e['allow'], net, `${at}: delegate line: allow`);
  return e as unknown as DelegateEntry;
}

/**
 * Every name the tree or the roots have ever used, parents included: a name, like an account
 * index, is never handed out twice. A new delegate under a revoked one's name would inherit its
 * spends and its revocation; one under a root the Owner removed would become the parent of
 * that root's orphans. `logged` is every agent (and pre-G1 bucket) name any spend.log line
 * names: a root the Owner removed, with no delegates, is in neither the roots nor the tree,
 * and a delegate given its name would read its /log, /history and /budget and answer its refs.
 */
export function usedNames(t: Tree, roots: Roots, logged: Iterable<string> = []): Set<string> {
  const s = new Set([...Object.keys(roots), ...logged]);
  for (const d of t.delegates.values()) { s.add(d.name); s.add(d.parent); }
  return s;
}
/** Every account index a root or a delegate — live, revoked or orphaned — has held. */
export function usedAccounts(t: Tree, roots: Roots): Set<number> {
  return new Set([...Object.values(roots).map((a) => a.account), ...[...t.delegates.values()].map((d) => d.account)]);
}

/**
 * Rebuild the tree from the log's tree lines, in order. Anything the service could never have
 * written is fatal — a name or account used twice, a revoke by someone who is not an ancestor —
 * because the log is what decides who holds a token. A delegate whose root is no longer in
 * policy.json is kept, and `status` calls it orphaned: its token is dead with its root.
 */
export function replay(entries: TreeEntry[], roots: Roots): Tree {
  const t: Tree = { delegates: new Map(), revoked: new Map() };
  for (const e of entries) {
    if (e.kind === 'delegate') {
      if (usedNames(t, roots).has(e.name)) throw new Error(`spend.log: delegate ${JSON.stringify(e.name)}: the name is already used (policy.json or an earlier line)`);
      if (usedAccounts(t, roots).has(e.account)) throw new Error(`spend.log: delegate ${JSON.stringify(e.name)}: account ${e.account} is already used — an account index is never reused`);
      t.delegates.set(e.name, e);
    } else {
      if (!t.delegates.has(e.name)) throw new Error(`spend.log: revoke of ${JSON.stringify(e.name)}, which is not a delegate`);
      if (!chain(t, e.name).slice(1).includes(e.by)) throw new Error(`spend.log: revoke of ${JSON.stringify(e.name)} by ${JSON.stringify(e.by)}, which is not its ancestor`);
      if (!t.revoked.has(e.name)) t.revoked.set(e.name, e);
    }
  }
  return t;
}

/** `[name, parent, …, root]`. Terminates: a parent is always an earlier line or a root. */
export function chain(t: Tree, name: string): string[] {
  const out: string[] = [];
  for (let n: string | undefined = name; n !== undefined; n = t.delegates.get(n)?.parent) out.push(n);
  return out;
}

/** A root is live while policy.json has it. A delegate is live unless it or an ancestor was revoked, or its root is gone. */
export function status(t: Tree, roots: Roots, name: string): Status | undefined {
  if (!t.delegates.has(name)) return own(roots, name) ? 'live' : undefined;
  const c = chain(t, name);
  if (c.some((n) => t.revoked.has(n))) return 'revoked';
  return own(roots, c.at(-1)!) ? 'live' : 'orphaned';
}

/**
 * The agent entry a spend is checked against: a root as policy.json has it; a live delegate
 * clamped by its parent's EFFECTIVE entry, hence by every ancestor. Caps are the minimum,
 * `period_seconds` the root's (one window for the whole chain), `allow` only what the parent
 * still covers, and `max_delegates` at most one less than the parent's (a delegate is one of
 * its parent's). A dead delegate has no entry, so its token matches nothing.
 */
export function effective(t: Tree, roots: Roots, name: string): Agent | undefined {
  const d = t.delegates.get(name);
  if (d === undefined) return own(roots, name) ? roots[name] : undefined;
  if (status(t, roots, name) !== 'live') return undefined;
  const p = effective(t, roots, d.parent)!;
  return {
    account: d.account, token_hash: d.token_hash, did: d.did, genesis: d.genesis,
    per_tx_max: min(d.caps.per_tx_max, p.per_tx_max), per_period_max: min(d.caps.per_period_max, p.per_period_max),
    period_seconds: p.period_seconds, rate_per_minute: Math.min(d.caps.rate_per_minute, p.rate_per_minute),
    allow: d.allow.filter((r) => covered(r, p.allow)), approval_above: lowest(d.approval_above, p.approval_above),
    max_delegates: Math.min(d.max_delegates, Math.max(0, p.max_delegates - 1)),
  };
}

/** The policy `evaluate` sees: the Owner's roots plus every live delegate, clamped. */
export function effectivePolicy(policy: Policy, t: Tree): Policy {
  const agents: Record<string, Agent> = { ...policy.agents };
  for (const name of t.delegates.keys()) { const a = effective(t, policy.agents, name); if (a !== undefined) agents[name] = a; }
  return { ...policy, agents };
}

/**
 * Does some rule in `allow` admit everything `r` admits? A literal is covered by the same
 * address (the label is the delegate's own name for it); an issuer rule by an issuer rule at
 * least as broad — same issuer, and no `did` or `ctx` the narrower one lacks.
 */
export function covered(r: AllowRule, allow: AllowRule[]): boolean {
  return allow.some((p) => (r.addr !== undefined ? p.addr === r.addr
    : p.addr === undefined && p.issuer === r.issuer && (p.did === undefined || p.did === r.did) && (p.ctx === undefined || p.ctx === r.ctx)));
}

/** `name` and every delegate below it, live or not, in creation order. */
export function subtree(t: Tree, name: string): string[] {
  return [...(t.delegates.has(name) ? [name] : []), ...[...t.delegates.keys()].filter((n) => n !== name && chain(t, n).includes(name))];
}

/**
 * The count rule. `max_delegates` bounds an agent's whole subtree, not just its children: each
 * LIVE child reserves 1 + its own `max_delegates`. So a delegate's subtree always fits inside
 * its delegator's allowance and the number of live accounts under a root never exceeds that
 * root's `max_delegates` — a per-child limit alone would let a chain of delegates multiply.
 */
export function reserved(t: Tree, roots: Roots, name: string): number {
  let n = 0;
  for (const d of t.delegates.values()) if (d.parent === name && status(t, roots, d.name) === 'live') n += 1 + d.max_delegates;
  return n;
}

export interface DelegateAsk {
  name: string;
  caps?: Partial<DelegateCaps & { max_delegates: number; approval_above: string | null }>;
  /** Absent: the delegator's effective allowlist, copied. */
  allow?: AllowRule[];
}
export type DelegatePlan = { ok: true; caps: DelegateCaps; allow: AllowRule[]; max_delegates: number; approval_above: string | null } | { ok: false; reason: string };

/**
 * What the tree alone does not know: every agent name spend.log has ever named (`usedNames`),
 * and how many `approvers` the policy lists.
 */
export interface PlanContext { logged?: Iterable<string>; approvers?: number }

/**
 * §4.3's nesting rule at creation, for `caller` (already known to be live). Every refusal
 * begins `delegate:`. A cap not asked for is the caller's own effective cap; one asked for
 * above it is refused, not clamped — silently getting less than was asked for is how an
 * operator ends up surprised.
 */
export function planDelegate(t: Tree, roots: Roots, caller: string, ask: DelegateAsk, ctx: PlanContext = {}): DelegatePlan {
  const no = (reason: string): DelegatePlan => ({ ok: false, reason: `delegate: ${reason}` });
  const p = effective(t, roots, caller);
  if (p === undefined) return no(`${JSON.stringify(caller)} is not a live agent`);
  if (p.max_delegates === 0) return no(`you may not create delegates (max_delegates is 0). Ask your operator.`);
  if (!NAME.test(ask.name)) return no(`name ${JSON.stringify(ask.name)} is not 1..64 of [A-Za-z0-9._-]`);
  if (usedNames(t, roots, ctx.logged).has(ask.name)) return no(`the name ${JSON.stringify(ask.name)} is taken (names are never reused)`);
  const c = ask.caps ?? {};
  const md = c.max_delegates ?? 0;
  if (!intIn(md, 0)) return no('max_delegates is not a non-negative integer');
  const used = reserved(t, roots, caller);
  if (used + 1 + md > p.max_delegates) {
    return no(`max_delegates: you have ${p.max_delegates - used} of ${p.max_delegates} left, and this delegate needs ${1 + md} (itself + its own max_delegates ${md})`);
  }
  for (const f of ['per_tx_max', 'per_period_max'] as const) {
    const v = c[f];
    if (v === undefined) continue;
    if (typeof v !== 'string' || !ATOMIC.test(v) || v === '0') return no(`${f} is not a non-zero decimal string of atomic units`);
    if (BigInt(v) > BigInt(p[f])) return no(`${f} ${v} exceeds yours, ${p[f]} — a delegate can never exceed its delegator`);
  }
  if (c.rate_per_minute !== undefined && !intIn(c.rate_per_minute, 1)) return no('rate_per_minute is not a positive integer');
  if (c.rate_per_minute !== undefined && c.rate_per_minute > p.rate_per_minute) return no(`rate_per_minute ${c.rate_per_minute} exceeds yours, ${p.rate_per_minute}`);
  // null asks for no threshold of its own; the parent's still applies (`effective`).
  const above = c.approval_above ?? null;
  if (above !== null && (typeof above !== 'string' || !ATOMIC.test(above))) return no('approval_above is not null or a decimal string of atomic units');
  if (above !== null && p.approval_above !== null && BigInt(above) > BigInt(p.approval_above)) return no(`approval_above ${above} exceeds yours, ${p.approval_above} — a delegate can never exceed its delegator`);
  // parsePolicy's rule for roots: a threshold nobody could ever approve is a freeze, not a policy.
  if (above !== null && (ctx.approvers ?? 0) === 0) return no('approval_above is set but policy.json lists no approvers — nobody could ever approve');
  const allow = ask.allow ?? p.allow.map((r) => ({ ...r }));
  const outside = allow.findIndex((r) => !covered(r, p.allow));
  if (outside >= 0) return no(`allow[${outside}] ${JSON.stringify(allow[outside])} is not in your own allowlist — a delegate's allowlist is a subset of its delegator's`);
  const labels = allow.flatMap((r) => (r.label === undefined ? [] : [r.label]));
  const dup = labels.find((l, i) => labels.indexOf(l) !== i);
  if (dup !== undefined) return no(`allow: label ${JSON.stringify(dup)} names two addresses`);
  return {
    ok: true, allow, max_delegates: md, approval_above: above,
    caps: { per_tx_max: c.per_tx_max ?? p.per_tx_max, per_period_max: c.per_period_max ?? p.per_period_max, rate_per_minute: c.rate_per_minute ?? p.rate_per_minute },
  };
}

export type RevokePlan = { ok: true; already: boolean; accounts: { name: string; account: number }[] } | { ok: false; reason: string };

/**
 * Who may revoke `name`: any strict ancestor (its delegator, or anyone above). Unknown and
 * not-yours read the same, as tokens do. `already` means a revoke line (its own or an
 * ancestor's) covers it, so no new line is written — re-running revoke only sweeps again.
 * `accounts` is the whole subtree, each swept one hop to the revoker.
 */
export function planRevoke(t: Tree, caller: string, name: string): RevokePlan {
  if (!t.delegates.has(name) || !chain(t, name).slice(1).includes(caller)) return { ok: false, reason: `revoke: you have no delegate named ${JSON.stringify(name)}` };
  return {
    ok: true, already: chain(t, name).some((n) => t.revoked.has(n)),
    accounts: subtree(t, name).map((n) => ({ name: n, account: t.delegates.get(n)!.account })),
  };
}
