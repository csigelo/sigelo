// SPDX-License-Identifier: MIT
/**
 * sigelo-spend — the Owner's signed policy change and signed read (`POST /policy`, `POST /agents`).
 *
 * Pure, like approval.ts: no I/O, no clock. Before this, whoever could write policy.json set the
 * limits, and nothing said who did. A change is now an object signed by an identity in the
 * policy's `owners`, checked here, applied by the service to policy.json whole, and logged as a
 * keeper-signed `policy` line naming the owner and the fields. The page signs with the identity it
 * holds; a phone signs on the phone and its paired computer only carries the bytes.
 *
 * Keeper-local objects, signed over `"sigelo\n" ‖ JCS(body)` (SPEC §3): `typ: "policy-change"` and
 * `typ: "owner-view"` are slots no bundle accepts, so neither can be replayed as anything else.
 * A change is single use (its nonce, kept in the log) and short-lived (`exp − iat` ≤ CHANGE_TTL).
 */
import { did as didOf, verify, verifySig, type Bundle, type Genesis } from 'sigelo';
import type { Net } from 'sigelo/dist/monero.js';
import { parsePolicy, plain } from './policy.js';

/** The fields an owner may set on one agent: its daily limits and its off switch, nothing that is setup. */
export const SETTABLE = ['per_tx_max', 'per_period_max', 'period_seconds', 'rate_per_minute', 'approval_above', 'max_delegates', 'allow', 'paused'] as const;
/** The longest a change or a view may live: it is signed for one tap, not kept. */
export const CHANGE_TTL = 600;
/** The clock skew a signer's `iat` may be ahead of the keeper's. */
const SKEW = 300;

export interface ChangeBody {
  v: 'sigelo/0'; typ: 'policy-change';
  /** This keeper's DID and network: a change for another keeper is not one for this one. */
  keeper: string; net: string;
  /** The agent's name in policy.json (a root; a delegate is set by its delegator). */
  agent: string;
  set: Record<string, unknown>;
  nonce: string; iat: number; exp: number;
}
export interface ViewBody { v: 'sigelo/0'; typ: 'owner-view'; keeper: string; net: string; nonce: string; iat: number; exp: number }
/** What `POST /policy` accepted: the `policy` line keeps it (the bundle is bulk; who signed is kept). */
export interface Changed { body: ChangeBody; sig: string; owner: string; key: string }

export interface OwnerContext {
  keeper: string; keeperKey: string; net: string; now: number;
  /** The policy's `owners`. */
  owners: string[];
  /** Every agent the keeper knows, roots and delegates: its DID and keys. None of them is an owner. */
  agents: { did?: string; keys: string[] }[];
  /** Has a `policy` line already used this nonce? */
  used?: (nonce: string) => boolean;
}

const CHANGE_FIELDS = ['v', 'typ', 'keeper', 'net', 'agent', 'set', 'nonce', 'iat', 'exp'];
const VIEW_FIELDS = ['v', 'typ', 'keeper', 'net', 'nonce', 'iat', 'exp'];
const why = (e: unknown): string => (e instanceof Error ? e.message : String(e));
const no = (reason: string): { ok: false; reason: string } => ({ ok: false, reason: `owner: ${reason}` });

/** The envelope `{body, sig, bundle}`, the owner behind it, and the body's closed field set. */
function signedByOwner(env: unknown, c: OwnerContext, typ: string, fields: string[]):
  { ok: true; body: Record<string, unknown>; sig: string; owner: string; key: string } | { ok: false; reason: string } {
  if (!plain(env)) return no('the request is not an object');
  if (Object.keys(env).sort().join() !== 'body,bundle,sig') return no('the request is { body, sig, bundle } and nothing else');
  const b = env['body'], sig = env['sig'];
  if (!plain(b)) return no('body is not an object');
  for (const k of Object.keys(b)) if (!fields.includes(k)) return no(`body has unknown field ${JSON.stringify(k)}`);
  for (const k of fields) if (!Object.hasOwn(b, k)) return no(`body is missing ${k}`);
  if (b['v'] !== 'sigelo/0') return no(`unknown v ${JSON.stringify(b['v'])}`);
  if (b['typ'] !== typ) return no(`typ is ${JSON.stringify(b['typ'])}, not "${typ}"`);
  for (const k of ['keeper', 'net', 'nonce']) if (typeof b[k] !== 'string' || b[k] === '') return no(`${k} is not a non-empty string`);
  if (!/^[0-9a-f]{32}$/.test(b['nonce'] as string)) return no('nonce is not 32 hex digits');
  if (!Number.isSafeInteger(b['iat']) || !Number.isSafeInteger(b['exp'])) return no('iat and exp must be integers (no floats in signed objects)');
  if (typeof sig !== 'string') return no('sig is not a string');
  if (b['keeper'] !== c.keeper) return no(`keeper is ${String(b['keeper'])}, this keeper is ${c.keeper}`);
  if (b['net'] !== c.net) return no(`net is ${String(b['net'])}, this keeper spends on ${c.net}`);
  const [iat, exp] = [b['iat'] as number, b['exp'] as number];
  if (!(iat <= c.now + SKEW && c.now < exp)) return no(`not valid at ${c.now} (iat ${iat}, exp ${exp}) — sign it again`);
  if (exp - iat > CHANGE_TTL) return no(`lives ${exp - iat}s, over ${CHANGE_TTL}s`);

  // The owner: its bundle verified OFFLINE; a DID of its chain in `owners`; signed by its CURRENT key.
  if (c.owners.length === 0) return no('this keeper\'s policy names no owners — add yours to "owners" in policy.json (or set limits there)');
  let current: string, chain: string[];
  try { ({ did: current, chain } = verify(env['bundle'] as Bundle, c.now)); } catch (e) { return no(`the bundle does not verify (${why(e)})`); }
  if (!chain.some((d) => c.owners.includes(d)) && !c.owners.includes(current)) return no(`${current} is not one of this keeper's owners`);
  const bundle = env['bundle'] as Bundle;
  const nodes = [bundle.genesis, ...bundle.rotations.map((r) => r.next_genesis)];
  const genesis = nodes.find((g: Genesis) => didOf(g) === current);
  if (genesis === undefined) return no(`no genesis for ${current} in the bundle`);
  if (!verifySig(genesis.key, b, sig)) return no(`signature does not verify under the current key of ${current}`);

  // Never an agent, by DID or by key anywhere in the chain, and never the keeper: an agent cannot
  // raise its own allowance, even with a DID minted from its own key.
  const keys = nodes.filter((g: Genesis) => chain.includes(didOf(g))).map((g: Genesis) => g.key);
  for (const a of c.agents) {
    if (a.did !== undefined && (a.did === current || chain.includes(a.did))) return no(`${current} is one of the keeper's agents — an agent cannot set its own limits`);
    if (keys.some((k) => a.keys.includes(k))) return no(`${current} signs with an agent's key (one key can mint many DIDs) — an agent cannot set its own limits`);
  }
  if (keys.includes(c.keeperKey)) return no('the keeper cannot change its own policy');
  return { ok: true, body: b, sig, owner: current, key: genesis.key };
}

/** `POST /policy {body, sig, bundle}`: a change of one agent's limits, by an owner. Every refusal begins `owner:`. */
export function checkChange(env: unknown, c: OwnerContext): { ok: true; changed: Changed } | { ok: false; reason: string } {
  const r = signedByOwner(env, c, 'policy-change', CHANGE_FIELDS);
  if (!r.ok) return r;
  const b = r.body;
  if (typeof b['agent'] !== 'string' || b['agent'] === '') return no('agent is not a non-empty string');
  if (!plain(b['set']) || Object.keys(b['set']).length === 0) return no('set is not an object with at least one field');
  for (const k of Object.keys(b['set'])) if (!(SETTABLE as readonly string[]).includes(k)) return no(`set: ${JSON.stringify(k)} is not a limit an owner sets here (${SETTABLE.join(', ')})`);
  if (c.used?.(b['nonce'] as string) === true) return no(`nonce ${String(b['nonce'])} was already used — a change applies once; sign it again`);
  return { ok: true, changed: { body: b as unknown as ChangeBody, sig: r.sig, owner: r.owner, key: r.key } };
}

/** `POST /agents {body, sig, bundle}`: an owner's read of every agent (a read; not single use). */
export function checkView(env: unknown, c: OwnerContext): { ok: true; owner: string } | { ok: false; reason: string } {
  const r = signedByOwner(env, c, 'owner-view', VIEW_FIELDS);
  return r.ok ? { ok: true, owner: r.owner } : r;
}

/**
 * The raw policy.json with `set` applied to agent `name`, validated whole by `parsePolicy`: a change
 * that leaves a policy the keeper would refuse at start is refused here, naming the field. `null`
 * approval_above and `false` paused remove the field. Throws; nothing is written by this function.
 */
export function applyChange(raw: unknown, name: string, set: Record<string, unknown>, net: Net): Record<string, unknown> {
  if (!plain(raw) || !plain(raw['agents'])) throw new Error('owner: policy.json is a buckets-style policy — write it as agents (MONERO.md §4.1) before setting limits this way');
  if (raw['net'] !== net) throw new Error(`owner: policy.json is now for ${String(raw['net'])}, this keeper runs on ${net} — restart it first`);
  const agents = raw['agents'];
  if (!Object.hasOwn(agents, name) || !plain(agents[name])) throw new Error(`owner: no agent ${JSON.stringify(name)} in policy.json (a delegate's limits are set by its delegator)`);
  const a: Record<string, unknown> = { ...agents[name] };
  for (const [k, v] of Object.entries(set)) {
    if ((k === 'approval_above' && v === null) || (k === 'paused' && v === false)) delete a[k];
    else a[k] = v;
  }
  const next = { ...raw, agents: { ...agents, [name]: a } };
  try { parsePolicy(next); } catch (e) { throw new Error(`owner: the change would leave a policy the keeper refuses (${why(e)})`); }
  return next;
}
