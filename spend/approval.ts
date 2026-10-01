/**
 * sigelo-spend — the spend-approval (MONERO.md §4.1 step 8, "The spend-approval"; §8 G6).
 *
 * Pure, like policy.ts and tree.ts: no I/O, no clock, no wallet. `now` is a parameter; the
 * pending line, the agent and what the log already knows about a nonce are handed in.
 *
 * One closed object, signed by an approver over `"sigelo\n" ‖ JCS(body)` (SPEC §3). It is
 * keeper-local: `typ: "spend-approval"` is a slot no bundle accepts (§5), so it cannot be
 * replayed as anything else, and it never enters SPEC or a bundle. The keeper builds the body
 * in its `202`; the approver signs exactly that body and posts `{body, sig, bundle}` to
 * `POST /approve`. It authorises ONE payment — that agent, ref, destination and amount — and
 * is spent by the intent line of the relay that uses it.
 */
import { did as didOf, verify, verifySig, type Bundle, type Genesis } from 'sigelo';

export interface ApprovalBody {
  v: 'sigelo/0'; typ: 'spend-approval';
  /** The keeper's own DID and network: an approval for another keeper, or another net, is not one for this one. */
  keeper: string; net: string;
  /** The requesting agent's DID. */
  agent: string;
  ref: string;
  /** The resolved destination address, as the plan will pay it. */
  to: string;
  amount: string; purpose: string;
  /**
   * One per pending line, chosen by the keeper. Not in the §4.1 field list: it ties the
   * approval to the one 202 that asked for it, so an approval is single-use by a key the log
   * can check, and a ref that is asked again after its approval expired gets a fresh request
   * an old signature cannot answer.
   */
  nonce: string;
  iat: number; exp: number;
}
/** What `POST /approve` accepted, as the `approved` line stores it (the bundle is bulk; its result is kept). */
export interface Approved { body: ApprovalBody; sig: string; approver: string; key: string }
/**
 * The agent the pending line is for: its DID and every key the keeper knows it by — the genesis
 * key in policy.json or in its `delegate` line. Not its CURRENT key if it has rotated since:
 * neither `/pay` nor `/approve` carries the agent's bundle, and one the approver attached would
 * be chosen by the party the self-approval check is about. An agent that rotates to a new key
 * and gets a DID minted from that key listed in `approvers` is not caught here; the Owner's
 * `approvers` list is the boundary (README "Threat notes").
 */
export interface Requester { did: string; keys: string[] }

export const FIELDS = ['v', 'typ', 'keeper', 'net', 'agent', 'ref', 'to', 'amount', 'purpose', 'nonce', 'iat', 'exp'] as const;
const STRINGS = ['keeper', 'net', 'agent', 'ref', 'to', 'amount', 'purpose', 'nonce'] as const;

const plain = (x: unknown): x is Record<string, unknown> =>
  x !== null && typeof x === 'object' && !Array.isArray(x) && [Object.prototype, null].includes(Object.getPrototypeOf(x));
const why = (e: unknown): string => (e instanceof Error ? e.message : String(e));
type Check = { ok: true } | { ok: false; reason: string };
const no = (reason: string): { ok: false; reason: string } => ({ ok: false, reason: `approval: ${reason}` });

/** The body the keeper's `202 approval_needed` hands out: exactly what an approver must sign. */
export function approvalRequest(a: Omit<ApprovalBody, 'v' | 'typ' | 'exp'> & { ttl: number }): ApprovalBody {
  return {
    v: 'sigelo/0', typ: 'spend-approval', keeper: a.keeper, net: a.net, agent: a.agent, ref: a.ref, to: a.to,
    amount: a.amount, purpose: a.purpose, nonce: a.nonce, iat: a.iat, exp: a.iat + a.ttl,
  };
}

export interface ApproveContext {
  keeper: string; keeperKey: string; net: string; now: number; maxTtl: number;
  /** The Owner's `approvers`: CURRENT DIDs. */
  approvers: string[];
  /** The keeper-signed pending line's request for `nonce`, if one exists; `undefined` otherwise. */
  pending: (nonce: string) => { request: ApprovalBody; agent: Requester } | undefined;
  /** Has an `approved` line for this nonce been written, or an intent line spent it? */
  used: (nonce: string) => 'approved' | 'spent' | undefined;
}

/**
 * `POST /approve {body, sig, bundle}`, in the order §4.1 lists the checks. Every refusal begins
 * `approval:` and names what failed.
 */
export function checkApproval(env: unknown, c: ApproveContext): { ok: true; approved: Approved; agent: Requester } | { ok: false; reason: string } {
  // shape: the envelope, then the body's closed field set
  if (!plain(env)) return no('the request is not an object');
  if (Object.keys(env).sort().join() !== 'body,bundle,sig') return no('the request is { body, sig, bundle } and nothing else');
  const b = env['body'], sig = env['sig'];
  if (!plain(b)) return no('body is not an object');
  for (const k of Object.keys(b)) if (!(FIELDS as readonly string[]).includes(k)) return no(`body has unknown field ${JSON.stringify(k)}`);
  for (const k of FIELDS) if (!Object.hasOwn(b, k)) return no(`body is missing ${k}`);
  if (b['v'] !== 'sigelo/0') return no(`unknown v ${JSON.stringify(b['v'])}`);
  if (b['typ'] !== 'spend-approval') return no(`typ is ${JSON.stringify(b['typ'])}, not "spend-approval"`);
  for (const k of STRINGS) if (typeof b[k] !== 'string' || b[k] === '') return no(`${k} is not a non-empty string`);
  if (!Number.isSafeInteger(b['iat']) || !Number.isSafeInteger(b['exp'])) return no('iat and exp must be integers (no floats in signed objects)');
  if (typeof sig !== 'string') return no('sig is not a string');
  const body = b as unknown as ApprovalBody;

  // this keeper, this network
  if (body.keeper !== c.keeper) return no(`keeper is ${body.keeper}, this keeper is ${c.keeper}`);
  if (body.net !== c.net) return no(`net is ${body.net}, this keeper spends on ${c.net}`);

  // time: valid now, and no longer-lived than the Owner allows
  if (!(body.iat <= c.now && c.now < body.exp)) return no(`not valid at ${c.now} (iat ${body.iat}, exp ${body.exp}) — expired or not yet valid; the agent's next pay gets a fresh request`);
  if (body.exp - body.iat > c.maxTtl) return no(`lives ${body.exp - body.iat}s, over max_approval_ttl ${c.maxTtl}s`);

  // the approver: its bundle verified OFFLINE, its CURRENT DID in `approvers`
  let current: string, chain: string[];
  try { ({ did: current, chain } = verify(env['bundle'] as Bundle, c.now)); } catch (e) { return no(`the approver's bundle does not verify (${why(e)})`); }
  if (!c.approvers.includes(current)) return no(`${current} is not in approvers${chain.length > 1 ? ' (a rotated-away DID of an approver is not one: the policy names current DIDs)' : ''}`);

  // signed by that DID's CURRENT key — the genesis the chain resolved to, not any key in the bundle
  const bundle = env['bundle'] as Bundle;
  const genesis = [bundle.genesis, ...bundle.rotations.map((r) => r.next_genesis)].find((g: Genesis) => didOf(g) === current);
  if (genesis === undefined) return no(`no genesis for ${current} in the bundle`);
  if (!verifySig(genesis.key, body, sig)) return no(`signature does not verify under the current key of ${current} (forged, or signed with a rotated-away key)`);

  // which request it answers: the pending line with this nonce, field for field
  const p = c.pending(body.nonce);
  if (p === undefined) return no(`no pending request with nonce ${JSON.stringify(body.nonce)} — ask the agent to run its pay again for a fresh one`);
  for (const k of FIELDS) {
    if (body[k] !== p.request[k]) return no(`${k} is ${JSON.stringify(body[k])}, the pending request says ${JSON.stringify(p.request[k])} — sign the request exactly as the keeper built it`);
  }

  // distinct: not the agent, not the agent's key under another DID (one key mints many DIDs) —
  // now or anywhere in the approver's verified chain — and not the keeper
  const chainKeys = [bundle.genesis, ...bundle.rotations.map((r) => r.next_genesis)].filter((g: Genesis) => chain.includes(didOf(g))).map((g: Genesis) => g.key);
  const self = distinct(current, chain, genesis.key, chainKeys, p.agent, c.keeperKey);
  if (!self.ok) return self;

  // single use
  const u = c.used(body.nonce);
  if (u === 'approved') return no(`nonce ${body.nonce} is already approved — one approval per request`);
  if (u === 'spent') return no(`nonce ${body.nonce} was already used by a payment — an approval pays once`);
  return { ok: true, approved: { body, sig, approver: current, key: genesis.key }, agent: p.agent };
}

/** The approver is not the requester — by DID, by any DID of its chain, or by any key of its chain — and not the keeper. */
function distinct(approver: string, chain: string[], key: string, chainKeys: string[], agent: Requester, keeperKey: string): Check {
  if (approver === agent.did || chain.includes(agent.did)) return no(`self-approval: the approver ${approver} is the requesting agent`);
  if (agent.keys.includes(key)) return no(`self-approval: the approver ${approver} signs with the requesting agent's key (one key can mint many DIDs)`);
  if (chainKeys.some((k) => agent.keys.includes(k))) return no(`self-approval: the approver ${approver} rotated away from the requesting agent's key (one key can mint many DIDs)`);
  if (key === keeperKey) return no('the keeper cannot approve its own agents\' payments');
  return { ok: true };
}

/**
 * At pay time (§4.1 step 8): the `approved` line for this ref still authorises THIS payment.
 * The line is keeper-signed and was checked at `/approve`; this re-checks what can have changed
 * since — the clock, the Owner's `approvers` — and that the request is the one approved.
 */
export function stillValid(a: Approved, want: { agent: string; ref: string; to: string; amount: string; purpose: string; net: string; keeper: string }, approvers: string[], now: number): Check {
  if (!(now < a.body.exp)) return no(`the approval for ref ${JSON.stringify(want.ref)} expired at ${a.body.exp}`);
  if (!approvers.includes(a.approver)) return no(`the approver ${a.approver} is no longer in approvers`);
  for (const k of ['agent', 'ref', 'to', 'amount', 'purpose', 'net', 'keeper'] as const) {
    if (a.body[k] !== want[k]) return no(`the approval on file says ${k} ${JSON.stringify(a.body[k])}, this payment is ${JSON.stringify(want[k])}`);
  }
  if (!verifySig(a.key, a.body, a.sig)) return no('the approval on file does not verify under the approver key it was accepted with');
  return { ok: true };
}
