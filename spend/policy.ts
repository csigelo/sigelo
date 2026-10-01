/**
 * sigelo-spend — policy evaluation (MONERO.md §4.1).
 *
 * Pure: no I/O, no clock, no network. `now` is a parameter and `state` is handed in, so the
 * same inputs always give the same decision and the whole file is testable without a wallet.
 *
 * The boundary that actually holds is the allowance wallet's balance (MONERO.md §4); between
 * agents of one keeper it is the account this file pins each agent to. This file is the second
 * fence, not the first: it bounds what an agent can ask for, and it is written to be read top
 * to bottom in the order §4.1 lists the checks.
 */
import { createHash } from 'node:crypto';
import { canonicalize, verify, verifySig, did as didOf, structure } from 'sigelo';
import type { Bundle, Genesis } from 'sigelo';
import { decodeAddress } from 'sigelo/dist/monero.js';
import type { Net } from 'sigelo/dist/monero.js';
import { stillValid, type Approved } from './approval.js';

/** Caps: what `affordable` needs. An agent entry is these plus who it is and where it may pay. */
export interface Caps { per_tx_max: string; per_period_max: string; period_seconds: number; rate_per_minute: number }
export interface Agent extends Caps {
  /** Monero **account** (major index). Never a subaddress — see the change trap in §4.1. */
  account: number;
  token_hash: string;
  allow: AllowRule[];
  /**
   * A payment whose amount is above this (atomic units) needs one valid spend-approval (§4.1
   * step 8, approval.ts). `null`: never. A delegate's is the lowest along its ancestors.
   */
  approval_above: string | null;
  /**
   * How many delegates this agent's whole subtree may hold (MONERO.md §4.3, tree.ts `reserved`);
   * 0, the default, means it cannot delegate (§9 decision 9).
   */
  max_delegates: number;
  /** The agent's sigelo DID. Optional; `POST /bind` cross-signs a binding for this DID and no other. */
  did?: string;
  /**
   * The genesis `did` hashes to. Required with a non-null `approval_above`: an approver must
   * not sign with the agent's own key under another DID (§4.1 "one key can mint many DIDs"),
   * and a DID alone does not say which key that is. Delegates carry theirs in the log.
   */
  genesis?: Genesis;
}
/**
 * `{addr, label?}` a literal address, `label` being the name the agent may pay it by;
 * `{did, issuer, ctx?}` that DID if it holds an attestation from `issuer`;
 * `{issuer, ctx?}` ANY DID holding such an attestation. The last two pay only the DID's
 * `proven` monero binding or a subaddress named by its valid §6.3 invoice.
 */
export interface AllowRule { addr?: string; label?: string; did?: string; issuer?: string; ctx?: string }
export interface Policy {
  net: Net; wallet: { rpc: string; login?: string }; agents: Record<string, Agent>;
  unlock_time: number; priority: number;
  /** How long a `ref` is remembered (§4.2 idempotency). Default 600. */
  dedupe_seconds: number;
  /** The longest an approval may live, `exp − iat` (§4.1). Default 3600. */
  max_approval_ttl: number;
  /** Who may approve: CURRENT DIDs; the approval carries the bundle that proves it (approval.ts). */
  approvers?: { did: string }[];
  /**
   * The root's recovery commitment (`sha256:<hex>`, from the keeper package the ceremony wrote).
   * Every delegate's genesis carries it (MONERO.md §2, §9 decision 2), so the Owner's one
   * offline recovery key recovers every agent. Without it `POST /delegate` refuses.
   */
  recovery_commitment?: string;
}
export interface InvoiceBody {
  v: string; typ: string; did: string; method: string; addr: string;
  iat: number; exp: number; nonce: string; amount?: string; memo?: string;
}
export interface Destination {
  /** Where the money goes: given, or resolved from `label`. A DID rule authorises an address, it is not one. */
  addr?: string;
  /** A name from the agent's own allowlist. Stands alone: `{label}` and nothing else. */
  label?: string;
  did?: string; bundle?: Bundle; invoice?: { body: InvoiceBody; sig: string };
}
export interface PayRequest {
  /** Filled in by the service from the Authorization header, not sent in the body. */
  token?: string;
  to: Destination; amount: string; purpose: string;
  /** Idempotency key (§4.2). Absent: derived from (account, to, amount, purpose). */
  ref?: string;
  /** Today's clients name their bucket; it must be the token's agent. Never selects an account. */
  bucket?: string;
}
/**
 * One past debit, as replayed from spend.log. `ts` and `now` are unix **seconds**. `amount`
 * is what left the wallet — the payment PLUS its fee (MONERO.md §4.1) — and a dry run's rate
 * tick is `'0'`. `invoice` is `invoiceKey(did, nonce)` when a §6.3 invoice authorised it.
 */
export interface Spent { ts: number; agent: string; amount: string; invoice?: string }
/**
 * What a log line says happened. `pending` is an approval wait (§4.1 step 8) and `approved`
 * the keeper's record of a valid spend-approval for it: neither debits anything.
 */
export type Status = 'intent' | 'relayed' | 'relay_failed' | 'pending' | 'approved';
/**
 * A logged spend that carried a `ref`, for the repeat check. `fp` is the fingerprint of the
 * request that wrote it; `line` is its index in the log, so the service can hand back the line.
 */
export interface Prior {
  ts: number; agent: string; ref: string; fp: string; status: Status; line: number;
  /**
   * The approval nonce: a pending line's request, an approved line's approval, or the one an
   * intent line spent. `until` is when a pending or approved line stops answering (its `exp`),
   * `approval` the keeper-verified approval an `approved` line carries.
   */
  nonce?: string; until?: number; approval?: Approved;
}
export interface Plan {
  account_index: number;
  /** `amount` stays a decimal string here; only the wallet call turns it into a number. */
  destinations: { address: string; amount: string }[];
  unlock_time: number; priority: number; do_not_relay: boolean;
}
/**
 * `ok: true` — pay, from `agent`'s account, under `ref`. `invoice` is set when a §6.3 invoice
 * authorised the destination (its nonce is spent), `did` when a DID rule did.
 * `ok: false` — a refusal naming its check; `repeat` means the ref already has an outcome and
 * that outcome is the answer; `conflict` means a used ref came back with a different request.
 */
export type Decision =
  | { ok: true; agent: string; ref: string; fp: string; plan: Plan; did?: string; invoice?: { did: string; nonce: string }; approval?: string }
  | { ok: false; reason: string; repeat?: Prior; conflict?: true; facts?: Facts; wait?: Wait };
/**
 * §4.1 step 8 refused for want of an approval: everything the service needs to write the
 * `pending` line and build the request, and nothing has touched the wallet.
 */
export interface Wait { agent: string; did: string; ref: string; fp: string; plan: Plan; to: { addr: string; did?: string; invoice?: { did: string; nonce: string } } }
/**
 * The numbers behind a cap refusal, so a client can say it in plain words (§4.2) without
 * parsing `reason`. Atomic-unit strings; `until` is when the oldest debit in the window rolls
 * out of it (unix seconds), absent when nothing in the window has been spent.
 */
export interface Facts { cost: string; limit: string; fee_included: boolean; left?: string; until?: number }

const ATOMIC = /^(0|[1-9][0-9]*)$/;
/** epee encodes amounts as JSON numbers, so anything above 2^53-1 cannot reach the wallet. */
const MAX_ATOMIC = 9007199254740991n;
const INVOICE_REQUIRED = ['v', 'typ', 'did', 'method', 'addr', 'iat', 'exp', 'nonce'];
const INVOICE_OPTIONAL = ['amount', 'memo'];
/** Everything a destination may carry. Anything else is refused, never ignored. */
const TO_FIELDS = ['addr', 'did', 'bundle', 'invoice', 'label'];
const PURPOSE_MAX = 200;
const REF_MAX = 128;

const no = (reason: string): Decision => ({ ok: false, reason });
const why = (e: unknown): string => (e instanceof Error ? e.message : String(e));
export const tokenHash = (token: string): string => 'sha256:' + createHash('sha256').update(token, 'utf8').digest('hex');
/** One string per (DID, nonce): a nonce is unique per issuer, not globally. */
export const invoiceKey = (did: string, nonce: string): string => JSON.stringify([did, nonce]);
const own = (o: object, k: string): boolean => Object.hasOwn(o, k);

/**
 * A JSON object as a strict parser builds it: not an array, and nothing inherited. A parser
 * that ASSIGNS a `"__proto__"` key swaps the prototype instead of adding a field, and every
 * `to.did` read after that answers from an object the agent chose while `Object.keys` shows
 * nothing. Checked here whatever the parser does, so this file does not depend on it.
 */
export function plain(x: unknown): x is Record<string, unknown> {
  if (x === null || typeof x !== 'object' || Array.isArray(x)) return false;
  const proto: unknown = Object.getPrototypeOf(x);
  return proto === Object.prototype || proto === null;
}

/**
 * Compare two `sha256:<hex>` strings without an early exit. Both sides are hashes rather than
 * the token itself, so a variable-time compare leaks little — but the bearer token is the only
 * thing standing between an agent's context and the balance, and not returning early costs
 * nothing. Lengths are fixed by `token_hash`'s own format check, so comparing them first
 * reveals nothing a rejected request would not.
 */
export function sameHash(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * §4.1 step 1: the agent whose `token_hash` this token hashes to. EVERY agent's hash is
 * compared, match or not, and nothing returns from inside the loop: the time taken depends on
 * how many agents there are, never on which one matched or whether any did. Load refuses two
 * agents with one hash, so at most one matches.
 */
export function agentOf(token: string, policy: Policy): string | undefined {
  const h = tokenHash(token);
  let hit: string | undefined;
  for (const [name, a] of Object.entries(policy.agents)) if (sameHash(h, a.token_hash)) hit = name;
  return hit;
}

/**
 * The request's fingerprint, and its `ref` when none is given (§4.1 step 4, §9 decision 6):
 * `sha256(account ‖ JCS({to, amount, purpose}))`. `to` is taken WITHOUT its bundle: the bundle
 * is evidence about the payee, not where the money goes, and a harness that refreshes it
 * between two tries is still making the same payment. The account makes two agents' identical
 * requests two payments.
 */
export function fingerprint(account: number, to: Record<string, unknown>, amount: unknown, purpose: unknown): string {
  const where = Object.fromEntries(Object.entries(to).filter(([k]) => k !== 'bundle'));
  return 'sha256:' + createHash('sha256').update(String(account) + canonicalize({ to: where, amount, purpose }), 'utf8').digest('hex');
}

/**
 * What the log knows beyond debits: logged refs (§4.1 step 4), revoked agents (§4.3, G5), and
 * the keeper's own DID, which an approval on file must name (step 8).
 */
export interface Seen { prior?: Prior[]; revoked?: ReadonlySet<string>; keeper?: string }
/** Outcome over wait: a settled line is the answer, an intent without one is next, then pending. */
const RANK: Record<Status, number> = { relayed: 2, relay_failed: 2, intent: 1, approved: 0, pending: 0 };
const waiting = (s: Status): boolean => s === 'pending' || s === 'approved';

/** MONERO.md §4.1, in order. Every refusal names the check that refused it. */
export function evaluate(req: PayRequest, policy: Policy, state: Spent[], now: number, seen: Seen = {}): Decision {
  // 1. token → agent. Unknown and revoked read the same: which one it is helps nobody but a thief.
  if (typeof req.token !== 'string' || req.token === '') return no('token: no bearer token presented');
  const name = agentOf(req.token, policy);
  if (name === undefined || seen.revoked?.has(name) === true) return no('token: this wallet is not set up for you (unknown or revoked token). Tell your operator.');
  const agent = policy.agents[name]!;

  // 2. account: the agent's, from the policy — never from the request. `bucket`, which today's
  // clients still send, can only confirm it.
  if (req.bucket !== undefined && req.bucket !== name) return no(`bucket: your token belongs to ${JSON.stringify(name)}, not ${JSON.stringify(req.bucket)}`);

  // 3. the request is exactly the shape the log will sign. `purpose` and `to` are copied into
  // a signed entry, so anything that cannot be signed must stop HERE, before any wallet call.
  if (typeof req.purpose !== 'string' || req.purpose === '' || req.purpose.length > PURPOSE_MAX) {
    return no(`purpose: must be a string of 1..${PURPOSE_MAX} characters`);
  }
  if (req.ref !== undefined && (typeof req.ref !== 'string' || req.ref === '' || req.ref.length > REF_MAX)) return no(`ref: must be a string of 1..${REF_MAX} characters`);
  const raw: unknown = req.to;
  if (!plain(raw)) return no('to: is not a JSON object (or carries an inherited prototype)');
  for (const k of Object.keys(raw)) if (!TO_FIELDS.includes(k)) return no(`to: unknown field ${JSON.stringify(k)} — a destination is { ${TO_FIELDS.join(', ')} }`);
  let addr: string;
  if (own(raw, 'label')) {
    // A name from THIS agent's allowlist, resolved here and nowhere else: another agent's
    // contacts are not reachable by name, and a label never carries an address of its own.
    if (Object.keys(raw).length !== 1 || typeof raw['label'] !== 'string') return no('to: a label is sent alone, as { label: "<name>" }');
    const rule = agent.allow.find((r) => plain(r) && own(r, 'label') && r.label === raw['label'] && typeof r.addr === 'string');
    if (rule === undefined) return no(`allowlist: you have no contact named ${JSON.stringify(raw['label'])}. Use an address or invoice file, or ask your operator to add them.`);
    addr = rule.addr!;
  } else {
    if (!own(raw, 'addr') || typeof raw['addr'] !== 'string') return no('to.addr: request carries no destination address');
    addr = raw['addr'];
  }
  if (own(raw, 'did') && typeof raw['did'] !== 'string') return no('to.did: is not a string');
  // Own properties only, copied: nothing below reads a field the agent did not send as one.
  const to: Destination & { addr: string } = {
    addr, ...(own(raw, 'did') && { did: raw['did'] as string }),
    ...(own(raw, 'bundle') && { bundle: raw['bundle'] as Bundle }),
    ...(own(raw, 'invoice') && { invoice: raw['invoice'] as Destination['invoice'] }),
  };

  // destination decodes to this network, and is payable
  let kind: string;
  try {
    const d = decodeAddress(to.addr);
    if (d.net !== policy.net) return no(`to.addr: address is ${d.net}, policy net is ${policy.net}`);
    kind = d.kind;
  } catch (e) { return no(`to.addr: does not decode as a Monero address (${why(e)})`); }
  // §7: integrated addresses exist only for the base address and carry a payment ID. Refuse.
  if (kind === 'integrated') return no('to.addr: integrated address refused (MONERO.md §7 — use a subaddress)');

  // 4. repeat. A ref this agent used within the window has an outcome, and that outcome is the
  // answer: nothing below runs, so a retry never builds a second transaction and never spends
  // budget twice. Refs are per agent — one agent's ref never answers with another's receipt.
  let fp: string;
  try { fp = fingerprint(agent.account, raw, req.amount, req.purpose); } catch (e) { return no(`request: cannot be canonicalized to derive its ref (${why(e)})`); }
  const ref = req.ref ?? fp;
  // A pending or approved line answers until its request expires, not for `dedupe_seconds`: an
  // approval takes a human, and the agent's re-run must still find it. Once an intent line has
  // spent its nonce it answers nothing — the intent (then the outcome) is the answer, and after
  // that window the same command is a new payment needing a new approval.
  const mine = (seen.prior ?? []).filter((p) => p.agent === name && p.ref === ref);
  const spent = new Set(mine.flatMap((p) => (p.status === 'intent' && p.nonce !== undefined ? [p.nonce] : [])));
  const used = mine.filter((p) => (waiting(p.status) && p.until !== undefined
    ? now < p.until && !spent.has(p.nonce!) : p.ts > now - policy.dedupe_seconds));
  if (used.some((p) => p.fp !== fp)) {
    return { ok: false, conflict: true, reason: `repeat: ref ${JSON.stringify(ref)} was already used for a different payment in the last ${policy.dedupe_seconds}s. Use a new ref.` };
  }
  const repeat = (first: Prior): Decision =>
    ({ ok: false, repeat: first, reason: `repeat: ref ${JSON.stringify(ref)} already has an outcome (${first.status}); it is returned instead of paying again` });
  // A settled line (or an intent without one) is the answer, whatever else is on file.
  const settled = used.filter((p) => !waiting(p.status));
  if (settled.length > 0) return repeat(settled.reduce((a, b) => (RANK[b.status] > RANK[a.status] ? b : a)));
  // Only waits are left, and they are judged by the policy as it is NOW, not as it was when
  // they were written: the Owner may have turned the threshold off or raised it (then no
  // approval is needed and the ref pays like any other), or removed the approver who signed
  // the approval on file (then that approval answers nothing, and step 8 asks afresh).
  const approvers = (policy.approvers ?? []).map((a) => a.did);
  const needs = agent.approval_above !== null && typeof req.amount === 'string' && ATOMIC.test(req.amount) && BigInt(req.amount) > BigInt(agent.approval_above);
  const onFile = used.filter((p) => p.status === 'approved' && p.approval !== undefined);
  // An approval on file lets the ref through, once: every check below runs again, and step 8
  // takes the approval instead of asking for one.
  const approved = onFile.find((p) => approvers.includes(p.approval!.approver));
  const stale = onFile.find((p) => !approvers.includes(p.approval!.approver));
  if (needs && approved === undefined) {
    // The same request back while it can still be approved: a pending line whose nonce no
    // approval has used. A request answered by a since-removed approver cannot be approved
    // again (its nonce is used), so it falls through to a fresh request with a new nonce.
    const used1 = new Set(onFile.map((p) => p.nonce));
    const open = used.find((p) => p.status === 'pending' && !used1.has(p.nonce));
    if (open !== undefined) return repeat(open);
  }

  // 5. allowlist — this agent's. Agent context is untrusted, so a destination is never taken on its word.
  const reasons: string[] = [];
  let matched: Match | undefined;
  for (const [i, rule] of agent.allow.entries()) {
    const r = safeMatch(rule, to, req.amount, policy, state, now);
    if (r.ok) { matched = r; break; }
    reasons.push(`allow[${i}] ${r.reason}`);
  }
  if (matched === undefined || !matched.ok) return no(`allowlist: you are not allowed to pay ${to.addr}. Ask the payee for an invoice file, or ask your operator to add them. (${reasons.join('; ') || 'your allowlist is empty'})`);

  // 6. amount. Atomic units as decimal strings, compared as BigInt. Never floats (SPEC §3.1).
  if (typeof req.amount !== 'string' || !ATOMIC.test(req.amount)) return no(`amount: ${JSON.stringify(req.amount)} is not a decimal string of atomic units`);
  const amount = BigInt(req.amount);
  if (amount === 0n) return no('amount: zero');
  if (amount > MAX_ATOMIC) return no(`amount: ${req.amount} exceeds 2^53-1 atomic units and cannot be represented in the wallet RPC`);

  // 7. caps, on the amount alone: the fee is not known until the wallet has built the
  // transaction. The service asks `affordable` again with amount + fee before it relays.
  const fits = affordable(name, agent, amount, 'amount', state, now);
  if (!fits.ok) return fits;
  const recent = state.filter((s) => s.agent === name && s.ts > now - 60).length;
  if (recent >= agent.rate_per_minute) return no(`rate_per_minute: ${recent} spends by ${JSON.stringify(name)} in the last 60s, limit ${agent.rate_per_minute}`);

  // 9. plan. The agent is an ACCOUNT. `subaddr_indices` is never set — change from a spend
  // restricted by subaddress returns to {account, 0}, so such a budget drains itself.
  const plan: Plan = {
    account_index: agent.account, destinations: [{ address: to.addr, amount: req.amount }],
    unlock_time: policy.unlock_time, priority: policy.priority, do_not_relay: false,
  };
  const where = { ...(matched.did !== undefined && { did: matched.did }), ...(matched.invoice !== undefined && { invoice: matched.invoice }) };

  // 8. approval — after the caps, so a payment the policy would refuse anyway never asks a
  // human; before the wallet, so a wait costs no fee quote. Amount alone: §4.1 compares
  // `amount`, and the fee is not known yet. Not a queue: the keeper never pays on its own.
  if (agent.approval_above !== null && amount > BigInt(agent.approval_above)) {
    if (agent.did === undefined) return no(`approval: ${JSON.stringify(name)} has no did, so no approval can name it — tell your operator`);
    if (approved === undefined) {
      const was = stale === undefined ? '' : ` (the approval on file was signed by ${stale.approval!.approver}, who is no longer in approvers — this is a new request)`;
      return { ok: false, reason: `approval: ${req.amount} is above your approval_above ${agent.approval_above}; an approver must sign this payment${was}. Tell your operator, then run the same command again.`,
        wait: { agent: name, did: agent.did, ref, fp, plan, to: { addr: to.addr, ...where } } };
    }
    const v = stillValid(approved.approval!, { agent: agent.did, ref, to: to.addr, amount: req.amount, purpose: req.purpose, net: policy.net, keeper: seen.keeper ?? '' },
      approvers, now);
    if (!v.ok) return no(v.reason);
    return { ok: true, agent: name, ref, fp, plan, ...where, approval: approved.approval!.body.nonce };
  }
  // No approval needed now. One on file is still spent by this payment's intent line, so it
  // can never let a later run of the same ref through a second time.
  const spare = approved ?? stale;
  return { ok: true, agent: name, ref, fp, plan, ...where, ...(spare !== undefined && { approval: spare.approval!.body.nonce }) };
}

/**
 * §4.1 step 7 for `cost` atomic units. BOTH caps count what leaves the wallet, amount plus
 * fee: a cap on the amount alone lets 1-atomic-unit payments at a 3e7 fee each spend ~3e7
 * times the budget. `evaluate` calls this with the amount (a lower bound, to refuse before
 * touching the wallet); the service calls it again with amount + fee, once the wallet has
 * priced the transaction and before anything is relayed.
 */
export function affordable(name: string, caps: Caps, cost: bigint, what: string, state: Spent[], now: number): { ok: true } | { ok: false; reason: string; facts: Facts } {
  const fee_included = what !== 'amount';
  if (cost > BigInt(caps.per_tx_max)) {
    return { ok: false, reason: `per_tx_max: ${what} ${cost} exceeds ${caps.per_tx_max} for ${JSON.stringify(name)}`, facts: { cost: String(cost), limit: caps.per_tx_max, fee_included } };
  }
  // Exhaustion is a refusal with a reason, never a queue (§4.1).
  const window = state.filter((s) => s.agent === name && s.ts > now - caps.period_seconds);
  const spent = window.reduce((t, s) => t + BigInt(s.amount), 0n), cap = BigInt(caps.per_period_max);
  if (spent + cost > cap) {
    const oldest = window.reduce((m, s) => Math.min(m, s.ts), Infinity);
    return {
      ok: false, reason: `per_period_max: ${what} ${cost} on top of ${spent} already spent would exceed ${caps.per_period_max} in the last ${caps.period_seconds}s for ${JSON.stringify(name)}`,
      facts: { cost: String(cost), limit: caps.per_period_max, fee_included, left: String(spent > cap ? 0n : cap - spent), ...(oldest !== Infinity && { until: oldest + caps.period_seconds }) },
    };
  }
  return { ok: true };
}

type Match = { ok: true; did?: string; invoice?: { did: string; nonce: string } } | { ok: false; reason: string };
const nope = (reason: string): Match => ({ ok: false, reason });

/**
 * `matchRule` walks JSON the agent supplied (a bundle, a §6.3 invoice) beside rules the
 * operator wrote. Anything malformed in either must come back as a refusal that NAMES the
 * check — an exception escaping `evaluate` still fails closed, but it reaches the agent as a
 * 500 with no reason in it, and `evaluate` is documented as total (CLAUDE.md: errors name the
 * failing check).
 */
function safeMatch(rule: AllowRule, to: Destination & { addr: string }, amount: string, policy: Policy, state: Spent[], now: number): Match {
  try {
    return matchRule(rule, to, amount, policy, state, now);
  } catch (e) {
    return nope(`rule: ${why(e)}`);
  }
}

function matchRule(rule: AllowRule, to: Destination & { addr: string }, amount: string, policy: Policy, state: Spent[], now: number): Match {
  if (rule === null || typeof rule !== 'object' || Array.isArray(rule)) return nope('rule: entry is not an object');
  if (typeof rule.addr === 'string') {
    return rule.addr === to.addr ? { ok: true } : nope(`addr: literal ${rule.addr} is not ${to.addr}`);
  }
  if (typeof rule.issuer !== 'string') return nope('rule: neither an addr rule nor an issuer rule');
  // `{did, issuer}` names one DID; `{issuer}` alone admits any DID the bundle proves.
  if (rule.did !== undefined && to.did !== rule.did) return nope(`did: request names ${JSON.stringify(to.did)}, rule names ${rule.did}`);
  if (to.bundle === undefined) return nope(`did: no bundle supplied${rule.did === undefined ? '' : ` for ${rule.did}`}`);
  let result;
  try { result = verify(to.bundle, now); } catch (e) { return nope(`did: bundle does not verify (${why(e)})`); }
  // verify() reports the chain's CURRENT DID. Only that one is allowed, and a request that
  // names a DID must name that one — an issuer rule is not a licence to pay a rotated-away DID.
  const want = rule.did ?? to.did;
  if (want !== undefined && result.did !== want) return nope(`did: bundle's current DID is ${result.did}, ${rule.did === undefined ? 'request' : 'rule'} names ${want}`);
  // Own properties only: `attestations` is a plain object, so `constructor` and `__proto__`
  // would otherwise answer for an issuer nobody attested (a Function has a `length` > 0).
  const att = own(result.attestations, rule.issuer) ? result.attestations[rule.issuer]! : [];
  if (!(rule.ctx === undefined ? att.length > 0 : att.some((a) => a.ctx === rule.ctx))) {
    return nope(`issuer: no accepted attestation from ${rule.issuer}${rule.ctx === undefined ? '' : ` with ctx ${JSON.stringify(rule.ctx)}`}`);
  }
  // SPEC §6.1: funds go to `proven` bindings only. §6.2: the hash does not cover the network
  // prefix, so the address must be checked against the network we are spending on.
  const bound = result.bindings.filter((b) => b.proof === 'proven' && b.body.method === 'monero' && netOf(b.body.addr) === policy.net);
  if (bound.length === 0) return nope(`binding: ${result.did} has no proven monero binding on ${policy.net}`);
  if (bound.some((b) => b.body.addr === to.addr)) return { ok: true, did: result.did };
  // §6.3: a binding names the wallet, an invoice names where to pay this time. sigelo cannot
  // prove the subaddress belongs to the bound wallet; the identity's signature is the claim.
  const inv = checkInvoice(to, result.did, to.bundle, amount, policy, state, now);
  return inv.ok ? { ...inv, did: result.did } : inv;
}

function netOf(addr: string): Net | null {
  try { return decodeAddress(addr).net; } catch { return null; }
}

function checkInvoice(to: Destination & { addr: string }, did: string, bundle: Bundle, amount: string, policy: Policy, state: Spent[], now: number): Match {
  const env: unknown = to.invoice;
  if (env === undefined) return nope(`invoice: ${to.addr} is not the bound address and no §6.3 invoice was supplied`);
  // Shape before dereference: `invoice: null` is agent-supplied and must name a check, not
  // throw a TypeError out of `evaluate`.
  if (!plain(env)) return nope('invoice: envelope is not an object');
  for (const k of Object.keys(env)) if (k !== 'body' && k !== 'sig') return nope(`invoice: envelope has unknown field ${JSON.stringify(k)}`);
  if (typeof env['sig'] !== 'string') return nope('invoice: envelope has no sig');
  const b = env['body'];
  if (!plain(b)) return nope('invoice: body is not an object');
  // SPEC §9 step 2 for the invoice slot — the library's own check, so `amount` as a JSON
  // number (a float somewhere) is refused here exactly as a verifier refuses it.
  try { structure(b, 'invoice'); } catch (e) { return nope(why(e).startsWith('invoice:') ? why(e) : `invoice: ${why(e)}`); }
  // Own-property twins of what `structure` checks with `in`, which also sees inherited keys.
  for (const f of INVOICE_REQUIRED) if (!own(b, f)) return nope(`invoice: missing ${f}`);
  for (const f of Object.keys(b)) if (!INVOICE_REQUIRED.includes(f) && !INVOICE_OPTIONAL.includes(f)) return nope(`invoice: unknown field ${JSON.stringify(f)}`);
  if (b['v'] !== 'sigelo/0') return nope(`invoice: unknown v ${JSON.stringify(b['v'])}`);
  if (b['typ'] !== 'invoice') return nope(`invoice: typ is ${JSON.stringify(b['typ'])}`);
  if (b['method'] !== 'monero') return nope(`invoice: method is ${JSON.stringify(b['method'])}`);
  if (b['did'] !== did) return nope(`invoice: did is ${JSON.stringify(b['did'])}, bundle's current DID is ${did}`);
  if (b['addr'] !== to.addr) return nope(`invoice: addr is ${JSON.stringify(b['addr'])}, destination is ${to.addr}`);
  if (typeof b['nonce'] !== 'string' || b['nonce'] === '') return nope(`invoice: nonce is not a non-empty string ${JSON.stringify(b['nonce'])}`);
  if (own(b, 'memo') && typeof b['memo'] !== 'string') return nope('invoice: memo is not a string');
  const [iat, exp] = [b['iat'], b['exp']];
  if (!(Number.isSafeInteger(iat) && Number.isSafeInteger(exp) && (iat as number) <= now && now < (exp as number))) {
    return nope(`invoice: not valid at ${now} (iat ${JSON.stringify(iat)}, exp ${JSON.stringify(exp)})`);
  }
  // MONERO.md §4.4 / §3: an invoice names a fresh SUBaddress on the policy's network. A
  // standard address here is not one the payee's `receive` minted — it is any wallet at all.
  const d = decodeAddress(to.addr);
  if (d.kind !== 'subaddress' || d.net !== policy.net) return nope(`invoice: addr is a ${d.net} ${d.kind} address — an invoice names a ${policy.net} subaddress (MONERO.md §4)`);
  // An invoice that names an amount is paid that amount, exactly — never more, never less.
  if (own(b, 'amount') && !(typeof amount === 'string' && ATOMIC.test(amount) && BigInt(amount) === BigInt(b['amount'] as string))) {
    return nope(`invoice: amount is ${JSON.stringify(b['amount'])}, request pays ${JSON.stringify(amount)} — an invoice with an amount is paid exactly that`);
  }
  // Signed by the identity's CURRENT key: the genesis the chain resolved to, found in the
  // bundle the caller supplied. A rotated-away key must not be able to name a destination.
  const genesis = [bundle.genesis, ...bundle.rotations.map((r) => r.next_genesis)].find((g: Genesis) => didOf(g) === did);
  if (genesis === undefined) return nope(`invoice: no genesis for ${did} in the bundle`);
  if (!verifySig(genesis.key, b, env['sig'])) return nope(`invoice: signature does not verify under the current key of ${did}`);
  // One invoice, one payment. `state` is the whole log, not the budget window, so a replay is
  // refused for as long as the log exists (the invoice's own `exp` bounds it anyway).
  const nonce = b['nonce'];
  if (state.some((s) => s.invoice === invoiceKey(did, nonce))) return nope(`invoice: already paid — nonce ${nonce} of ${did} is in spend.log`);
  return { ok: true, invoice: { did, nonce } };
}

// ---------------------------------------------------------------- the policy file

/** The fields each level may carry. Anything else is refused: a typo'd cap is not a missing one. */
const TOP = ['net', 'wallet', 'agents', 'unlock_time', 'priority', 'dedupe_seconds', 'max_approval_ttl', 'approvers', 'recovery_commitment'];
const LEGACY_TOP = ['net', 'wallet', 'buckets', 'allow', 'token_hash', 'unlock_time', 'priority', 'dedupe_seconds'];
const BUCKET_FIELDS = ['account', 'per_tx_max', 'per_period_max', 'period_seconds', 'rate_per_minute'];
const AGENT_FIELDS = [...BUCKET_FIELDS, 'token_hash', 'allow', 'approval_above', 'max_delegates', 'did', 'genesis'];
const DID = /^did:sigelo:z[1-9A-HJ-NP-Za-km-z]+$/;
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HASH = /^sha256:[0-9a-f]{64}$/;
const intIn = (x: unknown, min: number): x is number => Number.isSafeInteger(x) && (x as number) >= min;

/**
 * Validate a parsed policy file and return it in the `agents` shape (MONERO.md §4.1). Every
 * rejection names the field that failed.
 *
 * A pre-G1 file — `buckets`, with `allow` and `token_hash` at the top — loads as ONE agent
 * named after its one bucket. One with several buckets is refused rather than guessed at: its
 * one token reached every bucket, and there is no per-agent reading of that which keeps it.
 */
export function parsePolicy(raw: unknown): Policy {
  const fail = (m: string): never => { throw new Error(`policy: ${m}`); };
  if (!plain(raw)) return fail('not an object');
  const legacy = own(raw, 'buckets');
  if (legacy && own(raw, 'agents')) fail('has both buckets and agents — agents replaces buckets (MONERO.md §4.1)');
  for (const k of Object.keys(raw)) if (!(legacy ? LEGACY_TOP : TOP).includes(k)) fail(`unknown field ${JSON.stringify(k)}${legacy ? ' (in a buckets-style policy)' : ''}`);
  const net = raw['net'];
  if (net !== 'mainnet' && net !== 'stagenet' && net !== 'testnet') return fail(`net is ${JSON.stringify(net)}`);
  const w = raw['wallet'];
  if (!plain(w) || typeof w['rpc'] !== 'string') return fail('wallet.rpc is missing');
  for (const k of Object.keys(w)) if (k !== 'rpc' && k !== 'login') fail(`wallet: unknown field ${JSON.stringify(k)}`);
  if (own(w, 'login') && typeof w['login'] !== 'string') fail('wallet.login is not a string');
  // The wallet RPC holds the spend key. A non-loopback one means the key is reachable from
  // the network, or that we are about to send a spend request across it. Refuse to start.
  let host = '';
  try { host = new URL(w['rpc']).hostname; } catch (e) { fail(`wallet.rpc is not a URL (${why(e)})`); }
  if (!LOOPBACK.has(host)) fail(`wallet.rpc host ${host} is not loopback — refusing to start`);
  // §7: any unlock_time but 0 fingerprints the transaction on chain.
  if (raw['unlock_time'] !== 0) fail(`unlock_time is ${JSON.stringify(raw['unlock_time'])}, MONERO.md §7 requires 0`);
  if (!intIn(raw['priority'], 0) || raw['priority'] > 4) fail(`priority is ${JSON.stringify(raw['priority'])}, not 0..4`);
  const dedupe = own(raw, 'dedupe_seconds') ? raw['dedupe_seconds'] : 600;
  if (!intIn(dedupe, 1)) return fail('dedupe_seconds is not a positive integer');
  const ttl = own(raw, 'max_approval_ttl') ? raw['max_approval_ttl'] : 3600;
  if (!intIn(ttl, 1)) return fail('max_approval_ttl is not a positive integer');
  const approvers = own(raw, 'approvers') ? raw['approvers'] : [];
  if (!Array.isArray(approvers) || !approvers.every((a) => plain(a) && Object.keys(a).join() === 'did' && typeof a['did'] === 'string' && DID.test(a['did']))) fail('approvers is not a list of { did: "did:sigelo:z…" }');
  const approverDids = (approvers as { did: string }[]).map((a) => a.did);
  if (new Set(approverDids).size !== approverDids.length) fail('approvers names one DID twice');
  if (own(raw, 'recovery_commitment') && !(typeof raw['recovery_commitment'] === 'string' && HASH.test(raw['recovery_commitment']))) fail('recovery_commitment is not sha256:<64 hex>');

  let entries: [string, unknown][];
  if (legacy) {
    const b = raw['buckets'];
    if (!plain(b)) return fail('buckets is not an object');
    const names = Object.keys(b);
    if (names.length !== 1) fail(`buckets has ${names.length} entries under one token_hash — a buckets-style policy loads as one agent; write an agents entry with its own token per account (MONERO.md §4.1)`);
    const only = b[names[0]!];
    if (!plain(only)) return fail(`buckets.${names[0]} is not an object`);
    for (const k of Object.keys(only)) if (!BUCKET_FIELDS.includes(k)) fail(`buckets.${names[0]}: unknown field ${JSON.stringify(k)}`);
    entries = [[names[0]!, { ...only, token_hash: raw['token_hash'], allow: raw['allow'] }]];
  } else {
    if (!plain(raw['agents'])) return fail('agents is not an object');
    entries = Object.entries(raw['agents']);
  }
  if (entries.length === 0) fail('agents is empty');

  const agents: Record<string, Agent> = {};
  const accounts = new Map<number, string>(), hashes = new Map<string, string>(), dids = new Map<string, string>();
  for (const [name, a] of entries) {
    const at = `agents.${name}.`;
    if (!NAME.test(name)) fail(`agent name ${JSON.stringify(name)} is not 1..64 of [A-Za-z0-9._-]`);
    if (!plain(a)) return fail(`agents.${name} is not an object`);
    for (const k of Object.keys(a)) if (!AGENT_FIELDS.includes(k)) fail(`agents.${name}: unknown field ${JSON.stringify(k)}`);
    if (!intIn(a['account'], 0)) fail(`${at}account is not a Monero account index`);
    for (const f of ['per_tx_max', 'per_period_max']) if (typeof a[f] !== 'string' || !ATOMIC.test(a[f])) fail(`${at}${f} is not a decimal string of atomic units`);
    if (!intIn(a['period_seconds'], 1)) fail(`${at}period_seconds is not a positive integer`);
    if (!intIn(a['rate_per_minute'], 1)) fail(`${at}rate_per_minute is not a positive integer`);
    if (typeof a['token_hash'] !== 'string' || !HASH.test(a['token_hash'])) fail(`${at}token_hash is not sha256:<64 hex> — run \`sigelo-spend token new <policy> ${name}\``);
    // One account, one agent; one token, one agent. Two agents on one account would each spend
    // the other's balance, and a shared token would make "which agent?" a guess.
    const acct = a['account'] as number, hash = a['token_hash'] as string;
    if (accounts.has(acct)) fail(`agents ${accounts.get(acct)} and ${name} share account ${acct}`);
    if (hashes.has(hash)) fail(`agents ${hashes.get(hash)} and ${name} share a token_hash`);
    accounts.set(acct, name); hashes.set(hash, name);
    // §4.1 step 8. A threshold that nothing could ever satisfy is a typo'd policy, not a
    // freeze: refused here, like every other field that would make every spend fail.
    const above = own(a, 'approval_above') ? a['approval_above'] : null;
    if (above !== null && !(typeof above === 'string' && ATOMIC.test(above))) fail(`${at}approval_above is not null or a decimal string of atomic units`);
    if (above !== null && approverDids.length === 0) fail(`${at}approval_above is set but approvers is empty — nobody could ever approve`);
    if (above !== null && !(own(a, 'did') && own(a, 'genesis'))) fail(`${at}approval_above needs the agent's did and genesis — an approval names the agent's DID, and the keeper refuses an approver signing with the agent's own key`);
    if (own(a, 'genesis')) {
      try { structure(a['genesis'], 'genesis'); } catch (e) { fail(`${at}genesis: ${why(e)}`); }
      if (!own(a, 'did') || didOf(a['genesis']) !== a['did']) fail(`${at}genesis does not hash to ${at}did`);
    }
    if (own(a, 'did') && approverDids.includes(a['did'] as string)) fail(`${at}did is also in approvers — an agent cannot approve its own payments`);
    const delegates = own(a, 'max_delegates') ? a['max_delegates'] : 0;
    if (!intIn(delegates, 0)) fail(`${at}max_delegates is not a non-negative integer`);
    if (!Array.isArray(a['allow'])) fail(`${at}allow is not an array`);
    // One DID, one agent: `POST /bind` would otherwise cross-sign one identity for two accounts.
    if (own(a, 'did') && !(typeof a['did'] === 'string' && DID.test(a['did']))) fail(`${at}did is not a did:sigelo:z… DID`);
    if (own(a, 'did') && dids.has(a['did'] as string)) fail(`agents ${dids.get(a['did'] as string)} and ${name} share did ${a['did']}`);
    if (own(a, 'did')) dids.set(a['did'] as string, name);
    agents[name] = {
      account: acct, token_hash: hash, per_tx_max: a['per_tx_max'] as string, per_period_max: a['per_period_max'] as string,
      period_seconds: a['period_seconds'] as number, rate_per_minute: a['rate_per_minute'] as number,
      allow: (a['allow'] as unknown[]).map((r, i) => allowRule(r, `${at}allow[${i}]`, net, fail)),
      approval_above: above as string | null, max_delegates: delegates as number, ...(own(a, 'did') && { did: a['did'] as string }),
      ...(own(a, 'genesis') && { genesis: a['genesis'] as Genesis }),
    };
    const labels = agents[name]!.allow.flatMap((r) => (r.label === undefined ? [] : [r.label]));
    const dup = labels.find((l, i) => labels.indexOf(l) !== i);
    if (dup !== undefined) fail(`${at}allow: label ${JSON.stringify(dup)} names two addresses`);
  }
  return {
    net, wallet: { rpc: w['rpc'], ...(own(w, 'login') && { login: w['login'] as string }) }, agents,
    unlock_time: 0, priority: raw['priority'] as number, dedupe_seconds: dedupe, max_approval_ttl: ttl,
    ...(own(raw, 'approvers') && { approvers: approvers as { did: string }[] }),
    ...(own(raw, 'recovery_commitment') && { recovery_commitment: raw['recovery_commitment'] as string }),
  };
}

/**
 * A whole allowlist from outside policy.json — a `POST /delegate` body or a delegate line —
 * held to the same rules as the Owner's: each entry valid on `net`, no label twice.
 */
export function parseAllow(raw: unknown, net: Net, at: string): AllowRule[] {
  const fail = (m: string): never => { throw new Error(m); };
  if (!Array.isArray(raw)) return fail(`${at} is not an array`);
  const rules = raw.map((r, i) => allowRule(r, `${at}[${i}]`, net, fail));
  const labels = rules.flatMap((r) => (r.label === undefined ? [] : [r.label]));
  const dup = labels.find((l, i) => labels.indexOf(l) !== i);
  if (dup !== undefined) fail(`${at}: label ${JSON.stringify(dup)} names two addresses`);
  return rules;
}

/**
 * An allow entry decides where money may go. A malformed one has to stop the service at load,
 * not turn every later /pay into an unexplained refusal — and an entry that matches nothing is
 * a rule nobody wrote on purpose.
 */
function allowRule(r: unknown, at: string, net: Net, fail: (m: string) => never): AllowRule {
  if (!plain(r)) return fail(`${at} is not an object`);
  const keys = Object.keys(r);
  const str = (k: string): boolean => own(r, k) && typeof r[k] === 'string' && r[k] !== '';
  const only = (allowed: string[]): void => { for (const k of keys) if (!allowed.includes(k)) fail(`${at}: field ${JSON.stringify(k)} does not belong in this kind of rule`); };
  if (own(r, 'addr')) {
    only(['addr', 'label']);
    if (!str('addr')) fail(`${at}.addr is not a string`);
    if (own(r, 'label') && !(str('label') && NAME.test(r['label'] as string))) fail(`${at}.label is not 1..64 of [A-Za-z0-9._-]`);
    // Decoded now: a literal that is not a payable address on this network would match nothing.
    let d;
    try { d = decodeAddress(r['addr'] as string); } catch (e) { return fail(`${at}.addr does not decode as a Monero address (${why(e)})`); }
    if (d.net !== net || d.kind === 'integrated') fail(`${at}.addr is a ${d.net} ${d.kind} address — policy net is ${net}, and integrated addresses are refused (MONERO.md §7)`);
    return { addr: r['addr'] as string, ...(own(r, 'label') && { label: r['label'] as string }) };
  }
  only(['did', 'issuer', 'ctx']);
  if (!str('issuer')) fail(`${at} is neither { addr } nor { did?, issuer, ctx? } — an entry that matches nothing is a rule nobody wrote on purpose`);
  if (own(r, 'did') && !str('did')) fail(`${at}.did is not a string`);
  if (own(r, 'ctx') && typeof r['ctx'] !== 'string') fail(`${at}.ctx is not a string`);
  return { ...(own(r, 'did') && { did: r['did'] as string }), issuer: r['issuer'] as string, ...(own(r, 'ctx') && { ctx: r['ctx'] as string }) };
}
