#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// CLI plumbing for sigelo-agent.ts: argv, stdin, JSON out, exit codes. All of the identity
// logic — and everything a world integrator needs to read — is in sigelo-agent.ts.
import './node-check.ts';   // first: it exits on a Node.js too old, before the rest loads
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { did, parse, parseBytes } from 'sigelo';
import * as id from './sigelo-agent.ts';
import * as keys from './sigelo-agent-keys.ts';
import * as adopt from './sigelo-agent-adopt.ts';
import * as xmr from './sigelo-agent-monero.ts';
import * as contact from './sigelo-agent-contact.ts';
import * as ui from './sigelo-agent-ui.ts';
import * as enrol from './sigelo-agent-enrol.ts';
import * as watch from './sigelo-agent-watch.ts';

const USAGE = `sigelo-agent — a portable sigelo/0 identity for an AI agent, and its contacts

  --version                              print the version

  init --recovery <z…> | --no-recovery   create the identity (once, on first run)
  adopt <json|file|-> [--force]          take a key made elsewhere: { identity_seed_hex, genesis }
                                         (a keeper's POST /delegate answer as is)
  adopt --rotation <json|file|->         apply sigelo-offline recover's { rotation, identity_seed_hex }
  whoami                                 current DID + genesis
  sign-challenge <json|->                sign a world's { typ: "challenge", … } body
  add-issuer <genesis json|->            store a world's genesis document
  add-attestation <{body,sig} json|->    store a world's attestation about us
  forget-issuer <did>                    drop a retired issuer's attestations and genesis
  bundle                                 verify, then print the SPEC §8 bundle
  rotate                                 voluntary rotation to a fresh key (not on a key from your words)

Monero (MONERO.md §2-§3, SPEC §6):
  wallet-set <json|->                    install the treasury's VIEW-ONLY keys
  bind                                   cross-sign a §6 binding to the base address
  receive [--account <n>]                next unused receive subaddress
  invoice --addr <subaddress> [--amount <atomic>] [--memo <text>] [--ttl <s>]
  verify-invoice <json|-> --bundle <f>   the payer's side: check one invoice

${keys.USAGE}

The human's page (UI-API.md):
  ui [--no-open]                         a page on 127.0.0.1 for your own DID: contacts, codes, the four
                                         words, messages, your agents; $SIGELO_HUMAN, else
                                         ~/.config/sigelo/me.local.json (made by keeper --from-words)

Staying connected (WATCH.md):
  ${watch.USAGE.replaceAll('\n', '\n  ')}

A <json|-> argument may also be a file holding the JSON.
Identity file: $SIGELO_IDENTITY, else ~/.config/moadim/sigelo.local.json (0600).
This process never holds a Monero spend key: wallet-set refuses one.`;

const OFFLINE_KEYGEN = `
Make the recovery key first, and keep it off this machine (THREAT-MODEL §5):

  sigelo-agent init --recovery "$(sigelo-agent recovery-key)"

recovery-key writes the secret to recovery.key (0600) and the public key to recovery.pub, and
prints the public key: move both files offline. Only the key's hash reaches the identity (SPEC §4).`;

const OFFLINE_RECOVERY = `
A recovery rotation is signed by the offline recovery key and MUST NOT run in an agent
runtime — a recovery key in the same process as the identity key protects nothing
(THREAT-MODEL §5). On the air-gapped box, with recovery.key and the chain from
\`sigelo-agent bundle\`: rotate({ genesis: <head genesis>, next_genesis: <fresh genesis,
same or new recovery commitment>, iat, reason: "recovery", secret: <recovery seed> }), and
bring back { "rotation": <it>, "identity_seed_hex": <the fresh genesis's seed> } for
\`sigelo-agent adopt --rotation <file>\`.
Tier 1 (the operator's 25-word root): \`node ts/dist/offline.js recover --genesis <whoami.json>
--backup backup.age --identity <age id> --net <net> > recovery.local.json\` there, then
\`sigelo-agent adopt --rotation recovery.local.json\` here, and shred the file.`;

// Escaped as the contact verbs escape theirs: worlds write claims and error text reaches stderr.
const out = (x: unknown): void => console.log(contact.safeJson(JSON.stringify(x, null, 2)));
const note = (s: string): void => console.error(`sigelo-agent: ${contact.safeText(s)}`);
/** Read one JSON argument, a file holding it, or stdin for `-`/nothing. sigelo's parser, so
 *  duplicate keys are rejected rather than silently resolved (SPEC §3, THREAT-MODEL §2.8), and
 *  bytes are decoded fatally: invalid UTF-8 rejects the document, as the Go verifier does. */
const input = (v: string | undefined): unknown => {
  const from = v === undefined || v === '-' ? 'stdin' : /^\s*[{["]/.test(v) ? 'the argument' : existsSync(v) ? v : null;
  // A refusal names what was read: a bare "unexpected token" named neither the argument nor the file.
  if (from === null) throw new Error(`${cmd}: ${JSON.stringify(v!.slice(0, 40))} is neither a file nor JSON: pass inline JSON, a file holding it, or - for stdin`);
  try { return from === 'stdin' ? parseBytes(readFileSync(0)) : from === 'the argument' ? parse(v!) : parseBytes(readFileSync(v!)); } catch (e) {
    throw new Error(`${cmd}: ${from} is not strict JSON (${(e as Error).message})`, { cause: e });
  }
};

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === '--version' || cmd === '-v') { console.log(contact.version()); process.exit(0); }
// The contact verbs live apart from the identity core (INTEGRATION.md) and need nothing below.
// contact.exit never resolves: it exits once stdout has drained.
// A page or a watcher on the identity file holds its relay session: contact.main refuses a second login.
if (contact.VERBS.includes(cmd ?? '')) await contact.exit(await contact.main(cmd!, rest));
if (cmd === 'ui') await contact.exit(await ui.main(rest));
if (cmd === 'enrol') await contact.exit(await enrol.main(rest));
if (cmd === 'keeper') await contact.exit(await enrol.keeperMain(rest));
if (cmd === 'watch') await contact.exit(await watch.main(rest));
const flag = (name: string): string | undefined => (rest.includes(name) ? rest[rest.indexOf(name) + 1] : undefined);
const path = id.identityPath();
const now = Math.floor(Date.now() / 1000);
// The verbs that read the identity: with none, "run init" and exit 2, as the contact verbs say
// it (a bare "load: no identity" exited 1).
const READS = ['whoami', 'keys', 'sign-challenge', 'add-issuer', 'add-attestation', 'forget-issuer', 'bundle', 'rotate', 'wallet-set', 'bind', 'receive', 'invoice'];
// adopt --rotation changes an identity: with none, it took the lock in a missing directory, a raw ENOENT.
if ((READS.includes(cmd ?? '') || (cmd === 'adopt' && rest.includes('--rotation'))) && !existsSync(path)) {
  note(contact.noIdentity(path));
  process.exit(2);
}
/** The operator identity made by `keeper --from-words` (sigelo-agent-enrol.ts): seed-derived, no S in it. */
type Derived = { derived?: { path: string; n: number } };
/** A command line missing what it needs: exit 2, as an unknown command (USAGE). */
function usage(why: string): never { note(why); process.exit(2); }
/** The identity, or one line naming the file that does not load (it may be corrupt, or another file). */
const load = (): id.Store => {
  if (!existsSync(path)) { note(contact.noIdentity(path)); process.exit(2); }
  try { return id.load(path); } catch (e) { throw contact.unreadable(path, e); }
};
/** Every load → change → save holds the one lock `receive` takes. A command that saves a store
 *  it loaded before another command's save undoes that save: a reissued subaddress index
 *  (two payers who can link each other, MONERO.md §3), a lost attestation, a lost rotation. */
const update = <T>(fn: (s: id.Store) => { store: id.Store; result: T }): T =>
  xmr.withLock(path, () => { const { store, result } = fn(load()); id.save(path, store); return result; });

try {
  switch (cmd) {
    case 'init': {
      // An agent on another machine, enrolled by its operator's code: it becomes the operator's
      // worker, whose recovery is the operator's seed (sigelo-agent-enrol.ts), so no --recovery here.
      if (rest.includes('--enrol')) {
        const code = flag('--enrol');
        if (code === undefined || code.startsWith('--')) usage('init: --enrol needs the code the operator\'s sigelo-agent enrol printed (K7F3-Q9ZP)');
        if (rest.includes('--recovery') || rest.includes('--no-recovery')) usage('init --enrol: no --recovery: the worker this machine becomes commits to the operator\'s seed\'s recovery key');
        await contact.exit(await enrol.initEnrol(path, code, rest));
      }
      const recovery = flag('--recovery');
      // A null recovery commitment must be a decision, never a default: it means theft of the
      // identity key is terminal (SPEC §4). keygen prints the warning itself.
      if (recovery === undefined && !rest.includes('--no-recovery')) {
        usage(`init: pass --recovery <multibase pubkey>, or --no-recovery to accept that theft of this key is PERMANENT and unrecoverable.\n${OFFLINE_KEYGEN}`);
      }
      const store = keys.init(path, recovery ?? null, process.env['SIGELO_KEY_PROVIDER']);
      note(`identity written to ${path} (0600)`);
      // The recovery public key, when given as one: the identity keeps only its hash (SPEC §4), and
      // a data request needs the key (erase-request derives it from the secret file).
      out({ did: did(store.genesis), genesis: store.genesis, ...(recovery?.startsWith('z') && { recovery_key: recovery }) });
      break;
    }
    case 'adopt': {
      const file = flag('--rotation');
      if (file !== undefined) {
        const r = input(file);
        // A recovered key is not the pinned derivation `keeper --rotate-me` makes: the marker goes.
        const { store, dropped } = update((s) => { const x = adopt.applyRotation(s, r, now); delete (x.store as Derived).derived; return { store: x.store, result: x }; });
        if (dropped > 0) note(`dropped ${dropped} rotation(s) after ${store.rotations.at(-1)!.body.id}: the recovery supersedes them (SPEC §7.1)`);
        note('rotation applied; the previous key is retired. Shred the file you adopted from: it holds the new key.');
        out({ did: did(id.head(store)), chain: id.chainOf(store) });
        break;
      }
      const src = input(rest[0]?.startsWith('--') ? '-' : rest[0]);
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      const store = xmr.withLock(path, () => adopt.adopt(path, src, rest.includes('--force')));
      if (store.genesis.recovery === null) note('this identity has recovery: null — theft of its key is PERMANENT (SPEC §4)');
      note(`identity written to ${path} (0600)`);
      out({ did: did(store.genesis), genesis: store.genesis });
      break;
    }
    case 'whoami': {
      const store = load();
      out({ did: did(id.head(store)), genesis: id.head(store), chain: id.chainOf(store), attestations: store.attestations.length });
      break;
    }
    case 'sign-challenge':
      out(keys.signChallenge(path, load(), input(rest[0]) as Record<string, unknown>));
      break;
    case 'keys': {
      const r = keys.main(rest, path, load());
      if (r === null) usage(`keys: ${JSON.stringify(rest[0] ?? '')} is not a verb\n${keys.USAGE}`);
      out(r);
      break;
    }
    case 'add-issuer': {
      const g = input(rest[0]) as never;
      out(update((s) => { const store = id.addIssuer(s, g); return { store, result: { issuers: store.issuers.map(did) } }; }));
      break;
    }
    case 'add-attestation': {
      const a = input(rest[0]) as never;
      out(update((s) => { const store = id.addAttestation(s, a); return { store, result: { attestations: store.attestations.length } }; }));
      break;
    }
    case 'forget-issuer': {
      const d = rest[0];
      out(update((s) => { const { store, removed } = adopt.forgetIssuer(s, d); return { store, result: { removed, attestations: store.attestations.length, issuers: store.issuers.map(did) } }; }));
      break;
    }
    case 'bundle': {
      const { bundle, result } = id.bundle(load(), now);
      if (result.rejected.attestations > 0) note(`${result.rejected.attestations} stored attestation(s) do not verify at ${now} (expired, or the issuer genesis is missing) and count for nothing`);
      if (result.rejected.bindings > 0) note(`${result.rejected.bindings} stored binding(s) do not verify at ${now} (expired, or minted under a DID this chain does not have) — re-run \`bind\``);
      out(bundle);
      break;
    }
    case 'wallet-set': {
      const blob = input(rest[0]);
      const w = update((s) => { const store = xmr.walletSet(s, blob); return { store, result: xmr.wallet(store) }; });
      note(`treasury installed: ${w.net} ${w.address} — VIEW ONLY, this process cannot spend it`);
      out({ net: w.net, address: w.address });
      break;
    }
    case 'bind': {
      const binding = update((store) => ({ store, result: xmr.bindMonero(store, now, keys.signer(path, store)) }));
      // Same bytes as `monero-wallet-rpc sign { signature_type: "view", account_index: 0,
      // address_index: 0 }` over the §3 signing input — made here, with no wallet running.
      note('sig_addr signed in VIEW mode with the treasury view key (SPEC §6.2)');
      out(binding);
      break;
    }
    case 'receive': {
      // Read, bump and write the counter under one lock: a racing sidecar must not be handed
      // the same index, because two payers to one subaddress can link each other (MONERO.md §3).
      out(update((store) => ({ store, result: xmr.receive(store, Number(flag('--account') ?? 0)) })));
      break;
    }
    case 'invoice': {
      const addr = flag('--addr');
      if (addr === undefined) usage('invoice: --addr <subaddress> is required — take one from `sigelo-agent receive`');
      const s = load();
      out(xmr.invoice(s, { addr, amount: flag('--amount'), memo: flag('--memo'), ttl: Number(flag('--ttl') ?? 86400) }, now, keys.signer(path, s)));
      break;
    }
    case 'verify-invoice': {
      const file = flag('--bundle');
      if (file === undefined) usage('verify-invoice: --bundle <file> is required — an invoice means nothing without the bundle whose binding anchors it (SPEC §6.3)');
      out(xmr.verifyInvoice(input(rest[0]?.startsWith('--') ? '-' : rest[0]), parseBytes(readFileSync(file)) as never, now));
      break;
    }
    case 'rotate': {
      if (rest.includes('--recovery')) usage(`rotate: this command does voluntary rotations only.${OFFLINE_RECOVERY}`);
      // A derived identity (keeper --from-words) is refused there: its next key is rotation n + 1 of the words.
      const store = update((s) => { const r = keys.rotate(path, s, now); return { store: r, result: r }; });
      note('rotated; the previous key is retired. Ask each world to reissue its attestation to the new DID.');
      out({ did: did(id.head(store)), chain: id.chainOf(store) });
      break;
    }
    default:
      console.error(`${USAGE}\n\n${contact.USAGE}\n\n${enrol.USAGE}`);
      process.exit(2);
  }
} catch (e) {
  note(e instanceof Error ? e.message : String(e));
  contact.debug(e, { identity: path });
  process.exit(1);
}
