#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// CLI plumbing for sigelo-agent.ts: argv, stdin, JSON out, exit codes. All of the identity
// logic — and everything a world integrator needs to read — is in sigelo-agent.ts.
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { did, parse, parseBytes, SigeloError } from 'sigelo';
import * as id from './sigelo-agent.ts';
import * as adopt from './sigelo-agent-adopt.ts';
import * as xmr from './sigelo-agent-monero.ts';

const USAGE = `sigelo-agent — portable sigelo/0 identity for a moadim-run agent

  init --recovery <z…> | --no-recovery   create the identity (once, on first run)
  adopt <json|file|-> [--force]          take a key made elsewhere: { identity_seed_hex, genesis }
                                         (a keeper's POST /delegate answer as is)
  adopt --rotation <json|file|->         apply sigelo-offline recover's { rotation, identity_seed_hex }
  whoami                                 current DID + genesis
  sign-challenge <json|->                sign a world's { typ: "challenge", … } body
  add-issuer <genesis json|->            store a world's genesis document
  add-attestation <{body,sig} json|->    store a world's attestation about us
  bundle                                 verify, then print the SPEC §8 bundle
  rotate                                 voluntary rotation to a fresh key

Monero (MONERO.md §2-§3, SPEC §6):
  wallet-set <json|->                    install the treasury's VIEW-ONLY keys
  bind                                   cross-sign a §6 binding to the base address
  receive [--account <n>]                next unused receive subaddress
  invoice --addr <subaddress> [--amount <atomic>] [--memo <text>] [--ttl <s>]
  verify-invoice <json|-> --bundle <f>   the payer's side: check one invoice

A <json|-> argument may also be a file holding the JSON.
Identity file: $SIGELO_IDENTITY, else ~/.config/moadim/sigelo.local.json (0600).
This process never holds a Monero spend key: wallet-set refuses one.`;

const OFFLINE_KEYGEN = `
Generate the recovery key OFFLINE and keep it off this machine (THREAT-MODEL §5). In a
checkout of sigelo/ts (npm ci && npx tsc) on an air-gapped box:

  node --input-type=module -e 'import {keygen} from "./dist/sigelo.js";import {writeFileSync} from "node:fs";
  const k = keygen({ recovery: new Uint8Array(32) });      // this keypair IS the recovery key
  writeFileSync("recovery.key", Buffer.from(k.secret).toString("hex"), { mode: 0o600 });
  console.log(k.key);'

Pass the printed z… key as --recovery. Only its hash reaches this machine (SPEC §4).`;

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

const out = (x: unknown): void => console.log(JSON.stringify(x, null, 2));
const note = (s: string): void => console.error(`sigelo-agent: ${s}`);
/** Read one JSON argument, a file holding it, or stdin for `-`/nothing. sigelo's parser, so
 *  duplicate keys are rejected rather than silently resolved (SPEC §3, THREAT-MODEL §2.8), and
 *  bytes are decoded fatally: invalid UTF-8 rejects the document, as the Go verifier does. */
const input = (v: string | undefined): unknown => v === undefined || v === '-' ? parseBytes(readFileSync(0))
  : /^\s*[{["]/.test(v) || !existsSync(v) ? parse(v) : parseBytes(readFileSync(v));

const [cmd, ...rest] = process.argv.slice(2);
const flag = (name: string): string | undefined => (rest.includes(name) ? rest[rest.indexOf(name) + 1] : undefined);
const path = id.identityPath();
const now = Math.floor(Date.now() / 1000);
/** Every load → change → save holds the one lock `receive` takes. A command that saves a store
 *  it loaded before another command's save undoes that save: a reissued subaddress index
 *  (two payers who can link each other, MONERO.md §3), a lost attestation, a lost rotation. */
const update = <T>(fn: (s: id.Store) => { store: id.Store; result: T }): T =>
  xmr.withLock(path, () => { const { store, result } = fn(id.load(path)); id.save(path, store); return result; });

try {
  switch (cmd) {
    case 'init': {
      const recovery = flag('--recovery');
      // A null recovery commitment must be a decision, never a default: it means theft of the
      // identity key is terminal (SPEC §4). keygen prints the warning itself.
      if (recovery === undefined && !rest.includes('--no-recovery')) {
        throw new SigeloError(`init: pass --recovery <multibase pubkey>, or --no-recovery to accept that theft of this key is PERMANENT and unrecoverable.\n${OFFLINE_KEYGEN}`);
      }
      const store = id.init(path, recovery ?? null);
      note(`identity written to ${path} (0600)`);
      out({ did: did(store.genesis), genesis: store.genesis });
      break;
    }
    case 'adopt': {
      const file = flag('--rotation');
      if (file !== undefined) {
        const r = input(file);
        const { store, dropped } = update((s) => { const x = adopt.applyRotation(s, r, now); return { store: x.store, result: x }; });
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
      const store = id.load(path);
      out({ did: did(id.head(store)), genesis: id.head(store), chain: id.chainOf(store), attestations: store.attestations.length });
      break;
    }
    case 'sign-challenge':
      out(id.signChallenge(id.load(path), input(rest[0]) as Record<string, unknown>));
      break;
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
    case 'bundle': {
      const { bundle, result } = id.bundle(id.load(path), now);
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
      const binding = update((store) => ({ store, result: xmr.bindMonero(store, now) }));
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
      if (addr === undefined) throw new SigeloError('invoice: --addr <subaddress> is required — take one from `sigelo-agent receive`');
      out(xmr.invoice(id.load(path), { addr, amount: flag('--amount'), memo: flag('--memo'), ttl: Number(flag('--ttl') ?? 86400) }, now));
      break;
    }
    case 'verify-invoice': {
      const file = flag('--bundle');
      if (file === undefined) throw new SigeloError('verify-invoice: --bundle <file> is required — an invoice means nothing without the bundle whose binding anchors it (SPEC §6.3)');
      out(xmr.verifyInvoice(input(rest[0]?.startsWith('--') ? '-' : rest[0]), parseBytes(readFileSync(file)) as never, now));
      break;
    }
    case 'rotate': {
      if (rest.includes('--recovery')) throw new SigeloError(`rotate: this command does voluntary rotations only.${OFFLINE_RECOVERY}`);
      const store = update((s) => { const r = id.rotateKey(s, now); return { store: r, result: r }; });
      note('rotated; the previous key is retired. Ask each world to reissue its attestation to the new DID.');
      out({ did: did(id.head(store)), chain: id.chainOf(store) });
      break;
    }
    default:
      console.error(USAGE);
      process.exit(2);
  }
} catch (e) {
  note(e instanceof Error ? e.message : String(e));
  process.exit(1);
}
