#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// kit/ceremony/record.mjs <ceremony-public.json> <ceremony-record.json> — called by run.sh.
//
// Writes the record the operator keeps with the printed procedure: what was made, when, on which
// host (a sha256 of machine-id/hostname and uname, not the name), with which tools, and the
// sha256 of backup.age and fingerprint.txt so a later rerun or audit can tell it is the same root.
// Every value is public: the age RECIPIENT (never the identity), addresses, identity public keys,
// the fingerprint. It refuses to write anything that looks like key material, as a last guard.
import { readFileSync, writeFileSync } from 'node:fs';

const [pubPath, recPath] = process.argv.slice(2);
const pub = JSON.parse(readFileSync(pubPath, 'utf8'));
const e = (k) => process.env[k] ?? '';
const record = {
  v: 'sigelo-kit-ceremony/1',
  what: 'sigelo root ceremony (MONERO.md §4.5) run by the recovery kit: sigelo-offline ceremony --human',
  created: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
  started: e('SK_STARTED'),
  net: pub.net,
  keepers: pub.keepers.length,
  treasury_keeper: e('SK_TK') === '' ? null : Number(e('SK_TK')),
  keeper_identities: pub.keepers,
  fingerprint: pub.fingerprint,
  vault_address: pub.vault,
  age_recipient: e('SK_RCPT'),
  files: {
    'backup.age': 'encrypted to age_recipient; the root as Monero 25 words inside',
    'fingerprint.txt': 'JCS of the public values; restore checks against it',
    'ceremony-public.json': 'what sigelo-offline printed: public values only',
    keeper_packages: `${pub.keepers.length} plaintext keeper-<j>.json in ${e('SK_KOUT')}: move each to its host, then shred`,
  },
  backup_sha256: e('SK_BACKUP'),
  fingerprint_sha256: e('SK_FP'),
  host: { id_sha256: e('SK_HOST'), uname: e('SK_UNAME'), offline_check: e('SK_OFFLINE'), swap: e('SK_SWAP') || 'none' },
  tools: { node: process.version, age: e('SK_AGE'), sigelo_offline: e('SK_OFFJS'), sigelo_offline_sha256: e('SK_OFFSHA'), kit: e('SK_KIT') },
  people: { operator: e('SK_OPERATOR') || null, witnesses: e('SK_WITNESS') || null },
  words_shown: 'once, on /dev/tty of the host above; never on stdout, stderr or in a file',
  vendor: 'The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of yours.',
};
const text = JSON.stringify(record, null, 2) + '\n';
// Last guard: no 64-hex value but the file/host hashes and the public recovery commitment, no age identity.
const hexes = text.match(/\b[0-9a-f]{64}\b/g) ?? [];
const allowed = new Set([record.backup_sha256, record.fingerprint_sha256, record.host.id_sha256, record.tools.sigelo_offline_sha256,
  String(pub.public?.recovery_commitment ?? '').replace(/^sha256:/, '')]);
if (/AGE-SECRET-KEY-/i.test(text) || hexes.some((h) => !allowed.has(h))) {
  console.error('kit ceremony: the record would hold something that looks like key material; not written');
  process.exit(4);
}
writeFileSync(recPath, text, { mode: 0o644, flag: 'wx' });
