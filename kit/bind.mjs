#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// kit/bind.mjs — bind the printed procedures to one installation.
//
//   sigelo-kit-bind --kit kit.json [--record <ceremony out>/ceremony-record.json] --out <dir>
//
// Reads procedure/{CEREMONY,DRILL,RUNBOOK}.md, fills every {{placeholder}} from kit.json (the
// operator's paths, units, hosts, people; see kit.example.json) and, if given, the ceremony
// record (vault address, net), and writes the three bound files to <dir>. Then
// `procedure/print.sh <dir>` renders them for the printer.
//
// It refuses, naming each problem: a placeholder with no value, a value kit.json does not
// define, a net that disagrees with the record, and anything in kit.json that looks like key
// material — a 64-hex value, an age identity, a run of seed words, a field named like a secret.
// kit.json describes where things are; it never holds them.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const KIT = dirname(fileURLToPath(import.meta.url));
export const DOCS = ['CEREMONY.md', 'DRILL.md', 'RUNBOOK.md'];
export const GUARD = 'The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of yours — not even "for recovery".';

/** The Monero wordlist from the sigelo package beside the kit or the clone's ts/dist; null if neither. */
async function wordlist() {
  let dist;
  try { dist = dirname(createRequire(join(KIT, 'package.json')).resolve('sigelo/dist/offline.js')); } catch { dist = join(KIT, '..', 'ts', 'dist'); }
  const p = join(dist, 'monero-words.js');
  return existsSync(p) ? new Set((await import(pathToFileURL(p).href)).MONERO_WORDS) : null;
}

const SECRET_NAME = /(^|[_.-])(seed|mnemonic|words|secret|spend_?key|view_?key|private|token|password|passphrase|keeper_root|root_hex|identity_file)($|[_.-])/i;

/** Every problem with kit.json as key material, as messages. */
export function secretProblems(kit, words) {
  const out = [];
  (function walk(v, path) {
    if (Array.isArray(v)) return v.forEach((x, i) => walk(x, `${path}[${i}]`));
    if (v && typeof v === 'object') return Object.entries(v).forEach(([k, x]) => {
      if (SECRET_NAME.test(k)) out.push(`${path}${path ? '.' : ''}${k}: a field named like a secret — kit.json says where things are, never what they are`);
      walk(x, `${path}${path ? '.' : ''}${k}`);
    });
    if (typeof v !== 'string') return;
    if (/\b[0-9a-fA-F]{64}\b/.test(v)) out.push(`${path}: holds 64 hex characters, the shape of a key`);
    if (/AGE-SECRET-KEY-/i.test(v)) out.push(`${path}: holds an age identity`);
    const toks = v.toLowerCase().split(/[^a-z]+/).filter(Boolean);
    let run = 0, max = 0;
    for (const w of toks) { run = (words ? words.has(w) : /^[a-z]{3,12}$/.test(w)) ? run + 1 : 0; max = Math.max(max, run); }
    if (max >= (words ? 6 : 12)) out.push(`${path}: holds ${max} seed words in a row`);
  })(kit, '');
  return out;
}

/** The values the templates use: kit.json flattened, the record's, and the derived command blocks. */
export function values(kit, record) {
  const v = {};
  (function flat(o, p) {
    for (const [k, x] of Object.entries(o)) {
      const key = p ? `${p}.${k}` : k;
      if (x && typeof x === 'object' && !Array.isArray(x)) flat(x, key);
      else v[key] = Array.isArray(x) ? x.join(', ') : String(x);
    }
  })(kit, '');
  if (record) { v.vault_address ??= record.vault_address; v.fingerprint ??= record.fingerprint; }
  const k = kit.keeper ?? {};
  const sup = kit.supervisor;
  if (sup === 'systemd-user' || sup === 'systemd-system') {
    const sc = sup === 'systemd-user' ? 'systemctl --user' : 'sudo systemctl';
    v.freeze_keeper = `${sc} stop ${k.unit} && ${sc} disable ${k.unit}`;
    v.freeze_wallet = `${sc} stop ${k.wallet_rpc_unit} && ${sc} disable ${k.wallet_rpc_unit}`;
    v.freeze_verify = `${sc} is-active ${k.unit} ${k.wallet_rpc_unit}    # inactive, inactive — again after 15 s\n` +
      `${sc} is-enabled ${k.unit} ${k.wallet_rpc_unit}   # disabled, disabled\n` +
      `ls ${k.policy_dir}/spend.lock 2>/dev/null; pgrep -af 'sigelo-spend|cli.js serve'   # no keeper process`;
    v.restore_units = `${sc} enable --now ${k.wallet_rpc_unit} ${k.unit}`;
  } else if (sup === 'none') {
    v.freeze_keeper = `kill -9 "$(head -n1 ${k.policy_dir}/spend.lock)"   # keeps spend.lock as evidence; nothing restarts it`;
    v.freeze_wallet = 'kill -TERM "$(pgrep -f monero-wallet-rpc)"   # SIGTERM stores the wallet file';
    v.freeze_verify = `pgrep -af 'sigelo-spend|cli.js serve|monero-wallet-rpc'   # nothing, now and after 15 s`;
    v.restore_units = 'start the keeper and wallet-rpc by hand on the NEW policy directory';
  }
  return v;
}

/** Fill one template; returns { text, missing } — the placeholders with no value. */
export function fill(md, v) {
  const missing = new Set();
  const text = md.replace(/\{\{([\w.]+)\}\}/g, (_, key) => (v[key] !== undefined && v[key] !== '' ? v[key] : (missing.add(key), `{{${key}}}`)));
  return { text, missing: [...missing] };
}

export async function bind({ kitPath, recordPath, out }) {
  const raw = readFileSync(kitPath);
  const kit = JSON.parse(raw);
  const problems = [];
  if (kit.v !== 'sigelo-kit/1') problems.push(`v: expected "sigelo-kit/1", got ${JSON.stringify(kit.v)}`);
  if (!['mainnet', 'stagenet', 'testnet'].includes(kit.net)) problems.push('net: must be mainnet, stagenet or testnet');
  if (!['systemd-user', 'systemd-system', 'none'].includes(kit.supervisor)) problems.push('supervisor: must be systemd-user, systemd-system or none');
  problems.push(...secretProblems(kit, await wordlist()));
  const record = recordPath ? JSON.parse(readFileSync(recordPath, 'utf8')) : undefined;
  if (record && record.net !== kit.net) problems.push(`net: kit.json says ${kit.net}, the ceremony record says ${record.net}`);
  if (problems.length) throw new Error(`bind: kit.json refused:\n  ${problems.join('\n  ')}`);
  const v = values(kit, record);
  const filled = DOCS.map((d) => [d, fill(readFileSync(join(KIT, 'procedure', d), 'utf8'), v)]);
  const missing = filled.flatMap(([d, f]) => f.missing.map((m) => `${d}: {{${m}}}`));
  if (missing.length) throw new Error(`bind: no value in kit.json${recordPath ? ' or the record' : ''} for:\n  ${missing.join('\n  ')}`);
  mkdirSync(out, { recursive: true });
  const stamp = `\n---\n\nBound for ${kit.installation} from kit.json sha256 ${createHash('sha256').update(raw).digest('hex').slice(0, 16)}…` +
    `${record ? ` and ceremony-record.json of ${record.created}` : ''} by sigelo-recovery-kit bind.mjs.\n`;
  for (const [d, f] of filled) writeFileSync(join(out, d), f.text + stamp);
  return DOCS.map((d) => join(out, d));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === (await import('node:fs')).realpathSync(process.argv[1])) {
  const a = process.argv.slice(2), opt = (n) => { const i = a.indexOf(n); return i < 0 ? undefined : a[i + 1]; };
  if (a.includes('-h') || a.includes('--help') || !opt('--kit') || !opt('--out')) {
    console.error('usage: sigelo-kit-bind --kit kit.json [--record ceremony-record.json] --out <dir>\n(start from kit.example.json)');
    process.exit(a.includes('-h') || a.includes('--help') ? 0 : 2);
  }
  try {
    const files = await bind({ kitPath: opt('--kit'), recordPath: opt('--record'), out: opt('--out') });
    console.log(`bound: ${files.join(', ')}\nprint: sh ${join(KIT, 'procedure', 'print.sh')} ${opt('--out')}`);
  } catch (e) { console.error(e.message); process.exit(2); }
}
