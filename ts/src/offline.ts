#!/usr/bin/env node
// SPDX-License-Identifier: MIT
/**
 * `sigelo-offline` — root seed for sigelo × Monero (MONERO.md §2, §4.5). Run it with no network.
 *
 *   sigelo-offline ceremony --net <net> --recipient <age1…> --out <dir> [--keepers N] [--treasury-keeper j]
 *                           [--human] [--import <file|-> --i-know-this-seed-was-cold]
 *   sigelo-offline restore  (--backup <backup.age> --identity <age identity file> | --words <file|-> [--keepers N]
 *                           [--fingerprint fingerprint.txt]) --net <net> [--reveal-all]
 *   sigelo-offline new      [--net <net>]
 *   sigelo-offline derive   <25 words | 64 hex> [--net <net>] [--keepers N] [--reveal-all]
 *   sigelo-offline recover  --genesis <file> <root> [--agent i [--keeper j] --n m | --identity-n n | --new-keeper <j|random>]
 *                           [--next-recovery <z…|sha256:…|none>] [--iat <unix>]
 *
 * `ceremony` is §4.5: `S` never reaches stdout or a file other than the Owner's encrypted
 * backup (src/ceremony.ts) — and, with `--human`, the human's own terminal: the 25 words go to
 * /dev/tty, opened here, and a run without one is refused (ROADMAP §2 M4). `--import` makes
 * the root of existing words only with `--i-know-this-seed-was-cold`. `restore` is the Owner's:
 * it decrypts with age (or reads the 25 words from a file or stdin, never argv, where `ps`
 * shows them), re-derives, checks the fingerprint and prints it with each keeper root `K_j`. `new`/`derive` are the manual
 * path, where the human carries `S` as Monero's 25 words — the vault's own seed, which any
 * Monero wallet that takes a 25-word (legacy) seed restores (a Polyseed-only one cannot).
 * `derive` and `restore --reveal-all` print the same roles: agent,
 * agents' keeper, keeper roots, recovery public half, vault address; the vault's keys, the
 * treasury spend key and the recovery secret, which belong in the Owner's backup only, appear
 * solely under `--reveal-all`, as `owner_backup`.
 * `recover` signs SPEC §7's recovery rotation from the agent's last honest genesis and prints
 * `{ did, rotation, identity_seed_hex }` — the file `sigelo-agent adopt --rotation` takes. The
 * root comes from the backup (`--backup --identity --net`, decrypted in memory), a `restore
 * --reveal-all` file (`--restored`), `-` (25 words or hex on stdin) or argv words like `derive`.
 * The recovery secret is used in memory and printed nowhere; the new identity's seed is the
 * one secret in the output, because it is the agent's new key. `--new-keeper` recovers a KEEPER's
 * own DID (INCIDENT.md §5): `--genesis` is the keeper's bundle (`identity.json`, or a bare genesis),
 * the new key is `identitySeed(K', 0)` for `K' = keeperRoot(S, j)` (or random), and the output is
 * `{ did, current, rotation, keeper_root_hex, bundle }` for `sigelo-spend init --adopt`.
 * Warnings go to stderr so `... > handout.json` stays valid JSON.
 */
import { readFileSync } from 'node:fs';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { Age, ageBinary, ceremony, checkRecipient, IMPORT_LIABILITY, importRoot, NextKey, openTty, recover, recoverKeeper, restore, restoreWords, roles } from './ceremony.js';
import { deriveRoot, newRoot, parseRoot, recoverySeed, rootFromMnemonic } from './keys.js';
import { Net } from './monero.js';
import { Bundle, Genesis, parseBytes, SigeloError, VERSION } from './sigelo.js';

const USAGE = `sigelo-offline — root seed for sigelo × Monero (MONERO.md §2, §4.5)

  sigelo-offline ceremony --net <net> --recipient <age1…> --out <dir> [--keepers N] [--treasury-keeper j]
                          [--human] [--import <file|-> --i-know-this-seed-was-cold]
      --human: also show the 25 words to the person running it, on /dev/tty only (never stdout);
      refused without a terminal. --import: make the root of existing words, refused unless you
      vouch they were never in a hot wallet.
  sigelo-offline restore  (--backup <backup.age> --identity <file> | --words <file|-> [--keepers N]
                          [--fingerprint <fingerprint.txt>]) --net <net> [--reveal-all]
      --words reads the 25 words from a file or stdin (-); never put them on the command line.
  sigelo-offline new      [--net <net>]
  sigelo-offline derive   <25 words | 64 hex> [--net <net>] [--keepers N] [--reveal-all]
  sigelo-offline recover  --genesis <file> (--backup <f> --identity <f> --net <net> | --restored <f> | - | <25 words>)
                          [--agent i [--keeper j] --n m | --identity-n n | --new-keeper <j|random>]
                          [--next-recovery <z…|sha256:…|none>] [--iat <unix>]
      signs the SPEC §7 recovery rotation from --genesis (the agent's LAST HONEST genesis, or a
      file holding one as "genesis": whoami, a /delegate answer); prints { did, rotation,
      identity_seed_hex } for \`sigelo-agent adopt --rotation\`. New key: agentIdentitySeed(K_j, i, m)
      with --agent (keeper j default 0), identitySeed(S, n) with --identity-n, else random.
      --new-keeper: a keeper's own DID; --genesis is its identity.json (bundle) or genesis; the new
      key is identitySeed(K', 0), K' = keeperRoot(S, j) or random; prints { did, current, rotation,
      keeper_root_hex, bundle } for \`sigelo-spend init --adopt\` (INCIDENT.md §5).

<net> is mainnet, stagenet or testnet (default stagenet). Run with networking down.`;

const die = (msg: string): never => { console.error(msg); process.exit(2); };
const REVEAL = '\n*** --reveal-all: VAULT KEYS, TREASURY SPEND KEY AND RECOVERY SECRET BELOW ***\n' +
  'These belong in the Owner\'s backup and nowhere else. The vault spend key IS the root S:\n' +
  'it empties the vault and re-derives every identity. The treasury spend key empties the\n' +
  'treasury; the recovery key takes over every identity after a theft. Never paste them into\n' +
  'an agent, a keeper host, a password manager that syncs, or a terminal that logs.\n';

/** `--flag value` / `--flag=value` / bare words. Unknown flags are refused, never ignored. */
function parse(cmd: string, args: string[], valued: string[], bools: string[]) {
  const f: Record<string, string> = {}, words: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!, [name, eq] = a.startsWith('--') ? [a.split('=')[0]!.slice(2), a.includes('=') ? a.slice(a.indexOf('=') + 1) : undefined] : ['', undefined];
    if (name === '') words.push(a);
    else if (bools.includes(name)) f[name] = 'y';
    else if (valued.includes(name)) f[name] = eq ?? args[++i] ?? die(`${cmd}: --${name} needs a value`);
    else die(`${cmd}: unknown flag ${a}`);
  }
  const net = f['net'] ?? 'stagenet';
  if (!['mainnet', 'stagenet', 'testnet'].includes(net)) die(`${cmd}: --net must be mainnet, stagenet or testnet, got ${JSON.stringify(net)}`);
  const int = (k: string): number | undefined => (f[k] === undefined ? undefined : /^\d+$/.test(f[k]!) ? Number(f[k]) : die(`${cmd}: --${k} must be a non-negative integer`));
  return { f, words, net: net as Net, int };
}
const age = (): Age => { const a = ageBinary(); return typeof a === 'string' ? die(a) : a; };

function cmdDerive(args: string[]): void {
  // The mnemonic arrives as 25 argv words unless quoted; parseRoot takes either form.
  const { f, words, net, int } = parse('derive', args, ['net', 'keepers'], ['reveal-all']);
  if (words.length === 0) die('derive: pass the root as its 25 words or 64 hex characters');
  if (f['reveal-all']) console.error(REVEAL);
  console.log(JSON.stringify(roles(deriveRoot(parseRoot(words.join(' ')), net, 0, int('keepers') ?? 1), net, !!f['reveal-all']), null, 2));
}

/** The 25 words from a file or stdin (`-`); never argv, where `ps` and shell history show them. */
const readWords = (src: string): string => readFileSync(src === '-' ? 0 : src, 'utf-8');
const NO_ARGV = (cmd: string): string => `${cmd}: unexpected argument — the 25 words never go on the command line (ps and shell history show them); ` +
  (cmd === 'restore' ? 'pass --words <file> or --words - and type them on stdin' : 'pass --import <file|->');

function cmdCeremony(args: string[]): void {
  const { f, words, net, int } = parse('ceremony', args, ['net', 'recipient', 'out', 'keepers', 'treasury-keeper', 'import'], ['human', 'i-know-this-seed-was-cold']);
  if (words.length > 0) die(NO_ARGV('ceremony'));
  if (!f['net'] || !f['recipient'] || !f['out']) die(`ceremony: --net, --recipient and --out are required\n\n${USAGE}`);
  checkRecipient(f['recipient']!); // before looking for age: a typo is the likelier mistake
  if (f['i-know-this-seed-was-cold'] && f['import'] === undefined) die('ceremony: --i-know-this-seed-was-cold goes with --import <file|->');
  // Both refusals before anything is read or written: no terminal, or an import nobody vouched for.
  const opened = f['human'] ? openTty() : undefined;
  const tty = typeof opened === 'string' ? die(opened) : opened;
  const S = f['import'] === undefined ? undefined : importRoot(() => readWords(f['import']!), !!f['i-know-this-seed-was-cold']);
  if (S !== undefined) console.error(IMPORT_LIABILITY);
  const r = ceremony({ net, recipient: f['recipient']!, out: f['out']!, keepers: int('keepers'), treasuryKeeper: int('treasury-keeper'), age: age(), S, tty });
  S?.fill(0);
  console.error(`ceremony: wrote ${r.files.join(', ')} to ${f['out']}. ${tty ? 'The 25 words went to /dev/tty and nowhere else' : 'S is gone'}; backup.age opens only with the Owner's age identity.\n` +
    'The 25 words are the vault: vault only, never a hot wallet.\n' +
    'Move each keeper-<j>.json to its keeper host and delete it here; keep fingerprint.txt beside backup.age.');
  console.log(JSON.stringify(r, null, 2));
}

function cmdRestore(args: string[]): void {
  const { f, words, net, int } = parse('restore', args, ['backup', 'identity', 'net', 'words', 'fingerprint', 'keepers'], ['reveal-all']);
  if (words.length > 0) die(NO_ARGV('restore'));
  if (!f['net'] || (f['backup'] === undefined) === (f['words'] === undefined)) die(`restore: --net and exactly one of --backup (with --identity) or --words are required\n\n${USAGE}`);
  const revealAll = !!f['reveal-all'];
  let out: unknown;
  if (f['backup'] !== undefined) {
    if (!f['identity']) die('restore: --backup needs --identity <age identity file>');
    if (f['fingerprint'] !== undefined || f['keepers'] !== undefined) die('restore: --fingerprint and --keepers go with --words; backup.age carries both');
    out = restore({ backup: readFileSync(f['backup']!), identity: f['identity']!, net, age: age(), revealAll });
  } else {
    out = restoreWords({ words: readWords(f['words']!), net, keepers: int('keepers'), revealAll,
      fingerprint: f['fingerprint'] === undefined ? undefined : readFileSync(f['fingerprint']!, 'utf-8') });
    if (f['fingerprint'] === undefined) console.error('restore: no --fingerprint given, so nothing was checked — compare "fingerprint" below with fingerprint.txt');
  }
  if (revealAll) console.error(REVEAL);
  console.log(JSON.stringify(out, null, 2));
}

function cmdNew(net: Net): void {
  const words = newRoot(), S = rootFromMnemonic(words);
  console.error('*** sigelo: this root is printed ONCE and never written to disk. ***\n' +
    'It is the only backup of every identity and every wallet below it. Write the 25 words\n' +
    'on paper, off this screen, before closing this terminal. They are a Monero seed (25-word,\n' +
    'legacy): any Monero wallet that takes a 25-word seed restores the vault from them (a\n' +
    'Polyseed-only wallet cannot), and anyone who reads them owns the vault,\n' +
    'the treasury and every identity. Never type them into a keeper host.\n' +
    'Vault only, never a hot wallet: not a mobile or desktop wallet, not any networked device.\n' +
    'Prefer `sigelo-offline ceremony`, which never shows S to anyone (MONERO.md §4.5).\n');
  console.log(`root_hex  ${bytesToHex(S)}`);
  console.log(`mnemonic  ${words}`);
  console.log(`vault     ${deriveRoot(S, net).vault.address}`);
}

function cmdRecover(args: string[]): void {
  const { f, words, net, int } = parse('recover', args,
    ['genesis', 'backup', 'identity', 'net', 'restored', 'agent', 'keeper', 'n', 'identity-n', 'next-recovery', 'iat', 'new-keeper'], []);
  if (!f['genesis']) die(`recover: --genesis <file> is required — the agent's last honest genesis (SPEC §7.1)\n\n${USAGE}`);
  const g = parseBytes(readFileSync(f['genesis']!)) as (Genesis | Bundle) & { genesis?: Genesis };
  const from = g.typ === 'genesis' ? g : g.genesis ?? die(`recover: ${f['genesis']} holds neither a genesis nor a "genesis" field`);
  const nk = f['new-keeper'];
  if (nk !== undefined && !/^(\d+|random)$/.test(nk)) die('recover: --new-keeper is a keeper index (the next unused j) or random');
  if (nk !== undefined && ['agent', 'keeper', 'n', 'identity-n', 'next-recovery'].some((x) => f[x] !== undefined)) die('recover: --new-keeper names the new key itself; it takes none of --agent, --keeper, --n, --identity-n, --next-recovery');
  const sources = [f['backup'] !== undefined, f['restored'] !== undefined, words.length > 0].filter(Boolean).length;
  if (sources !== 1) die('recover: give the root exactly one way: --backup/--identity/--net, --restored <file>, - (stdin) or the 25 words');
  let S: Uint8Array | undefined, recoverySecret: Uint8Array | undefined;
  if (f['backup'] !== undefined) {
    if (!f['identity'] || !f['net']) die('recover: --backup needs --identity and --net (restore checks the fingerprint per net)');
    const r = restore({ backup: readFileSync(f['backup']!), identity: f['identity']!, net, age: age(), revealAll: true }) as { owner_backup?: { vault: { spend_key: string } } };
    S = hexToBytes(r.owner_backup!.vault.spend_key); // the vault spend key IS S (keys.ts vaultFromRoot)
  } else if (f['restored'] !== undefined) {
    // `restore --reveal-all` output: S is owner_backup.vault.spend_key; the recovery secret
    // beside it must be recoverySeed(S), or the file was edited.
    const ob = (parseBytes(readFileSync(f['restored']!)) as { owner_backup?: { vault?: { spend_key?: string }; recovery?: { secret_key_hex?: string } } }).owner_backup;
    const rec = ob?.recovery?.secret_key_hex, sk = ob?.vault?.spend_key;
    if (typeof rec !== 'string') die(`recover: ${f['restored']} has no owner_backup.recovery.secret_key_hex — make it with \`restore --reveal-all\``);
    if (typeof sk === 'string') {
      S = parseRoot(sk);
      if (bytesToHex(recoverySeed(S)) !== rec) die('recover: owner_backup.recovery is not the recovery key of owner_backup.vault (S) — the file is not one restore wrote');
    } else recoverySecret = hexToBytes(rec!);
  } else S = parseRoot(words.length === 1 && words[0] === '-' ? readFileSync(0, 'utf-8').trim() : words.join(' '));
  const iat = int('iat') ?? Math.floor(Date.now() / 1000);
  if (nk !== undefined) {
    const bundle: Bundle = g.typ === 'bundle' ? g as Bundle : { v: VERSION, typ: 'bundle', genesis: from as Genesis, rotations: [], bindings: [], attestations: [], issuers: [] };
    const out = recoverKeeper({ bundle, S, recoverySecret, keeper: nk === 'random' ? undefined : Number(nk), iat });
    S?.fill(0);
    console.error(`recover: keeper ${out.did} now ${out.current} (reason "recovery"). The output holds the NEW keeper root (keeper_root_hex):\n` +
      'carry it to the new keeper host by hand, run `sigelo-spend init --adopt <file> …` there (a NEW --dir), then shred every copy.');
    console.log(JSON.stringify(out, null, 2));
    return;
  }
  const agent = int('agent'), idn = int('identity-n');
  if (agent !== undefined && idn !== undefined) die('recover: --agent and --identity-n name two different new keys; pick one');
  if (agent !== undefined && int('n') === undefined) die('recover: --agent needs --n <rotation index> — the next unused one, never the stolen key\'s');
  const next: NextKey = agent !== undefined ? { kind: 'agent', keeper: int('keeper') ?? 0, agent, n: int('n')! }
    : idn !== undefined ? { kind: 'identity', n: idn } : { kind: 'random' };
  const nr = f['next-recovery'];
  const out = recover({ from: from as Genesis, S, recoverySecret, next, nextRecovery: nr === undefined ? undefined : nr === 'none' ? null : nr, iat });
  S?.fill(0);
  console.error(`recover: ${out.rotation.body.id} → ${out.did} (reason "recovery"). The output holds the NEW identity's secret:\n` +
    'carry it to the agent by hand, run `sigelo-agent adopt --rotation <file>` there, then shred every copy.');
  console.log(JSON.stringify(out, null, 2));
}

const [cmd, ...args] = process.argv.slice(2);
try {
  if (cmd === 'ceremony') cmdCeremony(args);
  else if (cmd === 'restore') cmdRestore(args);
  else if (cmd === 'new') cmdNew(parse('new', args, ['net'], []).net);
  else if (cmd === 'derive') cmdDerive(args);
  else if (cmd === 'recover') cmdRecover(args);
  else if (cmd === undefined || cmd === '-h' || cmd === '--help' || cmd === 'help') console.log(USAGE);
  else die(`unknown command ${JSON.stringify(cmd)}\n\n${USAGE}`);
} catch (e) {
  // Name the failing check, never dump a stack: a stack on this box may carry key material.
  die(e instanceof SigeloError ? e.message : `offline: ${e instanceof Error ? e.message : String(e)}`);
}
