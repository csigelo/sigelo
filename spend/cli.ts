#!/usr/bin/env node
/**
 * sigelo-spend — command line (MONERO.md §4).
 *
 *   sigelo-spend serve <policy.json> [--dry-run] [--port 38090]
 *   sigelo-spend token new <policy.json> [<agent>]
 *   sigelo-spend pay <policy.json> <request.json> [--port 38090]
 *   sigelo-spend approve-request <policy.json> <ref>
 *   sigelo-spend init | doctor | licence show|install | receipts export   (init.ts)
 */
import { randomBytes } from 'node:crypto';
import { chmodSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { operator } from './init.js';
import { describe } from './licence.js';
import { parsePolicy, tokenHash } from './policy.js';
import { loadPolicy, parseDaemons, readLog, serve } from './service.js';

const USAGE = `sigelo-spend serve <policy.json> [--dry-run] [--port 38090]
sigelo-spend token new <policy.json> [<agent>]
sigelo-spend pay <policy.json> <request.json> [--port 38090]
sigelo-spend approve-request <policy.json> <ref>
sigelo-spend init [--dir D] [--net stagenet|mainnet] (--wallet-rpc URL [--wallet-rpc-login u:p] | --create-wallet-rpc --wallet-file F --password-file P [--wallet-rpc-port N])
                  [--daemons a,b,c] [--port 38090] [--agent NAME] [--account N] [--allow label=addr ...] [--per-tx XMR] [--per-day XMR] [--notify] [--no-systemd] [--licence FILE]
                  [--keeper-package keeper-<j>.json | --recovery-commitment sha256:… | --adopt RECOVERED.json [--key F]]
sigelo-spend doctor [--dir D] [--notify]
sigelo-spend licence show [--dir D] | sigelo-spend licence install <file> [--dir D]
sigelo-spend receipts export [--dir D] --since <YYYY-MM-DD|unix> [--format json|csv]

\`init\` sets up one keeper on this host over your own wallet-rpc and wallet: nothing is hosted
and no key leaves the host. Free: one keeper, one agent, its whole policy. A licence (a sigelo
attestation, checked offline) adds delegation, approvals, receipts export and more keepers.
The bearer token is read from SIGELO_SPEND_TOKEN. It is a secret: anything holding it can
spend its agent's account within that agent's bounds. \`serve\` reads SIGELO_DAEMONS, an
ordered list of daemon addresses (the wallet-rpc's own first) it moves the wallet-rpc along when
its daemon stops answering. \`token new\` needs <agent> for an
agents-style policy; a buckets-style one has a single token and takes none.`;

const die = (msg: string): never => { console.error(`sigelo-spend: ${msg}`); return process.exit(1); };
const flag = (argv: string[], name: string): boolean => argv.includes(name);
function option(argv: string[], name: string, fallback: number): number {
  const i = argv.indexOf(name);
  if (i < 0) return fallback;
  const n = Number(argv[i + 1]);
  if (!Number.isInteger(n) || n <= 0 || n > 65535) return die(`${name}: ${JSON.stringify(argv[i + 1])} is not a port`);
  return n;
}
const positional = (argv: string[]): string[] => {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--port') { i++; continue; }
    if (argv[i]!.startsWith('--')) continue;
    out.push(argv[i]!);
  }
  return out;
};

async function main(argv: string[]): Promise<void> {
  if (['init', 'doctor', 'licence', 'receipts'].includes(argv[0] ?? '')) { process.exitCode = await operator(argv); return; }
  const args = positional(argv);
  const cmd = args[0];

  if (cmd === 'serve') {
    const path = args[1] ?? die('serve: needs a policy file');
    // SIGELO_DAEMONS: the daemon fallback list (service.ts `parseDaemons`); the first entry is the
    // wallet-rpc's own --daemon-address. A malformed list stops the start.
    const daemons = parseDaemons(process.env['SIGELO_DAEMONS'] ?? '');
    const svc = await serve({ policyPath: resolve(path), dryRun: flag(argv, '--dry-run'), port: option(argv, '--port', 38090), daemons });
    console.log(`sigelo-spend: http://127.0.0.1:${svc.port} · net ${svc.policy.net} · wallet ${svc.policy.wallet.rpc}` +
      `${flag(argv, '--dry-run') ? ' · DRY RUN (priced with do_not_relay: nothing is broadcast, no receipt is signed, no budget is spent; rate-limited like a spend)' : ''}`);
    console.log(`sigelo-spend: receipts signed by ${svc.did}${svc.identity.current === svc.did ? '' : ` (current key ${svc.identity.current}, recovered)`}`);
    if (!svc.identity.recoverable) console.warn('sigelo-spend: this keeper has no identity.json: its genesis commits to a recovery key derived from spend.key, so after a host compromise ' +
      'its DID can only be abandoned, never recovered (INCIDENT.md §5). Key a new keeper with `sigelo-spend init` (its recovery key is held off the host) and move the wallet over.');
    // The tier, and what it means for this policy: a paid feature it uses refuses, never silently.
    const lic = svc.licence();
    console.log(`sigelo-spend: ${describe(lic)}`);
    const paid = Object.entries(svc.policy.agents).filter(([, a]) => a.approval_above !== null || a.max_delegates > 0).map(([n]) => n);
    if (lic.tier === 'free' && paid.length > 0) console.warn(`sigelo-spend: ${paid.join(', ')} use approval_above or max_delegates: without a licence a payment above approval_above, /delegate, /fund and /approve refuse (licence_required); everything else pays as the policy says`);
    if (daemons.length > 1) console.log(`sigelo-spend: daemon fallback ${daemons.join(' → ')}`);
    // Stopping removes spend.lock (service.ts, on process exit). A kill -9, a crash or a reboot
    // leaves it behind; the next start takes it over by itself when its pid is dead, reused
    // (another starttime) or from an earlier boot.
    for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) process.on(sig, () => process.exit(0));
    return;
  }

  if (cmd === 'token' && args[1] === 'new') {
    const path = resolve(args[2] ?? die('token new: needs a policy file'));
    const name = args[3];
    const policy = JSON.parse(readFileSync(path, 'utf-8')) as Record<string, unknown>;
    const token = randomBytes(32).toString('hex');
    let where: string;
    if (Object.hasOwn(policy, 'agents')) {
      const agents = policy['agents'] as Record<string, Record<string, unknown>>;
      if (name === undefined) die('token new: an agents-style policy needs the agent: token new <policy.json> <agent>');
      if (!Object.hasOwn(agents, name!)) die(`token new: ${path} has no agent ${JSON.stringify(name)} — add its entry first`);
      agents[name!]!['token_hash'] = tokenHash(token);
      where = `agents.${name}.token_hash`;
    } else {
      // Buckets-style (pre-G1): one token at the top, loaded as the one agent its bucket names.
      if (typeof policy['buckets'] !== 'object' || policy['buckets'] === null) die(`token new: ${path} has neither agents nor buckets — it is not a policy file`);
      if (name !== undefined && !Object.hasOwn(policy['buckets'] as object, name)) die(`token new: ${path} has no bucket ${JSON.stringify(name)}`);
      policy['token_hash'] = tokenHash(token);
      where = 'token_hash';
    }
    // Validated WITH the new hash, before anything is written: a file that would not load is
    // left as it was. (An entry the Owner just added has no valid hash until this runs.)
    parsePolicy(policy);
    writeFileSync(path, JSON.stringify(policy, null, 2) + '\n', { mode: 0o600 });
    chmodSync(path, 0o600);
    // stdout is the token and nothing else, so `export SIGELO_SPEND_TOKEN=$(…)` is safe.
    // A running keeper re-reads root tokens on its next request (service.ts `refreshTokens`), but
    // only for roots it already serves: an entry added since it started exists after a restart.
    const who = name ?? 'the agent';
    console.error(`sigelo-spend: ${path} ${where} is now ${tokenHash(token)}. A running keeper switches on its next request: ` +
      `from then on only this token works for ${who} and the old one is refused, no restart needed. If ${who} was added to the policy ` +
      'since the keeper started, or anything else in it changed, restart the keeper (systemctl --user restart <its unit>, or stop and start `sigelo-spend serve`): until then that entry and those edits do not exist for it.');
    console.log(token);
    return;
  }

  if (cmd === 'pay') {
    const policyPath = resolve(args[1] ?? die('pay: needs a policy file'));
    const requestPath = resolve(args[2] ?? die('pay: needs a request file'));
    loadPolicy(policyPath); // fail here on a bad policy rather than on a confusing 403
    const token = process.env['SIGELO_SPEND_TOKEN'] ?? die('pay: SIGELO_SPEND_TOKEN is not set');
    // Bytes, decoded fatally: a 'utf-8' string read would send U+FFFD in place of invalid bytes,
    // a request the file never held (SPEC §3). A malformed request file is our error, not the service's.
    const body = ((): string => {
      try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(readFileSync(requestPath)); } catch { return die(`pay: ${requestPath} is not valid UTF-8`); }
    })();
    JSON.parse(body);
    const url = `http://127.0.0.1:${option(argv, '--port', 38090)}/pay`;
    const res = await fetch(url, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body,
    }).catch((e: unknown) => die(`pay: POST ${url} failed (${e instanceof Error ? e.message : String(e)}) — is the service running on that port?`));
    console.log(JSON.stringify(await res.json(), null, 2));
    if (!res.ok) process.exitCode = 1;
    return;
  }

  if (cmd === 'approve-request') {
    // MONERO.md §4.1: the approver signs the body the keeper built, with its own sigelo identity,
    // on its own device — nothing here holds or asks for an approver's key. This prints the body
    // for a ref that is waiting; the approver posts { body, sig, bundle } to POST /approve.
    const policyPath = resolve(args[1] ?? die('approve-request: needs a policy file'));
    const ref = args[2] ?? die('approve-request: needs the ref the agent was told (WAITING FOR APPROVAL (ref …))');
    loadPolicy(policyPath);
    const now = Math.floor(Date.now() / 1000), log = readLog(policyPath);
    const done = new Set(log.flatMap((r) => [r.entry.approval?.body.nonce, r.entry.request.approval]).filter((n) => n !== undefined));
    const waiting = log.map((r) => r.entry.approval_request).filter((b) => b !== undefined && b.ref === ref && now < b.exp && !done.has(b.nonce));
    if (waiting.length === 0) die(`approve-request: no request is waiting for ref ${JSON.stringify(ref)} (unknown, expired, already approved or paid) — the agent's next pay asks again`);
    console.error(`sigelo-spend: ${waiting.length} request(s) for ref ${ref}. Check every field; sign one with your identity key over "sigelo\n" + JCS(body); ` +
      'POST {"body": <it>, "sig": <sig>, "bundle": <your bundle>} to the keeper\'s /approve. The approval pays that payment once and expires at exp.');
    for (const b of waiting) console.log(JSON.stringify(b));
    return;
  }

  die(`unknown command ${JSON.stringify(cmd ?? '')}\n\n${USAGE}`);
}

main(process.argv.slice(2)).catch((e: unknown) => die(e instanceof Error ? e.message : String(e)));
