#!/usr/bin/env node
// Soak identities (stagenet, throwaway). Secrets stay in the soak data dir, never in the repo.
//
//   node gen-keys.mjs                 create keys/ if missing, print the identities they derive, then the licence step
//   node gen-keys.mjs check [<dir>]   exit 1 unless <dir>/policy.json (default <soak dir>/keeper) carries keys/' identities
//                                    and <dir>/licence.json makes the keeper pro under keys/vendor.json's test vendor
//   node gen-keys.mjs licence [<dir>] [--reissue | --rekey-vendor]
//                                    the soak as a "pro" customer of its own keeper, offline: create the soak-local
//                                    TEST VENDOR (keys/vendor.*) if missing, and issue <dir>/licence.json (default
//                                    <soak dir>/keeper) to the keeper's DID — tier pro, 4 seats, exp 400 days.
//                                    Keeps both if present (an existing licence must verify); --reissue signs a fresh
//                                    licence under the same vendor (renewal), --rekey-vendor replaces the vendor too
//                                    (then rerun setup.sh: the keeper unit names the vendor's DID). Refuses without
//                                    keys/S.hex, the keeper key's root.
//   node gen-keys.mjs policy <dir>    write <dir>/policy.json (from the template), <dir>/spend.key and <dir>/identity.json, if missing;
//                                    the identity placeholders become keys/' DIDs, genesis and recovery commitment,
//                                    the allowlist's become the wallet's subaddresses, asked from the wallet-rpc
//                                    (get_address; SIGELO_SOAK_WALLET_RPC, else the template's), so it must be up
//   node gen-keys.mjs compat <dir>    exit 1 if this code's verifier rejects the identities <dir>/policy.json and
//                                    keys/approver.json carry (a newer rule, e.g. SPEC §2 nonce form): rekey into
//                                    a NEW soak directory instead of redeploying over the live one
//
// keys/S.hex         throwaway root S: spend.key = keeperRoot(S, 0), soak-root = agentIdentitySeed(K, 0, 0),
//                    recovery_commitment = recoveryCommitment(S) — the ceremony's derivations. The keeper's own
//                    genesis (identity.json, sigelo-spend's keeperGenesis(K, recoveryCommitment(S))) commits to the
//                    same root recovery key, so `sigelo-offline recover --new-keeper` recovers the keeper DID from
//                    S.hex (INCIDENT.md §5). A soak keyed before that has a spend.key and no identity.json: its
//                    keeper keeps its legacy DID (recovery derived from spend.key, not recoverable) — never rewritten.
// keys/approver.hex  throwaway root A of the approver: identitySeed(A, 0)
// keys/approver.json {did, genesis, seed_hex} — what the approver signs with (agent.mjs)
// keys/vendor.hex    throwaway root V of this soak's TEST VENDOR: identitySeed(V, 0) signs the licence
// keys/vendor.json   {note, did, genesis} — setup.sh puts its did in the keeper unit as SIGELO_VENDOR_DID
//                    (a drop-in), the only reason the keeper accepts this licence. Not the real vendor: a real
//                    deployment gets its licence from the vendor (D1) and never sets SIGELO_VENDOR_DID.
//
// The template is read, never written: it holds no identity and no wallet address, only placeholders,
// filled in the policy.json written into the soak directory, so neither keying a new soak nor a redeploy
// changes the repository, and an export never names a live soak's DIDs or wallet. (Until the T14
// rehearsal a bare `node gen-keys.mjs` rewrote the tracked template with the new soak's DIDs.)
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const TS = join(HERE, '..', '..', 'ts', 'dist');
const { attest, keygen, structure } = await import(pathToFileURL(join(TS, 'sigelo.js')).href);
const { keeperRoot, agentIdentitySeed, identitySeed, recoveryCommitment, parseRoot } = await import(pathToFileURL(join(TS, 'keys.js')).href);

const DATA = process.env.SIGELO_SOAK_DIR ?? join(homedir(), '.local/share/sigelo-soak');
const KEYS = join(DATA, 'keys'), TEMPLATE = join(HERE, 'policy.template.json');
const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (s) => Uint8Array.from(Buffer.from(s.trim(), 'hex'));
// A root is a canonical ed25519 scalar (0 < S < l), as the ceremony makes it, so that
// `sigelo-offline recover - < keys/S.hex` accepts it (parseRoot). Soaks keyed before the T14 rehearsal
// hold 32 random bytes, which recover refuses; they keep them (a root is never rewritten).
const canonicalRoot = () => { for (;;) { const r = randomBytes(32); r[31] &= 0x1f; try { parseRoot(hex(r)); return r; } catch { /* >= l: draw again */ } } };
const secret = (name) => {
  const p = join(KEYS, name);
  if (!existsSync(p)) writeFileSync(p, hex(canonicalRoot()) + '\n', { mode: 0o600 });
  chmodSync(p, 0o600);
  const b = unhex(readFileSync(p, 'utf-8'));
  try { parseRoot(hex(b)); } catch { console.error(`gen-keys: note: ${p} is not a canonical root; sigelo-offline recover refuses it, so this soak's recovery rotations stay on paper (README steps 5–6)`); }
  return b;
};
const CREATED = '2026-09-23T00:00:00Z';

function identities() {
  mkdirSync(KEYS, { recursive: true, mode: 0o700 });
  chmodSync(KEYS, 0o700);
  const S = secret('S.hex'), A = secret('approver.hex');
  const K = keeperRoot(S, 0), RC = recoveryCommitment(S);
  // nonces as BYTES: keygen encodes them as SPEC §2 multibase; a string is stored verbatim, and the
  // soaks keyed before the nonce-form rule (hex strings here) carry a genesis every verifier now rejects
  const root = keygen({ seed: agentIdentitySeed(K, 0, 0), recovery: RC, created: CREATED, nonce: new Uint8Array(16) });
  const approver = keygen({ seed: identitySeed(A, 0), recovery: recoveryCommitment(A), created: CREATED, nonce: new Uint8Array(16).fill(0x11) });
  const aj = join(KEYS, 'approver.json');
  const record = JSON.stringify({ did: approver.did, genesis: approver.genesis, seed_hex: hex(identitySeed(A, 0)) }, null, 2) + '\n';
  if (!existsSync(aj)) writeFileSync(aj, record, { mode: 0o600 });
  else if (JSON.parse(readFileSync(aj, 'utf-8')).did !== approver.did) {
    console.error(`gen-keys: ${aj} holds a different approver identity than these keys derive now — refusing to overwrite a live soak's approver; rekey into a new SIGELO_SOAK_DIR`);
    process.exit(1);
  }
  chmodSync(aj, 0o600);
  return { K, RC, root, approver };
}

const SUBADDR_RE = /^<subaddress 0\/(\d+) of the soak wallet: gen-keys\.mjs policy fills it>$/;

async function subaddress(rpc, i) {
  const r = await fetch(rpc, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: '0', method: 'get_address', params: { account_index: 0, address_index: [i] } }) });
  const j = await r.json();
  if (j.error || !j.result?.addresses?.[0]) throw new Error(`get_address (0,${i}): ${JSON.stringify(j.error ?? j)} — create it with create_address {account_index: 0} first`);
  return j.result.addresses[0].address;
}

// The identity fields keys/ decides; the template carries a placeholder in each.
const identityOf = (id) => ({ approver: id.approver.did, recovery_commitment: id.RC, root_did: id.root.did, root_genesis: id.root.genesis });
const identityIn = (p) => ({ approver: p.approvers?.[0]?.did, recovery_commitment: p.recovery_commitment,
  root_did: p.agents?.['soak-root']?.did, root_genesis: p.agents?.['soak-root']?.genesis });
const mismatches = (have, want) => Object.keys(want).filter((k) => JSON.stringify(have[k]) !== JSON.stringify(want[k]));

// ---- the licence (spend/licence.ts): the soak is a pro customer of its own keeper, under a TEST vendor.
// The policy uses delegates and approvals, which a keeper without a valid licence refuses 403 licence_required.
const SEATS = 4; // a licence counts every keeper registered on the host (sigelo-spend init) plus this one
const LICENCE_DAYS = 400;
const VENDOR_NOTE = 'TEST VENDOR of this stagenet soak only (gen-keys.mjs licence). Not the sigelo vendor: a real keeper gets its licence from the vendor at D1.';
// spend/dist is beside this file in the repo and in the soak's app copy; imported only by the licence steps.
const spend = async () => ({ ...(await import(pathToFileURL(join(HERE, '..', 'dist', 'service.js')).href)),
  ...(await import(pathToFileURL(join(HERE, '..', 'dist', 'licence.js')).href)) });

function vendor(rekey) {
  const vh = join(KEYS, 'vendor.hex'), vj = join(KEYS, 'vendor.json');
  if (rekey) for (const p of [vh, vj]) if (existsSync(p)) renameSync(p, `${p}.replaced-${Date.now()}`);
  const V = secret('vendor.hex');
  const v = keygen({ seed: identitySeed(V, 0), recovery: recoveryCommitment(V), created: CREATED, nonce: new Uint8Array(16).fill(0x76) });
  if (!existsSync(vj)) writeFileSync(vj, JSON.stringify({ note: VENDOR_NOTE, did: v.did, genesis: v.genesis }, null, 2) + '\n', { mode: 0o600 });
  else if (JSON.parse(readFileSync(vj, 'utf-8')).did !== v.did) {
    console.error(`gen-keys: ${vj} holds a different vendor than keys/vendor.hex derives — refusing to overwrite; --rekey-vendor replaces both (then rerun setup.sh)`);
    process.exit(1);
  }
  chmodSync(vj, 0o600);
  return v;
}

/** The licence in <kdir>, checked against the keeper DID keys/ derives and keys/vendor.json's DID. */
// The keeper identity of <kdir>: identity.json if there; the legacy genesis where a spend.key predates it;
// else the one `policy` will write (keeperGenesis is deterministic: its nonce and created are pinned).
async function keeperOf(kdir, id) {
  const m = await spend();
  if (existsSync(join(kdir, 'identity.json')) || existsSync(join(kdir, 'spend.key'))) return m.loadKeeper(kdir, id.K);
  const g = m.keeperGenesis(id.K, id.RC);
  return { did: g.did, genesis: g.genesis, recoverable: true, fresh: true };
}

async function licenceStatus(kdir, id, vdid) {
  const m = await spend();
  process.env.SIGELO_VENDOR_DID = vdid; // what setup.sh's drop-in tells the keeper
  const keeper = await keeperOf(kdir, id);
  let keepers; try { keepers = m.liveKeepers(); } catch { keepers = []; }
  const p = join(kdir, m.LICENCE_FILE);
  if (!existsSync(p)) return { keeper, s: { tier: 'free', why: `no ${p}` }, m };
  let raw; try { raw = JSON.parse(readFileSync(p, 'utf-8')); } catch (e) { return { keeper, s: { tier: 'free', why: `${p} is not JSON (${e.message})` }, m }; }
  return { keeper, s: m.checkLicence(raw, keeper.genesis, kdir, Math.floor(Date.now() / 1000), keepers), m };
}

async function licence(kdir, id, { rekey, reissue }) {
  const key = join(kdir, 'spend.key');
  if (existsSync(key) && readFileSync(key, 'utf-8').trim() !== hex(id.K)) { console.error(`gen-keys: ${key} is not keeperRoot(S, 0) — refusing to license a keeper keys/ does not derive`); process.exit(1); }
  mkdirSync(kdir, { recursive: true, mode: 0o700 });
  const v = vendor(rekey);
  const p = join(kdir, 'licence.json');
  const had = existsSync(p);
  if (had && !rekey && !reissue) {
    const { s, m } = await licenceStatus(kdir, id, v.did);
    if (s.tier !== 'pro') { console.error(`gen-keys: kept ${p}, but it does not make the keeper pro: ${s.why} — gen-keys.mjs licence --reissue signs a fresh one under the same test vendor`); process.exit(1); }
    console.log(`kept ${p}: ${m.describe(s)}; test vendor ${v.did}`);
    return;
  }
  const { keeper } = await licenceStatus(kdir, id, v.did);
  const iat = Math.floor(Date.now() / 1000);
  const lic = { attestation: attest({ secret: identitySeed(unhex(readFileSync(join(KEYS, 'vendor.hex'), 'utf-8')), 0), iss: v.did, sub: keeper.did,
    iat, exp: iat + LICENCE_DAYS * 86400, ctx: 'sigelo-spend', admission: 'payment', claims: { tier: 'pro', seats: SEATS } }), issuer: v.genesis };
  writeFileSync(`${p}.new`, JSON.stringify(lic, null, 2) + '\n', { mode: 0o600 });
  renameSync(`${p}.new`, p);
  const { s, m } = await licenceStatus(kdir, id, v.did);
  if (s.tier !== 'pro') { console.error(`gen-keys: the licence just written to ${p} does not verify: ${s.why}`); process.exit(1); }
  console.log(`${had ? 'reissued' : 'wrote'} ${p}: ${m.describe(s)}; test vendor ${v.did} (setup.sh sets SIGELO_VENDOR_DID to it)`);
}

const args = process.argv.slice(2);
const flags = args.filter((a) => a.startsWith('--'));
const [mode, dir] = args.filter((a) => !a.startsWith('--'));
const unknown = flags.filter((f) => !['--rekey-vendor', '--reissue'].includes(f));
if (unknown.length || (flags.length && mode !== 'licence')) { console.error(`gen-keys: ${unknown.length ? `unknown flag(s) ${unknown.join(' ')}` : 'flags go with licence only'}`); process.exit(1); }
if (mode === 'licence' && !existsSync(join(KEYS, 'S.hex'))) { console.error(`gen-keys: no ${join(KEYS, 'S.hex')} — the keeper key's root is absent; key the soak first: node gen-keys.mjs`); process.exit(1); }
if (mode === 'compat') {
  // Before identities(): must not touch keys/. Checks the documents a live soak already runs on.
  if (!dir) { console.error('gen-keys: compat needs <dir>'); process.exit(1); }
  const docs = [];
  const pol = join(dir, 'policy.json'), aj = join(KEYS, 'approver.json');
  if (existsSync(pol)) for (const [name, a] of Object.entries(JSON.parse(readFileSync(pol, 'utf-8')).agents ?? {})) docs.push([`${pol} agents.${name}.genesis`, a.genesis]);
  if (existsSync(aj)) docs.push([`${aj} genesis`, JSON.parse(readFileSync(aj, 'utf-8')).genesis]);
  const bad = [];
  for (const [what, g] of docs) { try { structure(g, 'genesis'); } catch (e) { bad.push(`${what}: ${e.message}`); } }
  if (bad.length) {
    console.error(`gen-keys: this code's verifier rejects identities the soak in ${dir} already runs on:\n  ${bad.join('\n  ')}\n  a live keeper restarted on this code would refuse its own policy. Do not redeploy over it: rekey into a NEW soak directory (SIGELO_SOAK_DIR=<new> node gen-keys.mjs && sh setup.sh), or keep the deployed revision.`);
    process.exit(1);
  }
  console.log(`compat: ${docs.length} identity document(s) in ${dir} pass this code's verifier`);
  process.exit(0);
}
const id = identities();
if (mode === undefined) {
  console.log(`keys in ${KEYS}: soak-root ${id.root.did}, approver ${id.approver.did}; policy.json comes from: node gen-keys.mjs policy <dir> (setup.sh runs it)`);
  await licence(join(DATA, 'keeper'), id, {});
} else if (mode === 'licence') {
  await licence(dir ?? join(DATA, 'keeper'), id, { rekey: flags.includes('--rekey-vendor'), reissue: flags.includes('--reissue') });
} else if (mode === 'check') {
  const pol = join(dir ?? join(DATA, 'keeper'), 'policy.json');
  if (!existsSync(pol)) { console.error(`gen-keys: no ${pol}`); process.exit(1); }
  const bad = mismatches(identityIn(JSON.parse(readFileSync(pol, 'utf-8'))), identityOf(id));
  if (bad.length) { console.error(`gen-keys: ${pol} does not carry the identities ${KEYS} derives (${bad.join(', ')})`); process.exit(1); }
  console.log(`keys match ${pol}: soak-root ${id.root.did}`);
  const vj = join(KEYS, 'vendor.json');
  if (!existsSync(vj)) { console.error(`gen-keys: no ${vj} (the soak's test vendor) — run: node gen-keys.mjs licence`); process.exit(1); }
  const vdid = JSON.parse(readFileSync(vj, 'utf-8')).did;
  const { keeper, s, m } = await licenceStatus(dirname(pol), id, vdid);
  if (s.tier !== 'pro') { console.error(`gen-keys: ${m.describe(s)} — keeper ${keeper.did}, test vendor ${vdid}; the soak's delegates and approvals would refuse licence_required (gen-keys.mjs licence [--reissue])`); process.exit(1); }
  console.log(`licence ok: ${m.describe(s)}; keeper ${keeper.did}, test vendor ${vdid}`);
  console.log(keeper.recoverable ? 'keeper identity: recoverable from keys/S.hex (identity.json, root recovery commitment)' : 'keeper identity: legacy (no identity.json) — not recoverable after a compromise; the next rekey is');
} else if (mode === 'policy') {
  if (!dir) { console.error('gen-keys: policy needs <dir>'); process.exit(1); }
  const key = join(dir, 'spend.key'), pol = join(dir, 'policy.json'), idf = join(dir, 'identity.json');
  const m = await spend();
  if (!existsSync(key)) {
    // A new keeper: its genesis commits to the root's recovery key, never to one derived from spend.key.
    writeFileSync(idf, JSON.stringify(m.keeperBundle(m.keeperGenesis(id.K, id.RC).genesis), null, 2) + '\n', { mode: 0o600 });
    writeFileSync(key, hex(id.K) + '\n', { mode: 0o600 });
  } else if (readFileSync(key, 'utf-8').trim() !== hex(id.K)) { console.error(`gen-keys: ${key} is not keeperRoot(S, 0) — refusing to mix keys`); process.exit(1); }
  const keeper = m.loadKeeper(dir, id.K);
  if (keeper.recoverable && keeper.genesis.recovery !== id.RC) { console.error(`gen-keys: ${idf} commits to ${keeper.genesis.recovery}, not keys/' recoveryCommitment(S) — refusing to mix keys`); process.exit(1); }
  console.log(keeper.recoverable ? `keeper ${keeper.did}: identity.json commits to recoveryCommitment(S), so sigelo-offline recover --new-keeper recovers it from keys/S.hex`
    : `keeper ${keeper.did}: no identity.json (keyed before it) — legacy genesis, recovery derived from spend.key: NOT recoverable; the next rekey into a new soak directory is`);
  if (existsSync(pol)) {
    const bad = mismatches(identityIn(JSON.parse(readFileSync(pol, 'utf-8'))), identityOf(id));
    if (bad.length) { console.error(`gen-keys: ${pol} does not carry the identities ${KEYS} derives (${bad.join(', ')}) — refusing to mix keys`); process.exit(1); }
    console.log(`kept ${pol} (identities match keys/)`);
  } else {
    // A fresh parse of the template: this object is written to <dir>, the template file is never opened for writing.
    const t = JSON.parse(readFileSync(TEMPLATE, 'utf-8')), a = t.agents['soak-root'];
    t.approvers[0].did = id.approver.did; t.recovery_commitment = id.RC; a.did = id.root.did; a.genesis = id.root.genesis;
    if (process.env.SIGELO_SOAK_WALLET_RPC) t.wallet.rpc = process.env.SIGELO_SOAK_WALLET_RPC;
    for (const agent of Object.values(t.agents)) for (const e of agent.allow ?? []) {
      const m = SUBADDR_RE.exec(e.addr);
      if (m) e.addr = await subaddress(t.wallet.rpc, Number(m[1]));
    }
    const left = JSON.stringify(t).match(/"<[^"]*>"/g);
    if (left) { console.error(`gen-keys: ${TEMPLATE}: unfilled placeholder(s) ${left.join(', ')}`); process.exit(1); }
    writeFileSync(pol, JSON.stringify(t, null, 2) + '\n', { mode: 0o600 });
    console.log(`wrote ${pol} (soak-root ${id.root.did}; allowlist: ${Object.values(t.agents).flatMap((x) => (x.allow ?? []).map((e) => e.label)).join(', ')} from ${t.wallet.rpc})`);
  }
} else { console.error('usage: gen-keys.mjs [check [<dir>] | policy <dir> | licence [<dir>] [--reissue | --rekey-vendor] | compat <dir>]'); process.exit(1); }
