#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// world/test.mjs — the world end to end on a random loopback port, the ts library as the agent,
// the Go reference verifier as the judge. Run from anywhere after `cd ts && npx tsc`:
//   node world/test.mjs            (needs `go` on PATH or a built go/sigelo-verify; sh for the nginx allowlist)
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize, challenge, did, keygen, rotate, sign, verify } from '../ts/dist/sigelo.js';

const HERE = dirname(fileURLToPath(import.meta.url)), ROOT = dirname(HERE), GO = join(ROOT, 'go');
const SERVER = join(HERE, 'server.mjs');
const dir = mkdtempSync(join(tmpdir(), 'sigelo-world-'));
let n = 0, failed = 0;
const ok = (cond, what) => { n++; if (cond) console.log(`ok ${what}`); else { failed++; console.log(`FAIL ${what}`); } };
const cli = (...a) => spawnSync(process.execPath, [SERVER, ...a], { encoding: 'utf8' });
const same = (a, b) => canonicalize(a) === canonicalize(b);
console.warn = () => {};   // keygen's recovery: null warning is for humans; the agents here have none on purpose

// ---- issuer identity: recovery key "off-site" (here: another file), commitment only to keygen ----
const rec = cli('recovery-key', join(dir, 'recovery.key'));
const commitment = rec.stdout.trim();
ok(rec.status === 0 && /^sha256:[0-9a-f]{64}$/.test(commitment), 'recovery-key prints a commitment');
const kg = cli('keygen', commitment, join(dir, 'issuer.json'));
const issuerGenesis = JSON.parse(kg.stdout);
ok(kg.status === 0 && issuerGenesis.recovery === commitment, 'keygen: the issuer genesis carries only the commitment');
ok(cli('keygen', commitment, join(dir, 'issuer.json')).status === 1, 'keygen refuses to overwrite a key');
const ISS = did(issuerGenesis);

let proc;
const start = () => new Promise((resolve, reject) => {
  proc = spawn(process.execPath, [SERVER], { env: { ...process.env, SIGELO_WORLD_KEY: join(dir, 'issuer.json'), SIGELO_WORLD_PORT: '0' } });
  proc.stderr.on('data', (d) => process.stderr.write(d));
  proc.stdout.on('data', (d) => { const m = String(d).match(/127\.0\.0\.1:(\d+)/); if (m) resolve(`http://127.0.0.1:${m[1]}`); });
  proc.on('exit', (c) => reject(new Error(`server exited ${c}`)));
});
const stop = () => new Promise((r) => { proc.removeAllListeners('exit'); proc.on('exit', r); proc.kill('SIGTERM'); });
let base = await start();
const get = async (p) => { const r = await fetch(base + p); return { status: r.status, json: await r.json() }; };
const post = async (p, body) => { const r = await fetch(base + p, { method: 'POST', body: typeof body === 'string' ? body : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };

// ---- the agent: an identity with a recovery key, answering the §5.2 challenge ----
const agentRec = keygen({ recovery: null });
const agent = keygen({ recovery: agentRec.key });
const bundleOf = (g, rotations = [], attestations = [], issuers = []) => ({ v: 'sigelo/0', typ: 'bundle', genesis: g, rotations, bindings: [], attestations, issuers });
const answer = async (id, extra) => {
  const c = (await get(`/world/challenge?did=${encodeURIComponent(id.did)}`)).json;
  const signed = challenge({ secret: id.secret, genesis: id.genesis, ctx: c.ctx, nonce: c.nonce });
  return { c, signed, res: await post('/world/attest', { challenge: c, did: signed.body.did, sig: signed.sig, ...extra }) };
};

const c0 = await get(`/world/challenge?did=${encodeURIComponent(agent.did)}`);
ok(c0.status === 200 && Object.keys(c0.json).join() === 'v,typ,did,ctx,nonce' && c0.json.ctx === 'sigelo.io' && c0.json.did === agent.did, 'challenge: the five §5.2 fields, ctx sigelo.io');
ok((await get('/world/challenge?did=did:sigelo:short')).status === 400, 'challenge: a malformed DID is 400');

const first = await answer(agent, { bundle: bundleOf(agent.genesis) });
const a = first.res.json.attestation;
ok(first.res.status === 200 && Object.keys(first.res.json).join() === 'attestation,issuer' && Object.keys(a).join() === 'body,sig', 'attest: 200, { attestation: { body, sig }, issuer } (envelope = body + sig only)');
ok(a.body.iss === ISS && a.body.sub === agent.did && a.body.ctx === 'sigelo.io' && a.body.admission === 'open' && a.body.exp - a.body.iat === 90 * 86400, 'attestation: iss = the world, sub = the agent, open, 90 days');
ok(same(a.body.claims, { seen: new Date(a.body.iat * 1000).toISOString().slice(0, 10), bundle_valid: true, verifier: `sigelo ${JSON.parse(readFileSync(join(ROOT, 'ts/package.json'))).version}` }), `claims: ${JSON.stringify(a.body.claims)}`);
ok(same(first.res.json.issuer, issuerGenesis), 'issuer: the genesis keygen printed');

// ---- the Go reference verifier counts it ----
const goVerify = (bundle, now) => {
  const p = join(dir, `b${n}.json`); writeFileSync(p, JSON.stringify(bundle));
  const built = join(GO, 'sigelo-verify');
  const r = existsSync(built) ? spawnSync(built, [p, '--now', String(now)], { encoding: 'utf8' })
    : spawnSync('go', ['run', './cmd/sigelo-verify', p, '--now', String(now)], { cwd: GO, encoding: 'utf8' });
  return r.status === 0 ? JSON.parse(r.stdout) : { reject: r.stderr || r.error?.message };
};
const issuedBundle = bundleOf(agent.genesis, [], [a], [first.res.json.issuer]);
const g = goVerify(issuedBundle, a.body.iat + 60);
ok(g.attestations?.[ISS]?.length === 1 && g.rejected?.attestations === 0 && g.did === agent.did, `go sigelo-verify: ACCEPT, 1 attestation from ${ISS.slice(0, 20)}…, 0 rejected${g.reject ? ` (${g.reject})` : ''}`);
ok(goVerify(issuedBundle, a.body.exp).rejected?.attestations === 1, 'go sigelo-verify: rejected at exp (90 days later)');

// ---- refusals ----
const replay = await post('/world/attest', { challenge: first.c, did: agent.did, sig: first.signed.sig, genesis: agent.genesis });
ok(replay.status === 409, `replayed nonce: ${replay.status} ${replay.json.error}`);
const intruder = keygen({ recovery: agentRec.key });
const c1 = (await get(`/world/challenge?did=${encodeURIComponent(agent.did)}`)).json;
const wrong = await post('/world/attest', { challenge: c1, did: agent.did, sig: sign(intruder.secret, c1), genesis: agent.genesis });
ok(wrong.status === 400 && /sig does not verify/.test(wrong.json.error), `wrong signer: ${wrong.status} ${wrong.json.error}`);
ok((await post('/world/attest', { challenge: c1, did: agent.did, sig: sign(agent.secret, c1), genesis: agent.genesis })).status === 409, 'a failed answer used the nonce up');
const c2 = (await get(`/world/challenge?did=${encodeURIComponent(agent.did)}`)).json;
const tampered = await post('/world/attest', { challenge: { ...c2, ctx: 'elsewhere' }, did: agent.did, sig: sign(agent.secret, { ...c2, ctx: 'elsewhere' }), genesis: agent.genesis });
ok(tampered.status === 400, `a modified challenge: ${tampered.status} ${tampered.json.error}`);
const c3 = (await get(`/world/challenge?did=${encodeURIComponent(agent.did)}`)).json;
const noKey = await post('/world/attest', { challenge: c3, did: agent.did, sig: sign(agent.secret, c3) });
ok(noKey.status === 400, `neither bundle nor genesis: ${noKey.status}`);
const big = await post('/world/attest', JSON.stringify({ pad: 'x'.repeat(300 * 1024) }));
ok(big.status === 413, `300 KB body: ${big.status}`);
ok((await post('/world/attest', '{"did":"a","did":"b"}')).status === 400, 'duplicate keys: 400 (strict parser)');
ok((await get('/world/attestations.jsonl')).status === 404, 'the issued log is not served');

// ---- idempotent within 24 h, across a restart; the nonce ring survives the restart too ----
const again = await answer(agent, { genesis: agent.genesis });
ok(again.res.status === 200 && same(again.res.json.attestation, a), 'second attest within 24 h: the identical attestation');
const c4 = (await get(`/world/challenge?did=${encodeURIComponent(agent.did)}`)).json;
await stop(); base = await start();
const after = await post('/world/attest', { challenge: c4, did: agent.did, sig: sign(agent.secret, c4), genesis: agent.genesis });
ok(after.status === 200 && same(after.json.attestation, a), 'after a restart: the outstanding challenge still answers, the attestation is still the same');

// ---- a rotated agent answers with its new key; the world reads the key from the bundle's chain ----
const next = keygen({ recovery: agentRec.key });
const rot = rotate({ genesis: agent.genesis, next_genesis: next.genesis, iat: a.body.iat, reason: 'voluntary', secret: agent.secret });
const rotated = await answer(next, { bundle: bundleOf(agent.genesis, [rot], [a], [issuerGenesis]) });
ok(rotated.res.status === 200 && rotated.res.json.attestation.body.sub === next.did && rotated.res.json.attestation.body.claims.bundle_valid === true, 'rotated agent: attested under its current DID, key taken from the verified chain');
const oldKey = await (async () => { const c = (await get(`/world/challenge?did=${encodeURIComponent(next.did)}`)).json;
  return post('/world/attest', { challenge: c, did: next.did, sig: sign(agent.secret, c), bundle: bundleOf(agent.genesis, [rot]) }); })();
ok(oldKey.status === 400, 'rotated agent signing with its retired key: 400');
const badBundle = await answer(agent, { bundle: { ...bundleOf(agent.genesis), rotations: 'no' } });
ok(badBundle.res.status === 422 && /REJECT/.test(badBundle.res.json.error), `a bundle that does not verify: ${badBundle.res.status} ${badBundle.res.json.error}`);

// ---- /world/verify is the §9.1 verifier ----
const vec = JSON.parse(readFileSync(join(ROOT, 'test-vectors.json'))).vectors.bundle;
const vr = await post('/world/verify', { bundle: vec.bundle, now: vec.now });
ok(vr.status === 200 && same(vr.json, vec.expect), '/world/verify: the `bundle` vector\'s §9.1 result, by value');
const bare = await post('/world/verify', issuedBundle);
ok(bare.status === 200 && same(bare.json, verify(issuedBundle, Math.floor(Date.now() / 1000))), '/world/verify: a bare bundle as the body');
const rj = await post('/world/verify', { bundle: { ...vec.bundle, genesis: { ...vec.bundle.genesis, nonce: 1 } } });
ok(rj.status === 422 && /^REJECT: /.test(rj.json.error), `/world/verify on a broken genesis: ${rj.status} ${rj.json.error}`);

const st = await get('/world/stats');
ok(st.status === 200 && st.json.attestations === 2 && st.json.subjects === 2 && Object.keys(st.json).join() === 'issuer,ctx,attestations,subjects', `stats: counts only ${JSON.stringify(st.json)}`);
ok((await get('/world/')).json.issuer === ISS && (await post('/world/stats', {})).status === 405, 'GET /world/ describes the world; a wrong method is 405');
await stop();

// ---- issuer rotation with the off-site recovery key ----
const rec2 = cli('recovery-key', join(dir, 'recovery2.key')).stdout.trim();
const newIssuer = JSON.parse(cli('keygen', rec2, join(dir, 'issuer2.json')).stdout);
writeFileSync(join(dir, 'g1.json'), JSON.stringify(issuerGenesis)); writeFileSync(join(dir, 'g2.json'), JSON.stringify(newIssuer));
const rr = cli('rotate', '-', join(dir, 'g1.json'), join(dir, 'g2.json'), join(dir, 'recovery.key'));
const chain = rr.status === 0 ? JSON.parse(rr.stdout) : null;
ok(chain && chain.rotations.length === 1 && chain.rotations[0].body.reason === 'recovery'
  && verify(bundleOf(chain.genesis, chain.rotations), Math.floor(Date.now() / 1000)).did === did(newIssuer), 'rotate: a recovery rotation whose chain resolves to the new issuer');
ok(goVerify(issuedBundle, a.body.iat + 60).attestations?.[ISS]?.length === 1, 'attestations issued before the rotation still verify offline under the old issuer genesis');

// ---- nginx: the /world/ location passes the deploy helper's allowlist; a foreign upstream does not ----
const apply = join(ROOT, 'site/deploy/sigelo-nginx-apply'), conf = join(ROOT, 'site/deploy/nginx.conf');
ok(spawnSync('sh', [apply, '--check', conf]).status === 0, 'site/deploy/nginx.conf passes the allowlist');
const text = readFileSync(conf, 'utf8');
ok(/location \^~ \/world\/ \{[^}]*limit_req zone=sigelo_world[^}]*client_max_body_size 256k;[^}]*proxy_pass http:\/\/127\.0\.0\.1:8790;/s.test(text) && /limit_req_zone \$sigelo_net zone=sigelo_world:\d+m rate=60r\/m;/.test(text), 'nginx.conf: /world/ is rate-limited per truncated address (60 r/m), 256 KB, proxied to 127.0.0.1:8790');
for (const [bad, line] of [['foreign upstream', 'proxy_pass http://10.0.0.1:80;'], ['another zone key', 'limit_req_zone $remote_addr zone=x:1m rate=60r/m;'], ['header passing the address', 'proxy_set_header X-Real-IP $remote_addr;']]) {
  const p = join(dir, 'bad.conf'); writeFileSync(p, `server {\n    location ^~ /world/ {\n        ${line}\n    }\n}\n`);
  ok(spawnSync('sh', [apply, '--check', p]).status !== 0, `allowlist refuses ${bad}`);
}

rmSync(dir, { recursive: true, force: true });
console.log(failed ? `FAILURES (${failed} of ${n})` : `ALL PASS (${n})`);
process.exit(failed ? 1 : 0);
