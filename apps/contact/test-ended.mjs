// SPDX-License-Identifier: MIT
// A session the relay ends itself (carrier.mjs ENDED; relay/auth.mjs endWith), on a loopback relay
// that keeps no identity (policy.keep: false, so every session is cut after unprovenSeconds):
// `inbox --wait` waits the caller's whole time across the relay's cuts, logs in again at a slowing
// pace (1 s, 2 s, 4 s … not at once), and says why (the relay's session_unproven notice); the pace
// is kept in the state, so a new process waits too; a session this client ends resets it.
// (0.1.17: a temporary identity cut after 60 s logged in 30 times a minute, and `inbox --wait 300`
// returned after ~20 s saying no message came within 300 s.)
//   node apps/contact/test-ended.mjs   → ALL PASS (n)
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { keygen } from 'sigelo';

const HERE = dirname(fileURLToPath(import.meta.url));
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); else console.log(`ok ${what}`); };
const report = () => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
};
const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs'))) { console.log('ALL PASS (0): SKIP, no relay checkout beside apps/contact/: set SIGELO_RELAY_DIR'); process.exit(0); }
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { Carrier, pathsFor } = await import('./carrier.mjs');
setTimeout(() => { console.log(`FAIL the run did not finish in 120 s (${count} checks so far)`); process.exit(1); }, 120000).unref();

const HOST = 'relay.test', CREATED = '2026-10-01T00:00:00Z';
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-ended-test/0 ${l}`).digest());
const k = keygen({ seed: seed('temp'), recovery: 'sha256:' + '0'.repeat(64), created: CREATED, nonce: seed('temp nonce').slice(0, 16) });
const bundle = { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] };
const dir = mkdtempSync(join(tmpdir(), 'sigelo-ended-'));
const logins = [];
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, diskUsed: () => 0.1,
  unprovenSeconds: 1, log: (l) => { if (/^login /.test(l)) logins.push(Date.now()); }, policy: { keep: () => false } });
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
const paths = pathsFor(join(dir, 'temp.local.json'));
const make = () => new Carrier({ identity: () => ({ secret: k.secret, bundle }), ...paths, relay: HOST, endpoints, keep: true });   // the default backoff: 1 s … 60 s
const ended = () => JSON.parse(readFileSync(paths.state, 'utf8')).relays[HOST]?.ended ?? null;
try {
  const c = make(), t0 = Date.now();
  const r = await c.inbox({ wait: 8 });
  const took = Date.now() - t0;
  ok(took >= 7500, `inbox --wait 8 waits its 8 s across the relay's cuts, not the session's 1 s (${took} ms)`);
  ok(r.offline === undefined && r.ended?.code === 'session_unproven' && r.ended.n >= 2 && /proven no work/.test(r.ended.detail), `and says why the relay ended it, how often (${JSON.stringify(r.ended)})`);
  // Cut every second: at once, that is 8 logins; at 1 s, 2 s, 4 s after each cut, 4 at most.
  ok(logins.length >= 2 && logins.length <= 4, `logged in again at a slowing pace, not at once: ${logins.length} logins in 8 s`);
  const gaps = logins.slice(1).map((t, i) => t - logins[i]);
  ok(gaps.every((g, i) => i === 0 || g > gaps[i - 1]), `each wait longer than the last (${gaps.join(', ')} ms)`);
  const e = ended();
  ok(e?.n >= 2 && e.code === 'session_unproven', `the pace is kept in the state (${JSON.stringify(e)})`);
  // A new process (a new carrier on the same files) waits out the pace before its login.
  const due = e.at + Math.min(60000, 1000 * 2 ** (e.n - 1)), t1 = Date.now(), before = logins.length;
  const c2 = make();
  await c2.inbox();
  ok(logins.length === before + 1 && logins.at(-1) >= due - 50, `a new process logs in only once the pace allows (${logins.at(-1) - due} ms after due, ${Date.now() - t1} ms waited)`);
  ok(ended() === null, 'a session this client ended itself resets the pace');
  report();
  console.log(`ALL PASS (${count})`);
} finally {
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}
