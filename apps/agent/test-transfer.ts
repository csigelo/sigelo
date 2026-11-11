// SPDX-License-Identifier: MIT
// Transfers through the CLI (TRANSFER.md, apps/contact/transfer-node.mjs), one loopback relay in this
// process, each agent its own process: usage refusals; the direct switch asked (direct_ask without a
// terminal); alice sends a file to bob (both own), bob sees it in inbox and transfer list, accepts,
// both processes move it direct and exit 0; the file saved whole, one inbox item; decline; forget.
// SIGELO_TEST_MB: the file's size (default 20). Prints the MB/s of two processes.
//   node test-transfer.ts   → ALL PASS test-transfer.ts (n ok)
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { cliIn, done, hasRelay, NO_RELAY, ok, ROOT, startTestRelay, tmpHome } from './test-helpers.ts';

if (!hasRelay()) {
  console.log(`SKIP transfers through the CLI: ${NO_RELAY}`);
  done(import.meta.filename);
}
if (!existsSync(join(ROOT, 'apps', 'transfer', 'node_modules', 'werift'))) {
  console.log('SKIP transfers through the CLI: sigelo-transfer has no node_modules (npm ci in apps/transfer/)');
  done(import.meta.filename);
}
const H = tmpHome('transfer'), relay = await startTestRelay(H), endpoints = JSON.stringify(relay.endpoints);
const envOf = (n: string): Record<string, string> => ({ PATH: process.env['PATH'] ?? '', SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_IDENTITY: join(H, `${n}.local.json`), SIGELO_RELAY: 'relay.test',
  SIGELO_SHORT_RELAY: 'relay.test', SIGELO_RELAY_REGISTRY: 'off', SIGELO_RELAY_ENDPOINTS: endpoints, SIGELO_STUN: '', SIGELO_TOR: 'off' });
const cli = (n: string, ...args: string[]) => cliIn(envOf(n), H)(...args);
type Rec = { id: string; state: string; name: string; size: number; saved?: string; path_used?: string; reason?: string };
const json = <T>(s: string): T | null => { try { return JSON.parse(s) as T; } catch { return null; } };

try {
  for (const n of ['alice', 'bob']) await cli(n, 'init', '--no-recovery');
  const code = (await cli('alice', 'invite', '--long', '--name', 'bob')).stdout.trim();
  await cli('bob', 'accept', code, '--name', 'alice', '--wait', '0');
  await cli('alice', 'inbox', '--wait', '2'); await cli('bob', 'inbox', '--wait', '2');

  const u = [await cli('alice', 'transfer', 'fly'), await cli('alice', 'transfer', 'send', 'bob'), await cli('alice', 'transfer', 'send', 'bob', 'x', '--via', 'turn'), await cli('alice', 'transfer', 'direct', 'bob', 'maybe')];
  ok('transfer: an unknown verb, a missing argument, --via turn, direct maybe: exit 2', u.every((r) => r.status === 2), u.map((r) => r.stderr).join('|'));
  const MB = Number(process.env['SIGELO_TEST_MB'] ?? 20), bytes = Buffer.alloc(MB * 1000 * 1000);
  for (let i = 0; i < bytes.length; i += 32) createHash('sha256').update(String(i)).digest().copy(bytes, i);
  const file = join(H, 'film.bin');
  writeFileSync(file, bytes);
  const ask = await cli('alice', 'transfer', 'send', 'bob', file, '--wait', '0');
  ok('send to a friend contact, the switch not set, no terminal: exit 1, direct_ask, says --direct', ask.status === 1 && ask.stderr.includes('direct_ask') && ask.stderr.includes('--direct on'), ask.stderr);
  for (const [a, b] of [['alice', 'bob'], ['bob', 'alice']] as const) await cli(a, 'tier', b, 'own');

  // A no first: decline.
  const small = join(H, 'small.txt');
  writeFileSync(small, 'hello');
  const s0 = await cli('alice', 'transfer', 'send', 'bob', small, '--wait', '0');
  const id0 = json<Rec>(s0.stdout)?.id ?? '';
  ok('send --wait 0: exit 0, the manifest sent, a line to say so', s0.status === 0 && /^[0-9a-f]{32}$/.test(id0) && s0.stderr.includes('offered to bob'), s0.stderr);
  const ib = await cli('bob', 'inbox', '--wait', '3');
  ok('bob\'s inbox: an event {type: transfer, what: asked} and the line with the verbs', (json<{ events: { type: string; what?: string; id?: string }[] }>(ib.stdout)?.events ?? []).some((e) => e.type === 'transfer' && e.what === 'asked' && e.id === id0)
    && ib.stderr.includes(`transfer accept ${id0}`), ib.stdout + ib.stderr);
  const dl = await cli('bob', 'transfer', 'decline', id0);
  ok('decline: exit 0', dl.status === 0, dl.stderr);

  // The file, both processes moving it.
  const t0 = Date.now();
  const sending = cli('alice', 'transfer', 'send', 'bob', file, '--wait', '600');
  let id = '';
  for (let i = 0; i < 60 && !id; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    const l = json<{ in: Rec[] }>((await cli('bob', 'transfer', 'list')).stdout);
    id = l?.in.find((r) => r.name === 'film.bin' && r.state === 'asked')?.id ?? '';
  }
  ok('bob\'s transfer list: film.bin asked', id !== '');
  const t1 = Date.now();
  const acc = await cli('bob', 'transfer', 'accept', id, '--wait', '600');
  const snd = await sending;
  const secs = (Date.now() - t1) / 1000;
  console.log(`direct over werift, two processes: ${MB} MB in ${secs.toFixed(1)} s (accept to done, set-up included) = ${(MB / secs).toFixed(2)} MB/s; hashing and offer ${((t1 - t0) / 1000).toFixed(1)} s`);
  const rb = json<Rec>(acc.stdout), ra = json<Rec>(snd.stdout);
  ok('accept: exit 0, done, direct', acc.status === 0 && rb?.state === 'done' && rb.path_used === 'direct', acc.stderr.slice(-800));
  ok('send: exit 0, done', snd.status === 0 && ra?.state === 'done', snd.stderr.slice(-800));
  ok('saved whole', !!rb?.saved && existsSync(rb.saved) && createHash('sha256').update(readFileSync(rb.saved)).digest('hex') === createHash('sha256').update(bytes).digest('hex'));
  const box = json<{ messages: { type?: string; transfer?: string; path?: string }[] }>((await cli('bob', 'inbox', '--wait', '1')).stdout);
  ok('one inbox item type file, with the transfer id', (box?.messages ?? []).filter((m) => m.type === 'file' && m.transfer === id).length === 1, JSON.stringify(box));
  const hist = (await cli('bob', 'history')).stdout;
  ok('no sigelo-transfer/0 in history', !hist.includes('sigelo-transfer/0'));
  const fg = await cli('bob', 'transfer', 'forget', id), l2 = json<{ in: Rec[] }>((await cli('bob', 'transfer', 'list')).stdout);
  ok('forget: gone from the list', fg.status === 0 && !(l2?.in ?? []).some((r) => r.id === id), fg.stderr);
  const st = await cli('bob', 'transfer', 'settings', '--tor', 'off');
  ok('settings --tor off: kept, said', st.status === 0 && json<{ tor: boolean }>(st.stdout)?.tor === false && st.stderr.includes('Tor off'), st.stderr);
} finally { await relay.close?.(); }
done(import.meta.filename);
