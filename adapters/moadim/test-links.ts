// SPDX-License-Identifier: MIT
// Links end to end (LINKS.md, contact/link.mjs): the operator introduces its own agents. HOMEs as
// machines, one loopback relay in this process: the operator makes its keeper root, enrols three
// workers on three machines, and links them with `sigelo-agent link --operator`: own ↔ own with
// tiers and a purpose while both agents run `watch`; two agents already paired (the purpose
// attached); one lazily, each side's next inbox doing its part. Then the refusals by name
// (link_tier, link_from, busy), unlink (both sides forget), expiry (both sides, at their next inbox;
// the earlier pairing kept). External: a hotel (an identity of its own, the operator's contact) is
// introduced to vps-a with a note: pending at the hotel, a `watch --on-notice` event, accepted beside
// that watcher at quiet; refused silently; an allow rule accepts by itself; deny stops it. And no link
// message in any inbox output, history or inbox.log.
//   node test-links.ts   → ALL PASS test-links.ts (n ok)
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { newRoot } from 'sigelo/dist/keys.js';
import { lockPath } from './sigelo-agent-contact.ts';
import { CLI, done, hasRelay, NO_RELAY, ok, startTestRelay } from './test-helpers.ts';

if (!hasRelay()) {
  console.log(`SKIP links end to end: ${NO_RELAY}`);
  done(import.meta.filename);
}

const D = mkdtempSync(join(tmpdir(), 'sigelo-moadim-links-'));
const relay = await startTestRelay(D);
const endpoints = JSON.stringify(relay.endpoints);
const env = (home: string): Record<string, string> => ({ PATH: process.env['PATH'] ?? '', SIGELO_KEY_PROVIDER: 'file', HOME: home, SIGELO_RELAY: 'relay.test', SIGELO_RELAY_ENDPOINTS: endpoints });
type Run = { status: number | null; stdout: string; stderr: string };
const cli = (home: string, args: string[], o: { onLine?: (l: string) => void; input?: string } = {}) => new Promise<Run>((resolve) => {
  const c = spawn('node', [CLI, ...args], { env: env(home), cwd: home });
  let stdout = '', stderr = '', onLine = o.onLine;
  c.stdout.on('data', (d) => { stdout += d; if (onLine && stdout.includes('\n')) { onLine(stdout.split('\n')[0]!); onLine = undefined; } });
  c.stderr.on('data', (d) => { stderr += d; });
  c.on('close', (status) => resolve({ status, stdout, stderr }));
  c.stdin.end(o.input ?? '');
});
const verbose = (what: string, r: Run): void => { if (process.env['SIGELO_TEST_VERBOSE'] === '1') console.log(`  ${what} exit ${r.status}\n${r.stdout}${r.stderr}`.replace(/^/gm, '  | ')); };
const json = <T>(r: Run): T => { try { return JSON.parse(r.stdout) as T; } catch { return {} as T; } };

const OP = mkdtempSync(join(tmpdir(), 'sigelo-links-op-')), HA = mkdtempSync(join(tmpdir(), 'sigelo-links-a-'));
const HB = mkdtempSync(join(tmpdir(), 'sigelo-links-b-')), HC = mkdtempSync(join(tmpdir(), 'sigelo-links-c-')), HX = mkdtempSync(join(tmpdir(), 'sigelo-links-x-'));
const human = join(OP, '.config', 'sigelo', 'me.local.json'), agentFile = (h: string): string => join(h, '.config', 'moadim', 'sigelo.local.json');
type Rec = { name: string; did: string; revoked: boolean; tier: string; tier_by?: string; link?: { id: string; purpose: string; linked_by: string; expires: number | null; prior?: unknown } };
const storeOf = (f: string): string => f.replace(/\.json$/, '.contacts.json');
const contactsOf = (f: string): Record<string, Rec> => (JSON.parse(readFileSync(storeOf(f), 'utf8')) as { contacts: Record<string, Rec> }).contacts;
const byName = (f: string, name: string): Rec | undefined => Object.values(contactsOf(f)).find((c) => c.name === name && !c.revoked) ?? Object.values(contactsOf(f)).find((c) => c.name === name);
// A link record's expiry moved into the past, as a clock a day on would see it.
const expire = (f: string, did: string): void => { const s = JSON.parse(readFileSync(storeOf(f), 'utf8')); s.contacts[did].link.expires = Math.floor(Date.now() / 1000) - 10; writeFileSync(storeOf(f), JSON.stringify(s)); };
async function enrolOn(home: string, name: string): Promise<boolean> {
  let code = '';
  const got = new Promise<void>((r) => { const t = setInterval(() => { if (code) { clearInterval(t); r(); } }, 50); });
  const op = cli(OP, ['enrol', '--name', name, '--wait', '90'], { onLine: (l) => { code = l.trim(); } });
  await Promise.race([got, op]);
  const m = await cli(home, ['init', '--enrol', code, '--wait', '90', '--name', 'owner']);
  const o = await op;
  verbose(`enrol ${name}`, o); verbose(`init --enrol ${name}`, m);
  return o.status === 0 && m.status === 0;
}
// `watch` on a machine, until stopped; resolves once it says it is watching.
const watchers: ChildProcess[] = [];
const watch = (home: string, extra: string[] = []): Promise<{ c: ChildProcess; out: () => string }> => new Promise((resolve) => {
  const c = spawn('node', [CLI, 'watch', ...extra], { env: env(home), cwd: home });
  let all = '';
  const out = (): string => all;
  c.stdout.on('data', (d) => { all += d; });
  c.stderr.on('data', (d) => { all += d; if (all.includes('watching ')) resolve({ c, out }); });
  watchers.push(c);
});
const stop = (w: { c: ChildProcess }): Promise<void> => new Promise((r) => { w.c.on('close', () => r()); w.c.kill('SIGTERM'); });
const fa = agentFile(HA), fb = agentFile(HB), fc = agentFile(HC), fx = agentFile(HX);
const until = async (f: () => boolean, ms = 60_000): Promise<boolean> => { const end = Date.now() + ms; while (!f() && Date.now() < end) await new Promise((r) => setTimeout(r, 250)); return f(); };
// The label and a long code (sgl1…); not the temp directories' names, which say links.
const noLink = (s: string): boolean => !s.includes('sigelo-link/') && !/sgl1[1-9A-HJ-NP-Za-km-z]{16}/.test(s);

try {
  const kp = await cli(OP, ['keeper', '--from-words'], { input: newRoot() });
  ok('the operator: keeper --from-words', kp.status === 0, kp.stderr);
  const enrolled = [await enrolOn(HA, 'vps-a'), await enrolOn(HB, 'vps-b'), await enrolOn(HC, 'vps-c')];
  ok('three workers enrolled on three machines', enrolled.every(Boolean), JSON.stringify(enrolled));
  const opDid = Object.keys(contactsOf(fa))[0]!;   // the worker's contacts start with its operator
  const [dA, dB, dC] = ['vps-a', 'vps-b', 'vps-c'].map((n) => byName(human, n)!.did);

  // vps-a and vps-c pair by themselves first (a code, inbox on the inviter's side).
  const inv = await cli(HA, ['invite', '--long', '--name', 'vps-c']);
  const ia = cli(HA, ['inbox', '--wait', '30']);
  const ac = await cli(HC, ['accept', inv.stdout.trim(), '--name', 'vps-a', '--wait', '30']);
  await ia;
  await cli(HA, ['inbox', '--wait', '3']); await cli(HC, ['inbox', '--wait', '3']);
  ok('vps-a and vps-c paired directly, before any link', ac.status === 0 && byName(fa, 'vps-c')?.revoked === false && byName(fc, 'vps-a')?.revoked === false, ac.stderr);
  const tierAC = byName(fa, 'vps-c')!.tier;

  // Refusals before anything is sent.
  const own = await cli(OP, ['link', 'vps-a', 'vps-b', '--purpose', 'x', '--tier-a', 'own', '--operator']);
  ok('link --tier-a own: refused, exit 1, link_tier', own.status === 1 && own.stderr.includes('link_tier'), own.stderr);
  const noPurpose = await cli(OP, ['link', 'vps-a', 'vps-b', '--operator']);
  ok('link without --purpose: usage, exit 2', noPurpose.status === 2, noPurpose.stderr);
  writeFileSync(lockPath(human), `${process.pid} watch`);
  const busy = await cli(OP, ['link', 'vps-a', 'vps-b', '--purpose', 'x', '--operator']);
  rmSync(lockPath(human));
  ok('link beside a watcher on the operator\'s file: refused, exit 1, busy', busy.status === 1 && busy.stderr.includes('is watched by sigelo-agent watch'), busy.stderr);

  // ---- own ↔ own, both agents watching: linked within the operator's wait.
  const [wa, wb, wc] = [await watch(HA), await watch(HB), await watch(HC)];
  const l1 = await cli(OP, ['link', 'vps-a', 'vps-b', '--purpose', 'review the pull requests', '--tier-a', 'friend', '--tier-b', 'quiet', '--days', '30', '--wait', '120', '--operator']);
  verbose('link vps-a vps-b', l1);
  const r1 = json<{ id: string; status: string; expires: number }>(l1);
  ok(`link vps-a vps-b: exit 0, linked (${r1.id})`, l1.status === 0 && r1.status === 'linked' && l1.stderr.includes(`link ${r1.id}: linked vps-a ↔ vps-b`), l1.stdout + l1.stderr);
  const ab = byName(fa, 'vps-b'), ba = byName(fb, 'vps-a');
  ok('vps-a files vps-b: link {id, purpose, linked_by: the operator, expires in 30 days}, tier friend', ab?.link?.id === r1.id && ab.link.purpose === 'review the pull requests'
    && ab.link.linked_by === opDid && ab.link.expires === r1.expires && r1.expires - Math.floor(Date.now() / 1000) > 29 * 86400 && ab.tier === 'friend' && ab.did === dB, JSON.stringify(ab));
  ok('vps-b files vps-a: the same link, tier quiet', ba?.link?.id === r1.id && ba.link.linked_by === opDid && ba.tier === 'quiet' && ba.did === dA, JSON.stringify(ba));
  // ---- already paired: vps-a and vps-c, the purpose attached.
  const l2 = await cli(OP, ['link', 'vps-a', 'vps-c', '--purpose', 'share the build cache', '--days', '1', '--wait', '120', '--operator']);
  const r2 = json<{ id: string; status: string }>(l2);
  const acl = byName(fa, 'vps-c'), cal = byName(fc, 'vps-a');
  ok('link vps-a vps-c (paired already): linked, the purpose attached on both sides, no new pairing', l2.status === 0 && r2.status === 'linked' && acl?.link?.id === r2.id && cal?.link?.id === r2.id
    && Boolean(acl.link.prior) && Object.values(contactsOf(fa)).filter((c) => c.name === 'vps-c').length === 1, l2.stdout + l2.stderr);
  ok('the watchers said it, one line each', wa.out().includes(`link ${r1.id}: linked with vps-b`) && wb.out().includes(`link ${r1.id}: linked with vps-a`) && wc.out().includes(`link ${r2.id}: linked with vps-a`), wa.out());
  await stop(wb);

  // ---- link_from: vps-b (own, not vps-a's operator) asks vps-a, which is watching.
  const lf = await cli(HB, ['link', 'vps-a', 'owner', '--purpose', 'sneak', '--wait', '60']);
  ok('an own agent that is not the operator asks: refused link_from, exit 1', lf.status === 1 && json<{ status: string; check: string }>(lf).check === 'link_from' && lf.stderr.includes('link_from'), lf.stdout + lf.stderr);
  for (const w of [wa, wc]) await stop(w);

  // contacts and links show the purpose.
  const ca = await cli(HA, ['contacts']), la = await cli(HA, ['links']), lo = await cli(OP, ['links', '--operator']);
  const cj = json<{ contacts: { did: string; link: { purpose: string } | null }[] }>(ca);
  ok('contacts: link on the contact (JSON) and the purpose in its line', cj.contacts?.find((c) => c.did === dB)?.link?.purpose === 'review the pull requests' && ca.stderr.includes('linked (') && ca.stderr.includes('review the pull requests'), ca.stderr);
  const lj = json<{ links: { id: string; contact: string; tier: string; purpose: string; linked_by: string; expires: number }[] }>(la);
  ok('links on the agent: {id, contact, tier, purpose, linked_by, expires}', la.status === 0 && lj.links?.length === 2 && lj.links.some((x) => x.id === r1.id && x.contact === dB && x.tier === 'friend' && x.linked_by === opDid), la.stdout);
  const oj = json<{ made: { id: string; status: string }[] }>(lo);
  ok('links on the operator: the links it made, linked', oj.made?.filter((x) => x.status === 'linked').length === 2 && noLink(lo.stdout), lo.stdout);
  // The inbox labels a linked contact's messages: link {id, purpose}, on stdout with the message.
  const sb = await cli(HB, ['send', 'vps-a', 'the PR is ready']), ib = await cli(HA, ['inbox', '--wait', '5']);
  const lm = json<{ messages: { content: string; link?: { id: string; purpose: string } }[] }>(ib).messages?.find((m) => m.content === 'the PR is ready');
  ok('inbox: vps-b\'s message carries link {id, purpose}', sb.status === 0 && lm?.link?.id === r1.id && lm.link.purpose === 'review the pull requests', ib.stdout + ib.stderr);

  // ---- lazily: vps-b and vps-c, nobody watching; each next inbox does its part.
  const l3 = await cli(OP, ['link', 'vps-b', 'vps-c', '--purpose', 'write the docs', '--days', '1', '--wait', '0', '--operator']);
  const r3 = json<{ id: string; status: string }>(l3);
  ok('link --wait 0: pending, exit 0, says what it waits for', l3.status === 0 && r3.status === 'pending' && l3.stderr.includes('pending (waiting for vps-b)'), l3.stderr);
  const lazy: string[] = [];
  for (let k = 0; k < 5 && !(byName(fb, 'vps-c')?.link && byName(fc, 'vps-b')?.link); k++) {
    for (const [h, a] of [[HB, ['inbox', '--wait', '3']], [OP, ['link', '--finish', '--wait', '3', '--operator']], [HC, ['inbox', '--wait', '3']]] as [string, string[]][]) lazy.push(String((await cli(h, a)).status));
  }
  const fin = await cli(OP, ['link', '--finish', '--wait', '5', '--operator']);
  ok(`lazily (${lazy.join('')}): both filed the link, the operator's --finish ends linked`, byName(fb, 'vps-c')?.link?.id === r3.id && byName(fc, 'vps-b')?.link?.id === r3.id
    && json<{ id: string; status: string }[]>(fin).some?.((x) => x.id === r3.id && x.status === 'linked'), fin.stdout + fin.stderr);

  // ---- unlink vps-a ↔ vps-b: both forget.
  const u = await cli(OP, ['unlink', r1.id, '--operator']);
  for (let k = 0; k < 2; k++) { await cli(HA, ['inbox', '--wait', '3']); await cli(HB, ['inbox', '--wait', '3']); }
  ok('unlink: exit 0; vps-a and vps-b forgot each other', u.status === 0 && contactsOf(fa)[dB]?.revoked === true && contactsOf(fb)[dA]?.revoked === true, u.stderr);

  // ---- expiry, at each side's next inbox: vps-b ↔ vps-c forgotten; vps-a ↔ vps-c kept, the purpose dropped.
  expire(fb, dC); expire(fc, dB); expire(fa, dC); expire(fc, dA);
  const eb = await cli(HB, ['inbox', '--wait', '3']), ec = await cli(HC, ['inbox', '--wait', '3']), ea = await cli(HA, ['inbox', '--wait', '3']);
  ok('expired: vps-b and vps-c forget each other, each at its own inbox', contactsOf(fb)[dC]?.revoked === true && contactsOf(fc)[dB]?.revoked === true && eb.stderr.includes('ended (expired)'), eb.stderr + ec.stderr);
  const a1 = contactsOf(fa)[dC], c1 = contactsOf(fc)[dA];
  ok('expired, linked onto an earlier pairing: both keep it, the purpose gone, the tier as before', !a1?.revoked && !c1?.revoked && a1?.link === undefined && c1?.link === undefined && a1?.tier === tierAC, ea.stderr + JSON.stringify(a1));
  const lo2 = json<{ made: { id: string; status: string }[] }>(await cli(OP, ['link', '--finish', '--wait', '3', '--operator']).then(() => cli(OP, ['links', '--operator'])));
  ok('the operator: every link ended', lo2.made?.length === 3 && lo2.made.every((x) => x.status === 'ended'), JSON.stringify(lo2));
  // ---- relink after unlink (design/links.md §7.1a): the operator asks both again → linked again, a new id; then unlinked.
  ok('unlinked: each side remembers the end (ended: the link id)', (contactsOf(fa)[dB] as Rec & { ended?: { id: string } })?.ended?.id === r1.id && (contactsOf(fb)[dA] as Rec & { ended?: { id: string } })?.ended?.id === r1.id);
  const rl = await cli(OP, ['link', 'vps-a', 'vps-b', '--purpose', 'review again', '--wait', '0', '--operator']), rr = json<{ id: string; status: string }>(rl);
  for (let k = 0; k < 5 && !(contactsOf(fa)[dB]?.link && contactsOf(fb)[dA]?.link); k++) {
    await cli(HA, ['inbox', '--wait', '3']); await cli(OP, ['link', '--finish', '--wait', '3', '--operator']); await cli(HB, ['inbox', '--wait', '3']);
  }
  ok('relink: both asked afresh → linked again under a new id, neither revoked', rl.status === 0 && rr.id !== r1.id && contactsOf(fa)[dB]?.link?.id === rr.id && contactsOf(fb)[dA]?.link?.id === rr.id
    && !contactsOf(fa)[dB]?.revoked && !contactsOf(fb)[dA]?.revoked, rl.stdout + rl.stderr + JSON.stringify([contactsOf(fa)[dB], contactsOf(fb)[dA]]));
  await cli(OP, ['unlink', rr.id, '--operator']);
  for (let k = 0; k < 2; k++) { await cli(HA, ['inbox', '--wait', '3']); await cli(HB, ['inbox', '--wait', '3']); }

  // ================================================================ external: a hotel
  const xi = await cli(HX, ['init', '--no-recovery']);
  const oi = await cli(OP, ['invite', '--long', '--name', 'hotel', '--operator']);
  const oin = cli(OP, ['inbox', '--wait', '30', '--operator']);
  const xa = await cli(HX, ['accept', oi.stdout.trim(), '--name', 'op', '--wait', '30']);
  await oin;
  await cli(OP, ['inbox', '--wait', '3', '--operator']); await cli(HX, ['inbox', '--wait', '3']);
  const dX = byName(human, 'hotel')?.did ?? '';
  ok('a hotel (an identity of its own) pairs with the operator: not ours', xi.status === 0 && xa.status === 0 && byName(fx, 'op')?.revoked === false && json<{ contacts: { did: string; ours: boolean }[] }>(await cli(OP, ['contacts', '--operator'])).contacts?.find((c) => c.did === dX)?.ours === false, xi.stderr + xa.stderr);
  const tb = await cli(OP, ['link', 'vps-a', 'hotel', '--purpose', 'x', '--tier-b', 'quiet', '--operator']);
  ok('link to the hotel with --tier-b: refused, exit 1, link_tier', tb.status === 1 && tb.stderr.includes('link_tier'), tb.stderr);
  const nn = await cli(OP, ['link', 'vps-b', 'vps-a', '--purpose', 'x', '--operator', '--note']);
  ok('--note without a value: usage, exit 2', nn.status === 2, nn.stderr);

  // The hotel watches with --on-notice; the operator links vps-a to it, with a note.
  const notices = join(HX, 'notice.jsonl');
  const wx = await watch(HX, ['--on-notice', `cat >> '${notices}'`]);
  const wa2 = await watch(HA);
  const x1 = await cli(OP, ['link', 'hotel', 'vps-a', '--purpose', 'book rooms for the offsite', '--note', 'Ask for the group rate.', '--wait', '60', '--operator']);
  const rx1 = json<{ id: string; status: string; kind: string; a: string; b: string; tier_a: string; expires: number; relay: string }>(x1);
  ok(`link hotel vps-a: external, vps-a is A, pending at the hotel's operator, exit 0 (${rx1.id})`, x1.status === 0 && rx1.status === 'pending' && rx1.kind === 'external' && rx1.a === dA && rx1.b === dX && rx1.tier_a === 'friend'
    && rx1.relay === 'relay.test' && rx1.expires - Math.floor(Date.now() / 1000) > 29 * 86400 && x1.stderr.includes("waiting for hotel's operator"), x1.stdout + x1.stderr);
  const lines = (): Record<string, unknown>[] => (existsSync(notices) ? readFileSync(notices, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>) : []);
  ok('watch --on-notice at the hotel: {type: "link", id, from, purpose, note}', await until(() => lines().length > 0) && lines()[0]!['type'] === 'link' && lines()[0]!['id'] === rx1.id
    && lines()[0]!['from'] === Object.keys(contactsOf(fx))[0] && lines()[0]!['purpose'] === 'book rooms for the offsite' && lines()[0]!['note'] === 'Ask for the group rate.' && lines()[0]!['peer'] === dA, JSON.stringify(lines()) + wx.out());
  ok('never taken unasked: the hotel has no contact for vps-a', !byName(fx, 'vps-a'));
  const xl = await cli(HX, ['links']);
  ok('links on the hotel: the introduction, its purpose and note, no code', xl.status === 0 && json<{ received: { id: string; note: string }[] }>(xl).received?.[0]?.id === rx1.id && xl.stderr.includes(`links accept ${rx1.id}`) && noLink(xl.stdout + xl.stderr), xl.stdout + xl.stderr);
  const ownX = await cli(HX, ['links', 'accept', rx1.id, '--tier', 'own']);
  ok('links accept --tier own: usage, exit 2', ownX.status === 2, ownX.stderr);
  const acc = await cli(HX, ['links', 'accept', rx1.id]);
  ok('links accept beside the hotel\'s watcher: exit 0, the watcher does it', acc.status === 0 && acc.stderr.includes('sigelo-agent watch'), acc.stderr);
  const finLog: string[] = [];
  const fin1 = async (id: string): Promise<boolean> => (await until(() => {
    const r = JSON.parse(readFileSync(human.replace(/\.json$/, '.links.json'), 'utf8')) as { links: Record<string, { status: string }> };
    return r.links[id]?.status !== 'pending';
  }, 1000)) || (finLog.push((await cli(OP, ['link', '--finish', '--wait', '5', '--operator'])).stderr), false);
  // Both watchers do their part (the hotel's accepts, vps-a's files the link); then the operator's rounds.
  await until(() => Boolean(byName(fx, 'vps-a')?.link && byName(fa, 'hotel')?.link), 120_000);
  for (let k = 0; k < 6 && !(await fin1(rx1.id)); k++);
  const xa1 = byName(fx, 'vps-a'), ax1 = byName(fa, 'hotel');
  ok('accepted: the hotel files vps-a at quiet with the purpose; vps-a files the hotel at friend; the operator: linked', xa1?.link?.id === rx1.id && xa1.tier === 'quiet' && xa1.link.purpose === 'book rooms for the offsite'
    && ax1?.link?.id === rx1.id && ax1.tier === 'friend' && json<{ made: { id: string; status: string }[] }>(await cli(OP, ['links', '--operator'])).made?.find((x) => x.id === rx1.id)?.status === 'linked',
    finLog.join('|').slice(-800) + JSON.stringify(JSON.parse(readFileSync(human.replace(/\.json$/, '.links.json'), 'utf8')).links[rx1.id]));
  const ow = await cli(HX, ['tier', 'vps-a', 'own']);
  ok('tier vps-a own at the hotel: refused, link_tier', ow.status === 1 && ow.stderr.includes('link_tier'), ow.stderr);
  for (const w of [wx, wa2]) await stop(w);

  // Refused, silently: the operator's link stays pending.
  const x2 = await cli(OP, ['link', 'vps-b', 'hotel', '--purpose', 'book rooms', '--wait', '0', '--operator']);
  const rx2 = json<{ id: string }>(x2);
  await cli(HB, ['inbox', '--wait', '3']); await cli(OP, ['link', '--finish', '--wait', '3', '--operator']);
  const xin = await cli(HX, ['inbox', '--wait', '3']);
  ok('the hotel\'s inbox: a line for the introduction, nothing on stdout', xin.stderr.includes(`link ${rx2.id}: op introduces vps-b`) && noLink(xin.stdout) && !xin.stdout.includes('book rooms'), xin.stdout + xin.stderr);
  const rf = await cli(HX, ['links', 'refuse', rx2.id]);
  await cli(OP, ['link', '--finish', '--wait', '3', '--operator']);
  ok('links refuse: exit 0, nothing told; the operator\'s link still pending', rf.status === 0 && rf.stderr.includes('nothing was told')
    && json<{ made: { id: string; status: string }[] }>(await cli(OP, ['links', '--operator'])).made?.find((x) => x.id === rx2.id)?.status === 'pending' && json<{ received: unknown[] }>(await cli(HX, ['links'])).received?.length === 0, rf.stderr);

  // An allow rule: accepted by itself at its tier; deny: pending again.
  const al = await cli(HX, ['links', 'allow', 'op', '--tier', 'friend', '--days', '5']);
  ok('links allow op --tier friend --days 5: exit 0', al.status === 0 && json<{ tier: string; until: number }>(al).tier === 'friend', al.stderr);
  const x3 = await cli(OP, ['link', 'vps-c', 'hotel', '--purpose', 'book rooms', '--wait', '0', '--operator']);
  const rx3 = json<{ id: string }>(x3);
  for (let k = 0; k < 4 && !byName(fx, 'vps-c')?.link; k++) {
    await cli(HC, ['inbox', '--wait', '3']); await cli(OP, ['link', '--finish', '--wait', '3', '--operator']); await cli(HX, ['inbox', '--wait', '3']);
  }
  await cli(HC, ['inbox', '--wait', '3']); await cli(OP, ['link', '--finish', '--wait', '3', '--operator']);
  ok('allowed: the hotel accepted by itself, at friend; the operator: linked', byName(fx, 'vps-c')?.link?.id === rx3.id && byName(fx, 'vps-c')?.tier === 'friend'
    && json<{ made: { id: string; status: string }[] }>(await cli(OP, ['links', '--operator'])).made?.find((x) => x.id === rx3.id)?.status === 'linked', JSON.stringify(byName(fx, 'vps-c')));
  const dn = await cli(HX, ['links', 'deny', 'op']);
  ok('links deny op: exit 0, the rule gone', dn.status === 0 && json<{ allow: unknown[] }>(await cli(HX, ['links'])).allow?.length === 0, dn.stderr);
  const x4 = await cli(OP, ['link', 'vps-b', 'hotel', '--purpose', 'book rooms again', '--wait', '0', '--operator']);
  const rx4 = json<{ id: string }>(x4);
  await cli(HB, ['inbox', '--wait', '3']); await cli(OP, ['link', '--finish', '--wait', '3', '--operator']); await cli(HX, ['inbox', '--wait', '3']);
  ok('after deny: pending at the hotel, not taken', json<{ received: { id: string }[] }>(await cli(HX, ['links'])).received?.some((x) => x.id === rx4.id) && !byName(fx, 'vps-b'), '');
  const rt = await cli(HX, ['links', 'refuse', rx4.id, '--tell']);
  await cli(OP, ['link', '--finish', '--wait', '5', '--operator']);
  ok('links refuse --tell: exit 0; the operator\'s link refused, link_refused', rt.status === 0
    && json<{ made: { id: string; status: string; check: string }[] }>(await cli(OP, ['links', '--operator'])).made?.find((x) => x.id === rx4.id)?.check === 'link_refused', rt.stderr);

  // ---- no link message, and no code, anywhere a reader or the model looks.
  const outs = [ea, eb, ec, xin].map((r) => r.stdout).join('\n');
  const logs = [human, fa, fb, fc, fx].map((f) => { const p = f.replace(/\.json$/, '.inbox.log'); return existsSync(p) ? readFileSync(p, 'utf8') : ''; }).join('\n');
  const hist = (await Promise.all([HA, HB, HC, HX].map((h) => cli(h, ['history'])))).map((r) => r.stdout).join('\n');
  ok('no link message nor code in inbox output, history or any inbox.log', noLink(outs) && noLink(logs) && noLink(hist) && noLink(wa.out() + wb.out() + wc.out() + wx.out()), (outs + logs + hist).slice(0, 400));
  ok('nor in the operator\'s links file once forwarded', noLink(readFileSync(human.replace(/\.json$/, '.links.json'), 'utf8')));
  const send = await cli(HA, ['send', 'vps-c', 'x', '--label', 'sigelo-link/1']);
  ok('send --label sigelo-link/1: refused, exit 1 (the link handler\'s own)', send.status === 1 && send.stderr.includes('link handler'), send.stderr);
} finally {
  for (const w of watchers) if (w.exitCode === null) w.kill('SIGKILL');
  await relay.close?.();
  for (const d of [D, OP, HA, HB, HC, HX]) rmSync(d, { recursive: true, force: true });
}
done(import.meta.filename);
