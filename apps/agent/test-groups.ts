// SPDX-License-Identifier: MIT
// Groups through the CLI (GROUPS.md, apps/contact/group.mjs), one loopback relay in this process: four
// identities (lead, the creator; a and b, paired with each other; c, paired with lead only). lead
// makes a group; a and b, which file lead at own, join at once; c (lead at friend there) is asked
// once and joins. Messages labelled in `inbox` (group, mid, sender, role, tier, "not your
// operator"), c reached through the creator; a removal; the brake; usage refusals; nothing in history.
//   node test-groups.ts   → ALL PASS test-groups.ts (n ok)
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CLI, cliIn, done, hasRelay, NO_RELAY, ok, startTestRelay, tmpHome } from './test-helpers.ts';

if (!hasRelay()) {
  console.log(`SKIP groups through the CLI: ${NO_RELAY}`);
  done(import.meta.filename);
}
const H = tmpHome('groups'), relay = await startTestRelay(H), endpoints = JSON.stringify(relay.endpoints);
const envOf = (n: string): Record<string, string> => ({ PATH: process.env['PATH'] ?? '', SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_IDENTITY: join(H, `${n}.local.json`), SIGELO_RELAY: 'relay.test', SIGELO_SHORT_RELAY: 'relay.test', SIGELO_RELAY_REGISTRY: 'off', SIGELO_RELAY_ENDPOINTS: endpoints });
const cli = (n: string, ...args: string[]) => cliIn(envOf(n), H)(...args);
type Msg = { label?: string; content?: unknown; group?: { gid: string; name: string }; mid?: string; from?: string; name?: string; role?: string; tier?: string; note?: string; via?: string; mentioned?: boolean; contact?: boolean };
type Inbox = { messages: Msg[]; events: { type?: string; why?: string; gid?: string }[] };
const inbox = async (n: string): Promise<Inbox & { stderr: string; status: number | null }> => {
  const r = await cli(n, 'inbox', '--wait', '2');
  try { return { ...(JSON.parse(r.stdout) as Inbox), stderr: r.stderr, status: r.status }; } catch { return { messages: [], events: [], stderr: r.stderr + r.stdout, status: r.status }; }
};
const grp = (b: Inbox, text: string): Msg | undefined => b.messages.find((m) => m.label === 'sigelo-group/1' && m.content === text);

try {
  for (const n of ['lead', 'a', 'b', 'c']) await cli(n, 'init', '--no-recovery');
  const did = async (n: string) => (JSON.parse((await cli(n, 'whoami')).stdout) as { did: string }).did;
  const D = { lead: await did('lead'), a: await did('a'), b: await did('b'), c: await did('c') };
  const pair = async (inviter: string, invitee: string) => {
    const code = (await cli(inviter, 'invite', '--long', '--name', invitee)).stdout.trim();
    await cli(invitee, 'accept', code, '--name', inviter, '--wait', '0');
    await cli(inviter, 'inbox', '--wait', '2'); await cli(invitee, 'inbox', '--wait', '2');
  };
  for (const n of ['a', 'b', 'c']) await pair('lead', n);
  await pair('a', 'b');
  for (const n of ['a', 'b']) await cli(n, 'tier', 'lead', 'own');
  ok('set up: lead paired with a, b and c; a with b', (JSON.parse((await cli('lead', 'contacts')).stdout) as { contacts: unknown[] }).contacts.length === 3);

  // Usage, before anything connects.
  const u1 = await cli('lead', 'group', 'nope'), u2 = await cli('lead', 'group', 'create', 'solo'), u3 = await cli('lead', 'group', 'send', 'x', 'hi', '--wat'), u4 = await cli('lead', 'group', 'create', 'x', 'a', '--role', 'boss');
  ok('group: an unknown verb, a missing argument, an unknown flag, a bad --role: exit 2', [u1, u2, u3, u4].every((r) => r.status === 2), [u1, u2, u3, u4].map((r) => r.stderr).join('|'));
  const none = await cli('lead', 'group', 'create', 'x', 'nobody');
  ok('group create with no such contact: exit 1, not_contact', none.status === 1 && none.stderr.includes('not_contact'), none.stderr);

  const mk = await cli('lead', 'group', 'create', 'crew', 'a', 'b', 'c', '--brake', '5');
  const g = (JSON.parse(mk.stdout || '{}') as { group?: { gid: string; members: { role: string; me: boolean }[]; brake: number } }).group;
  ok('group create crew a b c: exit 0, four members, lead human (no operator), brake 5', mk.status === 0 && g?.members.length === 4 && g.members.find((m) => m.me)?.role === 'human' && g.brake === 5 && mk.stderr.includes('made, 4 members'), mk.stdout + mk.stderr);
  const ia = await inbox('a'), ic = await inbox('c');
  ok('a (lead at own there): joined at once, said on stderr', ia.stderr.includes('group crew: joined'), ia.stderr);
  ok('c (lead at friend): asked once, an event and a line with the verbs to answer', ic.events.some((e) => e.type === 'group' && e.why === 'invited' && e.gid === g?.gid) && ic.stderr.includes(`group join ${g?.gid}`), ic.stderr);
  const early = await cli('c', 'group', 'send', 'crew', 'too early');
  ok('c sends before joining: exit 1, group_pending', early.status === 1 && early.stderr.includes('group_pending'), early.stderr);
  const jn = await cli('c', 'group', 'join', 'crew');
  ok('c: group join crew', jn.status === 0 && jn.stderr.includes('joined'), jn.stderr);
  await inbox('b');

  const s1 = await cli('a', 'group', 'send', 'crew', 'hello', '@c');
  const r1 = JSON.parse(s1.stdout || '{}') as { copies?: { status: string }[]; via_creator?: { name: string }[]; mid?: string };
  ok('a sends: copies to lead and b, c via the creator', s1.status === 0 && r1.copies?.length === 2 && r1.copies.every((x) => x.status === 'sent') && r1.via_creator?.[0]?.name === 'c', s1.stdout + s1.stderr);
  await inbox('lead');
  const c1 = await inbox('c'), m1 = grp(c1, 'hello @c');
  ok('c: the message in inbox, labelled: group, mid, from a by DID, role, tier friend (no contact), via the creator, "not your operator", mentioned',
    m1?.group?.name === 'crew' && m1.mid === r1.mid && m1.from === D.a && m1.role === 'agent' && m1.tier === 'friend' && m1.via === D.lead && m1.note === 'not your operator' && m1.mentioned === true && m1.contact === false, JSON.stringify(c1.messages));
  const b1 = grp(await inbox('b'), 'hello @c');
  ok('b: direct from a (its contact), at its tier, not mentioned', b1?.from === D.a && b1.via === undefined && b1.contact === true && b1.mentioned === false, JSON.stringify(b1));

  const s3 = await cli('c', 'group', 'send', 'crew', 'from c');
  ok('c sends: one copy, to the creator, two via it', s3.status === 0 && (JSON.parse(s3.stdout) as { via_creator: unknown[] }).via_creator.length === 2, s3.stdout + s3.stderr);
  await inbox('lead');
  ok('a and b have c\'s message, carried by lead', grp(await inbox('a'), 'from c')?.via === D.lead && grp(await inbox('b'), 'from c')?.from === D.c);
  // The creator watched: its watcher carries copies on and files its own; its inbox beside it reads them.
  const w = spawn('node', [CLI, 'watch'], { env: envOf('lead'), cwd: H });
  let wout = '';
  w.stdout.on('data', (d) => { wout += d; }); w.stderr.on('data', (d) => { wout += d; });
  const until = async (f: () => boolean, ms = 30_000): Promise<boolean> => { const e = Date.now() + ms; while (!f() && Date.now() < e) await new Promise((r) => setTimeout(r, 200)); return f(); };
  await until(() => wout.includes('connected to relay.test'));
  await cli('a', 'group', 'send', 'crew', 'while watched');
  ok('lead\'s watcher: a friend\'s group message is a line naming the group, not its text', await until(() => wout.includes('friend a in crew: 1 new message (not shown: sigelo-agent inbox)')) && !wout.includes('while watched'), wout);
  ok('c has it, carried on by the watcher', await until(() => false, 1500) || grp(await inbox('c'), 'while watched')?.via === D.lead);
  const lw = await inbox('lead');
  ok('lead\'s inbox beside its watcher: the message, from the state', grp(lw, 'while watched')?.from === D.a, lw.stderr);
  await new Promise<void>((r) => { w.on('close', () => r()); w.kill('SIGTERM'); });
  // At own, pushed: --on-message gets the item as inbox gives it, labelled; taken once the hook exits 0.
  await cli('lead', 'tier', 'a', 'own');
  const hookOut = join(H, 'hook.jsonl');
  const w2 = spawn('node', [CLI, 'watch', '--on-message', `cat >> '${hookOut}'`], { env: envOf('lead'), cwd: H });
  let w2out = '';
  w2.stdout.on('data', (d) => { w2out += d; }); w2.stderr.on('data', (d) => { w2out += d; });
  await until(() => w2out.includes('connected to relay.test'));
  await cli('a', 'group', 'send', 'crew', 'pushed @lead');
  const hooked = (): Msg[] => { try { return readFileSync(hookOut, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l) as Msg); } catch { return []; } };
  const hk = await until(() => hooked().some((m) => m.content === 'pushed @lead')) ? hooked().find((m) => m.content === 'pushed @lead') : undefined;
  ok('lead\'s watcher, a at own: --on-message gets the group message labelled (group, mid, sender, role, tier, "not your operator", mentioned)',
    hk?.label === 'sigelo-group/1' && hk.group?.name === 'crew' && typeof hk.mid === 'string' && hk.from === D.a && hk.role === 'agent' && hk.tier === 'own' && hk.note === 'not your operator' && hk.mentioned === true, JSON.stringify(hk) + w2out);
  await new Promise<void>((r) => { w2.on('close', () => r()); w2.kill('SIGTERM'); });
  ok('…and taken: not in lead\'s next inbox', !grp(await inbox('lead'), 'pushed @lead'));
  await cli('lead', 'tier', 'a', 'friend');
  await inbox('b');
  const ls = await cli('a', 'group', 'list');
  ok('a: group list: crew, member, lead\'s, four members', ls.status === 0 && (JSON.parse(ls.stdout) as { name: string; status: string; members: unknown[] }[])[0]?.members.length === 4 && ls.stderr.includes('crew ('), ls.stdout + ls.stderr);

  // The brake, the creator's: 5 agent messages in a row.
  for (let i = 0; i < 5; i++) { await cli(i % 2 ? 'b' : 'a', 'group', 'send', 'crew', `step ${i}`); await inbox('a'); await inbox('b'); }
  const q = await cli('a', 'group', 'send', 'crew', 'step 5');
  ok('a 6th agent message in a row: exit 1, group_quiet', q.status === 1 && q.stderr.includes('group_quiet'), q.stderr);
  await cli('lead', 'group', 'send', 'crew', 'go on');
  await inbox('a');
  ok('lead (human) writes: a writes again', (await cli('a', 'group', 'send', 'crew', 'step 6')).status === 0);

  // Removal: c is told, and refused after.
  const notLead = await cli('a', 'group', 'remove', 'crew', 'c');
  ok('a removes: exit 1, group_creator', notLead.status === 1 && notLead.stderr.includes('group_creator'), notLead.stderr);
  const rm = await cli('lead', 'group', 'remove', 'crew', 'c');
  ok('lead removes c: ver 2, three members', rm.status === 0 && rm.stderr.includes('ver 2, 3 members'), rm.stderr);
  const c2 = await inbox('c');
  ok('c: "you were removed"', c2.stderr.includes('group crew: you were removed'), c2.stderr);
  ok('c sends after: exit 1', (await cli('c', 'group', 'send', g?.gid ?? '', 'still?')).status === 1);

  const logs = ['lead', 'a', 'b', 'c'].map((n) => { try { return readFileSync(join(H, `${n}.local.inbox.log`), 'utf8'); } catch { return ''; } }).join('');
  ok('no group message in any inbox.log (the chat is in <identity>.groups.json)', !logs.includes('sigelo-group'));
} finally {
  await relay.close?.();
}
done(import.meta.filename);
