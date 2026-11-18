// SPDX-License-Identifier: MIT
// sigelo-agent watch and the tiers (WATCH.md, apps/contact/store.mjs).
//   node test-watch.ts   (SKIPs without relay/ and its node_modules)
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { CLI, RELAY, ROOT, cliIn, done, fakeExe, hasRelay, NO_RELAY, ok, startTestRelay, tmpHome } from './test-helpers.ts';

// ── tiers and watch (apps/contact/store.mjs tiers, sigelo-agent-watch.ts, WATCH.md) ───────────────
// Against the in-process relay: alice makes three codes, then runs `watch` with no hook; three
// agents accept while it runs, so each pairing completes on alice's side by itself (a line each).
// alice files them own, friend and quiet (`tier`); each writes: own → its text on a line, friend → a
// count, quiet → nothing. Then a watcher with the three hooks: the own message waiting is pushed in
// full and taken, a friend's notice carries no content, a pairing runs --on-pairing; the friend's and
// quiet messages wait for alice's inbox, by tier.
{
  if (!hasRelay()) console.log(`SKIP watch: ${NO_RELAY}`);
  else {
    const { lockPath } = await import('./sigelo-agent-contact.ts');
    const H = tmpHome('watch'), relay = await startTestRelay(H), endpoints = JSON.stringify(relay.endpoints);
    const OUT = join(H, 'hooks');
    mkdirSync(OUT);
    const envOf = (n: string): Record<string, string> => ({ PATH: process.env['PATH'] ?? '', SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_IDENTITY: join(H, `${n}.local.json`), SIGELO_RELAY: 'relay.test', SIGELO_SHORT_RELAY: 'relay.test', SIGELO_RELAY_REGISTRY: 'off', SIGELO_RELAY_ENDPOINTS: endpoints, WOUT: OUT });
    const cli = (n: string, ...args: string[]) => cliIn(envOf(n), H)(...args);
    const watcher = (...args: string[]) => {
      const c = spawn('node', [CLI, 'watch', ...args], { env: envOf('alice'), cwd: H });
      const w = { out: '', err: '', c, exit: new Promise<number | null>((r) => c.on('close', r)) };
      c.stdout.on('data', (d) => { w.out += d; }); c.stderr.on('data', (d) => { w.err += d; });
      return w;
    };
    const until = async (f: () => boolean, ms = 30000): Promise<boolean> => { const e = Date.now() + ms; while (!f() && Date.now() < e) await new Promise((r) => setTimeout(r, 200)); return f(); };
    const lines = (f: string): Record<string, unknown>[] => (existsSync(join(OUT, f)) ? readFileSync(join(OUT, f), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>) : []);
    let w1: ReturnType<typeof watcher> | null = null, w2: ReturnType<typeof watcher> | null = null;
    try {
      for (const n of ['alice', 'mine', 'pal', 'hotel', 'late']) await cli(n, 'init', '--no-recovery');
      const didOf = async (n: string) => (JSON.parse((await cli(n, 'whoami')).stdout) as { did: string }).did;
      const D = { mine: await didOf('mine'), pal: await didOf('pal'), hotel: await didOf('hotel') };
      const code: Record<string, string> = {};
      for (const n of ['mine', 'pal', 'hotel']) code[n] = (await cli('alice', 'invite', '--long', '--name', n)).stdout.trim();
      ok('watch: usage errors exit 2', (await cli('alice', 'watch', '--on-message')).status === 2 && (await cli('alice', 'watch', '--nope')).status === 2);
      w1 = watcher();
      ok('watch: connects, says so on stderr, holds the lock ("<pid> watch")', await until(() => w1!.err.includes('connected to relay.test'))
        && readFileSync(lockPath(join(H, 'alice.local.json')), 'utf8').endsWith(' watch'), w1.err);
      const second = await cli('alice', 'watch');
      ok('watch: a second watcher on the file → exit 1, saying who holds it', second.status === 1 && second.stderr.includes('is watched by sigelo-agent watch'), second.stderr);
      const page = await (await import('./sigelo-agent-ui.ts')).startUi({ identity: join(H, 'alice.local.json'), agents: join(H, 'none') }).then(() => 'started', (e: Error) => e.message);
      ok('watch: and a page on it → refused', page.includes('is watched by sigelo-agent watch'), page);
      const acc: Record<string, { status: number | null; stdout: string; stderr: string }> = {};
      for (const n of ['mine', 'pal', 'hotel']) acc[n] = await cli(n, 'accept', code[n]!, '--name', 'alice', '--wait', '30', ...(n === 'hotel' ? ['--tier', 'quiet'] : []));
      ok('watch: each accept, made while alice\'s watcher runs, comes back connected: the invite completed by itself',
        ['mine', 'pal', 'hotel'].every((n) => acc[n]!.status === 0 && (JSON.parse(acc[n]!.stdout) as { status: string }).status === 'connected'), JSON.stringify(acc));
      ok('accept: prints the tier and how to change it (friend by default; --tier quiet)', acc['pal']!.stderr.includes('tier: friend (change with `tier alice quiet`)')
        && acc['hotel']!.stderr.includes('tier: quiet (change with `tier alice friend`)') && (JSON.parse(acc['hotel']!.stdout) as { contact: { tier: string } }).contact.tier === 'quiet', acc['pal']!.stderr + acc['hotel']!.stderr);
      const badTier = await cli('pal', 'accept', 'sgl1x', '--tier', 'own');
      ok('accept --tier own → exit 2 (own is detected)', badTier.status === 2 && badTier.stderr.includes('own is detected'), badTier.stderr);
      ok('watch: a line per pairing completed on alice\'s side, with the four words', await until(() => (w1!.out.match(/^paired /gm) ?? []).length === 3), w1.out);
      // alice's tiers: the tier verb, by name; refusals.
      const tOwn = await cli('alice', 'tier', 'mine', 'own'), tQuiet = await cli('alice', 'tier', D.hotel, 'quiet');
      ok('tier <name> own, tier <did> quiet → {did, name, tier}, a line saying what it means', tOwn.status === 0 && (JSON.parse(tOwn.stdout) as { tier: string; did: string }).did === D.mine
        && tOwn.stderr.includes('pushed in full') && (JSON.parse(tQuiet.stdout) as { tier: string; name: string }).name === 'hotel', tOwn.stderr + tQuiet.stdout);
      const tBad = await cli('alice', 'tier', 'pal', 'vip'), tNone = await cli('alice', 'tier', 'nobody', 'quiet');
      ok('tier: an unknown tier → exit 2; no such contact → exit 1, not_contact', tBad.status === 2 && tNone.status === 1 && tNone.stderr.includes('is not a contact'), tBad.stderr + tNone.stderr);
      const cs = await cli('alice', 'contacts'), listed = (JSON.parse(cs.stdout) as { contacts: { name: string; tier: string; ours: boolean }[] }).contacts;
      ok('contacts: each with its tier, none ours (no attestation; own by choice) (JSON and the stderr line)', listed.map((c) => `${c.name}:${c.tier}`).sort().join() === 'hotel:quiet,mine:own,pal:friend' && listed.every((c) => c.ours === false)
        && cs.stderr.includes('sigelo-agent: mine: a contact, its messages are pushed in full (tier own)\n') && cs.stderr.includes('sigelo-agent: hotel: a contact, its messages wait in the inbox, no notice (tier quiet)\n'), cs.stdout + cs.stderr);
      await new Promise((r) => setTimeout(r, 1500));
      for (const n of ['mine', 'pal', 'hotel']) await cli(n, 'send', 'alice', `hello from ${n}`);
      ok('watch, no hook: the own contact\'s message on a line, the friend\'s as a count', await until(() => w1!.out.includes('own mine: hello from mine') && w1!.out.includes('friend pal: 1 new message')), w1.out);
      await new Promise((r) => setTimeout(r, 2000));
      ok('watch, no hook: nothing for the quiet one, nor its content anywhere', !w1.out.includes('hello from hotel') && !/^(own|friend) hotel/m.test(w1.out), w1.out);
      for (const l of w1.out.split('\n').filter(Boolean)) console.log(`     watch stdout | ${l}`);
      w1.c.kill('SIGTERM');
      ok('watch: SIGTERM → exit 0, the lock gone', (await w1.exit) === 0 && !existsSync(lockPath(join(H, 'alice.local.json'))));
      w1 = null;

      // With the hooks. A code made first, answered while the watcher runs: --on-pairing.
      code['late'] = (await cli('alice', 'invite', '--long', '--name', 'late')).stdout.trim();
      w2 = watcher('--on-message', 'echo "$SIGELO_TYPE $SIGELO_TIER $SIGELO_NAME" >> "$WOUT/env.txt"; cat >> "$WOUT/message.jsonl"', '--on-notice', 'cat >> "$WOUT/notice.jsonl"', '--on-pairing', 'cat >> "$WOUT/pairing.jsonl"');
      await until(() => w2!.err.includes('connected to relay.test'));
      ok('watch, --on-message at start: the own message that waited, in full, as JSON on stdin; env SIGELO_TYPE, SIGELO_TIER, SIGELO_NAME',
        await until(() => lines('message.jsonl').length === 1) && lines('message.jsonl')[0]!['content'] === 'hello from mine' && lines('message.jsonl')[0]!['from'] === D.mine
          && readFileSync(join(OUT, 'env.txt'), 'utf8').trim() === 'message own mine', JSON.stringify(lines('message.jsonl')));
      ok('watch, --on-notice at start: {from, name, tier, count} for the friend, no content', await until(() => lines('notice.jsonl').length === 1)
        && JSON.stringify(lines('notice.jsonl')[0]) === JSON.stringify({ from: D.pal, name: 'pal', tier: 'friend', count: 1 }), JSON.stringify(lines('notice.jsonl')));
      const late = await cli('late', 'accept', code['late']!, '--name', 'alice', '--wait', '30');
      ok('watch, --on-pairing: the paired event as JSON, the invite completed by itself', late.status === 0 && await until(() => lines('pairing.jsonl').length === 1)
        && lines('pairing.jsonl')[0]!['type'] === 'paired' && lines('pairing.jsonl')[0]!['name'] === 'late' && /^\w+ \w+ \w+ \w+$/.test(String(lines('pairing.jsonl')[0]!['fingerprint'])), JSON.stringify(lines('pairing.jsonl')));
      for (const n of ['mine', 'pal', 'hotel']) await cli(n, 'send', 'alice', `again from ${n}`);
      ok('watch, --on-message: a new own message pushed in full', await until(() => lines('message.jsonl').length === 2) && lines('message.jsonl')[1]!['content'] === 'again from mine', JSON.stringify(lines('message.jsonl')));
      ok('watch, --on-notice: the friend\'s, now 2 waiting, no content', await until(() => lines('notice.jsonl').length === 2) && lines('notice.jsonl')[1]!['count'] === 2
        && !readFileSync(join(OUT, 'notice.jsonl'), 'utf8').includes('from pal'), readFileSync(join(OUT, 'notice.jsonl'), 'utf8'));
      await new Promise((r) => setTimeout(r, 2000));
      ok('watch: nothing ran for the quiet contact', !readFileSync(join(OUT, 'env.txt'), 'utf8').includes('hotel') && !JSON.stringify(lines('notice.jsonl')).includes(D.hotel));
      // The CLI beside a watcher: inbox reads what it received, without a session; by tier.
      const own = await cli('alice', 'inbox', '--tier', 'own');
      ok('inbox --tier own beside the watcher: no login (said), nothing left (the hook took the own ones)', own.status === 0 && own.stderr.includes('holds the relay session: reading what it received')
        && (JSON.parse(own.stdout) as { messages: unknown[] }).messages.length === 0, own.stderr);
      // The single-owner rule (WATCH.md): beside the watcher, send and send-file queue for it (no
      // login) and it sends them at once (the kick file); the other session verbs refuse, busy.
      const sw = await cli('alice', 'send', 'pal', 'reply while watched');
      ok('send beside the watcher: exit 0, queued for it, no login (said)', sw.status === 0 && (JSON.parse(sw.stdout) as { status: string }).status === 'queued'
        && sw.stderr.includes('send: queued for sigelo-agent watch (pid '), sw.stderr);
      writeFileSync(join(H, 'note.txt'), 'a file through the watcher\n');
      const sf = await cli('alice', 'send-file', 'pal', join(H, 'note.txt'));
      ok('send-file beside the watcher: exit 0, queued for it', sf.status === 0 && sf.stderr.includes('send-file: queued for sigelo-agent watch (pid '), sf.stderr);
      const got: { content?: unknown; type?: string; name?: string }[] = [], t1 = Date.now();
      while (Date.now() - t1 < 30000 && !(got.some((m) => m.content === 'reply while watched') && got.some((m) => m.type === 'file'))) {
        got.push(...(JSON.parse((await cli('pal', 'inbox', '--wait', '5')).stdout || '{"messages":[]}') as { messages: typeof got }).messages);
      }
      ok('the watcher sent both, well before its 60 s round: pal gets the message and the file', got.some((m) => m.content === 'reply while watched') && got.some((m) => m.type === 'file' && m.name === 'note.txt'), JSON.stringify(got));
      for (const args of [['invite'], ['accept', 'K7F3-Q9ZP'], ['forget', D.pal], ['pro', 'redeem', 'PRO-K7F3-Q9ZP']]) {
        const b = await cli('alice', ...args);
        ok(`${args[0]} beside the watcher: exit 1, busy, saying who holds the session`, b.status === 1 && b.stderr.includes(`is watched by sigelo-agent watch (pid ${w2.c.pid})`), b.stderr);
      }
      ok('the refused forget changed nothing', (JSON.parse((await cli('alice', 'contacts')).stdout) as { contacts: { name: string; revoked: boolean }[] }).contacts.find((c) => c.name === 'pal')?.revoked === false);
      ok('the watcher kept its one session throughout: connected once', (w2.err.match(/connected to relay\.test/g) ?? []).length === 1, w2.err);
      w2.c.kill('SIGTERM');
      ok('watch with hooks: SIGTERM → exit 0', (await w2.exit) === 0);
      w2 = null;

      // examples/reply-hook.sh (README "Answering by itself"): the own message's text through
      // $SIGELO_REPLY_CMD, the answer sent back labelled reply; a reply is never answered.
      const hookPath = CLI.replace(/cli\.ts$/, 'examples/reply-hook.sh');
      w2 = watcher('--on-message', `SIGELO_REPLY_CMD="tr a-z A-Z" sh '${hookPath}'`);
      await until(() => w2!.err.includes('connected to relay.test'));
      await cli('mine', 'send', 'alice', 'ping from mine');
      const back: { content?: unknown; label?: string }[] = [], t2 = Date.now();
      while (Date.now() - t2 < 40000 && !back.some((m) => m.content === 'PING FROM MINE')) back.push(...(JSON.parse((await cli('mine', 'inbox', '--wait', '5')).stdout || '{"messages":[]}') as { messages: typeof back }).messages);
      ok('reply-hook.sh: an own message answered by the command in SIGELO_REPLY_CMD, sent back labelled reply', back.some((m) => m.content === 'PING FROM MINE' && m.label === 'reply'), JSON.stringify(back) + w2.err.slice(-400));
      await cli('mine', 'send', 'alice', 'a reply itself', '--label', 'reply');
      await new Promise((r) => setTimeout(r, 4000));
      const none = (JSON.parse((await cli('mine', 'inbox', '--wait', '3')).stdout || '{"messages":[]}') as { messages: unknown[] }).messages;
      ok('reply-hook.sh: a message labelled reply is not answered (no loop between two such agents)', none.length === 0, JSON.stringify(none));
      w2.c.kill('SIGTERM');
      await w2.exit;
      w2 = null;

      // The agent task loop (WATCH.md "Slow agents"): --hook-timeout, SIGELO_MSG_ID, the killed-hook
      // rule, --spool (accept now), reply --to <id> later, reply --status.
      const mineIn = async (want: string): Promise<{ content?: unknown; label?: string }[]> => {
        const got: { content?: unknown; label?: string }[] = [], t = Date.now();
        while (Date.now() - t < 40000 && !got.some((m) => m.content === want)) got.push(...(JSON.parse((await cli('mine', 'inbox', '--wait', '5')).stdout || '{"messages":[]}') as { messages: typeof got }).messages);
        return got;
      };
      for (const [args, what] of [[['--hook-timeout', 'soon'], '--hook-timeout soon'], [['--hook-timeout', '-1'], '--hook-timeout -1'], [['--spool', join(H, 'sp'), '--on-message', 'true'], '--spool with --on-message']] as const) {
        const u = await cli('alice', 'watch', ...args);
        ok(`watch ${what} → exit 2`, u.status === 2, u.stderr);
      }
      const envBad = await cliIn({ ...envOf('alice'), SIGELO_HOOK_TIMEOUT: 'later' }, H)('watch');
      ok('watch with SIGELO_HOOK_TIMEOUT=later → exit 2, naming the variable', envBad.status === 2 && envBad.stderr.includes('SIGELO_HOOK_TIMEOUT: whole seconds, or 10m, 1h'), envBad.stderr);
      const slowHook = `echo "$SIGELO_MSG_ID" >> "$WOUT/ids.txt"; [ -f "$WOUT/go" ] || sleep 20; cat > "$WOUT/taken.json"`;
      w2 = watcher('--hook-timeout', '2', '--on-message', slowHook);
      await until(() => w2!.err.includes('connected to relay.test'));
      ok('watch --hook-timeout 2: said at start', w2.err.includes('hooks stopped after 2 s'), w2.err);
      await cli('mine', 'send', 'alice', 'a slow task');
      const ids = (): string[] => (existsSync(join(OUT, 'ids.txt')) ? readFileSync(join(OUT, 'ids.txt'), 'utf8').split('\n').filter(Boolean) : []);
      ok('a hook past --hook-timeout is stopped, saying the message stays unread and is offered again (dedupe on SIGELO_MSG_ID)',
        await until(() => w2!.err.includes('no exit within 2 s (--hook-timeout), stopped; message ')) && /^[0-9a-f]{32}$/.test(ids()[0] ?? '') && w2.err.includes(`message ${ids()[0]} stays unread, offered again at the next round (dedupe on SIGELO_MSG_ID)`), w2.err.slice(-600));
      w2.c.kill('SIGTERM');
      await w2.exit;
      writeFileSync(join(OUT, 'go'), '');
      w2 = watcher('--hook-timeout', '0', '--on-message', slowHook);
      ok('the stopped hook\'s message, offered again at the next start under the same SIGELO_MSG_ID, then taken', await until(() => existsSync(join(OUT, 'taken.json')))
        && ids().length === 2 && ids()[0] === ids()[1] && (JSON.parse(readFileSync(join(OUT, 'taken.json'), 'utf8')) as { id: string; content: string }).id === ids()[0]
        && (JSON.parse(readFileSync(join(OUT, 'taken.json'), 'utf8')) as { content: string }).content === 'a slow task' && w2.err.includes('hooks without a time limit'), JSON.stringify(ids()) + w2.err.slice(-400));
      const slowId = ids()[0]!;
      w2.c.kill('SIGTERM');
      await w2.exit;
      // Accept now: --spool, no hook; the task waits in a file named by its id; the answer goes later.
      const SPOOL = join(H, 'spool');
      w2 = watcher('--spool', SPOOL);
      await until(() => w2!.err.includes('connected to relay.test'));
      await cli('mine', 'send', 'alice', 'a task for later');
      const spooled = (): string[] => (existsSync(SPOOL) ? readdirSync(SPOOL).filter((f) => f.endsWith('.json')) : []);
      ok('watch --spool: the own message written to <dir>/<id>.json, a line saying how to answer', await until(() => spooled().length === 1) && await until(() => w2!.out.includes('(answer: sigelo-agent reply --to ')), w2.out + w2.err.slice(-300));
      const task = JSON.parse(readFileSync(join(SPOOL, spooled()[0]!), 'utf8')) as { id: string; content: string; from: string };
      ok('the spooled file: the message as inbox gives it, its id the file name', task.content === 'a task for later' && `${task.id}.json` === spooled()[0] && task.from === D.mine, JSON.stringify(task));
      // inbox beside a spooling watcher (the service): it takes what was spooled, files deleted, no login (which would evict it).
      const fromSpool = await cli('alice', 'inbox', '--tier', 'own');
      const fs1 = (JSON.parse(fromSpool.stdout) as { messages: { id: string; content: string }[] }).messages;
      ok('inbox beside the spooling watcher: the spooled message, taken (its file deleted), said', fs1.length === 1 && fs1[0]!.id === task.id && fs1[0]!.content === 'a task for later' && spooled().length === 0
        && fromSpool.stderr.includes('from the watcher\'s spool') && w2.c.exitCode === null, fromSpool.stdout + fromSpool.stderr);
      ok('and a second inbox has none left', (JSON.parse((await cli('alice', 'inbox', '--tier', 'own')).stdout) as { messages: unknown[] }).messages.length === 0);
      const rq = await cli('alice', 'reply', '--to', task.id, 'done:', 'the task');
      ok('reply --to <id> beside the watcher: queued for it (exit 0)', rq.status === 0 && (JSON.parse(rq.stdout) as { status: string; msg_id: string }).status === 'queued'
        && (JSON.parse(rq.stdout) as { msg_id: string }).msg_id === task.id && rq.stderr.includes('reply: queued for sigelo-agent watch'), rq.stdout + rq.stderr);
      const answer = await mineIn('done: the task');
      ok('the reply reaches the sender, labelled reply', answer.some((m) => m.content === 'done: the task' && m.label === 'reply'), JSON.stringify(answer));
      type St = { reply: { status: string; published_at: number | null; parts: number } | null; fetched: null; from: string; name: string };
      let st: St = { reply: null, fetched: null, from: '', name: '' };
      for (const t = Date.now(); Date.now() - t < 20000 && st.reply?.status !== 'published';) {
        st = JSON.parse((await cli('alice', 'reply', '--to', task.id, '--status')).stdout || '{}') as St;
        if (st.reply?.status !== 'published') await new Promise((r) => setTimeout(r, 500));
      }
      ok('reply --to <id> --status beside the watcher: published (the relay holds it), fetched null (no read receipt), the sender', st.reply?.status === 'published' && typeof st.reply.published_at === 'number'
        && st.fetched === null && st.from === D.mine && st.name === 'mine', JSON.stringify(st));
      w2.c.kill('SIGTERM');
      await w2.exit;
      w2 = null;
      // Without a watcher: reply logs in and sends; the earlier hook's message is answered by its id too.
      const r2 = await cli('alice', 'reply', '--to', slowId, 'the slow result', '--label', 'result');
      ok('reply --to <id> alone: sent', r2.status === 0 && (JSON.parse(r2.stdout) as { status: string; delivery: { status: string } }).status === 'sent'
        && (JSON.parse(r2.stdout) as { delivery: { status: string } }).delivery.status === 'published', r2.stdout + r2.stderr);
      ok('the slow task\'s answer reaches it, with its label', (await mineIn('the slow result')).some((m) => m.content === 'the slow result' && m.label === 'result'));
      const s2 = await cli('alice', 'reply', '--to', slowId, '--status');
      ok('reply --status: one line for people too', s2.status === 0 && s2.stderr.includes(`reply to ${slowId} (mine): published `) && s2.stderr.includes('fetched: not known (sigelo/0 has no read receipt)'), s2.stderr);
      writeFileSync(join(H, 'result.txt'), 'a result file\n');
      const rf = await cli('alice', 'reply', '--to', slowId, '--file', join(H, 'result.txt'));
      ok('reply --to <id> --file: the file to the sender', rf.status === 0 && (JSON.parse(rf.stdout) as { file: { name: string } }).file.name === 'result.txt', rf.stdout + rf.stderr);
      const unknown = await cli('alice', 'reply', '--to', '0'.repeat(32), 'hello'), malformed = await cli('alice', 'reply', '--to', 'nope', 'hello'), noTo = await cli('alice', 'reply', 'hello');
      ok('reply: an unknown id → exit 1, msg_unknown; a malformed one → msg_id; no --to → exit 2', unknown.status === 1 && unknown.stderr.includes('msg_unknown') && malformed.status === 1 && malformed.stderr.includes('a message id is 32 hex digits') && noTo.status === 2,
        unknown.stderr + malformed.stderr + noTo.stderr);
      const hist = (JSON.parse((await cli('alice', 'history')).stdout) as { messages: { id?: string; content?: unknown }[] }).messages;
      ok('history: each message with its id, the same as the hook and the spool saw', hist.find((m) => m.content === 'a slow task')?.id === slowId && hist.find((m) => m.content === 'a task for later')?.id === task.id, JSON.stringify(hist.map((m) => m.id)));
      // invite --ttl: 60 s to an hour for a short code (a slow agent), refused before any login otherwise.
      for (const t of ['30', '2h', 'soon']) {
        const iv = await cli('alice', 'invite', '--ttl', t);
        ok(`invite --ttl ${t} → exit 2`, iv.status === 2 && iv.stderr.includes('--ttl'), iv.stderr);
      }
      const hourly = await cli('alice', 'invite', '--ttl', '1h', '--json'), hj = JSON.parse(hourly.stdout || '{}') as { short_exp?: number; exp?: number };
      ok('invite --ttl 1h: a short code for an hour, said so', hourly.status === 0 && Math.abs((hj.short_exp ?? 0) - Date.now() / 1000 - 3600) < 30 && hourly.stderr.includes('good for 1 hour'), hourly.stdout + hourly.stderr);
      const fr = await cli('alice', 'inbox', '--tier', 'own,friend');
      const frm = (JSON.parse(fr.stdout) as { messages: { content: string }[] }).messages.map((m) => m.content);
      ok('inbox --tier own,friend: the friend\'s two messages; the quiet ones stay', frm.join() === 'hello from pal,again from pal', fr.stdout);
      ok('inbox --tier: a bad tier → exit 2', (await cli('alice', 'inbox', '--tier', 'vip')).status === 2);
      const qt = await cli('alice', 'inbox', '--tier', 'friend', '--quiet-too');
      ok('inbox --tier friend --quiet-too: the quiet contact\'s two', (JSON.parse(qt.stdout) as { messages: { content: string }[] }).messages.map((m) => m.content).join() === 'hello from hotel,again from hotel', qt.stdout);
      ok('inbox: then nothing', (JSON.parse((await cli('alice', 'inbox')).stdout) as { messages: unknown[] }).messages.length === 0);
      // pro redeem: a gift code (apps/contact/short.mjs giftHash), loaded as the runbook loads one
      // (node relay/gifts.mjs load), redeemed by alice as the operator; once only.
      const { giftHash } = await import(pathToFileURL(join(ROOT, 'apps', 'contact', 'short.mjs')).href) as { giftHash(t: string): string };
      const exp = Math.floor(Date.now() / 86400000) * 86400 + 30 * 86400;
      writeFileSync(join(H, 'gifts.jsonl'), `${JSON.stringify({ code_hash: giftHash('PRO-K7F3-Q9ZP'), months: 6, expires: exp, campaign: 'test' })}\n`);
      const load = spawnSync('node', [join(RELAY, 'gifts.mjs'), 'load', join(H, 'gifts.jsonl')], { env: { ...process.env, RELAY_DB: join(H, 'relay.db') }, encoding: 'utf8' });
      ok('pro redeem: a gift code loaded into the test relay', load.status === 0 && load.stdout.includes('1 codes loaded'), load.stderr);
      const pr = await cli('alice', 'pro', 'redeem', 'pro', 'k7f3', 'q9zp'), pj = JSON.parse(pr.stdout || '{}') as { operator?: string; months?: number; pro_until?: string; relay?: string };
      const aliceDid = await didOf('alice');
      ok('pro redeem, typed in lowercase, in three pieces: exit 0, the operator (alice\'s original DID), 6 months, the Pro expiry on stdout and stderr',
        pr.status === 0 && pj.operator === aliceDid && pj.months === 6 && pj.relay === 'relay.test' && /^\d{4}-\d\d-\d\dT00:00:00Z$/.test(pj.pro_until ?? '')
        && pr.stderr.includes(`Pro until ${pj.pro_until} at relay.test for the pool of ${aliceDid} (6 months added)`), pr.stdout + pr.stderr);
      const again = await cli('alice', 'pro', 'redeem', 'PRO-K7F3-Q9ZP');
      ok('pro redeem, the same code again: exit 1, "gift", and no code in the relay\'s words', again.status === 1 && again.stderr.includes('gift: the relay refused the gift code') && !/K7F3/i.test(again.stderr.replace(/redeem PRO-K7F3-Q9ZP/g, '')), again.stderr);
      const typo = await cli('alice', 'pro', 'redeem', 'PRO-K7F3-U9ZP');
      ok('pro redeem, a code with a U: exit 1, gift_code, before any login', typo.status === 1 && typo.stderr.includes('gift_code: not a gift code') && typo.stderr.includes('character 5'), typo.stderr);
      ok('pro <anything but redeem>: exit 2, usage', (await cli('alice', 'pro', 'renew', 'PRO-K7F3-Q9ZP')).status === 2);
    } finally {
      w1?.c.kill('SIGTERM'); w2?.c.kill('SIGTERM');
      await relay.close?.();
      rmSync(H, { recursive: true, force: true });
    }
  }
}

// ── service (sigelo-agent-service.ts, WATCH.md "Always on"): the unit written and read back, nothing installed ──────
// SIGELO_SERVICE_DIR: a temporary directory; SIGELO_SERVICE_DRY=1: no systemctl, what would run printed.
{
  const S = await import('./sigelo-agent-service.ts');
  const H = tmpHome('service'), id = join(H, 'my agent %1.local.json');
  const p = S.planFor(id, undefined, { SIGELO_RELAY: 'relay.example', SIGELO_SECRET_THING: 'x', SIGELO_NAME: 'Ana "the" agent' } as NodeJS.ProcessEnv, CLI);
  const u = S.unitOf(p), back = S.parseUnit(u);
  ok('service: the unit runs watch --identity <file> --spool <file>.spool --quiet, read back word for word (spaces, %, quotes)',
    JSON.stringify(back.exec) === JSON.stringify([process.execPath, CLI, 'watch', '--identity', id, '--spool', join(H, 'my agent %1.local.spool'), '--quiet']), JSON.stringify(back.exec));
  ok('service: SIGELO_IDENTITY set, the relay kept, nothing else of the environment', back.env['SIGELO_IDENTITY'] === id && back.env['SIGELO_RELAY'] === 'relay.example' && back.env['SIGELO_NAME'] === 'Ana "the" agent' && !('SIGELO_SECRET_THING' in back.env), JSON.stringify(back.env));
  ok('service: Restart=always, RestartSec=15, after network-online.target, WantedBy=default.target', back.restart === 'always' && u.includes('RestartSec=15') && u.includes('After=network-online.target') && back.wanted === 'default.target');
  const pl = S.plistOf(p);
  ok('service: the macOS LaunchAgent: RunAtLoad, KeepAlive, the same arguments, XML-escaped', pl.includes('<key>KeepAlive</key><true/>') && pl.includes('<key>RunAtLoad</key><true/>') && pl.includes('&quot;') === false && pl.includes('Ana "the" agent') && pl.includes(`<string>${CLI}</string>`));
  ok('service: Windows: the schtasks command, ONLOGON', /^schtasks \/Create \/SC ONLOGON .*\/TN sigelo-watch-[0-9a-f]{8} \/TR ".*watch --identity .*--quiet"$/.test(S.schtasksOf(p)), S.schtasksOf(p));
  const ph = S.planFor(id, undefined, { PATH: '/usr/bin:/x', SIGELO_RELAY: 'relay.example', SIGELO_SECRET_THING: 'x' } as NodeJS.ProcessEnv, CLI, { host: 'claude', cwd: H }), bh = S.parseUnit(S.unitOf(ph));
  ok('service --host claude: the unit runs host claude --identity --spool --cwd --quiet, PATH kept (the SDK finds claude), no secret',
    JSON.stringify(bh.exec) === JSON.stringify([process.execPath, CLI, 'host', 'claude', '--identity', id, '--spool', join(H, 'my agent %1.local.spool'), '--cwd', H, '--quiet'])
      && bh.env['PATH'] === '/usr/bin:/x' && !('SIGELO_SECRET_THING' in bh.env) && S.unitOf(ph).includes('(sigelo-agent host claude)') && !('PATH' in back.env), JSON.stringify(bh));
  const ps = S.planFor(id, undefined, {} as NodeJS.ProcessEnv, CLI, { host: 'claude', cwd: H, skipPermissions: true });
  ok('service --host claude --dangerously-skip-permissions: the flag in the unit, before --quiet', S.parseUnit(S.unitOf(ps)).exec.slice(-2).join(' ') === '--dangerously-skip-permissions --quiet');
  const pq = S.planFor(id, undefined, {} as NodeJS.ProcessEnv, CLI, { host: 'claude', cwd: H, quietProgress: true, others: 'data' });
  ok('service --host claude --quiet-progress --others data: passed through into the unit', S.parseUnit(S.unitOf(pq)).exec.slice(-4).join(' ') === '--quiet-progress --others data --quiet');
  ok('service: one name per identity: 8 hex of its path\'s sha256 (unit, LaunchAgent label, task); another file, another name',
    /^sigelo-watch-[0-9a-f]{8}\.service$/.test(S.namesOf(id).unit) && S.namesOf(id).label === `io.sigelo.watch.${S.tagOf(id)}` && S.namesOf(id).task === `sigelo-watch-${S.tagOf(id)}` && S.tagOf(id) !== S.tagOf(`${id}2`) && S.plistOf(p).includes(`<string>io.sigelo.watch.${S.tagOf(id)}</string>`));
  {
    // A fake systemctl and launchctl on a temp PATH (no SIGELO_SERVICE_DRY): each call recorded; is-active answers
    // active for the units named in $D/active; launchctl print answers for the labels in it.
    // SIGELO_SERVICE_OS=linux: the systemd branch on any machine (Windows too); the fakes are Node scripts (fakeExe).
    const env0 = { PATH: process.env['PATH'] ?? '', HOME: H, SIGELO_KEY_PROVIDER: 'file', SIGELO_SERVICE_DIR: join(H, 'units'), SIGELO_SERVICE_OS: 'linux' };
    const fb = join(H, 'fakebin');
    mkdirSync(fb, { recursive: true });
    for (const t of ['systemctl', 'launchctl']) fakeExe(fb, t, `const fs = require('fs'), path = require('path'), d = __dirname, a = process.argv.slice(2);
fs.appendFileSync(path.join(d, 'calls'), ${JSON.stringify(t)} + ' ' + a.join(' ') + '\\n');
if (a.includes('is-active') || a.includes('print')) {
  let on = [];
  try { on = fs.readFileSync(path.join(d, 'active'), 'utf8').split('\\n'); } catch {}
  const n = a[a.length - 1].split('/').pop();
  console.log(on.includes(n) ? 'active' : 'inactive');
  process.exit(on.includes(n) ? 0 : 3);
}
`);
    const calls = (): string => { try { return readFileSync(join(fb, 'calls'), 'utf8'); } catch { return ''; } };
    const A = join(H, 'a.local.json'), B = join(H, 'b.local.json');
    const runA = cliIn({ ...env0, PATH: `${fb}${delimiter}${env0.PATH}`, SIGELO_IDENTITY: A }, H), runB = cliIn({ ...env0, PATH: `${fb}${delimiter}${env0.PATH}`, SIGELO_IDENTITY: B }, H);
    await runA('init', '--no-recovery'); await runB('init', '--no-recovery');
    // An install from before: the legacy fixed name, for A.
    mkdirSync(join(H, 'units'), { recursive: true });
    writeFileSync(join(H, 'units', 'sigelo-watch.service'), S.unitOf(S.planFor(A, undefined, {} as NodeJS.ProcessEnv, CLI)));
    const ia = await runA('service', 'install'), ib = await runB('service', 'install', '--host', 'claude', '--cwd', H, '--dangerously-skip-permissions');
    const nb = S.namesOf(B).unit;
    ok('service install: A\'s legacy unit kept under its name (rewritten, restarted); B gets its own, sigelo-watch-<tag>.service, the skip flag in it',
      ia.status === 0 && ia.stdout.includes('sigelo-watch.service (the name of an earlier install, kept)') && !existsSync(join(H, 'units', S.namesOf(A).unit)) && calls().includes('systemctl --user enable --now sigelo-watch.service')
        && calls().includes('systemctl --user restart sigelo-watch.service') && ib.status === 0 && existsSync(join(H, 'units', nb)) && calls().includes(`systemctl --user enable --now ${nb}`)
        && S.parseUnit(readFileSync(join(H, 'units', nb), 'utf8')).exec.includes('--dangerously-skip-permissions') && ib.stdout.includes(`journalctl --user -u ${nb.replace('.service', '')}`), ia.stdout + ia.stderr + ib.stdout + ib.stderr);
    writeFileSync(join(fb, 'active'), `${nb}\n`);
    const st = await runA('service', 'status'), sj = JSON.parse(st.stdout) as { unit: string; legacy: boolean; installed: boolean; active: string; units: { name: string; identity: string; runs: string; legacy: boolean; active: string; mine: boolean }[] };
    ok('service status: every sigelo unit listed (the legacy one, B\'s), each with its identity, what it runs, active or not; A\'s marked',
      st.status === 3 && sj.unit === 'sigelo-watch.service' && sj.legacy && sj.installed && sj.active === 'inactive' && sj.units.length === 2
        && sj.units.some((x) => x.name === 'sigelo-watch.service' && x.legacy && x.identity === A && x.runs === 'watch' && x.mine && x.active === 'inactive')
        && sj.units.some((x) => x.name === nb && !x.legacy && x.identity === B && x.runs === 'host claude' && !x.mine && x.active === 'active'), st.stdout + st.stderr);
    const ra = await runA('service', 'remove'), rb = await runB('service', 'remove');
    ok('service remove: A\'s legacy unit removed (the one that exists), B\'s own; disable --now each', ra.status === 0 && rb.status === 0 && readdirSync(join(H, 'units')).length === 0
      && calls().includes('systemctl --user disable --now sigelo-watch.service') && calls().includes(`systemctl --user disable --now ${nb}`), ra.stdout + rb.stdout);
    ok('service remove with nothing installed: said, exit 0', (await runA('service', 'remove')).stdout.includes('nothing removed'));
    // macOS, on this machine (SIGELO_SERVICE_OS=darwin): the LaunchAgent per identity, launchctl faked.
    const runM = cliIn({ ...env0, PATH: `${fb}${delimiter}${env0.PATH}`, SIGELO_IDENTITY: A, SIGELO_SERVICE_OS: 'darwin' }, H), la = S.namesOf(A).label;
    const im = await runM('service', 'install');
    writeFileSync(join(fb, 'active'), `${la}\n`);
    const sm = JSON.parse((await runM('service', 'status')).stdout) as { unit: string; active: boolean; units: { name: string }[] };
    const rm2 = await runM('service', 'remove');
    ok('service on macOS: io.sigelo.watch.<tag>.plist, launchctl bootstrap; status lists it, loaded; remove: bootout, gone',
      im.status === 0 && calls().includes(`launchctl bootstrap gui/${process.getuid?.() ?? 0} ${join(H, 'units', `${la}.plist`)}`) && sm.unit === la && sm.active === true && sm.units.length === 1
        && rm2.status === 0 && calls().includes(`launchctl bootout gui/${process.getuid?.() ?? 0}/${la}`) && !existsSync(join(H, 'units', `${la}.plist`)), im.stdout + im.stderr + JSON.stringify(sm));
    const w = await cliIn({ ...env0, SIGELO_IDENTITY: A, SIGELO_SERVICE_OS: 'win32' }, H)('service', 'install');
    ok('service on Windows: the schtasks step printed with the identity\'s task name', w.status === 0 && w.stdout.includes(`/TN ${S.namesOf(A).task} /TR`), w.stdout);
  }
  if (process.platform === 'linux') {
    const env = { PATH: process.env['PATH'] ?? '', HOME: H, SIGELO_KEY_PROVIDER: 'file', SIGELO_IDENTITY: join(H, 'svc.local.json'), SIGELO_SERVICE_DIR: join(H, 'units'), SIGELO_SERVICE_DRY: '1' };
    const run = cliIn(env, H);
    const none = await run('service', 'install');
    await run('init', '--no-recovery');
    const ins = await run('service', 'install');
    const un = S.namesOf(join(H, 'svc.local.json')).unit, unit = join(H, 'units', un);
    ok('service install: refused with no identity; then the unit written, systemctl --user daemon-reload and enable --now (dry), how to check, linger',
      none.status === 2 && ins.status === 0 && existsSync(unit) && ins.stderr.includes(`(dry run) systemctl --user enable --now ${un}`) && ins.stdout.includes(`journalctl --user -u ${un.replace('.service', '')}`) && ins.stdout.includes('loginctl enable-linger')
      && S.parseUnit(readFileSync(unit, 'utf8')).exec.includes(join(H, 'svc.local.spool')), ins.stdout + ins.stderr);
    const st = await run('service', 'status');
    ok('service status: installed, no watcher now (exit 3, said)', st.status === 3 && (JSON.parse(st.stdout) as { installed: boolean; listening: boolean }).installed === true && st.stderr.includes('no watcher holds'), st.stdout + st.stderr);
    const rm = await run('service', 'remove');
    ok('service remove: the unit gone, disable --now (dry)', rm.status === 0 && !existsSync(unit) && rm.stderr.includes(`systemctl --user disable --now ${un}`), rm.stdout + rm.stderr);
    ok('service: a bad subcommand, or --dangerously-skip-permissions without --host → exit 2', (await run('service', 'start')).status === 2 && (await run('service', 'install', '--dangerously-skip-permissions')).status === 2);
    const hi = await run('service', 'install', '--host', 'claude', '--cwd', H);
    const HS = await import('./sigelo-agent-host.ts'), sdkHere = await import(HS.SDK_MODULE).then(() => true, () => false);
    ok(`service install --host claude: the unit runs host claude in --cwd (dry)${sdkHere ? '' : '; without the SDK said, written all the same (host keeps the listener)'}`,
      hi.status === 0 && S.parseUnit(readFileSync(unit, 'utf8')).exec.slice(2, 4).join(' ') === 'host claude' && hi.stdout.includes('sigelo-agent host claude for') && (sdkHere || (hi.stderr.includes(HS.SDK_MISSING) && hi.stderr.includes('keeps the listener'))), hi.stdout + hi.stderr);
    ok('service install: --host other than claude, or --cwd without --host → exit 2', (await run('service', 'install', '--host', 'codex')).status === 2 && (await run('service', 'install', '--cwd', H)).status === 2);
    await run('service', 'remove');
    rmSync(H, { recursive: true, force: true });
  }
}

done(import.meta.filename);
