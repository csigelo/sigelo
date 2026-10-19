// SPDX-License-Identifier: MIT
// sigelo-agent watch and the tiers (WATCH.md, contact/store.mjs).
//   node test-watch.ts   (SKIPs without relay/ and its node_modules)
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { CLI, RELAY, ROOT, cliIn, done, hasRelay, NO_RELAY, ok, startTestRelay, tmpHome } from './test-helpers.ts';

// ── tiers and watch (contact/store.mjs tiers, sigelo-agent-watch.ts, WATCH.md) ───────────────
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
    const envOf = (n: string): Record<string, string> => ({ PATH: process.env['PATH'] ?? '', SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_IDENTITY: join(H, `${n}.local.json`), SIGELO_RELAY: 'relay.test', SIGELO_RELAY_ENDPOINTS: endpoints, WOUT: OUT });
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
      const fr = await cli('alice', 'inbox', '--tier', 'own,friend');
      const frm = (JSON.parse(fr.stdout) as { messages: { content: string }[] }).messages.map((m) => m.content);
      ok('inbox --tier own,friend: the friend\'s two messages; the quiet ones stay', frm.join() === 'hello from pal,again from pal', fr.stdout);
      ok('inbox --tier: a bad tier → exit 2', (await cli('alice', 'inbox', '--tier', 'vip')).status === 2);
      const qt = await cli('alice', 'inbox', '--tier', 'friend', '--quiet-too');
      ok('inbox --tier friend --quiet-too: the quiet contact\'s two', (JSON.parse(qt.stdout) as { messages: { content: string }[] }).messages.map((m) => m.content).join() === 'hello from hotel,again from hotel', qt.stdout);
      ok('inbox: then nothing', (JSON.parse((await cli('alice', 'inbox')).stdout) as { messages: unknown[] }).messages.length === 0);
      // pro redeem: a gift code (contact/short.mjs giftHash), loaded as the runbook loads one
      // (node relay/gifts.mjs load), redeemed by alice as the operator; once only.
      const { giftHash } = await import(pathToFileURL(join(ROOT, 'contact', 'short.mjs')).href) as { giftHash(t: string): string };
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

done(import.meta.filename);
