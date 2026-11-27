// SPDX-License-Identifier: MIT
// Voice messages (voice.mjs, voice-web.mjs, transfer-node.mjs voiceFiles): the
// sigelo-voice/0 message's shape and checks, the line the CLI and MCP print, a group msg's voice, the
// recorder over a fake MediaRecorder (format, duration, waveform, cancel, the refusals), and the
// computer's recordings on disk (pieces, kept outside the files received, read back only from its own).
//   node apps/contact/test-voice.mjs   → ALL PASS (n)
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { VOICE_LABEL, VOICE_MAX_S, checkVoice, clock, peaksOf, voiceItems, voiceLine, voiceName } from './voice.mjs';
import { canRecord, downsample, record, recorderType, sniff } from './voice-web.mjs';
import { GROUP_V, checkBody } from './group.mjs';
import { voiceFiles } from './transfer-node.mjs';
import { sendable } from './platform-node.mjs';

let count = 0;
const fails = [];
const ok = (cond, what, more) => { count++; if (!cond) fails.push(more === undefined ? what : `${what} (${String(more).slice(0, 600)})`); };
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.constructor.name}: ${e.message}`; } };
const failure = async (f) => { try { await f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.message}`; } };

// ---- the message
const SHA = 'ab'.repeat(32), WAVE = Buffer.from([0, 40, 255, 128]).toString('base64');
const V = { name: 'voice-20261117-142301.webm', size: 21000, type: 'audio/webm', sha256: SHA, duration_s: 42, waveform: WAVE };
ok(VOICE_LABEL === 'sigelo-voice/0' && VOICE_MAX_S === 300, 'the label sigelo-voice/0; at most 300 s');
ok(JSON.stringify(checkVoice(V)) === JSON.stringify(V), 'a voice message with a waveform: accepted as it is');
const { waveform: _w, ...noWave } = V;
ok(checkOf(() => checkVoice(noWave)) === 'accepted' && !('waveform' in checkVoice(noWave)), 'the waveform is optional');
const bad = [
  [null, 'not an object'], [[], 'an array'], [{ ...V, data: 'AAAA' }, 'audio inline (data)'], [{ ...V, extra: 1 }, 'an extra key'],
  [{ ...V, type: 'audio/mpeg' }, 'type audio/mpeg'], [{ ...V, type: 'audio/webm;codecs=opus' }, 'a type with its codecs'],
  [{ ...V, name: '' }, 'an empty name'], [{ ...V, name: '../x.webm' }, 'a name with a slash'], [{ ...V, name: 'x'.repeat(256) }, 'a name of 256'],
  [{ ...V, size: 0 }, 'size 0'], [{ ...V, size: 16 * 2 ** 20 + 1 }, 'size over 16 MiB'], [{ ...V, size: 1.5 }, 'a float size'],
  [{ ...V, sha256: 'AB'.repeat(32) }, 'sha256 upper case'], [{ ...V, sha256: 'ab' }, 'sha256 short'],
  [{ ...V, duration_s: 0 }, 'duration 0'], [{ ...V, duration_s: 301 }, 'duration 301'], [{ ...V, duration_s: 4.2 }, 'a float duration (no floats)'],
  [{ ...V, waveform: '' }, 'an empty waveform'], [{ ...V, waveform: Buffer.alloc(65).toString('base64') }, 'a waveform of 65 bytes'],
  [{ ...V, waveform: [1, 2] }, 'a waveform as a list'], [{ ...V, waveform: 'a!==' }, 'a waveform not base64'],
];
for (const [x, what] of bad) ok(checkOf(() => checkVoice(x)) === 'voice', `checkVoice refuses ${what}: check voice`, checkOf(() => checkVoice(x)));
ok(checkOf(() => checkVoice({ ...V, waveform: Buffer.alloc(64, 7).toString('base64') })) === 'accepted', 'a waveform of 64 bytes: accepted');
ok(peaksOf(V).join() === '0,40,255,128' && peaksOf(noWave).length === 0, 'peaksOf: the waveform as numbers, [] without one');
ok(clock(42) === '0:42' && clock(300) === '5:00' && clock(61) === '1:01', 'clock: m:ss');
ok(voiceName(new Date(2026, 10, 17, 14, 23, 1), 'audio/webm') === 'voice-20261117-142301.webm' && voiceName(new Date(2026, 0, 2, 3, 4, 5), 'audio/mp4') === 'voice-20260102-030405.m4a'
  && voiceName(new Date(2026, 0, 2, 3, 4, 5), 'audio/ogg').endsWith('.ogg'), 'voiceName: voice-<date>-<time>.<webm|m4a|ogg>');
ok(voiceLine(V) === '[voice 0:42 voice-20261117-142301.webm]', 'voiceLine: [voice 0:42 <name>]');

// ---- what the CLI and the MCP print
{
  const batch = { messages: [{ id: 'a', from: 'did:x', label: VOICE_LABEL, content: V }, { id: 'b', label: '', content: 'hi' }, { id: 'c', label: VOICE_LABEL, content: { ...V, duration_s: 0 } },
    { id: 'd', label: 'sigelo-group/1', content: 'Voice message', voice: V }], events: [{ type: 'paired' }] };
  const r = voiceItems(batch);
  ok(r.messages[0].text === '[voice 0:42 voice-20261117-142301.webm]' && r.messages[0].voice.sha256 === SHA && r.messages[0].content === V, 'voiceItems: a voice message gains text [voice 0:42 name] and its fields (voice); content kept');
  ok(r.messages[1] === batch.messages[1] && r.events === batch.events, 'voiceItems: other messages and the events as they were');
  ok(r.messages[2].voice_error?.includes('duration_s') && r.messages[2].text === undefined, 'voiceItems: one that does not check says why (voice_error), no line');
  const caps = { label: 'sigelo-host-caps/0', content: { v: 'sigelo-host-caps/0', model: { value: 'x' } } };
  const rc = voiceItems({ messages: [caps], events: [] }).messages[0];
  ok(rc.data === 'sigelo-host-caps/0' && /data, not a message/.test(rc.text) && rc.content === caps.content, 'voiceItems: a sigelo-host-caps/0 message is marked data with one line, content kept');
  ok(r.messages[3].text === voiceLine(V) && r.messages[3].voice.duration_s === 42, 'voiceItems: a group msg with a voice gets the line too');
}

// ---- a group's msg
{
  const D0 = 'did:sigelo:z' + '1'.repeat(44), msg = { v: GROUP_V, typ: 'msg', gid: '0'.repeat(32), mid: '1'.repeat(16), iat: 1_800_000_000, from: D0, text: 'Voice message' };
  ok(checkOf(() => checkBody({ ...msg, voice: V })) === 'accepted', 'a group msg with a voice: accepted');
  ok(checkOf(() => checkBody({ ...msg, voice: { ...V, duration_s: 999 } })) === 'group_message', 'a group msg with a bad voice: group_message');
}

// ---- the recorder over a fake MediaRecorder
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const WEBM = Uint8Array.from([0x1a, 0x45, 0xdf, 0xa3, 1, 2, 3, 4, 5, 6]), MP4 = Uint8Array.from([0, 0, 0, 24, 0x66, 0x74, 0x79, 0x70, 0x4d, 0x34, 0x41]);
function fakeEnv({ supported = ['audio/webm;codecs=opus'], bytes = WEBM, deny = null, audio = true, level = 60 } = {}) {
  const env = { stopped: 0, asked: null, made: null };
  class Rec {
    static isTypeSupported(t) { return supported.includes(t); }
    constructor(stream, o) { this.mimeType = o?.mimeType ?? 'audio/webm'; this.state = 'inactive'; this.opts = o; env.made = this; }
    start(ms) { this.state = 'recording'; this.slice = ms; }
    stop() { this.state = 'inactive'; setTimeout(() => { this.ondataavailable?.({ data: new Blob([bytes.subarray(0, 4)]) }); this.ondataavailable?.({ data: new Blob([bytes.subarray(4)]) }); this.onstop?.(); }, 5); }
  }
  class AC {
    createAnalyser() { return { fftSize: 0, getByteTimeDomainData(b) { b.fill(128); b[3] = 128 + level; } }; }
    createMediaStreamSource() { return { connect() {} }; }
    close() { env.closed = true; }
  }
  Object.assign(env, {
    navigator: { mediaDevices: { getUserMedia: async (c) => { env.asked = c; if (deny) throw Object.assign(new Error(deny), { name: deny }); return { getTracks: () => [{ stop: () => { env.stopped++; } }] }; } } },
    MediaRecorder: Rec, Blob, ...(audio && { AudioContext: AC }),
  });
  return env;
}
{
  ok(recorderType(fakeEnv().MediaRecorder) === 'audio/webm;codecs=opus' && recorderType(fakeEnv({ supported: ['audio/mp4', 'audio/ogg;codecs=opus'] }).MediaRecorder) === 'audio/mp4'
    && recorderType(fakeEnv({ supported: ['audio/ogg;codecs=opus'] }).MediaRecorder) === 'audio/ogg;codecs=opus' && recorderType(fakeEnv({ supported: [] }).MediaRecorder) === null,
  'the format: webm/opus where the recorder has it, else mp4 (AAC), else ogg/opus, else its own');
  ok(canRecord(fakeEnv()) && !canRecord({ navigator: {} }) && !canRecord({}), 'canRecord: getUserMedia and MediaRecorder both');
  ok(sniff(WEBM) === 'audio/webm' && sniff(MP4) === 'audio/mp4' && sniff(Uint8Array.from([0x4f, 0x67, 0x67, 0x53, 0])) === 'audio/ogg' && sniff(Uint8Array.from([1, 2, 3, 4, 5])) === null, 'sniff: webm, mp4, ogg by their first bytes');
  const d = downsample(Array.from({ length: 640 }, (_, i) => (i === 5 ? 250 : i % 10)));
  ok(d.length === 64 && d[0] === 250 && d[1] === 9, 'downsample: 640 levels → 64 peaks, the loudest of each stretch', [...d.slice(0, 3)]);
  ok(downsample([1, 2, 3]).join() === '1,2,3', 'downsample: fewer than 64 kept as they are');

  let t = 1_000_000;
  const env = fakeEnv(), ticks = [];
  const r = await record({ env, now: () => t, onTick: (x) => ticks.push(x) });
  ok(env.asked?.audio === true && env.made?.opts?.mimeType === 'audio/webm;codecs=opus' && env.made.state === 'recording', 'record: getUserMedia({audio: true}), MediaRecorder with webm/opus, started at once');
  await sleep(450);
  t += 42_400;
  ok(ticks.length >= 2 && ticks.at(-1).level === 120, 'record: ticks with the level while it records', JSON.stringify(ticks.slice(-1)));
  const out = await r.stop();
  ok(out.type === 'audio/webm' && out.bytes.length === WEBM.length && out.duration_s === 42 && /^voice-\d{8}-\d{6}\.webm$/.test(out.name), `stop: the bytes, audio/webm, 42 s, voice-<date>.webm (${out.name})`);
  ok(typeof out.waveform === 'string' && checkOf(() => checkVoice({ name: out.name, size: out.bytes.length, type: out.type, sha256: SHA, duration_s: out.duration_s, waveform: out.waveform })) === 'accepted',
    'stop: a waveform that checks as sigelo-voice/0\'s');
  ok(env.stopped === 1 && env.closed === true, 'stop: the microphone let go (the track stopped, the audio context closed)');

  // MP4 where the recorder says webm: the bytes decide.
  const e2 = fakeEnv({ supported: ['audio/mp4'], bytes: MP4, audio: false });
  const r2 = await record({ env: e2 });
  const o2 = await r2.stop();
  ok(o2.type === 'audio/mp4' && o2.name.endsWith('.m4a') && o2.duration_s === 1 && o2.waveform === undefined, 'AAC (WebKit): audio/mp4, .m4a; under a second counts 1; no Web Audio: no waveform');
  // The five minutes: it stops by itself.
  let t3 = 0;
  const r3 = await record({ env: fakeEnv(), now: () => t3, max: 300 });
  t3 = 301_000;
  await sleep(450);
  const o3 = await r3.done;
  ok(o3?.duration_s === 300, 'at 5:00 it stops by itself (300 s)', JSON.stringify(o3?.duration_s));
  // Cancel: nothing kept.
  const e4 = fakeEnv(), r4 = await record({ env: e4 });
  r4.cancel();
  ok((await r4.stop()) === null && e4.stopped === 1, 'cancel: nothing kept, the microphone let go');
  ok(await failure(() => record({ env: fakeEnv({ deny: 'NotAllowedError' }) })) === 'mic_permission', 'the microphone refused: mic_permission');
  ok(await failure(() => record({ env: fakeEnv({ deny: 'NotFoundError' }) })) === 'no_mic', 'no microphone: no_mic');
  ok(await failure(() => record({ env: { navigator: {} } })) === 'no_recorder', 'no MediaRecorder: no_recorder');
}

// ---- the computer's recordings (the `ui` server's hooks.transfers.rec)
{
  const dir = mkdtempSync(join(tmpdir(), 'sigelo-voice-')), identity = join(dir, 'me.local.json');
  writeFileSync(identity, '{}');
  const R = voiceFiles(identity), rec = 'cd'.repeat(16);
  await R.write(rec, 0, WEBM.subarray(0, 6));
  await R.write(rec, 6, WEBM.subarray(6));
  const { path } = await R.keep(rec, 'voice-20261117-142301.webm');
  ok(path === join(dir, 'me.local.voice', 'voice-20261117-142301.webm') && Buffer.compare(readFileSync(path), Buffer.from(WEBM)) === 0 && (statSync(path).mode & 0o777) === 0o600,
    'pieces at their offsets, kept whole as <identity>.voice/<name>, 0600', path);
  ok(checkOf(() => sendable(path, { base: join(dir, 'me.local'), files: join(dir, 'me.local.files'), log: join(dir, 'me.local.inbox.log') }, 16 * 2 ** 20)) === 'accepted',
    'the kept recording is sendable (not one of the identity\'s files)');
  await R.write(rec, 0, WEBM);
  const again = await R.keep(rec, 'voice-20261117-142301.webm');
  ok(again.path.endsWith('voice-20261117-142301 (2).webm'), 'the same name again: (2)');
  ok(await failure(() => R.keep('ef'.repeat(16), 'x.webm')) === 'voice' && await failure(() => R.write('nothex', 0, WEBM)) === 'usage', 'keep with no pieces: voice; a rec not 32 hex: usage');
  mkdirSync(join(dir, 'me.local.files', 'bo-1'), { recursive: true });
  const landed = join(dir, 'me.local.files', 'bo-1', 'abcd-voice.webm');
  writeFileSync(landed, WEBM);
  ok(Buffer.compare(Buffer.from(await R.read(landed)), Buffer.from(WEBM)) === 0, 'read: a voice message that landed under the identity\'s files');
  ok(await failure(() => R.read(identity)) === 'voice' && await failure(() => R.read(join(dir, 'me.local.files', '..', 'me.local.json'))) === 'voice', 'read: nothing else (the identity, a path climbing out)');
  rmSync(dir, { recursive: true, force: true });
  ok(!existsSync(dir), 'cleaned');
}

for (const f of fails) console.log('FAIL ' + f);
if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
console.log(`ALL PASS (${count})`);
