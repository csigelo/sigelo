// SPDX-License-Identifier: MIT
// Recording a voice message in the page (design/transfer.md "Voice"): the browser's MediaRecorder over
// getUserMedia({audio: true}); the same code in the Android WebView, WebKitGTK and a browser tab. Loaded by
// ui.js at the first Voice (`/voice-web.mjs`: the `ui` server, the app's import map). No dependency.
//
//   canRecord(env)           a microphone API here (getUserMedia and MediaRecorder)
//   const r = await record({ env, max, onTick })     starts at once; refused mic_permission | no_mic | no_recorder
//     r.elapsed() → s        r.stop() → { bytes, type, name, duration_s, waveform? }   r.cancel(): nothing kept
//     onTick({ elapsed, level, done }) every 200 ms; at max (300 s) it stops by itself (done: true; r.done: the stop's promise)
// Format: audio/webm;codecs=opus where the recorder has it (Chromium: the Android WebView, a Chrome tab), else
// audio/mp4 (AAC: WebKit, Safari), else audio/ogg;codecs=opus (Firefox); the file's kind read from its first
// bytes, whatever the recorder said. 32 kbit/s: five minutes are about 1.2 MB.
import { VOICE_EXT, VOICE_MAX_S, WAVE_MAX, voiceName } from './voice.mjs';
import { fail } from './kdf.mjs';

export const TYPES = ['audio/webm;codecs=opus', 'audio/mp4', 'audio/ogg;codecs=opus'];
const TICK_MS = 200, BITRATE = 32000;

/** The first of TYPES this recorder makes, or null (its own default then). */
export function recorderType(Rec) {
  for (const t of TYPES) { try { if (Rec?.isTypeSupported?.(t)) return t; } catch {} }
  return null;
}

export const canRecord = (env = globalThis) => typeof env?.navigator?.mediaDevices?.getUserMedia === 'function' && typeof env?.MediaRecorder === 'function';

/** The container by its first bytes: 'audio/webm' (EBML), 'audio/ogg' (OggS), 'audio/mp4' (ftyp), or null. */
export function sniff(b) {
  if (b.length > 4 && b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3) return 'audio/webm';
  if (b.length > 4 && b[0] === 0x4f && b[1] === 0x67 && b[2] === 0x67 && b[3] === 0x53) return 'audio/ogg';
  if (b.length > 8 && b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70) return 'audio/mp4';
  return null;
}

/** Levels (0 to 255, one per tick) as at most n peaks: the loudest of each stretch. */
export function downsample(levels, n = WAVE_MAX) {
  if (levels.length <= n) return Uint8Array.from(levels, (x) => Math.max(0, Math.min(255, Math.round(x))));
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    const a = Math.floor((i * levels.length) / n), z = Math.max(a + 1, Math.floor(((i + 1) * levels.length) / n));
    out[i] = Math.max(0, Math.min(255, Math.round(Math.max(...levels.slice(a, z)))));
  }
  return out;
}

const b64 = (bytes) => { let t = ''; for (const x of bytes) t += String.fromCharCode(x); return btoa(t); };

/** Starts recording now. → the handle (above); the microphone is let go at stop or cancel. */
export async function record({ env = globalThis, max = VOICE_MAX_S, onTick = () => {}, now = () => Date.now() } = {}) {
  if (!canRecord(env)) fail('no_recorder', 'this page cannot record sound');
  let stream;
  try { stream = await env.navigator.mediaDevices.getUserMedia({ audio: true }); } catch (e) {
    if (e?.name === 'NotAllowedError' || e?.name === 'SecurityError') fail('mic_permission', 'the microphone is not allowed here');
    fail('no_mic', `no microphone here${e?.message ? ` (${e.message})` : ''}`);
  }
  const type = recorderType(env.MediaRecorder);
  let rec;
  try { rec = new env.MediaRecorder(stream, { ...(type && { mimeType: type }), audioBitsPerSecond: BITRATE }); } catch (e) {
    for (const t of stream.getTracks?.() ?? []) t.stop();
    fail('no_recorder', `this page cannot record sound (${e?.message ?? e})`);
  }
  // The level: an analyser where the page has Web Audio (a meter while recording, the waveform after); else none.
  let ctx = null, an = null, buf = null;
  try {
    const AC = env.AudioContext ?? env.webkitAudioContext;
    if (AC) { ctx = new AC(); an = ctx.createAnalyser(); an.fftSize = 512; buf = new Uint8Array(an.fftSize); ctx.createMediaStreamSource(stream).connect(an); }
  } catch { ctx = null; an = null; }
  const level = () => {
    if (!an) return 0;
    an.getByteTimeDomainData(buf);
    let p = 0;
    for (const v of buf) p = Math.max(p, Math.abs(v - 128));
    return Math.min(255, p * 2);
  };
  const chunks = [], levels = [], t0 = now();
  let ended = null, cancelled = false, timer = null;
  const elapsed = () => Math.min(max, (now() - t0) / 1000);
  const release = () => {
    if (timer !== null) { clearInterval(timer); timer = null; }
    for (const t of stream.getTracks?.() ?? []) t.stop();
    try { void ctx?.close?.(); } catch {}
  };
  rec.ondataavailable = (e) => { if (e?.data?.size) chunks.push(e.data); };
  const finished = new Promise((ok) => { rec.onstop = () => ok(); });
  const finish = () => {
    if (ended) return ended;
    const secs = elapsed();
    ended = (async () => {
      if (rec.state !== 'inactive') rec.stop();
      await finished;
      release();
      if (cancelled) return null;
      const blob = new env.Blob(chunks, { type: rec.mimeType || type || '' });
      const bytes = new Uint8Array(await blob.arrayBuffer());
      if (!bytes.length) fail('voice', 'nothing was recorded');
      const said = String(rec.mimeType || type || '').split(';')[0].trim();
      const kind = sniff(bytes) ?? (Object.hasOwn(VOICE_EXT, said) ? said : null) ?? fail('voice', `this recorder makes ${said || 'an unknown kind'}, not webm, ogg or mp4`);
      const peaks = downsample(levels);
      return { bytes, type: kind, name: voiceName(new Date(t0), kind), duration_s: Math.max(1, Math.min(max, Math.round(secs))), ...(peaks.length && levels.some((x) => x > 0) && { waveform: b64(peaks) }) };
    })();
    return ended;
  };
  const handle = { type: type ?? '', elapsed, stop: finish, done: null, cancel: () => { cancelled = true; void finish().catch(() => {}); } };
  rec.start(1000);
  timer = setInterval(() => {
    const l = level();
    levels.push(l);
    const s = elapsed();
    if (s >= max && !ended) handle.done = finish();
    try { onTick({ elapsed: s, level: l, done: handle.done !== null }); } catch {}
  }, TICK_MS);
  return handle;
}
