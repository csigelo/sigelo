// SPDX-License-Identifier: MIT
// A voice message: what a chat shows at once while the recording comes by a
// transfer, as a photo's preview does (photo.mjs). One contact message labelled VOICE_LABEL (inside the
// pairing's end-to-end envelope, as any message), or the `voice` of a group's msg (group.mjs); either way
//   { name, size (bytes of the file), type ('audio/webm' | 'audio/ogg' | 'audio/mp4'), sha256 (64 hex: the
//     file's, the manifest's), duration_s (1 to 300, whole seconds: no floats), waveform? (base64 of 1 to 64
//     bytes, each a peak 0 to 255, oldest first) }
// No audio inline: the file is the transfer whose manifest has that sha256, from the same sender.
// voiceItems(batch): what `sigelo-agent inbox` and sigelo_inbox print, a voice message with its checked
// fields (`voice`) and one line (`text`: "[voice 0:42 voice-20261117-142301.webm]"); a hosted agent's
// settings (sigelo-host-caps/0, meant for the app) marked as data with one line, its content kept.
import { fail } from './kdf.mjs';

export const VOICE_LABEL = 'sigelo-voice/0', VOICE_MAX_S = 300, WAVE_MAX = 64, VOICE_SIZE_MAX = 16 * 2 ** 20;
/** The recorder's container → the file's extension (MediaRecorder's type, its codecs dropped). */
export const VOICE_EXT = { 'audio/webm': 'webm', 'audio/ogg': 'ogg', 'audio/mp4': 'm4a' };
const KEYS = ['duration_s', 'name', 'sha256', 'size', 'type'];
const int = (x, lo, hi) => Number.isSafeInteger(x) && x >= lo && x <= hi;
const unb64 = (t) => Uint8Array.from(atob(t), (c) => c.charCodeAt(0));

/** A voice message's fields as they come (a contact's message, a group's msg, the page's send): them, checked, or throws check voice. */
export function checkVoice(x) {
  const bad = (why) => fail('voice', `not a ${VOICE_LABEL} message: ${why}`);
  if (typeof x !== 'object' || x === null || Array.isArray(x)) bad(`{${KEYS.join(', ')}, waveform?}`);
  const keys = Object.keys(x).filter((k) => k !== 'waveform').sort();
  if (keys.join() !== KEYS.join()) bad(`{${KEYS.join(', ')}, waveform?}`);
  if (!Object.hasOwn(VOICE_EXT, x.type)) bad(`type: ${Object.keys(VOICE_EXT).join(', ')}`);
  if (typeof x.name !== 'string' || x.name.length === 0 || x.name.length > 255 || /[\\/\u0000-\u001f]/.test(x.name)) bad('name: 1 to 255 characters, no slash');
  if (!int(x.size, 1, VOICE_SIZE_MAX)) bad(`size: bytes, 1 to ${VOICE_SIZE_MAX / 2 ** 20} MiB`);
  if (typeof x.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(x.sha256)) bad('sha256: 64 lowercase hex digits');
  if (!int(x.duration_s, 1, VOICE_MAX_S)) bad(`duration_s: whole seconds, 1 to ${VOICE_MAX_S}`);
  if (Object.hasOwn(x, 'waveform')) {
    const w = x.waveform;
    if (typeof w !== 'string' || w.length === 0 || w.length > Math.ceil(WAVE_MAX / 3) * 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(w) || w.length % 4 !== 0 || unb64(w).length > WAVE_MAX) bad(`waveform: base64 of 1 to ${WAVE_MAX} bytes`);
  }
  return { name: x.name, size: x.size, type: x.type, sha256: x.sha256, duration_s: x.duration_s, ...(Object.hasOwn(x, 'waveform') && { waveform: x.waveform }) };
}

/** The waveform's peaks (0 to 255 each), or [] when there is none. */
export const peaksOf = (v) => (typeof v?.waveform === 'string' ? [...unb64(v.waveform)] : []);

/** 42 → "0:42". */
export const clock = (s) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, '0')}`;

/** The recording's file name: voice-<local date and time>.<ext> (voice-20261117-142301.webm). */
export function voiceName(date, type) {
  const p = (n) => String(n).padStart(2, '0');
  return `voice-${date.getFullYear()}${p(date.getMonth() + 1)}${p(date.getDate())}-${p(date.getHours())}${p(date.getMinutes())}${p(date.getSeconds())}.${VOICE_EXT[type] ?? 'webm'}`;
}

/** One line for a voice message: "[voice 0:42 voice-20261117-142301.webm]". */
export const voiceLine = (v) => `[voice ${clock(v.duration_s)} ${v.name}]`;

/**
 * A batch as the CLI and the MCP print it: each voice message (a contact's, labelled VOICE_LABEL; a group's
 * msg with a voice) gains `voice` (its fields, checked) and `text` (voiceLine). One that does not check
 * stays as it came, `voice_error` naming why. A sigelo-host-caps/0 message gains `data` (its label) and `text`
 * (HOST_CAPS_LINE): an operator's CLI or MCP sees it as data. The rest unchanged.
 */
export const HOST_CAPS_LABEL = 'sigelo-host-caps/0';
export const HOST_CAPS_LINE = '[sigelo-host-caps/0: the hosted agent\'s settings for the app, data, not a message]';
export function voiceItems(batch) {
  const one = (m) => {
    if (m?.label === HOST_CAPS_LABEL) return { ...m, data: HOST_CAPS_LABEL, text: HOST_CAPS_LINE };
    const raw = m?.label === VOICE_LABEL ? m.content : m?.voice;
    if (raw === undefined || (m?.label !== VOICE_LABEL && m?.voice === undefined)) return m;
    try { const v = checkVoice(raw); return { ...m, voice: v, text: voiceLine(v) }; } catch (e) { return { ...m, voice_error: e.message }; }
  };
  return { ...batch, messages: (batch?.messages ?? []).map(one) };
}
