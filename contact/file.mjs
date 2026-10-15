// SPDX-License-Identifier: MIT
// File transfer over contact messages (design/human-ui-plan.md §4, decision 3): pure code, no I/O.
// A file goes as messages labelled FILE_LABEL to one contact, in one login (carrier.sendFile →
// sendAll): first a manifest {id, name, size, sha256, chunks}, then `chunks` messages {id, i,
// data}, each CHUNK bytes of the file (the last one the rest) as base64. 256 KiB is 349,528
// characters of base64: with the signed body around it, a message well under the free tier's
// 512 KiB less the 1,198 bytes an envelope carrying its epoch's encapsulation adds. At most
// MAX_FILE bytes, so at most MAX_CHUNKS chunks (about 11 MB of the reader's 100 MB at the relay).
// The receiver keeps the chunks until all have come, then checks size and SHA-256 (assemble); what
// is still incomplete at its retention goes (carrier.mjs). The name is the sender's word: the
// receiver keeps safeName of it only, and never opens or runs what it saves.
import { createHash, randomBytes } from 'node:crypto';
import { fail } from './kdf.mjs';

export const FILE_LABEL = 'sigelo-file/0';
export const CHUNK = 256 * 1024, MAX_FILE = 8 * 1024 * 1024, MAX_CHUNKS = MAX_FILE / CHUNK;
// A name as kept on disk: at most this many UTF-8 bytes (a file system allows 255, and the
// receiver puts 9 characters of hash in front). A manifest's name past NAME_MAX_IN is refused.
export const NAME_MAX = 200, NAME_MAX_IN = 1024;
const ID = /^[0-9a-f]{32}$/, HEX64 = /^[0-9a-f]{64}$/;
const b64 = (b) => Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString('base64');
const int = (n, lo, hi) => Number.isSafeInteger(n) && n >= lo && n <= hi;
const keysAre = (o, keys) => o !== null && typeof o === 'object' && !Array.isArray(o)
  && Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));

export const sha256Hex = (b) => createHash('sha256').update(b).digest('hex');
/** How many chunks a file of n bytes goes in. */
export const chunksOf = (n) => Math.ceil(n / CHUNK);

/**
 * A name safe to put in a directory: its last path segment (either slash), without control or
 * format characters (C0, DEL, C1, bidi overrides, zero-width), without leading dots or spaces (no
 * hidden file, no "..") and cut to NAME_MAX UTF-8 bytes on a character boundary. Nothing left:
 * "file".
 */
export function safeName(raw) {
  let s = String(raw ?? '').split(/[\\/]/).pop();
  s = s.replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, '').replace(/^[.\s]+/, '').trim();
  if (Buffer.byteLength(s) > NAME_MAX) {
    let n = 0, cut = '';
    for (const ch of s) { n += Buffer.byteLength(ch); if (n > NAME_MAX) break; cut += ch; }
    s = cut.trim();
  }
  return s || 'file';
}

/**
 * A file's messages: [manifest, ...chunks], all to go with label FILE_LABEL. bytes: the file
 * (Uint8Array or Buffer); name: what the receiver is told (safeName of it goes); id: 16 random
 * bytes as hex unless given (tests).
 */
export function splitFile(bytes, name, { id } = {}) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('bytes: a Uint8Array');
  if (bytes.length > MAX_FILE) fail('file_too_large', `${bytes.length} bytes, at most ${MAX_FILE} (8 MiB) a file`);
  id ??= randomBytes(16).toString('hex');
  if (!ID.test(id)) throw new TypeError('id: 32 lowercase hex digits');
  const n = chunksOf(bytes.length);
  const manifest = { id, name: safeName(name), size: bytes.length, sha256: sha256Hex(bytes), chunks: n };
  const chunks = [];
  for (let i = 0; i < n; i++) chunks.push({ id, i, data: b64(bytes.subarray(i * CHUNK, (i + 1) * CHUNK)) });
  return { manifest, chunks };
}

/** Whether a FILE_LABEL message's content is a manifest (else it should be a chunk). */
export const isManifest = (c) => c !== null && typeof c === 'object' && Object.hasOwn(c, 'sha256');

/** A manifest as received, checked; → { id, name: safeName of the sender's, size, sha256, chunks }. */
export function checkManifest(c) {
  if (!keysAre(c, ['id', 'name', 'size', 'sha256', 'chunks'])) fail('file', 'a manifest is {id, name, size, sha256, chunks}');
  if (typeof c.id !== 'string' || !ID.test(c.id)) fail('file', 'manifest id: 32 lowercase hex digits');
  if (typeof c.name !== 'string' || c.name.length > NAME_MAX_IN) fail('file', `manifest name: a string of at most ${NAME_MAX_IN} characters`);
  if (!int(c.size, 0, Number.MAX_SAFE_INTEGER)) fail('file', 'manifest size: a whole number of bytes');
  if (c.size > MAX_FILE) fail('file_too_large', `the manifest says ${c.size} bytes, at most ${MAX_FILE} (8 MiB) a file`);
  if (typeof c.sha256 !== 'string' || !HEX64.test(c.sha256)) fail('file', 'manifest sha256: 64 lowercase hex digits');
  if (c.chunks !== chunksOf(c.size)) fail('file', `manifest chunks: ${c.size} bytes go in ${chunksOf(c.size)} chunks, not ${JSON.stringify(c.chunks)}`);
  return { id: c.id, name: safeName(c.name), size: c.size, sha256: c.sha256, chunks: c.chunks };
}

/** A chunk's id and index, checked for shape only (its manifest may not be known yet). */
export function chunkHead(c) {
  if (!keysAre(c, ['id', 'i', 'data'])) fail('file_chunk', 'a chunk is {id, i, data}');
  if (typeof c.id !== 'string' || !ID.test(c.id)) fail('file_chunk', 'chunk id: 32 lowercase hex digits');
  if (!int(c.i, 0, MAX_CHUNKS - 1)) fail('file_chunk', `chunk index: 0 to ${MAX_CHUNKS - 1}`);
  return { id: c.id, i: c.i };
}

/** A chunk of manifest m, checked: its index, canonical base64, its exact length; → its bytes. */
export function checkChunk(c, m) {
  const { id, i } = chunkHead(c);
  if (id !== m.id) fail('file_chunk', 'a chunk of another file');
  if (i >= m.chunks) fail('file_chunk', `chunk ${i} of a file in ${m.chunks}`);
  const want = Math.min(CHUNK, m.size - i * CHUNK);
  if (typeof c.data !== 'string' || c.data.length !== 4 * Math.ceil(want / 3)) fail('file_chunk', `chunk ${i}: ${want} bytes as base64 expected`);
  const bytes = Buffer.from(c.data, 'base64');
  if (bytes.length !== want || b64(bytes) !== c.data) fail('file_chunk', `chunk ${i}: not canonical base64 of ${want} bytes`);
  return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.length);
}

/** The file of manifest m from its chunks in order; refused (file_hash) unless size and SHA-256 match. */
export function assemble(m, parts) {
  if (!Array.isArray(parts) || parts.length !== m.chunks) fail('file_hash', `${parts?.length} chunks of ${m.chunks}`);
  const bytes = Buffer.concat(parts);
  if (bytes.length !== m.size) fail('file_hash', `${bytes.length} bytes, the manifest says ${m.size}`);
  if (sha256Hex(bytes) !== m.sha256) fail('file_hash', 'the SHA-256 of the chunks is not the manifest\'s: a chunk was altered');
  return bytes;
}

/** n bytes for people: "812 B", "12.0 KiB", "1.0 MiB". */
export function sizeText(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}
