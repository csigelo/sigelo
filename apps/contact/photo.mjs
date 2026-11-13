// SPDX-License-Identifier: MIT
// A photo's inline preview (design/transfer.md §10.4): what a chat shows at once while the full file
// comes by a transfer. Not sigelo-picture/0, which sets a contact's own picture. One contact message
// labelled PHOTO_LABEL (inside the pairing's end-to-end envelope, as any message), or the `photo` of a
// group's msg (group.mjs); either way the content is
//   { type: 'image/jpeg' | 'image/webp', data: base64 of at most 64 KB, w, h (1 to 4096 pixels),
//     sha256 (64 hex: the full file's, the manifest's), size (bytes of the full file), name }
// The full file is the transfer whose manifest has that sha256, from the same sender.
import { fail } from './kdf.mjs';

export const PHOTO_LABEL = 'sigelo-photo/0', PHOTO_MAX = 64 * 1024, PHOTO_SIDE = 4096, PHOTO_TYPES = new Set(['image/jpeg', 'image/webp']);
const KEYS = ['data', 'h', 'name', 'sha256', 'size', 'type', 'w'];
const unb64 = (t) => Uint8Array.from(atob(t), (c) => c.charCodeAt(0));
const int = (x, lo, hi) => Number.isSafeInteger(x) && x >= lo && x <= hi;

/** The image's kind by its first bytes: 'image/jpeg', 'image/webp', or null. */
export function imageType(b) {
  if (b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (b.length > 12 && String.fromCharCode(...b.subarray(0, 4)) === 'RIFF' && String.fromCharCode(...b.subarray(8, 12)) === 'WEBP') return 'image/webp';
  return null;
}

/** A preview as it comes (a contact's message, a group's msg, the page's send): it, checked, or throws check photo. */
export function checkPhoto(x) {
  const bad = (why) => fail('photo', `not a ${PHOTO_LABEL} preview: ${why}`);
  if (typeof x !== 'object' || x === null || Array.isArray(x) || Object.keys(x).sort().join() !== KEYS.join()) bad(`{${KEYS.join(', ')}}`);
  if (!PHOTO_TYPES.has(x.type)) bad('type: image/jpeg or image/webp');
  if (typeof x.data !== 'string' || x.data.length === 0 || x.data.length > Math.ceil(PHOTO_MAX / 3) * 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(x.data)) bad(`data: base64 of at most ${PHOTO_MAX / 1024} KB`);
  const b = unb64(x.data);
  if (b.length > PHOTO_MAX) bad(`at most ${PHOTO_MAX / 1024} KB`);
  if (imageType(b) !== x.type) bad(`not a ${x.type === 'image/jpeg' ? 'JPEG' : 'WebP'} image`);
  if (!int(x.w, 1, PHOTO_SIDE) || !int(x.h, 1, PHOTO_SIDE)) bad(`w and h: 1 to ${PHOTO_SIDE} pixels`);
  if (typeof x.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(x.sha256)) bad('sha256: 64 lowercase hex digits');
  if (!int(x.size, 0, 16 * 2 ** 30)) bad('size: bytes, at most 16 GiB');
  if (typeof x.name !== 'string' || x.name.length === 0 || x.name.length > 255) bad('name: 1 to 255 characters');
  return { type: x.type, data: x.data, w: x.w, h: x.h, sha256: x.sha256, size: x.size, name: x.name };
}
