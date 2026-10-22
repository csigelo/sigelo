// SPDX-License-Identifier: MIT
// node:zlib for contact/qr-decode.mjs and qr.mjs in a page (ui.html's import map; apps/gtk): pages decode
// pixels (jsQR) and draw modules, never PNG bytes, so the PNG paths (inflate, deflate, crc32) are never reached.
const none = () => { throw new Error('not in the app: images are decoded from pixels'); };
export const crc32 = none, inflateSync = none, deflateSync = none;
