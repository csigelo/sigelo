// SPDX-License-Identifier: MIT
// The one name apps/contact/qr.mjs, qr-decode.mjs, voice.mjs and voice-web.mjs take from kdf.mjs: fail(check, why) throws.
export const fail = (check, why) => { throw Object.assign(new Error(why), { check }); };
