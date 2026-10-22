// SPDX-License-Identifier: MIT
// The one name contact/qr.mjs and qr-decode.mjs take from kdf.mjs: fail(check, why) throws.
export const fail = (check, why) => { throw Object.assign(new Error(why), { check }); };
