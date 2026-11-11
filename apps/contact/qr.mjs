// SPDX-License-Identifier: MIT
// QR codes for the device flows (design/devices.md §6): encode text to a module matrix, show it in a
// terminal with half blocks, write it as a PNG. No I/O and no dependency beyond node:zlib.
//
//   encode(text, { ecc: 'M', minVersion: 1, maxVersion: 40, mask })  → { version, size, ecc, mask, modules }
//             modules[y][x] true = dark. One segment: alphanumeric when the text is all of
//             0-9 A-Z space $ % * + - . / : (ALNUM), else numeric when all digits, else UTF-8 bytes.
//             The smallest version from minVersion that holds it, else qr_too_long.
//   toTerminal(m, { quiet: 2, invert })  → lines of half blocks, one column per module, two
//             modules a row; light modules drawn (a dark terminal), invert for a light one
//   toPng(m, { scale: 8, quiet: 4 })     → PNG bytes, 8-bit greyscale, filter 0, deflated
//
// Encoder: a port of the "QR Code generator library" (TypeScript edition, MIT, notice below),
// written down in JavaScript for this tree:
// the tables, the bit stream, Reed-Solomon over GF(2^8)/0x11D, function patterns, the codeword
// zigzag, the eight masks and the penalty rule are the library's; kanji, ECI, ECC boosting and the
// segment optimiser are left out. Upstream: v1.8.0, commit 720f62bddb7226106071d4728c292cb1df519ceb,
// typescript-javascript/qrcodegen.ts SHA-256
// c4749095a91bf9696e3a303998b9905e467094f53041e64393e65e6d887737fd (41,025 bytes).
// Cross-checked module for module against an independent encoder (qrcode 1.5.4), versions 1–20,
// masks 0–7 (test-device.mjs keeps the round trip through the decoder, qr-decode.mjs).
//
// Upstream licence (MIT), kept as its notice asks:
//   Copyright (c) Project Nayuki. (MIT License)
//   Permission is hereby granted, free of charge, to any person obtaining a copy of this software
//   and associated documentation files (the "Software"), to deal in the Software without
//   restriction, including without limitation the rights to use, copy, modify, merge, publish,
//   distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
//   Software is furnished to do so, subject to the following conditions:
//   - The above copyright notice and this permission notice shall be included in all copies or
//     substantial portions of the Software.
//   - The Software is provided "as is", without warranty of any kind, express or implied,
//     including but not limited to the warranties of merchantability, fitness for a particular
//     purpose and noninfringement. In no event shall the authors or copyright holders be liable for
//     any claim, damages or other liability, whether in an action of contract, tort or otherwise,
//     arising from, out of or in connection with the Software or the use or other dealings in the
//     Software.
import { crc32, deflateSync } from 'node:zlib';
import { fail } from './kdf.mjs';

export const ALNUM = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
export const ECC = { L: { ord: 0, bits: 1 }, M: { ord: 1, bits: 0 }, Q: { ord: 2, bits: 3 }, H: { ord: 3, bits: 2 } };
export const MIN_VERSION = 1, MAX_VERSION = 40;

// ISO/IEC 18004 Table 9, by ECC ordinal then version (index 0 unused).
const ECC_CODEWORDS_PER_BLOCK = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
];
const NUM_ERROR_CORRECTION_BLOCKS = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
];
// Mode indicator and character-count bits for versions 1–9, 10–26, 27–40.
const MODE = { numeric: [0x1, [10, 12, 14]], alnum: [0x2, [9, 11, 13]], byte: [0x4, [8, 16, 16]] };
const PENALTY_N1 = 3, PENALTY_N2 = 3, PENALTY_N3 = 40, PENALTY_N4 = 10;

const bitAt = (x, i) => ((x >>> i) & 1) !== 0;
const countBits = (mode, ver) => MODE[mode][1][ver <= 9 ? 0 : ver <= 26 ? 1 : 2];
const eccOf = (name) => ECC[name] ?? fail('qr', `ecc: L, M, Q or H, not ${JSON.stringify(name)}`);

/** Data modules of a version, function patterns excluded, remainder bits included. */
export function rawDataModules(ver) {
  let r = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const n = Math.floor(ver / 7) + 2;
    r -= (25 * n - 10) * n - 55;
    if (ver >= 7) r -= 36;
  }
  return r;
}
/** Data codewords (8 bits) a version holds at an error correction level. */
export const dataCodewords = (ver, ecc) => {
  const e = eccOf(ecc).ord;
  return Math.floor(rawDataModules(ver) / 8) - ECC_CODEWORDS_PER_BLOCK[e][ver] * NUM_ERROR_CORRECTION_BLOCKS[e][ver];
};
/** The two error-correction tables at (version, ecc): { blocks, eccPerBlock }. The decoder reads them too. */
export const blockLayout = (ver, ecc) => ({ blocks: NUM_ERROR_CORRECTION_BLOCKS[eccOf(ecc).ord][ver], eccPerBlock: ECC_CODEWORDS_PER_BLOCK[eccOf(ecc).ord][ver] });

/** Alphanumeric characters a version holds at a level (one segment). */
export function alnumCapacity(ver, ecc = 'M') {
  const bits = dataCodewords(ver, ecc) * 8 - 4 - countBits('alnum', ver);
  return Math.floor(bits / 11) * 2 + (bits % 11 >= 6 ? 1 : 0);
}

// ---------------------------------------------------------------- segments

function segmentOf(text) {
  if (typeof text !== 'string') fail('qr', 'the text to encode must be a string');
  const bits = [];
  const put = (v, n) => { for (let i = n - 1; i >= 0; i--) bits.push((v >>> i) & 1); };
  if (/^[0-9]*$/.test(text)) {
    for (let i = 0; i < text.length; i += 3) { const g = text.slice(i, i + 3); put(Number(g), g.length * 3 + 1); }
    return { mode: 'numeric', chars: text.length, bits };
  }
  if ([...text].every((c) => ALNUM.includes(c))) {
    let i = 0;
    for (; i + 2 <= text.length; i += 2) put(ALNUM.indexOf(text[i]) * 45 + ALNUM.indexOf(text[i + 1]), 11);
    if (i < text.length) put(ALNUM.indexOf(text[i]), 6);
    return { mode: 'alnum', chars: text.length, bits };
  }
  const b = new TextEncoder().encode(text);
  for (const x of b) put(x, 8);
  return { mode: 'byte', chars: b.length, bits };
}

// ---------------------------------------------------------------- Reed-Solomon over GF(2^8), 0x11D

/** Product of two field elements. */
export function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}
/** The generator polynomial of degree n, roots α^0 … α^(n-1), leading 1 dropped. */
export function rsDivisor(n) {
  const r = new Array(n).fill(0);
  r[n - 1] = 1;
  let root = 1;
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      r[j] = gfMul(r[j], root);
      if (j + 1 < n) r[j] ^= r[j + 1];
    }
    root = gfMul(root, 0x02);
  }
  return r;
}
/** The remainder of data(x)·x^n divided by the divisor: the n error-correction codewords. */
export function rsRemainder(data, divisor) {
  const r = divisor.map(() => 0);
  for (const b of data) {
    const f = b ^ r.shift();
    r.push(0);
    divisor.forEach((c, i) => { r[i] ^= gfMul(c, f); });
  }
  return r;
}

// ---------------------------------------------------------------- the symbol

/** Centre coordinates of the alignment patterns of a version, ascending. */
export function alignmentPositions(ver) {
  if (ver === 1) return [];
  const n = Math.floor(ver / 7) + 2, size = ver * 4 + 17;
  const step = Math.floor((ver * 8 + n * 3 + 5) / (n * 4 - 4)) * 2;
  const r = [6];
  for (let pos = size - 7; r.length < n; pos -= step) r.splice(1, 0, pos);
  return r;
}

/** The 15 format bits (level, mask, BCH, the 0x5412 mask). */
export function formatBits(ecc, mask) {
  const data = (eccOf(ecc).bits << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}
/** The 18 version bits (versions 7 and up). */
export function versionBits(ver) {
  let rem = ver;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (ver << 12) | rem;
}

/** Whether mask k darkens module (x, y): the eight ISO masks. */
export function maskBit(k, x, y) {
  switch (k) {
    case 0: return (x + y) % 2 === 0;
    case 1: return y % 2 === 0;
    case 2: return x % 3 === 0;
    case 3: return (x + y) % 3 === 0;
    case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    case 7: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
    default: return fail('qr', `mask: 0 to 7, not ${k}`);
  }
}

/**
 * The function patterns of a version: { modules, isFunction }, format area reserved (light), version
 * bits drawn. Shared with the decoder, which reads the data modules in the same zigzag.
 */
export function functionPatterns(ver) {
  const size = ver * 4 + 17;
  const modules = Array.from({ length: size }, () => new Array(size).fill(false));
  const isFunction = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, dark) => { modules[y][x] = dark; isFunction[y][x] = true; };
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  const finder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const d = Math.max(Math.abs(dx), Math.abs(dy)), x = cx + dx, y = cy + dy;
      if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, d !== 2 && d !== 4);
    }
  };
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
  const al = alignmentPositions(ver), n = al.length;
  for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) {
    if ((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(al[i] + dx, al[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  drawFormat(set, size, 0, true);
  if (ver >= 7) {
    const bits = versionBits(ver);
    for (let i = 0; i < 18; i++) {
      const dark = bitAt(bits, i), a = size - 11 + (i % 3), b = Math.floor(i / 3);
      set(a, b, dark); set(b, a, dark);
    }
  }
  return { size, modules, isFunction };
}

// The format bits, both copies, and the dark module. reserve: all light (the area kept free).
function drawFormat(set, size, bits, reserve = false) {
  const b = (i) => !reserve && bitAt(bits, i);
  for (let i = 0; i <= 5; i++) set(8, i, b(i));
  set(8, 7, b(6)); set(8, 8, b(7)); set(7, 8, b(8));
  for (let i = 9; i < 15; i++) set(14 - i, 8, b(i));
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, b(i));
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, b(i));
  set(8, size - 8, true);
}

/** Positions (x, y) of the data modules in reading order: the two-column zigzag from the bottom right. */
export function dataPositions(size, isFunction) {
  const out = [];
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j, upward = ((right + 1) & 2) === 0, y = upward ? size - 1 - vert : vert;
        if (!isFunction[y][x]) out.push([x, y]);
      }
    }
  }
  return out;
}

// The data codewords split in blocks, each with its error correction, interleaved.
function addEccAndInterleave(data, ver, ecc) {
  const { blocks: numBlocks, eccPerBlock } = blockLayout(ver, ecc), raw = Math.floor(rawDataModules(ver) / 8);
  const numShort = numBlocks - (raw % numBlocks), shortLen = Math.floor(raw / numBlocks), div = rsDivisor(eccPerBlock);
  const blocks = [];
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const dat = data.slice(k, k + shortLen - eccPerBlock + (i < numShort ? 0 : 1));
    k += dat.length;
    const e = rsRemainder(dat, div);
    if (i < numShort) dat.push(0);
    blocks.push(dat.concat(e));
  }
  const out = [];
  for (let i = 0; i < blocks[0].length; i++) blocks.forEach((b, j) => { if (i !== shortLen - eccPerBlock || j >= numShort) out.push(b[i]); });
  return out;
}

// The library's penalty: runs (N1), 2×2 blocks (N2), finder-like patterns (N3), balance (N4).
function penalty(m) {
  const size = m.length;
  let result = 0;
  const addHistory = (run, h) => { if (h[0] === 0) run += size; h.pop(); h.unshift(run); };
  const countPatterns = (h) => {
    const n = h[1], core = n > 0 && h[2] === n && h[3] === n * 3 && h[4] === n && h[5] === n;
    return (core && h[0] >= n * 4 && h[6] >= n ? 1 : 0) + (core && h[6] >= n * 4 && h[0] >= n ? 1 : 0);
  };
  const terminate = (color, run, h) => { if (color) { addHistory(run, h); run = 0; } run += size; addHistory(run, h); return countPatterns(h); };
  for (const byRow of [true, false]) {
    for (let a = 0; a < size; a++) {
      let color = false, run = 0;
      const h = [0, 0, 0, 0, 0, 0, 0];
      for (let b = 0; b < size; b++) {
        const v = byRow ? m[a][b] : m[b][a];
        if (v === color) {
          run++;
          if (run === 5) result += PENALTY_N1; else if (run > 5) result++;
        } else {
          addHistory(run, h);
          if (!color) result += countPatterns(h) * PENALTY_N3;
          color = v; run = 1;
        }
      }
      result += terminate(color, run, h) * PENALTY_N3;
    }
  }
  for (let y = 0; y < size - 1; y++) for (let x = 0; x < size - 1; x++) {
    const c = m[y][x];
    if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) result += PENALTY_N2;
  }
  let dark = 0;
  for (const row of m) for (const v of row) if (v) dark++;
  const total = size * size, k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
  return result + k * PENALTY_N4;
}

/**
 * `text` as a QR symbol. ecc: L, M (default), Q, H; minVersion, maxVersion: 1–40; mask: 0–7, else the
 * one of least penalty. → { version, size, ecc, mask, mode, modules } (modules[y][x], true = dark).
 */
export function encode(text, { ecc = 'M', minVersion = MIN_VERSION, maxVersion = MAX_VERSION, mask = -1 } = {}) {
  eccOf(ecc);
  if (!(Number.isInteger(minVersion) && Number.isInteger(maxVersion) && MIN_VERSION <= minVersion && minVersion <= maxVersion && maxVersion <= MAX_VERSION)) fail('qr', 'versions: 1 ≤ minVersion ≤ maxVersion ≤ 40');
  if (!(Number.isInteger(mask) && mask >= -1 && mask <= 7)) fail('qr', 'mask: 0 to 7, or -1 for the best');
  const seg = segmentOf(text);
  let ver = minVersion, cap;
  for (; ; ver++) {
    cap = dataCodewords(ver, ecc) * 8;
    const used = 4 + countBits(seg.mode, ver) + seg.bits.length;
    if (seg.chars < 2 ** countBits(seg.mode, ver) && used <= cap) break;
    if (ver >= maxVersion) fail('qr_too_long', `${seg.chars} ${seg.mode === 'byte' ? 'bytes' : 'characters'} do not fit a version ${maxVersion} symbol at level ${ecc}`);
  }
  const bits = [];
  const put = (v, n) => { for (let i = n - 1; i >= 0; i--) bits.push((v >>> i) & 1); };
  put(MODE[seg.mode][0], 4); put(seg.chars, countBits(seg.mode, ver));
  for (const b of seg.bits) bits.push(b);
  put(0, Math.min(4, cap - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < cap; pad ^= 0xec ^ 0x11) put(pad, 8);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  const { size, modules, isFunction } = functionPatterns(ver), all = addEccAndInterleave(data, ver, ecc);
  const pos = dataPositions(size, isFunction);
  pos.forEach(([x, y], i) => { modules[y][x] = i < all.length * 8 && bitAt(all[i >>> 3], 7 - (i & 7)); });
  const set = (x, y, dark) => { modules[y][x] = dark; };
  const applyMask = (k) => { for (const [x, y] of pos) if (maskBit(k, x, y)) modules[y][x] = !modules[y][x]; };
  if (mask === -1) {
    let best = Infinity;
    for (let k = 0; k < 8; k++) {
      applyMask(k); drawFormat(set, size, formatBits(ecc, k));
      const p = penalty(modules);
      if (p < best) { mask = k; best = p; }
      applyMask(k);
    }
  }
  applyMask(mask); drawFormat(set, size, formatBits(ecc, mask));
  return { version: ver, size, ecc, mask, mode: seg.mode, modules };
}

// ---------------------------------------------------------------- output

/**
 * The symbol as lines of text: each character two modules high (▀ ▄ █ space), the quiet zone
 * `quiet` modules on every side. Light modules are drawn, for a terminal with a dark background;
 * invert: dark modules drawn (a light background). Width: size + 2·quiet columns.
 */
export function toTerminal(m, { quiet = 2, invert = false } = {}) {
  const mods = m.modules ?? m, n = mods.length, total = n + 2 * quiet;
  const light = (x, y) => { const xx = x - quiet, yy = y - quiet; const dark = xx >= 0 && yy >= 0 && xx < n && yy < n && mods[yy][xx]; return invert ? dark : !dark; };
  const lines = [];
  for (let y = 0; y < total; y += 2) {
    let s = '';
    for (let x = 0; x < total; x++) {
      const t = light(x, y), b = y + 1 < total ? light(x, y + 1) : false;
      s += t && b ? '█' : t ? '▀' : b ? '▄' : ' ';
    }
    lines.push(s);
  }
  return lines;
}

/** The symbol as a PNG: black on white, `scale` pixels a module, `quiet` modules of white around it. */
export function toPng(m, { scale = 8, quiet = 4 } = {}) {
  const mods = m.modules ?? m, n = mods.length, side = (n + 2 * quiet) * scale;
  if (!(Number.isInteger(scale) && scale >= 1 && scale <= 64 && Number.isInteger(quiet) && quiet >= 0 && quiet <= 16)) fail('qr', 'png: scale 1–64, quiet 0–16');
  const raw = Buffer.alloc((side + 1) * side, 0xff);
  for (let y = 0; y < side; y++) {
    raw[y * (side + 1)] = 0;
    const my = Math.floor(y / scale) - quiet;
    for (let x = 0; x < side; x++) {
      const mx = Math.floor(x / scale) - quiet;
      if (my >= 0 && mx >= 0 && my < n && mx < n && mods[my][mx]) raw[y * (side + 1) + 1 + x] = 0;
    }
  }
  const chunk = (type, data) => {
    const len = Buffer.alloc(4), crc = Buffer.alloc(4), td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    len.writeUInt32BE(data.length); crc.writeUInt32BE(crc32(td) >>> 0);
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(side, 0); ihdr.writeUInt32BE(side, 4);
  ihdr[8] = 8; ihdr[9] = 0; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}
