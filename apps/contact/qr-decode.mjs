// SPDX-License-Identifier: Apache-2.0
// Reading QR codes from images (design/devices.md §5.3, §6.4): a PNG reader and a QR decoder, pure
// JavaScript over node:zlib. No I/O: the caller reads the file (sigelo-agent device scan, which also
// tries zbarimg first when it is on PATH; this package starts no process).
//
//   readPng(bytes)                 → { width, height, data }: RGBA, 8 bits a channel. 1–16-bit grey,
//                                    grey+alpha, RGB, RGBA and palette; interlaced refused (scan_format)
//   jsQR(data, width, height)      → { data: text, binaryData: bytes, version, ecc, location } | null
//   scanPng(bytes)                 → the text of the QR code in a PNG, or throws scan_none / scan_format
//
// The decoder follows jsQR 1.4.0 (Apache-2.0), itself after ZXing
// (Apache-2.0): the same four steps and names. binarize (8×8 regions, a 5×5 neighbourhood mean,
// 24 levels of minimum range), locate (the 1:1:3:1:1 finder scan with vertical and horizontal
// cross-checks; the three centres that make the best right isosceles triangle; the bottom-right
// alignment pattern by template), extract (a perspective transform through four points, one sample
// a module), decode (format and version bits within 3 bit errors, the mask, the codeword zigzag,
// de-interleaving, Reed-Solomon by Berlekamp-Massey and Forney, then numeric, alphanumeric, byte,
// ECI and kanji segments). It is written for this tree from those designs, not a verbatim copy of
// either. Upstream: the jsqr 1.4.0 npm tarball, SHA-256
// b5299b37917a1fe7a8cab9dd5cc6b8accf82663add80abe5bf7761a921cc6602 (dist/jsQR.js
// bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859). The
// symbol tables come from qr.mjs, the encoder, so both read one geometry. Mirrored symbols and
// Model 1 codes are not read.
//
// Licence of the work it follows:
//   Copyright the jsQR authors and the ZXing authors.
//   Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//   except in compliance with the License. You may obtain a copy of the License at
//       http://www.apache.org/licenses/LICENSE-2.0
//   Unless required by applicable law or agreed to in writing, software distributed under the
//   License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//   either express or implied. See the License for the specific language governing permissions
//   and limitations under the License.
// NOTICE: this file is a modified work: ported to JavaScript modules for sigelo-contact,
// restructured, and limited to Model 2 symbols.
import { crc32, inflateSync } from 'node:zlib';
import { fail } from './kdf.mjs';
import { ALNUM, blockLayout, dataPositions, formatBits, functionPatterns, maskBit, rawDataModules, versionBits } from './qr.mjs';

// The largest image read: 40 megapixels (a phone camera's photo is 12–50).
export const MAX_PIXELS = 40e6;

// ---------------------------------------------------------------- PNG

const SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const CHANNELS = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };
const DEPTHS = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };

/** A PNG's pixels as RGBA (8 bits a channel). Refused, scan_format, what it does not read. */
export function readPng(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : fail('scan_format', 'readPng: bytes');
  if (b.length < 8 || SIGNATURE.some((v, i) => b[i] !== v)) fail('scan_format', 'not a PNG file (its first 8 bytes are not the PNG signature)');
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let at = 8, ihdr = null, palette = null, trns = null;
  const idat = [];
  while (at + 12 <= b.length) {
    const len = view.getUint32(at), type = String.fromCharCode(...b.subarray(at + 4, at + 8));
    if (at + 12 + len > b.length) fail('scan_format', `PNG chunk ${type} runs past the end of the file`);
    const data = b.subarray(at + 8, at + 8 + len);
    if ((crc32(b.subarray(at + 4, at + 8 + len)) >>> 0) !== view.getUint32(at + 8 + len)) fail('scan_format', `PNG chunk ${type}: bad CRC (a damaged file)`);
    at += 12 + len;
    if (type === 'IHDR') ihdr = { width: view.getUint32(at - len - 4), height: view.getUint32(at - len), depth: data[8], color: data[9], compression: data[10], filter: data[11], interlace: data[12] };
    else if (type === 'PLTE') palette = data;
    else if (type === 'tRNS') trns = data;
    else if (type === 'IDAT') idat.push(data);
    else if (type === 'IEND') break;
  }
  if (!ihdr) fail('scan_format', 'PNG without an IHDR chunk');
  const { width, height, depth, color } = ihdr;
  if (!CHANNELS[color] || !DEPTHS[color].includes(depth) || ihdr.compression !== 0 || ihdr.filter !== 0) fail('scan_format', `PNG colour type ${color}, depth ${depth}: not one PNG defines`);
  if (ihdr.interlace !== 0) fail('scan_format', 'an interlaced PNG: save it again without interlacing, or install zbar (zbarimg)');
  if (width < 1 || height < 1 || width * height > MAX_PIXELS) fail('scan_format', `PNG of ${width}×${height}: at most ${MAX_PIXELS / 1e6} megapixels`);
  if (color === 3 && !palette) fail('scan_format', 'a palette PNG without its palette');
  const bitsPx = CHANNELS[color] * depth, stride = Math.ceil((width * bitsPx) / 8), bpp = Math.max(1, bitsPx >> 3);
  let raw;
  try { raw = inflateSync(Buffer.concat(idat), { maxOutputLength: (stride + 1) * height + 1 }); } catch (e) { fail('scan_format', `PNG image data does not inflate (${e.code ?? e.message})`); }
  if (raw.length !== (stride + 1) * height) fail('scan_format', `PNG image data: ${raw.length} bytes, ${(stride + 1) * height} expected`);
  const px = new Uint8Array(stride * height);
  for (let y = 0; y < height; y++) {
    const f = raw[y * (stride + 1)], src = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1)), row = px.subarray(y * stride, (y + 1) * stride);
    const up = y > 0 ? px.subarray((y - 1) * stride, y * stride) : null;
    for (let i = 0; i < stride; i++) {
      const a = i >= bpp ? row[i - bpp] : 0, u = up ? up[i] : 0, c = up && i >= bpp ? up[i - bpp] : 0;
      let v = src[i];
      if (f === 1) v += a;
      else if (f === 2) v += u;
      else if (f === 3) v += (a + u) >> 1;
      else if (f === 4) { const p = a + u - c, pa = Math.abs(p - a), pb = Math.abs(p - u), pc = Math.abs(p - c); v += pa <= pb && pa <= pc ? a : pb <= pc ? u : c; } else if (f !== 0) fail('scan_format', `PNG row ${y}: filter ${f} is no PNG filter`);
      row[i] = v & 0xff;
    }
  }
  const out = new Uint8ClampedArray(width * height * 4), max = (1 << Math.min(depth, 8)) - 1;
  const sample = (row, k) => {
    if (depth === 8) return row[k];
    if (depth === 16) return row[k * 2];
    const bit = k * depth, v = (row[bit >> 3] >> (8 - depth - (bit & 7))) & max;
    return color === 3 ? v : Math.round((v * 255) / max);
  };
  for (let y = 0; y < height; y++) {
    const row = px.subarray(y * stride, (y + 1) * stride);
    for (let x = 0; x < width; x++) {
      const o = (y * width + x) * 4, n = CHANNELS[color];
      if (color === 3) {
        const k = sample(row, x);
        out[o] = palette[k * 3] ?? 0; out[o + 1] = palette[k * 3 + 1] ?? 0; out[o + 2] = palette[k * 3 + 2] ?? 0; out[o + 3] = trns?.[k] ?? 255;
      } else if (color === 0 || color === 4) {
        const g = sample(row, x * n);
        out[o] = out[o + 1] = out[o + 2] = g; out[o + 3] = color === 4 ? sample(row, x * n + 1) : 255;
      } else {
        out[o] = sample(row, x * n); out[o + 1] = sample(row, x * n + 1); out[o + 2] = sample(row, x * n + 2); out[o + 3] = color === 6 ? sample(row, x * n + 3) : 255;
      }
    }
  }
  return { width, height, data: out };
}

// ---------------------------------------------------------------- binarize

const REGION = 8, MIN_RANGE = 24;
/** Dark (1) or light (0) per pixel, by the mean of a 5×5 neighbourhood of 8×8 region levels. Alpha is composed on white. */
export function binarize(data, width, height, invert = false) {
  const grey = new Uint8Array(width * height);
  for (let i = 0; i < width * height; i++) {
    const a = data[i * 4 + 3] / 255, l = 0.2126 * data[i * 4] + 0.7152 * data[i * 4 + 1] + 0.0722 * data[i * 4 + 2];
    grey[i] = Math.round(l * a + 255 * (1 - a));
  }
  const hc = Math.ceil(width / REGION), vc = Math.ceil(height / REGION), level = new Float64Array(hc * vc);
  for (let vr = 0; vr < vc; vr++) for (let hr = 0; hr < hc; hr++) {
    let min = 255, max = 0, sum = 0, n = 0;
    for (let y = vr * REGION; y < Math.min(height, (vr + 1) * REGION); y++) for (let x = hr * REGION; x < Math.min(width, (hr + 1) * REGION); x++) {
      const g = grey[y * width + x];
      sum += g; n++;
      if (g < min) min = g;
      if (g > max) max = g;
    }
    let avg = sum / n;
    if (max - min <= MIN_RANGE) {
      // A flat region: below its neighbours' level when it is darker than they are, else light.
      avg = min / 2;
      if (vr > 0 && hr > 0) {
        const near = (level[(vr - 1) * hc + hr] + 2 * level[vr * hc + hr - 1] + level[(vr - 1) * hc + hr - 1]) / 4;
        if (min < near) avg = near;
      }
    }
    level[vr * hc + hr] = avg;
  }
  const out = new Uint8Array(width * height);
  for (let vr = 0; vr < vc; vr++) for (let hr = 0; hr < hc; hr++) {
    let sum = 0;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) {
      const y = Math.min(vc - 1, Math.max(0, vr + dy)), x = Math.min(hc - 1, Math.max(0, hr + dx));
      sum += level[y * hc + x];
    }
    const t = sum / 25;
    for (let y = vr * REGION; y < Math.min(height, (vr + 1) * REGION); y++) for (let x = hr * REGION; x < Math.min(width, (hr + 1) * REGION); x++) {
      out[y * width + x] = (grey[y * width + x] <= t) !== invert ? 1 : 0;
    }
  }
  return out;
}

// ---------------------------------------------------------------- locate

const ratioOk = (s) => {
  const total = s[0] + s[1] + s[2] + s[3] + s[4];
  if (total < 7 || s.some((v) => v === 0)) return false;
  const m = total / 7, v = m / 2;
  return Math.abs(m - s[0]) < v && Math.abs(m - s[1]) < v && Math.abs(3 * m - s[2]) < 3 * v && Math.abs(m - s[3]) < v && Math.abs(m - s[4]) < v;
};
const centreFromEnd = (s, end) => end - s[4] - s[3] - s[2] / 2;

/** The finder pattern centres in a bit matrix: [{ x, y, size (module, px), count }]. */
export function finderCandidates(bm, width, height) {
  const dark = (x, y) => bm[y * width + x] === 1, found = [];
  // Along one line through (cx, cy), in direction (dx, dy): the five runs about the centre, or NaN.
  const cross = (cx, cy, dx, dy, maxCount, total) => {
    const s = [0, 0, 0, 0, 0], inside = (x, y) => x >= 0 && y >= 0 && x < width && y < height;
    let x = cx, y = cy;
    while (inside(x, y) && dark(x, y)) { s[2]++; x -= dx; y -= dy; }
    if (!inside(x, y)) return NaN;
    while (inside(x, y) && !dark(x, y) && s[1] <= maxCount) { s[1]++; x -= dx; y -= dy; }
    if (!inside(x, y) || s[1] > maxCount) return NaN;
    while (inside(x, y) && dark(x, y) && s[0] <= maxCount) { s[0]++; x -= dx; y -= dy; }
    if (s[0] > maxCount) return NaN;
    x = cx + dx; y = cy + dy;
    while (inside(x, y) && dark(x, y)) { s[2]++; x += dx; y += dy; }
    if (!inside(x, y)) return NaN;
    while (inside(x, y) && !dark(x, y) && s[3] < maxCount) { s[3]++; x += dx; y += dy; }
    if (!inside(x, y) || s[3] >= maxCount) return NaN;
    while (inside(x, y) && dark(x, y) && s[4] < maxCount) { s[4]++; x += dx; y += dy; }
    if (s[4] >= maxCount) return NaN;
    const t = s[0] + s[1] + s[2] + s[3] + s[4];
    if (5 * Math.abs(t - total) >= 2 * total || !ratioOk(s)) return NaN;
    return centreFromEnd(s, dx ? x : y);
  };
  const consider = (s, row, end) => {
    const total = s[0] + s[1] + s[2] + s[3] + s[4], max = s[2] * 2;
    let cx = centreFromEnd(s, end);
    const cy = cross(Math.floor(cx), row, 0, 1, max, total);
    if (Number.isNaN(cy)) return false;
    cx = cross(Math.floor(cx), Math.floor(cy), 1, 0, max, total);
    if (Number.isNaN(cx)) return false;
    const size = total / 7;
    const hit = found.find((c) => Math.abs(cy - c.y) <= size && Math.abs(cx - c.x) <= size && (Math.abs(size - c.size) <= 1 || Math.abs(size - c.size) <= c.size));
    if (hit) {
      const n = hit.count + 1;
      hit.x = (hit.x * hit.count + cx) / n; hit.y = (hit.y * hit.count + cy) / n; hit.size = (hit.size * hit.count + size) / n; hit.count = n;
    } else found.push({ x: cx, y: cy, size, count: 1 });
    return true;
  };
  for (let y = 0; y < height; y++) {
    let s = [0, 0, 0, 0, 0], state = 0;
    for (let x = 0; x < width; x++) {
      if (dark(x, y)) {
        if (state & 1) state++;
        s[state]++;
      } else if (!(state & 1)) {
        if (state === 4) {
          if (ratioOk(s) && consider(s, y, x)) { s = [0, 0, 0, 0, 0]; state = 0; } else { s = [s[2], s[3], s[4], 1, 0]; state = 3; }
        } else s[++state]++;
      } else s[state]++;
    }
    if (state === 4 && ratioOk(s)) consider(s, y, width);
  }
  return found;
}

const dist = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
/** The three finder patterns as { topLeft, topRight, bottomLeft }, the triangle that fits best; null when none does. */
export function pickFinders(candidates) {
  const pool = [...candidates].sort((a, b) => b.count - a.count).slice(0, 12);
  let best = null;
  for (let i = 0; i < pool.length; i++) for (let j = i + 1; j < pool.length; j++) for (let k = j + 1; k < pool.length; k++) {
    const p = [pool[i], pool[j], pool[k]], ms = (p[0].size + p[1].size + p[2].size) / 3;
    if (p.some((q) => q.size > ms * 1.6 || q.size < ms / 1.6)) continue;
    // The corner is the point opposite the longest side.
    const sides = [[dist(p[1], p[2]), 0], [dist(p[0], p[2]), 1], [dist(p[0], p[1]), 2]].sort((a, b) => b[0] - a[0]);
    const [hyp, corner] = sides[0], l1 = sides[1][0], l2 = sides[2][0], leg = (l1 + l2) / 2;
    if (leg / ms < 10 || leg / ms > 200) continue;
    const score = Math.abs(l1 - l2) / leg + Math.abs(hyp - Math.SQRT2 * leg) / hyp;
    if (score < 0.25 && (!best || score < best.score)) {
      const b = p[corner], [a, c] = p.filter((_, n) => n !== corner);
      // Image y grows downward: with bottom-left a, the cross product (c − b) × (a − b) is positive.
      const z = (c.x - b.x) * (a.y - b.y) - (c.y - b.y) * (a.x - b.x);
      best = { score, topLeft: b, topRight: z > 0 ? c : a, bottomLeft: z > 0 ? a : c, size: ms };
    }
  }
  return best;
}

// ---------------------------------------------------------------- extract

// 3×3 matrices, row-major: [X, Y, W] = M · [x, y, 1].
const mul3 = (a, b) => Array.from({ length: 9 }, (_, n) => a[Math.floor(n / 3) * 3] * b[n % 3] + a[Math.floor(n / 3) * 3 + 1] * b[3 + (n % 3)] + a[Math.floor(n / 3) * 3 + 2] * b[6 + (n % 3)]);
const adj3 = (m) => [
  m[4] * m[8] - m[5] * m[7], m[2] * m[7] - m[1] * m[8], m[1] * m[5] - m[2] * m[4],
  m[5] * m[6] - m[3] * m[8], m[0] * m[8] - m[2] * m[6], m[2] * m[3] - m[0] * m[5],
  m[3] * m[7] - m[4] * m[6], m[1] * m[6] - m[0] * m[7], m[0] * m[4] - m[1] * m[3],
];
// The unit square (0,0) (1,0) (1,1) (0,1) onto the quadrilateral p0 p1 p2 p3.
function squareTo([p0, p1, p2, p3]) {
  const dx3 = p0.x - p1.x + p2.x - p3.x, dy3 = p0.y - p1.y + p2.y - p3.y;
  if (dx3 === 0 && dy3 === 0) return [p1.x - p0.x, p3.x - p0.x, p0.x, p1.y - p0.y, p3.y - p0.y, p0.y, 0, 0, 1];
  const dx1 = p1.x - p2.x, dx2 = p3.x - p2.x, dy1 = p1.y - p2.y, dy2 = p3.y - p2.y, den = dx1 * dy2 - dx2 * dy1;
  const g = (dx3 * dy2 - dx2 * dy3) / den, h = (dx1 * dy3 - dx3 * dy1) / den;
  return [p1.x - p0.x + g * p1.x, p3.x - p0.x + h * p3.x, p0.x, p1.y - p0.y + g * p1.y, p3.y - p0.y + h * p3.y, p0.y, g, h, 1];
}
/** The transform taking quadrilateral `from` onto `to` (four points each, in order). */
export const quadToQuad = (from, to) => mul3(squareTo(to), adj3(squareTo(from)));
export const apply = (m, x, y) => { const w = m[6] * x + m[7] * y + m[8]; return { x: (m[0] * x + m[1] * y + m[2]) / w, y: (m[3] * x + m[4] * y + m[5]) / w }; };

// The bottom-right alignment pattern near its estimate: the best 5×5 template match in a window.
function alignmentNear(bm, width, height, f, dim) {
  const ux = { x: (f.topRight.x - f.topLeft.x) / (dim - 7), y: (f.topRight.y - f.topLeft.y) / (dim - 7) };
  const uy = { x: (f.bottomLeft.x - f.topLeft.x) / (dim - 7), y: (f.bottomLeft.y - f.topLeft.y) / (dim - 7) };
  const k = dim - 7 - 3, est = { x: f.topLeft.x + k * (ux.x + uy.x), y: f.topLeft.y + k * (ux.y + uy.y) };
  const at = (x, y) => { const xi = Math.floor(x), yi = Math.floor(y); return xi >= 0 && yi >= 0 && xi < width && yi < height && bm[yi * width + xi] === 1; };
  const radius = Math.ceil(f.size * 5), step = Math.max(1, f.size / 4);
  let best = { score: -1 };
  for (let oy = -radius; oy <= radius; oy += step) for (let ox = -radius; ox <= radius; ox += step) {
    const cx = est.x + ox, cy = est.y + oy;
    let score = 0;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) {
      const want = Math.max(Math.abs(dx), Math.abs(dy)) !== 1;
      if (at(cx + dx * ux.x + dy * uy.x, cy + dx * ux.y + dy * uy.y) === want) score++;
    }
    // Light around the pattern too (the ring at distance 3 is data, so only the score of 25 decides).
    if (score > best.score || (score === best.score && Math.hypot(ox, oy) < Math.hypot(best.ox, best.oy))) best = { score, x: cx, y: cy, ox, oy };
  }
  return best.score >= 23 ? { x: best.x, y: best.y } : null;
}

/** Sample the grid of a `dim`-module symbol: modules[y][x], true = dark. */
export function extract(bm, width, height, f, dim) {
  const align = dim > 21 ? alignmentNear(bm, width, height, f, dim) : null;
  const br = align ?? { x: f.topRight.x - f.topLeft.x + f.bottomLeft.x, y: f.topRight.y - f.topLeft.y + f.bottomLeft.y };
  const brModule = align ? dim - 6.5 : dim - 3.5;
  const t = quadToQuad([{ x: 3.5, y: 3.5 }, { x: dim - 3.5, y: 3.5 }, { x: brModule, y: brModule }, { x: 3.5, y: dim - 3.5 }], [f.topLeft, f.topRight, br, f.bottomLeft]);
  const modules = [];
  for (let y = 0; y < dim; y++) {
    const row = [];
    for (let x = 0; x < dim; x++) {
      const p = apply(t, x + 0.5, y + 0.5), xi = Math.floor(p.x), yi = Math.floor(p.y);
      row.push(xi >= 0 && yi >= 0 && xi < width && yi < height && bm[yi * width + xi] === 1);
    }
    modules.push(row);
  }
  return { modules, location: { topLeft: apply(t, 0, 0), topRight: apply(t, dim, 0), bottomRight: apply(t, dim, dim), bottomLeft: apply(t, 0, dim), alignment: align } };
}

// ---------------------------------------------------------------- Reed-Solomon decoding

const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
const gmul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);
const gdiv = (a, b) => (a === 0 ? 0 : EXP[(LOG[a] + 255 - LOG[b]) % 255]);
const evalPoly = (p, x) => { let y = 0; for (let i = p.length - 1; i >= 0; i--) y = gmul(y, x) ^ p[i]; return y; };   // p[i]: coefficient of x^i

/** A block (data ‖ error correction) corrected in place, or false when it holds more errors than it can mend. */
export function rsCorrect(block, nsym) {
  const n = block.length, S = [];
  for (let j = 0; j < nsym; j++) { let s = 0; for (const b of block) s = gmul(s, EXP[j]) ^ b; S.push(s); }
  if (S.every((s) => s === 0)) return true;
  // Berlekamp-Massey: the error locator Λ (C), Λ[0] = 1.
  let C = [1], B = [1], L = 0, m = 1, b = 1;
  for (let k = 0; k < nsym; k++) {
    let d = S[k];
    for (let i = 1; i <= L; i++) d ^= gmul(C[i] ?? 0, S[k - i]);
    if (d === 0) { m++; continue; }
    const T = C.slice(), coef = gdiv(d, b), next = C.slice();
    for (let i = 0; i < B.length; i++) next[i + m] = (next[i + m] ?? 0) ^ gmul(coef, B[i]);
    C = next.map((v) => v ?? 0);
    if (2 * L <= k) { L = k + 1 - L; B = T; b = d; m = 1; } else m++;
  }
  if (2 * L > nsym) return false;
  // Ω = S·Λ mod x^nsym; Λ' the formal derivative.
  const omega = new Array(nsym).fill(0);
  for (let i = 0; i < nsym; i++) for (let j = 0; j < C.length && i + j < nsym; j++) omega[i + j] ^= gmul(S[i], C[j]);
  const deriv = C.map((c, i) => (i % 2 === 1 ? c : 0)).slice(1);
  let roots = 0;
  for (let i = 0; i < n; i++) {
    const xinv = EXP[(255 - i) % 255];
    if (evalPoly(C, xinv) !== 0) continue;
    roots++;
    const den = evalPoly(deriv, xinv);
    if (den === 0) return false;
    block[n - 1 - i] ^= gmul(EXP[i], gdiv(evalPoly(omega, xinv), den));
  }
  if (roots !== L) return false;
  for (let j = 0; j < nsym; j++) { let s = 0; for (const x of block) s = gmul(s, EXP[j]) ^ x; if (s !== 0) return false; }
  return true;
}

// ---------------------------------------------------------------- decode

const popcount = (x) => { let n = 0; for (; x; x &= x - 1) n++; return n; };
const ECCS = ['L', 'M', 'Q', 'H'];
const FORMATS = ECCS.flatMap((ecc) => [0, 1, 2, 3, 4, 5, 6, 7].map((mask) => ({ ecc, mask, bits: formatBits(ecc, mask) })));

/** The format (ecc, mask) of a sampled grid, the closer of its two copies within 3 bit errors, or null. */
export function readFormat(m) {
  const size = m.length, at = (x, y) => (m[y][x] ? 1 : 0);
  let a = 0, b = 0;
  for (let i = 0; i <= 5; i++) a |= at(8, i) << i;
  a |= at(8, 7) << 6; a |= at(8, 8) << 7; a |= at(7, 8) << 8;
  for (let i = 9; i < 15; i++) a |= at(14 - i, 8) << i;
  for (let i = 0; i < 8; i++) b |= at(size - 1 - i, 8) << i;
  for (let i = 8; i < 15; i++) b |= at(8, size - 15 + i) << i;
  let best = null;
  for (const f of FORMATS) for (const x of [a, b]) {
    const d = popcount(f.bits ^ x);
    if (d <= 3 && (!best || d < best.d)) best = { ...f, d };
  }
  return best;
}
/** The version a grid's version bits name (versions 7–40), within 3 bit errors, or null. */
export function readVersion(m) {
  const size = m.length;
  let a = 0, b = 0;
  for (let i = 0; i < 18; i++) {
    const p = size - 11 + (i % 3), q = Math.floor(i / 3);
    a |= (m[q][p] ? 1 : 0) << i; b |= (m[p][q] ? 1 : 0) << i;
  }
  let best = null;
  for (let v = 7; v <= 40; v++) for (const x of [a, b]) {
    const d = popcount(versionBits(v) ^ x);
    if (d <= 3 && (!best || d < best.d)) best = { v, d };
  }
  return best?.v ?? null;
}

const COUNT_BITS = { 1: [10, 12, 14], 2: [9, 11, 13], 4: [8, 16, 16], 8: [8, 10, 12] };
/** The data of a sampled grid of version `ver`: { bytes, text, ecc, mask }, or null. */
export function decodeGrid(m, ver) {
  const fmt = readFormat(m);
  if (!fmt) return null;
  const { size, isFunction } = functionPatterns(ver);
  if (m.length !== size) return null;
  const pos = dataPositions(size, isFunction), raw = Math.floor(rawDataModules(ver) / 8);
  const cw = new Uint8Array(raw);
  for (let i = 0; i < raw * 8; i++) {
    const [x, y] = pos[i];
    if (m[y][x] !== maskBit(fmt.mask, x, y)) cw[i >> 3] |= 0x80 >> (i & 7);
  }
  const { blocks: nb, eccPerBlock } = blockLayout(ver, fmt.ecc), numShort = nb - (raw % nb), shortLen = Math.floor(raw / nb);
  const blocks = Array.from({ length: nb }, () => []);
  let k = 0;
  for (let i = 0; i <= shortLen; i++) for (let j = 0; j < nb; j++) {
    if (i === shortLen - eccPerBlock && j < numShort) { blocks[j].push(null); continue; }
    blocks[j].push(cw[k++]);
  }
  const data = [];
  for (const blk of blocks) {
    const b = blk.filter((v) => v !== null);
    if (!rsCorrect(b, eccPerBlock)) return null;
    data.push(...b.slice(0, b.length - eccPerBlock));
  }
  const seg = parseSegments(data, ver);
  return seg && { ...seg, ecc: fmt.ecc, mask: fmt.mask };
}

function parseSegments(data, ver) {
  let bit = 0;
  const left = () => data.length * 8 - bit;
  const read = (n) => { let v = 0; for (let i = 0; i < n; i++, bit++) v = (v << 1) | ((data[bit >> 3] >> (7 - (bit & 7))) & 1); return v; };
  const band = ver <= 9 ? 0 : ver <= 26 ? 1 : 2, bytes = [];
  let text = '';
  while (left() >= 4) {
    const mode = read(4);
    if (mode === 0) break;
    if (mode === 7) {
      // ECI: the designator is read and set aside; the bytes are taken as UTF-8.
      const first = read(8);
      if ((first & 0x80) === 0) continue;
      if ((first & 0xc0) === 0x80) { read(8); continue; }
      if ((first & 0xe0) === 0xc0) { read(16); continue; }
      return null;
    }
    if (mode === 3) { read(16); continue; }
    if (mode === 5) continue;
    if (mode === 9) { read(8); continue; }
    if (!COUNT_BITS[mode] || left() < COUNT_BITS[mode][band]) return null;
    const count = read(COUNT_BITS[mode][band]);
    if (mode === 1) {
      let s = '';
      for (let n = count; n > 0; n -= 3) {
        const g = Math.min(3, n), need = g * 3 + 1;
        if (left() < need) return null;
        const v = read(need);
        if (v >= 10 ** g) return null;
        s += String(v).padStart(g, '0');
      }
      text += s; for (const c of s) bytes.push(c.charCodeAt(0));
    } else if (mode === 2) {
      let s = '';
      for (let n = count; n > 0; n -= 2) {
        if (n >= 2) { if (left() < 11) return null; const v = read(11); if (v >= 45 * 45) return null; s += ALNUM[Math.floor(v / 45)] + ALNUM[v % 45]; } else { if (left() < 6) return null; const v = read(6); if (v >= 45) return null; s += ALNUM[v]; }
      }
      text += s; for (const c of s) bytes.push(c.charCodeAt(0));
    } else if (mode === 4) {
      if (left() < count * 8) return null;
      const b = [];
      for (let n = 0; n < count; n++) b.push(read(8));
      bytes.push(...b);
      text += new TextDecoder('utf-8').decode(Uint8Array.from(b));
    } else if (mode === 8) {
      // Kanji: 13 bits a character (Shift JIS); not read here, kept as U+FFFD.
      if (left() < count * 13) return null;
      for (let n = 0; n < count; n++) read(13);
      text += '�'.repeat(count);
    }
  }
  return { bytes: Uint8Array.from(bytes), text };
}

/** Dimensions to try from a module-size estimate: the nearest 17 + 4v first, then its neighbours. */
function dimensions(f) {
  const est = (dist(f.topLeft, f.topRight) + dist(f.topLeft, f.bottomLeft)) / 2 / f.size + 7;
  const v = Math.max(1, Math.min(40, Math.round((est - 17) / 4)));
  return [v, v - 1, v + 1, v - 2, v + 2].filter((x) => x >= 1 && x <= 40);
}

/** The QR code in an RGBA image (jsQR's signature): → { data, binaryData, version, ecc, location }, or null. */
export function jsQR(data, width, height) {
  for (const invert of [false, true]) {
    const bm = binarize(data, width, height, invert), f = pickFinders(finderCandidates(bm, width, height));
    if (!f) continue;
    const tried = new Set();
    for (let v of dimensions(f)) {
      if (tried.has(v)) continue;
      tried.add(v);
      let g = extract(bm, width, height, f, 17 + 4 * v);
      if (v >= 7) {
        const named = readVersion(g.modules);
        if (named && named !== v) { if (tried.has(named)) continue; tried.add(named); v = named; g = extract(bm, width, height, f, 17 + 4 * v); }
      }
      const r = decodeGrid(g.modules, v);
      if (r) return { data: r.text, binaryData: r.bytes, version: v, ecc: r.ecc, mask: r.mask, location: g.location };
    }
  }
  return null;
}

/** The text of the QR code in a PNG file's bytes; scan_none when the image holds none it can read. */
export function scanPng(bytes) {
  const img = readPng(bytes), r = jsQR(img.data, img.width, img.height);
  if (!r) fail('scan_none', 'no QR code read in the image: a sharper or closer picture, the whole code with its white border; or install zbar (zbarimg)');
  return r.data;
}
