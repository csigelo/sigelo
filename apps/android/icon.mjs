// SPDX-License-Identifier: MIT
// The store icon (apps/android/FDROID.md): apps/gtk/io.sigelo.App.svg drawn as a 512×512 PNG into
// app/fastlane/metadata/android/en-US/images/icon.png. F-Droid takes no icon from an APK whose
// launcher icon is XML only (ours is adaptive, a vector), so the listing needs this file. No
// dependency: the SVG's three shapes (rounded square, ring, check with round caps) read from the SVG
// as check.mjs reads them, 4×4 samples a pixel, a PNG written with node:zlib. Same pixels every run;
// --check compares the decoded pixels, not the bytes (zlib builds deflate the same data differently).
//
//   node apps/android/icon.mjs           write icon.png
//   node apps/android/icon.mjs --check   write nothing: icon.png holds the pixels this draws now
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { deflateSync, inflateSync } from 'node:zlib';

const HERE = dirname(fileURLToPath(import.meta.url));
export const OUT = join(HERE, 'app', 'fastlane', 'metadata', 'android', 'en-US', 'images', 'icon.png');
const SVG = join(HERE, '..', 'gtk', 'io.sigelo.App.svg');

/** The SVG's shapes: { size, rx, fill: [r,g,b], ring: {cx,cy,r}, path: [[x,y]...], stroke: width, ink: [r,g,b] }. */
export function shapes(svg = readFileSync(SVG, 'utf8')) {
  const rect = /<rect width="(\d+)" height="(\d+)" rx="(\d+)" fill="#([0-9a-f]{6})"\/>/.exec(svg);
  const c = /<circle cx="(\d+)" cy="(\d+)" r="(\d+)" fill="none" stroke="#fff" stroke-width="(\d+)"\/>/.exec(svg);
  const p = /<path d="M(\d+) (\d+)l(\d+) (\d+) (\d+)-(\d+)" fill="none" stroke="#fff" stroke-width="(\d+)" stroke-linecap="round" stroke-linejoin="round"\/>/.exec(svg);
  if (!rect || !c || !p || rect[1] !== rect[2] || c[4] !== p[7]) throw new Error('io.sigelo.App.svg: not the shapes this draws (rect, circle, a two-segment path, one stroke)');
  const hex = (h) => [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  const [x0, y0, a, b, d, e] = p.slice(1, 7).map(Number);
  return { size: Number(rect[1]), rx: Number(rect[3]), fill: hex(rect[4]), ring: { cx: Number(c[1]), cy: Number(c[2]), r: Number(c[3]) },
    path: [[x0, y0], [x0 + a, y0 + b], [x0 + a + d, y0 + b - e]], stroke: Number(c[4]), ink: [255, 255, 255] };
}

const seg = (x, y, [ax, ay], [bx, by]) => {
  const dx = bx - ax, dy = by - ay, t = Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(x - ax - t * dx, y - ay - t * dy);
};

/** The icon as RGBA rows (size × size × 4 bytes). */
export function draw(s = shapes()) {
  const N = 4, n = s.size, px = Buffer.alloc(n * n * 4), h = s.stroke / 2;
  const inSquare = (x, y) => { const qx = Math.max(s.rx - x, 0, x - (n - s.rx)), qy = Math.max(s.rx - y, 0, y - (n - s.rx)); return qx * qx + qy * qy <= s.rx * s.rx; };
  const inInk = (x, y) => Math.abs(Math.hypot(x - s.ring.cx, y - s.ring.cy) - s.ring.r) <= h
    || s.path.slice(1).some((q, i) => seg(x, y, s.path[i], q) <= h);
  for (let j = 0; j < n; j++) for (let i = 0; i < n; i++) {
    let sq = 0, ink = 0;
    for (let v = 0; v < N; v++) for (let u = 0; u < N; u++) {
      const x = i + (u + 0.5) / N, y = j + (v + 0.5) / N;
      if (inSquare(x, y)) { sq++; if (inInk(x, y)) ink++; }
    }
    const o = (j * n + i) * 4;
    if (sq === 0) continue;
    for (let k = 0; k < 3; k++) px[o + k] = Math.round((s.fill[k] * (sq - ink) + s.ink[k] * ink) / sq);
    px[o + 3] = Math.round((255 * sq) / (N * N));
  }
  return { n, px };
}

const crcTable = Array.from({ length: 256 }, (_, c) => { for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc = (b) => { let c = 0xffffffff; for (const x of b) c = crcTable[(c ^ x) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
const chunk = (type, data) => { const t = Buffer.from(type, 'latin1'), len = Buffer.alloc(4), sum = Buffer.alloc(4); len.writeUInt32BE(data.length); sum.writeUInt32BE(crc(Buffer.concat([t, data]))); return Buffer.concat([len, t, data, sum]); };

const SIG = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
/** draw()'s pixels as PNG scanlines (filter byte 0 each) and the IHDR data (8-bit RGBA). */
function rawOf({ n, px } = draw()) {
  const raw = Buffer.alloc(n * (n * 4 + 1));
  for (let j = 0; j < n; j++) px.copy(raw, j * (n * 4 + 1) + 1, j * n * 4, (j + 1) * n * 4);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(n, 0); ihdr.writeUInt32BE(n, 4); ihdr[8] = 8; ihdr[9] = 6;
  return { raw, ihdr };
}

/** A PNG (8-bit RGBA, no filter, no metadata) of draw()'s pixels. */
export function png(d = draw()) {
  const { raw, ihdr } = rawOf(d);
  return Buffer.concat([SIG, chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

/** True when `file` is a PNG holding exactly draw()'s pixels: same header, same scanlines, CRCs valid. */
export function same(file, d = draw()) {
  const { raw, ihdr } = rawOf(d);
  if (file.length < 8 || !file.subarray(0, 8).equals(SIG)) return false;
  let i = 8, head = null; const idat = [];
  while (i + 12 <= file.length) {
    const len = file.readUInt32BE(i), type = file.toString('latin1', i + 4, i + 8), data = file.subarray(i + 8, i + 8 + len);
    if (i + 12 + len > file.length || file.readUInt32BE(i + 8 + len) !== crc(file.subarray(i + 4, i + 8 + len))) return false;
    if (type === 'IHDR') head = data; else if (type === 'IDAT') idat.push(data); else if (type === 'IEND') break;
    i += 12 + len;
  }
  try { return head !== null && head.equals(ihdr) && inflateSync(Buffer.concat(idat)).equals(raw); } catch { return false; }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const want = png();
  if (process.argv.includes('--check')) {
    if (!existsSync(OUT) || !same(readFileSync(OUT))) { console.log('FAIL icon.png is not what icon.mjs draws from io.sigelo.App.svg (node apps/android/icon.mjs)'); process.exit(1); }
  } else { mkdirSync(dirname(OUT), { recursive: true }); writeFileSync(OUT, want); }
  console.log(`ok icon.png, 512×512, ${want.length} bytes${process.argv.includes('--check') ? ', as drawn' : ''}`);
}
