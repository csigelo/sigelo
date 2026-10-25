// SPDX-License-Identifier: MIT
// The store icon (apps/android/FDROID.md): assets/brand/app-icon.svg (the seal, design/logo/make.py)
// drawn as a 512×512 PNG into app/fastlane/metadata/android/en-US/images/icon.png. F-Droid takes no
// icon from an APK whose launcher icon is XML only (ours is adaptive, a vector), so the listing needs
// this file. No dependency: the SVG is one paper rounded square and one wax path (evenodd) under a
// translate + scale, read as check.mjs reads it; the path (M L H V C A Z, absolute or relative) is
// flattened to polygons, 4×4 samples a pixel, a PNG written with node:zlib. Same pixels every run;
// --check compares the decoded pixels, not the bytes (zlib builds deflate the same data differently).
// vector() is the launcher icon's foreground (res/drawable/ic_launcher_foreground.xml) from the same SVG.
//
//   node apps/android/icon.mjs           write icon.png and ic_launcher_foreground.xml
//   node apps/android/icon.mjs --check   write nothing: both hold what this draws now
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { deflateSync, inflateSync } from 'node:zlib';

const HERE = dirname(fileURLToPath(import.meta.url));
export const OUT = join(HERE, 'app', 'fastlane', 'metadata', 'android', 'en-US', 'images', 'icon.png');
export const FOREGROUND = join(HERE, 'app', 'src', 'main', 'res', 'drawable', 'ic_launcher_foreground.xml');
export const SVG = join(HERE, '..', '..', 'assets', 'brand', 'app-icon.svg');

const hex = (h) => [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
/** The SVG's shapes: { size, rx, fill: [r,g,b], paper: 'rrggbb', tx, ty, scale, d, ink: [r,g,b], wax: 'rrggbb' }. */
export function shapes(svg = readFileSync(SVG, 'utf8')) {
  const m = /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 (\d+) \1"[^>]*><title>[^<]*<\/title><rect width="\1" height="\1" rx="(\d+)" fill="#([0-9a-f]{6})"\/><g transform="translate\(([\d.-]+) ([\d.-]+)\) scale\(([\d.]+)\)"><path fill="#([0-9a-f]{6})" fill-rule="evenodd" d="([^"]+)"\/><\/g><\/svg>\n?$/.exec(svg);
  if (!m) throw new Error('app-icon.svg: not the shapes this draws (a rounded square, one evenodd path under translate + scale)');
  return { size: Number(m[1]), rx: Number(m[2]), paper: m[3], fill: hex(m[3]), tx: Number(m[4]), ty: Number(m[5]), scale: Number(m[6]), wax: m[7], ink: hex(m[7]), d: m[8] };
}

/** SVG path data → closed polygons [[x, y]...] (curves and arcs flattened). */
export function polygons(d, steps = 16) {
  const tok = d.match(/[MLHVCAZmlhvcaz]|-?(?:\d+\.?\d*|\.\d+)(?:e-?\d+)?/g) ?? [];
  if (tok.join('').length !== d.replace(/[\s,]/g, '').length) throw new Error('path: unsupported command');
  const polys = []; let poly = null, x = 0, y = 0, sx = 0, sy = 0, cmd = '', i = 0;
  const num = () => Number(tok[i++]);
  while (i < tok.length) {
    if (/[a-z]/i.test(tok[i])) cmd = tok[i++];
    const rel = cmd === cmd.toLowerCase(), C = cmd.toUpperCase(), ox = rel ? x : 0, oy = rel ? y : 0;
    if (C === 'Z') { if (poly) polys.push(poly); poly = null; x = sx; y = sy; continue; }
    if (C === 'M') { if (poly) polys.push(poly); x = ox + num(); y = oy + num(); sx = x; sy = y; poly = [[x, y]]; cmd = rel ? 'l' : 'L'; continue; }
    if (C === 'L') { x = ox + num(); y = oy + num(); }
    else if (C === 'H') x = ox + num();
    else if (C === 'V') y = oy + num();
    else if (C === 'C') {
      const [x1, y1, x2, y2, x3, y3] = [ox + num(), oy + num(), ox + num(), oy + num(), ox + num(), oy + num()];
      for (let k = 1; k <= steps; k++) { const t = k / steps, u = 1 - t;
        poly.push([u * u * u * x + 3 * u * u * t * x1 + 3 * u * t * t * x2 + t * t * t * x3, u * u * u * y + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t * t * t * y3]); }
      x = x3; y = y3; continue;
    } else if (C === 'A') {
      let rx = Math.abs(num()), ry = Math.abs(num()); const phi = (num() * Math.PI) / 180, large = num(), sweep = num(), x2 = ox + num(), y2 = oy + num();
      // SVG 1.1 F.6.5: endpoint to centre parameterisation
      const cp = Math.cos(phi), sp = Math.sin(phi), dx = (x - x2) / 2, dy = (y - y2) / 2, x1p = cp * dx + sp * dy, y1p = -sp * dx + cp * dy;
      const lam = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry); if (lam > 1) { rx *= Math.sqrt(lam); ry *= Math.sqrt(lam); }
      const num2 = rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p, den = rx * rx * y1p * y1p + ry * ry * x1p * x1p;
      const co = (large === sweep ? -1 : 1) * Math.sqrt(Math.max(0, num2 / den)), cxp = (co * rx * y1p) / ry, cyp = (-co * ry * x1p) / rx;
      const cx = cp * cxp - sp * cyp + (x + x2) / 2, cy = sp * cxp + cp * cyp + (y + y2) / 2;
      const ang = (ux, uy, vx, vy) => Math.atan2(ux * vy - uy * vx, ux * vx + uy * vy);
      const t1 = ang(1, 0, (x1p - cxp) / rx, (y1p - cyp) / ry); let dt = ang((x1p - cxp) / rx, (y1p - cyp) / ry, (-x1p - cxp) / rx, (-y1p - cyp) / ry);
      if (!sweep && dt > 0) dt -= 2 * Math.PI; else if (sweep && dt < 0) dt += 2 * Math.PI;
      const n = Math.max(4, Math.ceil((Math.abs(dt) / Math.PI) * steps * 2));
      for (let k = 1; k <= n; k++) { const t = t1 + (dt * k) / n; poly.push([cx + rx * Math.cos(t) * cp - ry * Math.sin(t) * sp, cy + rx * Math.cos(t) * sp + ry * Math.sin(t) * cp]); }
      x = x2; y = y2; continue;
    } else throw new Error(`path: unsupported command ${cmd}`);
    poly.push([x, y]);
  }
  if (poly) polys.push(poly);
  return polys;
}

/** The icon as RGBA rows (size × size × 4 bytes). */
export function draw(s = shapes()) {
  const N = 4, n = s.size, px = Buffer.alloc(n * n * 4);
  const polys = polygons(s.d).map((p) => p.map(([x, y]) => [s.tx + x * s.scale, s.ty + y * s.scale]));
  const edges = polys.flatMap((p) => p.map((a, k) => [a, p[(k + 1) % p.length]])).filter(([a, b]) => a[1] !== b[1]);
  const inSquare = (x, y) => { const qx = Math.max(s.rx - x, 0, x - (n - s.rx)), qy = Math.max(s.rx - y, 0, y - (n - s.rx)); return qx * qx + qy * qy <= s.rx * s.rx; };
  const sq = new Uint8Array(n * n), ink = new Uint8Array(n * n);
  for (let r = 0; r < n * N; r++) {
    const y = (r + 0.5) / N, xs = [];
    for (const [a, b] of edges) if ((a[1] > y) !== (b[1] > y)) xs.push(a[0] + ((y - a[1]) * (b[0] - a[0])) / (b[1] - a[1]));
    xs.sort((p, q) => p - q);
    for (let c = 0; c < n * N; c++) {
      const x = (c + 0.5) / N, o = Math.floor(y) * n + Math.floor(x);
      if (!inSquare(x, y)) continue;
      sq[o]++;
      let k = 0; while (k < xs.length && xs[k] < x) k++;
      if (k % 2) ink[o]++;   // evenodd: an odd number of crossings to the left
    }
  }
  for (let o = 0; o < n * n; o++) {
    if (sq[o] === 0) continue;
    for (let k = 0; k < 3; k++) px[o * 4 + k] = Math.round((s.fill[k] * (sq[o] - ink[o]) + s.ink[k] * ink[o]) / sq[o]);
    px[o * 4 + 3] = Math.round((255 * sq[o]) / (N * N));
  }
  return { n, px };
}

/** The adaptive icon's foreground: the SVG's square (512) as the full 108 dp (viewport 768 = 512 × 1.5),
 *  so the mark, which app-icon.svg fits in the 66 dp safe circle, stays in it; same path, same transform × 1.5. */
export function vector(s = shapes()) {
  const k = 768 / s.size, f = (v) => String(Math.round(v * 1e4) / 1e4);
  return `<?xml version="1.0" encoding="utf-8"?>
<!-- Generated by apps/android/icon.mjs from assets/brand/app-icon.svg (the seal, design/logo/make.py):
     its square as the adaptive icon's 108 dp (viewport 768 = 512 x 1.5), the wax path under the
     SVG's translate + scale x 1.5; paper behind it (@color/sigelo_paper). Do not edit: run icon.mjs. -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="768"
    android:viewportHeight="768">
    <group
        android:translateX="${f(s.tx * k)}"
        android:translateY="${f(s.ty * k)}"
        android:scaleX="${f(s.scale * k)}"
        android:scaleY="${f(s.scale * k)}">
        <path
            android:fillColor="#FF${s.wax.toUpperCase()}"
            android:fillType="evenOdd"
            android:pathData="${s.d}" />
    </group>
</vector>
`;
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
  const want = png(), vec = vector();
  if (process.argv.includes('--check')) {
    if (!existsSync(OUT) || !same(readFileSync(OUT))) { console.log('FAIL icon.png is not what icon.mjs draws from assets/brand/app-icon.svg (node apps/android/icon.mjs)'); process.exit(1); }
    if (!existsSync(FOREGROUND) || readFileSync(FOREGROUND, 'utf8') !== vec) { console.log('FAIL ic_launcher_foreground.xml is not what icon.mjs makes from assets/brand/app-icon.svg (node apps/android/icon.mjs)'); process.exit(1); }
  } else { mkdirSync(dirname(OUT), { recursive: true }); writeFileSync(OUT, want); writeFileSync(FOREGROUND, vec); }
  console.log(`ok icon.png, 512×512, ${want.length} bytes; ic_launcher_foreground.xml${process.argv.includes('--check') ? ', as drawn' : ''}`);
}
