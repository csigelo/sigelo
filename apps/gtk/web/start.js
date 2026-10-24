// SPDX-License-Identifier: MIT
// The app's start page (sigelo-app.js): this phone's page, or a computer's (sigelo-remote/0 on the LAN,
// SIGELO:CTL: over the relay: paired, the four words shown to compare with the computer's). The
// scan view (design/apps.md §9): camera (getUserMedia, the back camera) or an image file or a pasted
// image → pixels → jsQR (contact/qr-decode.mjs when installed); or the text pasted. What is scanned
// is held in this page's memory until it goes to the app, never stored by the page.
const $ = (id) => document.getElementById(id);
const shell = globalThis.webkit?.messageHandlers?.sigelo;
const ask = (op, o = {}) => shell ? shell.postMessage({ op, ...o }) : Promise.resolve({ ok: false, message: 'Open this page in the sigelo app.' });
const note = (t) => { $('note').hidden = !t; $('note').textContent = t ?? ''; };
const status = (t) => { $('status').textContent = t ?? ''; };
if (location.hash.length > 1) { note(decodeURIComponent(location.hash.slice(1))); history.replaceState(null, '', location.pathname); }

let jsQR = null;
try { ({ jsQR } = await import('./qr-decode.mjs')); } catch {}
if (!jsQR) { $('camera').disabled = $('file').disabled = true; status('QR reading is not installed (contact/qr-decode.mjs): paste the text.'); }

async function connect(text) {
  stopCamera();
  if (/^\s*SIGELO:CTL:/i.test(text)) return pair(text.trim());
  if (!/^SIGELO:UI:/.test(text)) { status(text.startsWith('SIGELO:') ? 'This QR is not a computer\'s page (SIGELO:UI: or SIGELO:CTL:).' : 'Not a SIGELO:UI: or SIGELO:CTL: text.'); return; }
  status('Connecting…');
  const r = await ask('connect', { text });
  status(r.ok ? `Connected to ${r.where}${r.kept ? '' : ' (not kept: no keyring; scan again next time)'}` : r.message);
}

// Over the relay: pair, show the four words; the computer must confirm them before it answers.
async function pair(text) {
  status('Pairing through the relay…');
  const r = await ask('pair', { text });
  if (!r.ok) { status(r.message); return; }
  $('words').textContent = r.words ?? '(none)';
  $('paired').hidden = false;
  status('');
}
$('open').onclick = async () => { status('Connecting…'); const r = await ask('relay'); if (!r.ok) status(r.message); };

// ---- pixels → text
const canvas = document.createElement('canvas'), g = canvas.getContext('2d', { willReadFrequently: true });
function decode(src, w, h, max) {
  const k = Math.min(1, max / Math.max(w, h));
  canvas.width = Math.round(w * k); canvas.height = Math.round(h * k);
  g.drawImage(src, 0, 0, canvas.width, canvas.height);
  const px = g.getImageData(0, 0, canvas.width, canvas.height);
  try { return jsQR(px.data, px.width, px.height)?.data ?? null; } catch { return null; }
}
async function fromImage(blob) {
  status('Reading the image…');
  let bm;
  try { bm = await createImageBitmap(blob); } catch { status('Not an image this app can read.'); return; }
  const t = decode(bm, bm.width, bm.height, 1600) ?? decode(bm, bm.width, bm.height, 800);
  bm.close();
  if (t) await connect(t); else status('No QR code found in that image.');
}

// ---- camera, about 5 frames a second
let stream = null, timer = 0;
function stopCamera() {
  clearInterval(timer); timer = 0;
  stream?.getTracks().forEach((t) => t.stop()); stream = null;
  $('video').hidden = true; $('camera').textContent = 'Scan its QR';
}
$('camera').onclick = async () => {
  if (stream) { stopCamera(); status(''); return; }
  try { stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false }); } catch (e) {
    status(`No camera here (${e.name}). Take a photo with the Camera app, then use "From an image".`); return;
  }
  const v = $('video');
  v.srcObject = stream; v.hidden = false; $('camera').textContent = 'Stop the camera';
  await v.play().catch(() => {});
  status('Point the camera at the QR the computer shows.');
  timer = setInterval(() => {
    if (v.readyState < 2) return;
    const t = decode(v, v.videoWidth, v.videoHeight, 640);
    if (t) connect(t);
  }, 200);
};
$('file').onclick = () => $('pick').click();
$('pick').onchange = () => { const f = $('pick').files?.[0]; $('pick').value = ''; if (f) fromImage(f); };
$('text').addEventListener('paste', (ev) => {
  const img = [...(ev.clipboardData?.items ?? [])].find((i) => i.type.startsWith('image/'));
  if (img && jsQR) { ev.preventDefault(); fromImage(img.getAsFile()); }
});
$('go').onclick = () => { const t = $('text').value.replace(/^\s+/, ''); $('text').value = ''; connect(t); };   // base45 has spaces: never trim the end

// ---- this phone; a computer kept from before
// The relay goes to the page's setting only when changed here (a kept setting is not reset to the default).
let relayEdited = false;
$('relay').addEventListener('input', () => { relayEdited = true; });
$('self').onclick = async () => {
  $('self').disabled = true; note('Starting this phone\'s page…');
  const r = await ask('self', relayEdited ? { relay: $('relay').value.trim() } : {});
  $('self').disabled = false; if (!r.ok) note(r.message);
};
$('resume').onclick = async () => { status('Connecting…'); const r = await ask('resume'); if (!r.ok) status(r.message); };
$('forget').onclick = async () => { await ask('forget'); $('saved').hidden = true; status('Forgotten here. Revoke it on the computer too: sigelo-agent ui --revoke-control <name>.'); };
const saved = await ask('saved');
$('saved').hidden = !saved.text;
if (saved.keyring === false) status('No keyring: a computer\'s text lasts for this run only.');
