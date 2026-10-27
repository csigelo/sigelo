// SPDX-License-Identifier: MIT
// The app's start page (sigelo-app.js): this phone's page, or a computer's (sigelo-remote/0 on the LAN,
// SIGELO:CTL: over the relay: paired, the four words shown to compare with the computer's). The
// scan view (design/apps.md §9): camera (getUserMedia, the back camera) or an image file or a pasted
// image → pixels → jsQR (contact/qr-decode.mjs when installed); or the text pasted. What is scanned
// is held in this page's memory until it goes to the app, never stored by the page.
// Restore from seed (design/apps-seed.md): "I have my 25 words on paper", then one box checked as it is
// typed (seed-check.mjs); the words go to the app once (op restore), which hands them to
// `sigelo-agent keeper --from-words --keychain` on stdin: sealed in the keyring before anything is written.
// Create new identity (pass A10a): the app draws 25 words (op newwords); they are shown here once in a
// numbered grid with their wallet's address, copy on stagenet only (the clipboard emptied after 60 s), no
// way back but on; then three asked by number (op quiz) and typed back, checked by the app (op create),
// which makes the identity from them. Wrong: back to the grid. The words are dropped from the page after.
const $ = (id) => document.getElementById(id);
const shell = globalThis.webkit?.messageHandlers?.sigelo;
const ask = (op, o = {}) => shell ? shell.postMessage({ op, ...o }) : Promise.resolve({ ok: false, message: 'Open this page in the sigelo app.' });
const note = (t) => { $('note').hidden = !t; $('note').textContent = t ?? ''; };
const status = (t) => { $('status').textContent = t ?? ''; };
if (location.hash.length > 1) { note(decodeURIComponent(location.hash.slice(1))); history.replaceState(null, '', location.pathname); }

let checkWords = null;
try { ({ checkWords } = await import('./seed-check.mjs')); } catch {}

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

// ---- restore from seed
const seedSay = (t) => { $('seed-status').textContent = t ?? ''; };
$('seed-seen').onchange = () => { $('seed-go').disabled = !$('seed-seen').checked; };
$('seed-go').onclick = () => { $('seed-ack').hidden = true; $('seed-form').hidden = false; $('seed-words').focus(); };
const clearWords = () => { $('seed-words').value = ''; $('seed-count').textContent = '0 of 25 words'; $('seed-restore').disabled = true; };
$('seed-cancel').onclick = () => { clearWords(); $('seed-form').hidden = true; $('seed-ack').hidden = false; $('seed-seen').checked = false; $('seed-go').disabled = true; seedSay(''); };
function live() {
  const c = checkWords?.($('seed-words').value) ?? { count: 0, ok: false, error: 'the word check is not installed (install.sh)' };
  $('seed-count').textContent = c.error ? `${c.count} of 25 words: ${c.error}` : c.ok ? '25 of 25 words, checksum ok' : `${c.count} of 25 words`;
  $('seed-count').className = c.error ? 'warn' : c.ok ? 'good' : 'muted';
  $('seed-restore').disabled = !c.ok;
}
$('seed-words').addEventListener('input', live);
// A paste is allowed; the app empties the clipboard after it.
$('seed-words').addEventListener('paste', () => setTimeout(() => { void ask('clipclear'); live(); }, 0));
$('seed-restore').onclick = async () => {
  const h = $('seed-height').value.trim();
  if (h !== '' && !/^\d{1,10}$/.test(h) && !/^\d{4}-\d{2}-\d{2}$/.test(h)) { seedSay('Restore height or date: a block height (digits) or a date as YYYY-MM-DD.'); return; }
  $('seed-restore').disabled = true; seedSay('Sealing in the keyring…');
  const r = await ask('restore', { words: $('seed-words').value, name: $('seed-name').value.trim(), height: h, net: document.querySelector('input[name=seed-net]:checked')?.value ?? 'mainnet',
    elsewhere: $('seed-elsewhere').checked, ...(relayEdited && { relay: $('relay').value.trim() }) });
  if (!r.ok) { seedSay(`Not restored: ${r.message}`); $('seed-restore').disabled = false; return; }
  clearWords(); $('seed-form').hidden = true;
  if (r.seat === 'elsewhere') { $('seed-standby').hidden = false; seedSay('Restored. Another device keeps the seat: take it here only if that device is stopped or lost.'); return; }
  seedSay(r.seat === 'here' ? 'Restored: this phone holds the seat.' : `Restored. The seat: ${r.message}`);
  const s = await ask('self', {}); if (!s.ok) seedSay(s.message);
};
$('seed-take').onclick = async () => {
  if (!confirm('Take the seat here only if that other device is stopped or lost: two devices logging in as you lose each other\'s messages. Take it?')) return;
  seedSay('Taking the seat…');
  const r = await ask('take');
  if (!r.ok) { seedSay(r.message); return; }
  $('seed-standby').hidden = true;
  const s = await ask('self', {}); if (!s.ok) seedSay(s.message);
};
if (saved.standby) { $('seed-ack').hidden = true; $('seed-standby').hidden = false; }

// ---- create a new identity
const createSay = (t) => { $('create-status').textContent = t ?? ''; };
const CLIP_SECONDS = 60;
let createNet = 'mainnet', clipTimer = 0;
const show = (step) => { for (const x of ['form', 'words', 'check']) $(`create-${x}`).hidden = x !== step; };
function drop() {
  $('create-grid').replaceChildren(); $('create-vault').textContent = '';
  for (const i of [0, 1, 2]) $(`create-a${i}`).value = '';
}
function grid(words, note) {
  const g = $('create-grid');
  g.classList.toggle('nocopy', createNet === 'mainnet');
  g.replaceChildren(...words.map((w, i) => { const li = document.createElement('li'), n = document.createElement('small'); n.textContent = `${i + 1} `; li.append(n, w); return li; }));
  $('create-note').hidden = !note; $('create-note').textContent = note ?? '';
  $('create-copy').hidden = createNet !== 'stagenet'; $('create-nocopy').hidden = createNet === 'stagenet';
  show('words');
}
$('create-grid').addEventListener('copy', (e) => { if (createNet === 'mainnet') e.preventDefault(); });
let shown = null;   // the words while the grid is up (again after a wrong check); dropped once made
$('create-go').onclick = async () => {
  const name = $('create-name').value.trim();
  if (!/^[a-z0-9][a-z0-9_-]{0,19}$/.test(name)) { createSay('Name for this device: lowercase letters, digits, _ and -, at most 20.'); return; }
  createNet = document.querySelector('input[name=create-net]:checked')?.value ?? 'mainnet';
  $('create-go').disabled = true; createSay('Making your words…');
  const r = await ask('newwords', { net: createNet });
  $('create-go').disabled = false;
  if (!r.ok) { createSay(r.message); return; }
  shown = r.words; $('create-vault').textContent = r.vault; createSay('');
  grid(shown);
};
$('create-copy').onclick = async () => {
  if (createNet !== 'stagenet' || !shown) return;
  try {
    await navigator.clipboard.writeText(shown.join(' '));
    clearTimeout(clipTimer); clipTimer = setTimeout(() => { void ask('clipclear'); }, CLIP_SECONDS * 1000);
    createSay(`Copied. The clipboard is emptied in ${CLIP_SECONDS} s.`);
  } catch (e) { createSay(`Not copied: ${e.message}`); }
};
$('create-written').onclick = async () => {
  if (clipTimer) { clearTimeout(clipTimer); clipTimer = 0; void ask('clipclear'); }
  const q = await ask('quiz');
  if (!q.ok) { createSay(q.message); return; }
  q.asked.forEach((n, i) => { $(`create-l${i}`).textContent = `Word ${n}`; });
  $('create-grid').replaceChildren(); createSay('');
  show('check'); $('create-a0').focus();
};
$('create-verify').onclick = async () => {
  const answers = [0, 1, 2].map((i) => $(`create-a${i}`).value);
  for (const i of [0, 1, 2]) $(`create-a${i}`).value = '';
  $('create-verify').disabled = true; createSay('Checking, then sealing in the keyring…');
  const r = await ask('create', { answers, name: $('create-name').value.trim() });
  $('create-verify').disabled = false;
  if (r.wrong) { grid(shown, `Word${r.wrong.length > 1 ? 's' : ''} ${r.wrong.join(', ')} did not match. Look at your paper again, then check once more.`); createSay(''); return; }
  if (!r.ok) { createSay(`Not made: ${r.message}`); grid(shown); return; }
  shown = null; drop(); show('form'); $('create-form').hidden = true;
  createSay(r.seat === 'here' ? 'Made: this phone holds the seat.' : `Made. The seat: ${r.message}`);
  const s = await ask('self', relayEdited ? { relay: $('relay').value.trim() } : {}); if (!s.ok) createSay(s.message);
};
