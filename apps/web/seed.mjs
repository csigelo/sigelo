// SPDX-License-Identifier: MIT
// Restore from seed (design/apps-seed.md, pass A9; Monerujo's restore as the model): the first-start
// screen's fourth choice. The 25 words make this app's operator identity and keeper root K_1, the files
// `sigelo-agent keeper --from-words` writes (contact/restore.mjs), sealed at once: in the Android app
// under the FULL keystore key (the phone's screen lock or biometric), in a browser under a WebCrypto key
// it cannot export. The words are never written anywhere and never shown again (no "show seed").
//
//   restoreInto(platform, fields)   derive, seal, write; the network held from the first word to the
//                                   last commit (platform-web.mjs holdNetwork) → { did, worker, seat };
//                                   no height and no date → restore_height 0 (the birth is unknown)
//   seatOf(platform, identity)      the router's seat: { info, take, here, restored } from the files below
//   restoreView(box, platform, o)   the two screens: "I have my 25 words on paper", then the form
//
// Files (as the CLI keeps them beside me.local.json): identity.{sealed|keystore}, keeper.{sealed|keystore},
// app/me.local.devices.json (the signed list; seat here only), app/me.local.seat.json (the seat notes),
// app/settings.json ({ mode: { kind: 'full', standby }, restored: { on, keeper, net, created? } }); created: a new identity
// made here (create.mjs), whose words the human wrote down at its review screen.
//   writeOperator(platform, r, o)   seal and write the files above (restoreInto's, and create.mjs's)
//   keeperOf(platform)              the router's keeper: { load, save } of the sealed keeper, or null when this app holds none
import { did as didOf } from 'sigelo';
import { DEFAULT_RELAY } from './vendor/contact/carrier.mjs';
import { checkList } from './vendor/contact/device.mjs';
import { NETS, WORD_COUNT, checkWords, parseRestore, restoreFromWords, takeSeat } from './vendor/contact/restore.mjs';
import { holdNetwork, loadSealed, saveSealed } from './platform-web.mjs';
import { presetRelay } from './router.mjs';

export const SETTINGS = 'app/settings.json', LIST = 'app/me.local.devices.json', NOTES = 'app/me.local.seat.json';
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
const readJson = (files, name) => { const b = files.read(name); if (b === null) return null; try { return JSON.parse(new TextDecoder().decode(b)); } catch { return null; } };

/**
 * The restore: fields { words, name, relay, net, restore ({} | {restore_height} | {restore_date}), seat
 * ("here" | "elsewhere"), now }. Nothing reaches the network until both sealed files are committed.
 */
export async function restoreInto(platform, { words, name, relay, net = 'mainnet', restore = {}, seat = 'here', now = Math.floor(Date.now() / 1000) }) {
  const release = holdNetwork();
  try {
    const host = String(relay ?? '').trim().toLowerCase() || DEFAULT_RELAY;
    // No height and no date: the wallet's birth is unknown, so its scan starts at block 0. Never `created`
    // (the day of this restore), which a wallet restore would read as the birth and miss older payments.
    const from = Object.keys(restore ?? {}).length ? restore : { restore_height: 0 };
    const r = restoreFromWords(words, { name, relay: host, net, restore: from, seat, now });
    await writeOperator(platform, r, { host, net, seat });
    return { did: r.did, worker: r.worker, seat };
  } finally { release(); }
}

/**
 * The operator's files (contact/restore.mjs's, from the words or a new root) into the app: the identity
 * and the keeper sealed under the FULL key, the list and the seat notes plain, the settings ({ created:
 * true } for a new identity made here, create.mjs), then one flush. The caller holds the network.
 */
export async function writeOperator(platform, r, { host, net, seat = 'here', created = false }) {
  presetRelay(platform.files, host);
  const id = enc(r.identity), keeper = enc(r.keeper);
  try {
    await saveSealed(platform, 'identity', id, undefined, { full: true });
    await saveSealed(platform, 'keeper', keeper, undefined, { full: true });
  } finally { id.fill(0); keeper.fill(0); }
  if (r.list) platform.files.write(LIST, enc(r.list));
  platform.files.write(NOTES, enc(r.notes));
  platform.files.write(SETTINGS, enc({ mode: { kind: 'full', standby: seat !== 'here' }, restored: { on: r.keeper.created, keeper: r.keeper.keeper, net, ...(created && { created: true }) } }));
  await platform.flush();
}

/** The sealed keeper (a restore's or a create's) for the router's Agents: opened per use, resealed under the FULL key on a change. */
export function keeperOf(platform) {
  if (platform.files.read('keeper.sealed') === null && platform.files.read('keeper.keystore') === null) return null;
  return { load: () => loadSealed(platform, 'keeper'), save: (bytes) => saveSealed(platform, 'keeper', bytes, undefined, { full: true }) };
}

/** The seat of a restored app, for the router (router.mjs `seat`); null when it was not restored from seed. */
export function seatOf(platform, identity) {
  const { files } = platform;
  if (readJson(files, NOTES) === null) return null;
  const info = () => {
    const n = readJson(files, NOTES);
    if (!n) return null;
    if (n.elsewhere) return { holder: 'another device', epoch: null, here: false };
    const s = identity(), l = readJson(files, LIST);
    try { checkList(l, { keys: [s.genesis.key, ...(s.rotations ?? []).map((x) => x.next_genesis.key)], operator: didOf(s.genesis) }); } catch { return null; }
    if (!l.seat) return null;
    return { holder: l.devices.find((d) => d.did === l.seat.holder)?.name ?? l.seat.holder, epoch: l.seat.epoch, here: l.seat.holder === n.here?.did };
  };
  return {
    info,
    async take(now) {
      const r = takeSeat(readJson(files, NOTES), identity(), now), set = readJson(files, SETTINGS) ?? {};
      files.write(LIST, enc(r.list));
      files.write(NOTES, enc(r.notes));
      files.write(SETTINGS, enc({ ...set, mode: { ...(set.mode ?? { kind: 'full' }), standby: false } }));
      await platform.flush();
      return { seat: r.list.seat, holder: r.notes.here.name };
    },
    /** This device as the keeper's roster has it: { name, did, worker } (the Agents list marks it "this device"). */
    here() { return readJson(files, NOTES)?.here ?? null; },
    restored() {
      const s = readJson(files, SETTINGS)?.restored;
      return s ? { on: s.on, keeper: s.keeper, seat: info()?.here ? 'here' : 'elsewhere', ...(s.created && { created: true }) } : null;
    },
  };
}

// ---------------------------------------------------------------- the screens

const el = (tag, props = {}, ...kids) => {
  const { attrs, ...rest } = props, e = Object.assign(document.createElement(tag), rest);
  for (const [k, v] of Object.entries(attrs ?? {})) e.setAttribute(k, v);
  e.append(...kids);
  return e;
};
// The words' box: no suggestions, no autocorrect, no capitals, no spellcheck, no autofill; the keyboard's
// learning off where it reads these (Gboard and others honour autocomplete/autocorrect off).
export const WORDS_ATTRS = Object.freeze({ autocomplete: 'off', autocorrect: 'off', autocapitalize: 'none', spellcheck: 'false', 'data-lpignore': 'true', 'data-1p-ignore': 'true', 'aria-describedby': 'seed-count' });

/**
 * Restore from seed: the acknowledgement, then the form; done → reload (the page starts as the operator,
 * or as a standby). o: { bridge (the Android shell: FLAG_SECURE, the clipboard), back() (the screen before) }.
 */
export function restoreView(box, platform, { bridge = null, back = null } = {}) {
  const secure = (on) => { try { void bridge?.secure(on).catch(() => {}); } catch {} };
  const leave = () => { secure(false); back?.(); };
  const seen = el('input', { type: 'checkbox' }), go = el('button', { className: 'primary', textContent: 'Continue', disabled: true });
  seen.onchange = () => { go.disabled = !seen.checked; };
  go.onclick = () => form();
  box.replaceChildren(el('div', { className: 'card' },
    el('h2', { textContent: 'Restore from your 25 words' }),
    el('p', { textContent: 'Your 25 words make your identity and your keeper again on this phone: the same DID, the same agents. This app never shows the words back, and keeps them nowhere.' }),
    el('label', {}, seen, ' I have my 25 words on paper'),
    el('div', { className: 'bar' }, go, back ? el('button', { textContent: 'Back', onclick: leave }) : '')));
  box.hidden = false;

  function form() {
    secure(true);
    const name = el('input', { value: 'phone', attrs: { autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', maxlength: '20' } });
    const words = el('textarea', { rows: 5, attrs: WORDS_ATTRS }), count = el('p', { className: 'muted', id: 'seed-count', textContent: `0 of ${WORD_COUNT} words` });
    const height = el('input', { placeholder: '3100000 or 2024-02-29', attrs: { autocomplete: 'off', inputmode: 'text', spellcheck: 'false' } });
    const nets = NETS.map((n, i) => el('input', { type: 'radio', name: 'seed-net', value: n, checked: i === 0 }));
    const elsewhere = el('input', { type: 'checkbox' });
    const relay = el('input', { value: DEFAULT_RELAY, attrs: { autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none' } });
    const say = el('p', { className: 'muted' }), restore = el('button', { className: 'primary', textContent: 'Restore', disabled: true });
    const live = () => {
      const c = checkWords(words.value);
      count.textContent = c.error ? `${c.count} of ${WORD_COUNT} words: ${c.error}` : c.ok ? `${WORD_COUNT} of ${WORD_COUNT} words, checksum ok` : `${c.count} of ${WORD_COUNT} words`;
      count.className = c.error ? 'warn' : c.ok ? 'good' : 'muted';
      restore.disabled = !c.ok;
    };
    words.addEventListener('input', live);
    // A paste is allowed; the clipboard is emptied after it (the shell's, else the page's own where it may).
    words.addEventListener('paste', () => setTimeout(() => {
      if (bridge) void bridge.clipClear().catch(() => {});
      else void globalThis.navigator?.clipboard?.writeText?.('').catch(() => {});
      live();
    }, 0));
    restore.onclick = async () => {
      let r;
      try { r = parseRestore(height.value, Math.floor(Date.now() / 1000)); } catch (e) { say.textContent = e.message; return; }
      restore.disabled = true;
      say.textContent = platform.sealer ? 'Sealing under this phone\'s screen lock: confirm it when asked…' : 'Sealing…';
      try {
        await restoreInto(platform, { words: words.value, name: name.value.trim(), relay: relay.value, net: nets.find((x) => x.checked)?.value ?? 'mainnet', restore: r, seat: elsewhere.checked ? 'elsewhere' : 'here' });
        words.value = '';
        secure(false);
        location.hash = '';
        location.reload();
      } catch (e) { say.textContent = `Not restored: ${e.message}`; restore.disabled = false; }
    };
    box.replaceChildren(el('div', { className: 'card' },
      el('h2', { textContent: 'Restore from your 25 words' }),
      el('label', { textContent: 'Name for this device' }), name,
      el('label', { textContent: 'Your 25 words' }), words, count,
      el('label', { textContent: 'Restore height or date (optional)' }), height,
      el('p', { className: 'muted', textContent: 'The block height or the day your words were made: your keeper\'s wallet scans from there. Empty: from Monero\'s first block (complete, slower).' }),
      el('div', { className: 'bar' }, ...nets.flatMap((n) => [el('label', {}, n, ` ${n.value}`)])),
      el('label', {}, elsewhere, ' sigelo already runs as me on another device (it keeps the seat)'),
      el('label', { textContent: 'Relay for new codes' }), relay,
      el('div', { className: 'bar' }, restore, el('button', { textContent: 'Cancel', onclick: () => { words.value = ''; leave(); } })), say));
    words.focus?.();
  }
}
