#!/usr/bin/env node
// The soak's daemon pin, as sigelo-spend init sets it (spend/daemontls.ts). setup.sh runs it for an
// https:// first daemon:
//   node pin.mjs <keeper dir> <wallet-rpc.conf> <first daemon> [<hard pins, comma-separated>]
// Hard pins (SIGELO_SOAK_DAEMON_PINS): daemon-pins.json mode hard; they go on wallet-rpc's argv, none in
// the config file; never re-pinned. None: the certificate is verified (Node's CA store, the hostname)
// and its SHA-256 pinned in the config file and daemon-pins.json (auto), where the keeper re-pins it
// when the node renews it. A certificate that does not verify is refused (exit 1). One line on stdout.
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const t = await import(pathToFileURL(join(HERE, '..', 'dist', 'daemontls.js')).href);
const [dir, conf, first, hard = ''] = process.argv.slice(2);
const die = (m) => { console.error(`pin.mjs: ${m}`); process.exit(1); };
if (!dir || !conf || !first) die('usage: pin.mjs <keeper dir> <wallet-rpc.conf> <first daemon> [<hard pins>]');
if (hard !== '') {
  const fps = hard.split(',').filter((x) => x.trim() !== '').map((x) => t.normalFingerprint(x) ?? die(`${JSON.stringify(x)} is not a SHA-256 fingerprint`));
  t.writePins(dir, { v: 1, mode: 'hard', hard: fps, daemons: {} });
  t.writeConfPins(conf, []);
  console.log(`pin: ${first} hard-pinned to ${fps.join(', ')} (on wallet-rpc's argv; never re-pinned)`);
} else if (!t.pinnable(first)) {
  console.log(`pin: ${first} needs none (not an https:// clearnet daemon)`);
} else {
  let p;
  try { p = await t.probeTls(first); } catch (e) { die(`${first}: no certificate read (${e instanceof Error ? e.message : String(e)})`); }
  if (!p.valid) die(`${first}: certificate sha256 ${p.fingerprint} refused, ${p.why}; a node with its own certificate: SIGELO_SOAK_DAEMON_PINS=<that fingerprint>`);
  let pins;
  try { pins = t.readPins(dir); } catch { pins = undefined; }
  if (pins?.mode !== 'auto') pins = { v: 1, mode: 'auto', hard: [], daemons: {} };
  pins.daemons[first] = t.pinOf(p);
  t.writePins(dir, pins);
  t.writeConfPins(conf, [p.fingerprint]);
  console.log(`pin: ${first} sha256 ${p.fingerprint}, valid until ${p.notAfter}, verified for ${p.host} (${p.issuer}); auto-pinned, re-pinned by the keeper when it renews`);
}
