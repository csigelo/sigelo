#!/bin/sh
# SPDX-License-Identifier: MIT
# site/deploy/indexnow.sh — tells IndexNow (Bing, Yandex, Naver, Seznam, Yep…) which URLs of a site changed.
#
#   site/deploy/indexnow.sh [--dry-run] [--origin URL] [--key-file F] [--sitemap F] [--state F]
#
# Defaults are sigelo.io's: --origin https://sigelo.io, --key-file site/deploy/indexnow-key.txt,
# --sitemap site/dist/sitemap.xml, --state $XDG_STATE_HOME/sigelo/indexnow-<host>.json
# (XDG_STATE_HOME defaults to ~/.local/state). The relay's site runs it with its own three.
#
# Only URLs whose built file changed or vanished since the last accepted submission are sent:
# IndexNow is for added, updated or deleted URLs, and asks not to resubmit unchanged ones. A
# sitemap <loc> is the file beside the sitemap (/ -> index.html, /x.html -> x.html); the state
# file keeps each URL's sha256 and is rewritten only after a 200 or 202, so a failed or refused
# submission is retried by the next run. Nothing changed: nothing sent. --dry-run prints the URLs
# it would send and makes no request at all.
#
# The key is published as /<key>.txt (site/build.mjs), which is how the engines check that the
# submitter controls the host; it is public by design. deploy.sh runs this after a passing check.
# It never fails a deploy over the network: any HTTP answer, or none, exits 0 with the outcome
# printed. A bad key, a missing sitemap or a <loc> with no built file is a bug and exits 1.
# The fetch of our own key file sends User-Agent sigelo-selfcheck/1 (out of the visit statistics).
# Node >= 22 (fetch).
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
origin=https://sigelo.io; dry=0
key_file=$root/site/deploy/indexnow-key.txt; sitemap=$root/site/dist/sitemap.xml; state=
while [ $# -gt 0 ]; do
  case $1 in
    --dry-run) dry=1; shift ;;
    --origin|--key-file|--sitemap|--state)
      [ $# -ge 2 ] || { echo "indexnow.sh: $1 needs a value" >&2; exit 2; }
      case $1 in --origin) origin=$2 ;; --key-file) key_file=$2 ;; --sitemap) sitemap=$2 ;; --state) state=$2 ;; esac
      shift 2 ;;
    *) echo "indexnow.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
INDEXNOW_DRY=$dry INDEXNOW_ORIGIN=$origin INDEXNOW_KEY_FILE=$key_file INDEXNOW_SITEMAP=$sitemap INDEXNOW_STATE=$state \
  node --input-type=module - <<'JS'
import { readFileSync, writeFileSync, mkdirSync, renameSync, existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';
const UA = 'sigelo-selfcheck/1 (+https://sigelo.io/privacy)';
const die = (msg) => { console.error(`indexnow.sh: ${msg}`); process.exit(1); };
const env = process.env;
const key = readFileSync(resolve(env.INDEXNOW_KEY_FILE), 'utf8').trim();
if (!/^[a-zA-Z0-9-]{8,128}$/.test(key)) die(`bad key in ${env.INDEXNOW_KEY_FILE}`);
const origin = env.INDEXNOW_ORIGIN.replace(/\/+$/, '');
const host = new URL(origin).host;
const sitemap = resolve(env.INDEXNOW_SITEMAP);
if (!existsSync(sitemap)) die(`no sitemap at ${sitemap} (build the site first)`);
const stateFile = env.INDEXNOW_STATE ? resolve(env.INDEXNOW_STATE)
  : join(env.XDG_STATE_HOME || join(homedir(), '.local', 'state'), 'sigelo', `indexnow-${host}.json`);

// The built file behind each <loc>, hashed: a changed hash is a changed URL.
const dist = dirname(sitemap);
const now = {};
for (const [, url] of readFileSync(sitemap, 'utf8').matchAll(/<loc>([^<]+)<\/loc>/g)) {
  if (!url.startsWith(`${origin}/`)) die(`${url} in ${sitemap} is not on ${origin}`);
  const path = decodeURIComponent(new URL(url).pathname);
  const file = join(dist, path.endsWith('/') ? `${path}index.html` : path);
  if (path.includes('..') || !existsSync(file) || !statSync(file).isFile()) die(`${url}: no built file ${file}`);
  now[url] = createHash('sha256').update(readFileSync(file)).digest('hex');
}
// The state's `urls` must be an object of sha256s. Anything else is unreadable: every URL counts
// as changed and none as vanished, because a junk key would be submitted and refused (422), and
// as the state is kept after a refusal, every later run would be refused the same way.
let before = {};
if (existsSync(stateFile)) {
  let urls = null;
  try { urls = JSON.parse(readFileSync(stateFile, 'utf8')).urls; } catch { /* below */ }
  if (urls && typeof urls === 'object' && !Array.isArray(urls)) before = urls;
  else console.log(`indexnow: ${stateFile} is unreadable: every URL counts as changed`);
}
// Vanished: only this origin's URLs (another site run with the same --state file has its own).
const vanished = Object.keys(before).filter((u) => u.startsWith(`${origin}/`) && !(u in now));
const urlList = [...Object.keys(now).filter((u) => before[u] !== now[u]), ...vanished];
if (!urlList.length) { console.log(`indexnow: nothing changed since the last accepted submission (${stateFile}); nothing sent`); process.exit(0); }
if (env.INDEXNOW_DRY === '1') {
  console.log(`indexnow (dry run): ${urlList.length} changed or vanished URLs would go to https://api.indexnow.org/indexnow; nothing sent`);
  for (const u of urlList) console.log(u);
  process.exit(0);
}
const body = { host, key, keyLocation: `${origin}/${key}.txt`, urlList };
try {
  const keyFile = await fetch(body.keyLocation, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(20000) });
  if (keyFile.status !== 200 || (await keyFile.text()).trim() !== key) { console.log(`indexnow: ${body.keyLocation} does not serve the key (${keyFile.status}); nothing submitted`); process.exit(0); }
  const r = await fetch('https://api.indexnow.org/indexnow', { method: 'POST', headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify(body), signal: AbortSignal.timeout(20000) });
  // 200 accepted, 202 accepted while the key is being validated; 403 key not valid, 422 URLs not on the host, 429 too often
  const accepted = r.status === 200 || r.status === 202;
  console.log(`indexnow: ${urlList.length} URLs submitted, HTTP ${r.status}${accepted ? '' : ` (${(await r.text()).slice(0, 200)}); state kept, the next run retries`}`);
  if (accepted) {
    mkdirSync(dirname(stateFile), { recursive: true });
    writeFileSync(`${stateFile}.new`, JSON.stringify({ host, submitted: new Date().toISOString(), urls: now }, null, 1) + '\n');
    renameSync(`${stateFile}.new`, stateFile);
  }
} catch (e) { console.log(`indexnow: not submitted (${e.cause?.code ?? e.message})`); }
JS
