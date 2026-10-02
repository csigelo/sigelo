#!/bin/sh
# SPDX-License-Identifier: MIT
# site/deploy/indexnow.sh — tells IndexNow (Bing, Yandex, Naver, Seznam, Yep…) that sigelo.io changed.
#
#   site/deploy/indexnow.sh [--dry-run] [--origin https://sigelo.io]
#
# One HTTPS POST to https://api.indexnow.org/indexnow with every <loc> of the built
# site/dist/sitemap.xml. The key is site/deploy/indexnow-key.txt; site/build.mjs publishes it as
# /<key>.txt, which is how the engines check that the submitter controls the host (the key is
# public by design: anyone can read it at that URL). deploy.sh runs this after a passing check;
# it never fails a deploy (exit 0 on any HTTP answer, the status printed). Node >= 22 (fetch).
# The fetch of our own key file sends User-Agent sigelo-selfcheck/1 (out of the visit statistics).
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
origin=https://sigelo.io; dry=0
while [ $# -gt 0 ]; do
  case $1 in
    --dry-run) dry=1; shift ;;
    --origin) origin=$2; shift 2 ;;
    *) echo "indexnow.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
INDEXNOW_DRY=$dry INDEXNOW_ORIGIN=$origin node --input-type=module - "$root" <<'JS'
import { readFileSync } from 'node:fs';
const root = process.argv[2];
const UA = 'sigelo-selfcheck/1 (+https://sigelo.io/privacy)';
const key = readFileSync(`${root}/site/deploy/indexnow-key.txt`, 'utf8').trim();
if (!/^[a-zA-Z0-9-]{8,128}$/.test(key)) { console.error('indexnow.sh: bad key in site/deploy/indexnow-key.txt'); process.exit(1); }
const origin = process.env.INDEXNOW_ORIGIN;
const host = new URL(origin).host;
if (process.env.INDEXNOW_DRY === '1') { console.log('+ POST https://api.indexnow.org/indexnow (the URLs of site/dist/sitemap.xml; dry run, nothing sent)'); process.exit(0); }
const urlList = [...readFileSync(`${root}/site/dist/sitemap.xml`, 'utf8').matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
const body = { host, key, keyLocation: `${origin}/${key}.txt`, urlList };
try {
  const keyFile = await fetch(body.keyLocation, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(20000) });
  if (keyFile.status !== 200 || (await keyFile.text()).trim() !== key) { console.log(`indexnow: ${body.keyLocation} does not serve the key (${keyFile.status}); nothing submitted`); process.exit(0); }
  const r = await fetch('https://api.indexnow.org/indexnow', { method: 'POST', headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify(body), signal: AbortSignal.timeout(20000) });
  // 200 accepted, 202 accepted while the key is being validated; 403 key not valid, 422 URLs not on the host, 429 too often
  console.log(`indexnow: ${urlList.length} URLs submitted, HTTP ${r.status}${r.status === 200 || r.status === 202 ? '' : ` (${(await r.text()).slice(0, 200)})`}`);
} catch (e) { console.log(`indexnow: not submitted (${e.cause?.code ?? e.message})`); }
JS
