#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// release/prepack.mjs — what a tarball needs that the package directory lacks (ROADMAP T4).
//
//   node <repo>/release/prepack.mjs pre     (the package's `prepack`)
//   node <repo>/release/prepack.mjs post    (the package's `postpack`)
//
// 1. LICENSE. npm packs a LICENSE only from the package's own directory, and the MIT notice
//    must travel with the code; there is one, at the repository root. `pre` copies it in when
//    the package has none, `post` removes the copy.
// 2. No `file:` dependency in the published manifest.
// In the repository, spend/, adapters/moadim and integrations/mcp depend on their siblings as
// `file:../ts` etc., so a clone builds without a registry. A `file:` path means nothing inside
// a tarball, and npm has no manifest field that swaps it at pack time (publishConfig only takes
// registry settings), so `pre` rewrites package.json in place — each `file:<dir>` dependency
// becomes `^<version>` of the package.json in <dir> — and `post` puts the original back. npm
// copies package.json into the tarball after `prepack` and before `postpack`. The original is
// kept under node_modules/ (gitignored, never packed); a pack that died between the two leaves
// it there, and the next `pre` restores it first rather than pinning an already-pinned file.
import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkg = resolve('package.json');
const keep = resolve('node_modules', '.sigelo-pack-orig.json');
const license = resolve('LICENSE');
const copied = resolve('node_modules', '.sigelo-pack-license');   // marker: LICENSE is our copy
const rootLicense = join(dirname(fileURLToPath(import.meta.url)), '..', 'LICENSE');
const mode = process.argv[2];
const die = (m) => { console.error(`prepack: ${m}`); process.exit(1); };

if (mode === 'post') {
  if (existsSync(keep)) renameSync(keep, pkg);   // nothing saved: nothing was pinned
  if (existsSync(copied)) { rmSync(license, { force: true }); rmSync(copied); }
} else if (mode === 'pre') {
  if (existsSync(keep)) renameSync(keep, pkg);   // a previous pack died before postpack
  mkdirSync(resolve('node_modules'), { recursive: true });
  if (!existsSync(license)) { copyFileSync(rootLicense, license); writeFileSync(copied, ''); }
  const text = readFileSync(pkg, 'utf8');
  const m = JSON.parse(text);
  let n = 0;
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [name, spec] of Object.entries(m[field] ?? {})) {
      if (!spec.startsWith('file:')) continue;
      const dep = JSON.parse(readFileSync(join(resolve(spec.slice(5)), 'package.json'), 'utf8'));
      if (dep.name !== name) die(`${field}.${name} points at ${spec}, which is package "${dep.name}"`);
      m[field][name] = `^${dep.version}`;
      n++;
    }
  }
  if (n === 0) process.exit(0);
  writeFileSync(keep, text);
  writeFileSync(pkg, JSON.stringify(m, null, 2) + '\n');
  console.error(`prepack: ${n} file: dependenc${n === 1 ? 'y' : 'ies'} pinned for the tarball`);
} else {
  die('usage: prepack.mjs pre|post');
}
