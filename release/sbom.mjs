#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// release/sbom.mjs — one CycloneDX 1.6 SBOM for a release (release/RELEASE-v2.md §6).
//
//   node release/sbom.mjs [<repo>] > sigelo-<v>.cdx.json        default repo: this checkout
//
// Per npm package that release/build.sh packs: `npm sbom --sbom-format cyclonedx --omit dev
// --package-lock-only`, run on a copy of its package.json and package-lock.json from which the
// `file:` sibling dependencies are taken out (the published manifest has `^<v>` there instead,
// release/prepack.mjs; npm cannot resolve a link in lockfile-only mode). Each sibling comes back
// as a dependency edge to that package's own component. The Go module: `go list -m -json all` in
// go/, with the go.sum hash of each required module. Everything is merged into one document:
// serialNumber is a UUID (v5) of the commit, metadata.timestamp is SOURCE_DATE_EPOCH (else the
// commit time), only fields that come from the lockfiles and go.mod are kept (no npm version, no
// local path), components and edges sorted, keys sorted. Same commit, same bytes, on any host.
// Node 22+, no dependencies. Network: none for npm; Go reads its module cache (build.sh built it).
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// The package directories release/build.sh packs (its npm loop).
const PACKAGES = ['ts', 'apps/contact', 'apps/keeper', 'apps/agent', 'apps/integrations/mcp', 'apps/kit', 'apps/keyagent'];

const root = resolve(process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), '..'));
const die = (m) => { console.error(`sbom.mjs: ${m}`); process.exit(1); };
const run = (cmd, args, cwd, env = process.env) =>
  execFileSync(cmd, args, { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 << 20 });
const json = (f) => JSON.parse(readFileSync(f, 'utf8'));

const commit = run('git', ['-C', root, 'rev-parse', 'HEAD'], root).trim();
const epoch = process.env.SOURCE_DATE_EPOCH || run('git', ['-C', root, 'log', '-1', '--format=%ct', 'HEAD'], root).trim();
if (!/^[0-9]+$/.test(epoch)) die(`SOURCE_DATE_EPOCH is not a number: ${epoch}`);
const v = json(join(root, 'ts/package.json')).version;

// RFC 4122 v5 (SHA-1, URL namespace) of the commit's URN: a stable serial number per commit.
function uuid5(name) {
  const ns = Buffer.from('6ba7b8119dad11d180b400c04fd430c8', 'hex');
  const h = createHash('sha1').update(ns).update(name).digest().subarray(0, 16);
  h[6] = (h[6] & 0x0f) | 0x50; h[8] = (h[8] & 0x3f) | 0x80;
  const x = h.toString('hex');
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
}

const components = new Map();   // bom-ref → component
const edges = new Map();        // bom-ref → Set of bom-refs
const edge = (from, to) => { if (!edges.has(from)) edges.set(from, new Set()); if (to) edges.get(from).add(to); };
// Only what the lockfile says: npm versions differ in what else they write.
function keep(c) {
  const out = { 'bom-ref': c['bom-ref'], type: c.type, name: c.name, version: c.version };
  if (c.purl) out.purl = c.purl;
  if (Array.isArray(c.hashes) && c.hashes.length) out.hashes = c.hashes.map((h) => ({ alg: h.alg, content: h.content }));
  if (Array.isArray(c.licenses) && c.licenses.length) out.licenses = c.licenses;
  const dist = (c.externalReferences ?? []).filter((r) => r.type === 'distribution');
  if (dist.length) out.externalReferences = dist.map((r) => ({ type: r.type, url: r.url }));
  return out;
}
function add(c) {
  const prev = components.get(c['bom-ref']);
  if (prev && JSON.stringify(sortKeys(prev)) !== JSON.stringify(sortKeys(c))) die(`two different components named ${c['bom-ref']}`);
  components.set(c['bom-ref'], c);
}

const names = Object.fromEntries(PACKAGES.map((p) => [p, json(join(root, p, 'package.json')).name]));
const tmp = mkdtempSync(join(tmpdir(), 'sigelo-sbom-'));
try {
  for (const p of PACKAGES) {
    const dir = join(root, p);
    const pkg = json(join(dir, 'package.json'));
    if (pkg.version !== v) die(`${p}/package.json is ${pkg.version}, ts/package.json is ${v}`);
    const siblings = [];
    for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const [n, spec] of Object.entries(pkg[field] ?? {})) {
        if (typeof spec === 'string' && spec.startsWith('file:')) { siblings.push(n); delete pkg[field][n]; }
      }
    }
    for (const n of siblings) if (!Object.values(names).includes(n)) die(`${p}: file: dependency ${n} is not a released package`);
    const lockPath = join(dir, 'package-lock.json');
    let lock;
    if (existsSync(lockPath)) {
      lock = json(lockPath);
      const pk = lock.packages ?? die(`${p}/package-lock.json: no "packages" (lockfileVersion 2 or 3)`);
      for (const k of Object.keys(pk)) if (k !== '' && (!k.startsWith('node_modules/') || pk[k].link === true)) delete pk[k];
      for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) for (const n of siblings) delete pk['']?.[field]?.[n];
      delete lock.dependencies;   // lockfileVersion 2's legacy copy
    } else {
      if (Object.keys(pkg.dependencies ?? {}).length || Object.keys(pkg.optionalDependencies ?? {}).length) die(`${p}: registry dependencies but no package-lock.json`);
      lock = { name: pkg.name, version: pkg.version, lockfileVersion: 3, requires: true, packages: { '': { name: pkg.name, version: pkg.version, license: pkg.license } } };
    }
    const w = join(tmp, p.replace(/\//g, '_'));
    mkdirSync(w);
    writeFileSync(join(w, 'package.json'), JSON.stringify(pkg));
    writeFileSync(join(w, 'package-lock.json'), JSON.stringify(lock));
    let bom;
    try { bom = JSON.parse(run('npm', ['sbom', '--sbom-format', 'cyclonedx', '--omit', 'dev', '--package-lock-only'], w)); }
    catch (e) { die(`${p}: npm sbom: ${(e.stderr || e.message).trim().split('\n').slice(0, 6).join(' | ')}`); }
    const top = bom.metadata?.component ?? die(`${p}: npm sbom wrote no metadata.component`);
    const self = `${pkg.name}@${pkg.version}`;
    if (top['bom-ref'] !== self) die(`${p}: npm sbom named the package ${top['bom-ref']}, not ${self}`);
    // npm names the root after its directory; the release names it after the package.
    add(keep({ ...top, name: pkg.name, type: 'library', purl: top.purl ?? `pkg:npm/${encodeURIComponent(pkg.name)}@${pkg.version}` }));
    for (const c of bom.components ?? []) add(keep(c));
    edge(self);
    for (const d of bom.dependencies ?? []) { edge(d.ref); for (const t of d.dependsOn ?? []) edge(d.ref, t); }
    for (const n of siblings) edge(self, `${n}@${v}`);
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

// Go: the build list of go/ (the main module and every module it requires) with go.sum's hashes.
const goDir = join(root, 'go');
const sums = new Map();
for (const line of readFileSync(join(goDir, 'go.sum'), 'utf8').split('\n')) {
  const [m, ver, h] = line.trim().split(/\s+/);
  if (m && ver && h && !ver.endsWith('/go.mod')) sums.set(`${m}@${ver}`, h);
}
const toolchain = (readFileSync(join(goDir, 'go.mod'), 'utf8').match(/^toolchain\s+(\S+)\s*$/m) ?? [])[1] ?? die('go/go.mod: no toolchain line');
const goEnv = { ...process.env, GOFLAGS: '-mod=readonly', GOTOOLCHAIN: process.env.GOTOOLCHAIN || toolchain, GOWORK: 'off' };
let goList;
try { goList = run('go', ['list', '-m', '-json', 'all'], goDir, goEnv); } catch (e) { die(`go list -m -json all: ${(e.stderr || e.message).trim()}`); }
const mods = [];
{ let depth = 0, start = 0, str = false, esc = false;   // a stream of JSON objects
  for (let i = 0; i < goList.length; i++) {
    const ch = goList[i];
    if (str) { if (esc) esc = false; else if (ch === '\\') esc = true; else if (ch === '"') str = false; continue; }
    if (ch === '"') str = true; else if (ch === '{') { if (depth++ === 0) start = i; } else if (ch === '}' && --depth === 0) mods.push(JSON.parse(goList.slice(start, i + 1)));
  } }
const main = mods.find((m) => m.Main) ?? die('go list: no main module');
const goRef = (m) => `pkg:golang/${m.Path}@${m.Main ? `v${v}` : m.Version}`;
add({ 'bom-ref': goRef(main), type: 'library', name: main.Path, version: `v${v}`, purl: goRef(main) });
edge(goRef(main));
for (const m of mods) {
  if (m.Main) continue;
  if (!m.Version) die(`go list: ${m.Path} has no version`);
  const h = sums.get(`${m.Path}@${m.Version}`) ?? die(`go/go.sum: no hash for ${m.Path} ${m.Version}`);
  add({ 'bom-ref': goRef(m), type: 'library', name: m.Path, version: m.Version, purl: goRef(m),
    properties: [{ name: 'sigelo:go.sum', value: h }] });
  edge(goRef(main), goRef(m));
}

for (const [from, to] of edges) {
  if (!components.has(from)) die(`a dependency edge from ${from}, which is no component`);
  for (const t of to) if (!components.has(t)) die(`${from} depends on ${t}, which is no component`);
}
const byRef = (a, b) => (a['bom-ref'] < b['bom-ref'] ? -1 : a['bom-ref'] > b['bom-ref'] ? 1 : 0);
const release = `sigelo-release@${v}`;
const doc = {
  $schema: 'http://cyclonedx.org/schema/bom-1.6.schema.json',
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  serialNumber: `urn:uuid:${uuid5(`urn:sigelo:sbom:${commit}`)}`,
  version: 1,
  metadata: {
    timestamp: new Date(Number(epoch) * 1000).toISOString().replace(/\.000Z$/, 'Z'),
    lifecycles: [{ phase: 'pre-build' }],
    tools: { components: [{ type: 'application', name: 'release/sbom.mjs' }] },
    component: {
      'bom-ref': release, type: 'application', name: 'sigelo', version: v,
      externalReferences: [{ type: 'vcs', url: `https://github.com/csigelo/sigelo/tree/${commit}` }],
      properties: [{ name: 'sigelo:commit', value: commit }, { name: 'sigelo:go-toolchain', value: toolchain }],
    },
  },
  components: [...components.values()].sort(byRef),
  dependencies: [
    { ref: release, dependsOn: [...PACKAGES.map((p) => `${names[p]}@${v}`), goRef(main)].sort() },
    ...[...edges].map(([ref, to]) => ({ ref, dependsOn: [...to].sort() })).sort((a, b) => (a.ref < b.ref ? -1 : 1)),
  ],
};
function sortKeys(x) {
  if (Array.isArray(x)) return x.map(sortKeys);
  if (x && typeof x === 'object') return Object.fromEntries(Object.keys(x).sort().map((k) => [k, sortKeys(x[k])]));
  return x;
}
process.stdout.write(JSON.stringify(sortKeys(doc), null, 2) + '\n');
