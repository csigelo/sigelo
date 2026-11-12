#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// release/check-deps.mjs: the dependency cooldown (release/RELEASE-v2.md §7).
//
//   node release/check-deps.mjs          from the repository root; exit 1 on any failure
//
// For every package-lock.json in the tree (not under node_modules or crosscheck/.work) and for
// go/go.sum, each locked third-party version must be at least 14 days old at the author time of
// HEAD: npm's publish time is registry.npmjs.org/<name> `time[<version>]`, Go's is
// proxy.golang.org/<module>/@v/<version>.info `Time`. A lockfile entry with
// "hasInstallScript": true fails too. Exceptions: release/cooldown-exceptions.json, a list of
// {package, version, reason, expires} (expires "YYYY-MM-DD", valid through that UTC day, or null);
// an exception expired at that time is itself a failure. No dependencies, nothing cached on disk; Node 22+.
// SIGELO_DEPS_NOW=<ISO time> replaces the commit time (to test a date).
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const DAYS = 14, DAY = 86400e3, CONCURRENCY = 6;
const root = process.cwd();
const bad = [];

let now;
if (process.env.SIGELO_DEPS_NOW) now = new Date(process.env.SIGELO_DEPS_NOW);
else {
  try { now = new Date(execFileSync("git", ["log", "-1", "--format=%aI"], { encoding: "utf8" }).trim()); }
  catch { now = new Date(); }
}
if (Number.isNaN(now.getTime())) { console.error("check-deps: no valid commit time"); process.exit(1); }

// Exceptions, each checked for shape and expiry.
const exFile = path.join(root, "release", "cooldown-exceptions.json");
const exceptions = fs.existsSync(exFile) ? JSON.parse(fs.readFileSync(exFile, "utf8")) : [];
if (!Array.isArray(exceptions)) { console.error(`check-deps: ${exFile} is not a list`); process.exit(1); }
const used = new Set();
for (const x of exceptions) {
  if (typeof x?.package !== "string" || typeof x.version !== "string" || typeof x.reason !== "string" || x.reason === ""
    || !(x.expires === null || /^\d{4}-\d{2}-\d{2}$/.test(x.expires ?? "")))
    bad.push(`cooldown-exceptions.json: malformed entry ${JSON.stringify(x)}`);
  else if (x.expires !== null && new Date(`${x.expires}T00:00:00Z`).getTime() + DAY <= now)   // valid through that UTC day
    bad.push(`cooldown-exceptions.json: ${x.package}@${x.version} expired on ${x.expires}: remove it or renew it with a reason`);
}
const excepted = (name, version) => {
  const x = exceptions.find((e) => e?.package === name && e.version === version);
  if (x) used.add(x);
  return x;
};

// The lockfiles.
const lockfiles = [];
const walk = (dir) => {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name), rel = path.relative(root, p).split(path.sep).join("/");
    if (e.isDirectory()) {
      if (e.name === "node_modules" || e.name === ".git" || rel === "crosscheck/.work") continue;
      walk(p);
    } else if (e.name === "package-lock.json") lockfiles.push(rel);
  }
};
walk(root);
lockfiles.sort();

// npm: name and version from each registry entry; file: links and workspaces have none.
const npmUse = [];   // { file, name, version }
for (const file of lockfiles) {
  const l = JSON.parse(fs.readFileSync(path.join(root, file), "utf8"));
  for (const [key, e] of Object.entries(l.packages ?? {})) {
    if (key === "" || e.link === true) continue;
    const m = /^https:\/\/registry\.npmjs\.org\/((?:@[^/]+\/)?[^/]+)\/-\//.exec(e.resolved ?? "");
    if (e.hasInstallScript === true) {
      const name = m ? decodeURIComponent(m[1]) : key.replace(/^.*node_modules\//, "");
      if (!excepted(name, e.version)) bad.push(`${file}: ${name}@${e.version} has an install script ("hasInstallScript": true)`);
    }
    if (!m || typeof e.version !== "string") continue;   // a local directory, not fetched
    npmUse.push({ file, name: decodeURIComponent(m[1]), version: e.version });
  }
}
// Go: go/go.sum, one line per module version (the /go.mod line names the same version).
const goSum = "go/go.sum", goUse = [];
if (fs.existsSync(path.join(root, goSum))) {
  const seen = new Set();
  for (const line of fs.readFileSync(path.join(root, goSum), "utf8").split("\n")) {
    const [mod, ver] = line.trim().split(/\s+/);
    if (!mod || !ver) continue;
    const v = ver.replace(/\/go\.mod$/, "");
    if (!seen.has(`${mod}@${v}`)) { seen.add(`${mod}@${v}`); goUse.push({ file: goSum, name: mod, version: v }); }
  }
}

// Politely: a few requests at a time, three tries each, one fetch per package name.
async function getJSON(url) {
  for (let i = 0; ; i++) {
    try {
      const r = await fetch(url, { headers: { accept: "application/json", "user-agent": "sigelo-check-deps" } });
      if (r.ok) return await r.json();
      if (r.status === 404 || i === 2) throw new Error(`HTTP ${r.status}`);
    } catch (err) {
      if (i === 2 || /HTTP 404/.test(err.message)) throw err;
    }
    await new Promise((res) => setTimeout(res, 1000 * 2 ** i));
  }
}
async function pool(items, fn) {
  const out = new Map(), queue = [...items];
  await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
    for (let it; (it = queue.shift()) !== undefined;) {
      try { out.set(it, await fn(it)); } catch (err) { out.set(it, err); }
    }
  }));
  return out;
}
const goEscape = (s) => s.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);

const npmNames = [...new Set(npmUse.map((u) => u.name))];
const npmDocs = await pool(npmNames, async (n) => {
  const doc = await getJSON(`https://registry.npmjs.org/${n.startsWith("@") ? `@${encodeURIComponent(n.slice(1))}` : encodeURIComponent(n)}`);
  return doc.time ?? {};   // keep the times only: some packuments are tens of MB
});
const goTimes = await pool(goUse.map((u) => `${u.name}@${u.version}`), async (k) => {
  const [mod, ver] = k.split("@");
  return (await getJSON(`https://proxy.golang.org/${goEscape(mod)}/@v/${goEscape(ver)}.info`)).Time;
});

// Judge each use; one line per lockfile.
const byFile = new Map();
const judge = (u, published) => {
  const list = byFile.get(u.file) ?? byFile.set(u.file, []).get(u.file);
  const err = (why) => { if (!excepted(u.name, u.version)) list.push(`${u.file}: ${u.name}@${u.version} ${why}`); };
  if (published instanceof Error) return err(`publish time unreadable: ${published.message}`);
  const t = new Date(published ?? NaN);
  if (Number.isNaN(t.getTime())) return err("has no publish time in the registry");
  const age = (now - t) / DAY;
  if (age < DAYS) err(`is ${age.toFixed(1)} days old (published ${t.toISOString().slice(0, 10)}; ${DAYS} needed)`);
};
for (const u of npmUse) { const d = npmDocs.get(u.name); judge(u, d instanceof Error ? d : d[u.version]); }
for (const u of goUse) judge(u, goTimes.get(`${u.name}@${u.version}`));

console.log(`check-deps: at ${now.toISOString()} (HEAD's author time), cooldown ${DAYS} days`);
for (const file of [...lockfiles, ...(goUse.length ? [goSum] : [])]) {
  const n = new Set([...npmUse, ...goUse].filter((u) => u.file === file).map((u) => `${u.name}@${u.version}`)).size;
  const errs = [...new Set(byFile.get(file) ?? [])];
  console.log(`${errs.length ? "FAIL" : "ok  "} ${file}: ${n} third-party versions${errs.length ? `, ${errs.length} too young or unreadable` : ""}`);
  bad.push(...errs);
}
for (const x of exceptions) if (!used.has(x)) console.log(`note: unused exception ${x.package}@${x.version} (remove it)`);
if (bad.length) { for (const b of bad) console.log(`FAIL ${b}`); process.exit(1); }
console.log("ALL PASS");
