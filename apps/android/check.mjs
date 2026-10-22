// SPDX-License-Identifier: MIT
// The Android project checked without the SDK (design/apps.md §8): what can be known of it on a
// machine with Node alone. The build itself runs on CI (.github/workflows/android.yml).
//   node apps/android/check.mjs     → ALL PASS (n)
// The manifest and resources (well-formed, two permissions, no backup, references resolve, the
// icon as the GTK app's SVG), the Gradle files (AGP pinned, minSdk 28, targetSdk 35, no
// dependency, braces balanced), the wrapper (its jar by SHA-256, the distribution pinned), the Java
// (the bridge's operations as platform-android.mjs sends them, the WebView's settings, every asset
// type served), the workflow (actions pinned by SHA, no secret, the outputs), and assets/web/ as
// assets.mjs writes it when it is there.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url)), REPO = join(HERE, '..', '..');
const MAIN = join(HERE, 'app', 'src', 'main'), JAVA = join(MAIN, 'java', 'io', 'sigelo', 'app');
// The Gradle wrapper's jar for the version gradle-wrapper.properties names (services.gradle.org
// publishes it as gradle-<v>-wrapper.jar.sha256; CI's wrapper-validation checks it again).
const WRAPPER = { version: '8.10.2', jar: '2db75c40782f5e8ba1fc278a5574bab070adccb2d21ca5a6e5ed840888448046', dist: '31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26' };
const AGP = '8.7.3';

let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
const read = (...p) => readFileSync(join(...p), 'utf8');
const walk = (d) => readdirSync(d).flatMap((n) => { const p = join(d, n); return statSync(p).isDirectory() ? walk(p) : [p]; });
const rel = (p) => relative(REPO, p).split(sep).join('/');

// ---------------------------------------------------------------- XML, strictly enough
/** A small XML reader: → { name, attrs, kids } of the root, or throws why the text is not well-formed. */
export function parseXml(text) {
  let i = 0;
  const fail = (why) => { throw new Error(`${why} at ${text.slice(0, i).split('\n').length}:${i - text.lastIndexOf('\n', i - 1)}`); };
  const skipMisc = () => {
    for (;;) {
      while (/\s/.test(text[i] ?? '')) i++;
      if (text.startsWith('<?', i)) { const e = text.indexOf('?>', i); if (e < 0) fail('an unclosed <?'); i = e + 2; continue; }
      if (text.startsWith('<!--', i)) {
        const e = text.indexOf('-->', i + 4);
        if (e < 0) fail('an unclosed comment');
        if (text.slice(i + 4, e).includes('--')) fail('"--" inside a comment');
        i = e + 3; continue;
      }
      return;
    }
  };
  const element = () => {
    if (text[i] !== '<') fail('an element expected');
    const m = /^<([A-Za-z_][\w.:-]*)/.exec(text.slice(i));
    if (!m) fail('a tag name expected');
    i += m[0].length;
    const el = { name: m[1], attrs: {}, kids: [] };
    for (;;) {
      while (/\s/.test(text[i])) i++;
      if (text.startsWith('/>', i)) { i += 2; return el; }
      if (text[i] === '>') { i++; break; }
      const a = /^([A-Za-z_][\w.:-]*)\s*=\s*("([^"<]*)"|'([^'<]*)')/.exec(text.slice(i));
      if (!a) fail(`an attribute expected in <${el.name}>`);
      if (Object.hasOwn(el.attrs, a[1])) fail(`attribute ${a[1]} twice`);
      el.attrs[a[1]] = a[3] ?? a[4];
      i += a[0].length;
    }
    for (;;) {
      const lt = text.indexOf('<', i);
      if (lt < 0) fail(`</${el.name}> missing`);
      const t = text.slice(i, lt);
      if (/&(?!(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)/.test(t)) fail('a bare &');
      if (t.trim()) el.kids.push(t);
      i = lt;
      if (text.startsWith('<!--', i)) { skipMisc(); continue; }
      if (text.startsWith('</', i)) {
        const c = /^<\/([A-Za-z_][\w.:-]*)\s*>/.exec(text.slice(i));
        if (!c || c[1] !== el.name) fail(`</${el.name}> expected`);
        i += c[0].length;
        return el;
      }
      el.kids.push(element());
    }
  };
  skipMisc();
  const root = element();
  skipMisc();
  if (i !== text.length) fail('text after the root element');
  return root;
}
const all = (el, name) => [...(el.name === name ? [el] : []), ...el.kids.filter((k) => typeof k === 'object').flatMap((k) => all(k, name))];

// ---------------------------------------------------------------- code with strings and comments blanked
/** Java or Groovy text with comments and string/char literals blanked: braces and words outside them. */
export function code(text) {
  return text.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'/g, (m) => (m.startsWith('/') ? ' ' : m[0] + ' '.repeat(Math.max(0, m.length - 2)) + m.at(-1)));
}
const balanced = (t) => { let d = 0; for (const c of t) { if ('{(['.includes(c)) d++; if ('})]'.includes(c)) d--; if (d < 0) return false; } return d === 0; };

// ================================================================ the manifest and the resources
const xmlFiles = [join(MAIN, 'AndroidManifest.xml'), ...walk(join(MAIN, 'res')).filter((f) => f.endsWith('.xml'))];
const xml = {};
for (const f of xmlFiles) {
  try { xml[rel(f)] = parseXml(read(f)); } catch (e) { xml[rel(f)] = null; ok(false, `${rel(f)}: not well-formed XML (${e.message})`); }
}
ok(Object.values(xml).every(Boolean), `XML: ${xmlFiles.length} files well-formed (no "--" in a comment, attributes quoted once, tags closed)`);
const man = xml['apps/android/app/src/main/AndroidManifest.xml'];
{
  const perms = all(man, 'uses-permission').map((p) => p.attrs['android:name']).sort();
  ok(perms.join() === 'android.permission.CAMERA,android.permission.INTERNET', `manifest: INTERNET and CAMERA only (${perms})`);
  ok(all(man, 'uses-sdk').length === 0 && man.attrs.package === undefined, 'manifest: no uses-sdk, no package (minSdk, targetSdk and the namespace are in app/build.gradle)');
  const app = all(man, 'application')[0]?.attrs ?? {};
  ok(app['android:allowBackup'] === 'false' && app['android:dataExtractionRules'] === '@xml/data_extraction_rules' && app['android:debuggable'] === undefined && app['android:usesCleartextTraffic'] === undefined,
    'manifest: no backup, no transfer (data extraction rules), not debuggable by the manifest');
  const acts = all(man, 'activity');
  ok(acts.length === 1 && acts[0].attrs['android:name'] === '.MainActivity' && acts[0].attrs['android:exported'] === 'true'
    && all(acts[0], 'action').some((a) => a.attrs['android:name'] === 'android.intent.action.MAIN') && all(acts[0], 'category').some((a) => a.attrs['android:name'] === 'android.intent.category.LAUNCHER'),
  'manifest: one activity, MainActivity, exported for the launcher only');
  ok(all(man, 'service').length + all(man, 'receiver').length + all(man, 'provider').length === 0 && all(acts[0], 'data').length === 0, 'manifest: no service, receiver, provider or URL handler');
  const dx = xml['apps/android/app/src/main/res/xml/data_extraction_rules.xml'];
  const domains = (k) => all(all(dx, k)[0] ?? { kids: [] }, 'exclude').map((e) => `${e.attrs.domain}:${e.attrs.path}`).sort().join();
  ok(all(dx, 'include').length === 0 && domains('cloud-backup') === 'database:.,external:.,file:.,root:.,sharedpref:.' && domains('device-transfer') === domains('cloud-backup'), 'data extraction: every domain excluded from backup and transfer');
  const nsc = xml['apps/android/app/src/main/res/xml/network_security_config.xml'];
  ok(all(nsc, 'certificates').map((c) => c.attrs.src).join() === 'system' && all(nsc, 'domain-config').length === 0 && all(nsc, 'pin-set').length === 0, 'network security: the system\'s CAs only, no user CA');
}
{
  // Every @type/name the manifest and resources name exists; every R.string the Java names too.
  const have = new Set();
  for (const f of walk(join(MAIN, 'res'))) {
    const [dir, file] = relative(join(MAIN, 'res'), f).split(sep), type = dir.split('-')[0], el = xml[rel(f)];
    if (type === 'values') for (const k of el.kids.filter((x) => typeof x === 'object')) have.add(`${k.name === 'style' ? 'style' : k.name}/${k.attrs.name}`);
    else have.add(`${type}/${file.replace(/\.xml$/, '')}`);
  }
  const refs = new Set();
  for (const f of xmlFiles) for (const m of read(f).matchAll(/"@(string|color|drawable|mipmap|xml|style)\/([\w.]+)"/g)) refs.add(`${m[1]}/${m[2]}`);
  for (const f of walk(JAVA)) for (const m of read(f).matchAll(/(?<!android\.)\bR\.(string|drawable|mipmap|xml|color)\.(\w+)/g)) refs.add(`${m[1]}/${m[2]}`);
  const missing = [...refs].filter((r) => !have.has(r));
  ok(missing.length === 0 && refs.size > 10, `resources: every reference resolves (${refs.size}; missing ${missing})`);
  ok(read(MAIN, 'res', 'values-v35', 'themes.xml').includes('windowOptOutEdgeToEdgeEnforcement') && read(MAIN, 'res', 'values', 'themes.xml').includes('@android:style/Theme.Material.Light.DarkActionBar'), 'theme: the platform\'s Material (no AndroidX); Android 15 not edge to edge');
}
{
  // The icon: apps/gtk/io.sigelo.App.svg in the adaptive icon's 108 dp, the SVG's 512 as its 72 dp safe zone.
  const svg = read(REPO, 'apps', 'gtk', 'io.sigelo.App.svg'), vec = read(MAIN, 'res', 'drawable', 'ic_launcher_foreground.xml');
  const c = /<circle cx="(\d+)" cy="(\d+)" r="(\d+)"[^>]*stroke-width="(\d+)"/.exec(svg), p = /<path d="M(\d+) (\d+)l(\d+) (\d+) (\d+)-(\d+)"[^>]*stroke-width="(\d+)"/.exec(svg);
  const fill = /<rect[^>]*fill="#([0-9a-f]{6})"/.exec(svg)?.[1];
  const [cx, cy, r, sw] = c.slice(1).map(Number), [px, py, a, b, d, e, sw2] = p.slice(1).map(Number), off = (768 - 512) / 2;
  ok(vec.includes('android:viewportWidth="768"') && vec.includes(`M${cx + off - r},${cy + off} a${r},${r} 0 1,0 ${2 * r},0 a${r},${r} 0 1,0 -${2 * r},0`)
    && vec.includes(`M${px + off},${py + off} l${a},${b} l${d},-${e}`) && (vec.match(new RegExp(`strokeWidth="${sw}"`, 'g')) ?? []).length === 2 && sw === sw2
    && read(MAIN, 'res', 'values', 'colors.xml').toLowerCase().includes(`#ff${fill}`), 'icon: the GTK app\'s SVG (ring, check, stroke, blue) in the adaptive icon');
}

// ================================================================ Gradle
const settings = read(HERE, 'settings.gradle'), root = read(HERE, 'build.gradle'), app = read(HERE, 'app', 'build.gradle'), props = read(HERE, 'gradle.properties');
ok([settings, root, app].every((t) => balanced(code(t))), 'gradle: braces and brackets balanced (outside strings and comments)');
ok(new RegExp(`id 'com\\.android\\.application' version '${AGP.replace(/\./g, '\\.')}' apply false`).test(root) && (code(root).match(/\bid\b/g) ?? []).length === 1, `gradle: one plugin, the Android Gradle Plugin, pinned (${AGP})`);
ok(/include ':app'/.test(settings) && /FAIL_ON_PROJECT_REPOS/.test(settings) && !/maven\s*\{/.test(code(settings)) && !/jcenter/.test(settings), 'settings.gradle: one module; repositories google() and mavenCentral() only, none per project');
const num = (k) => Number(new RegExp(`\\b${k}\\s+(\\d+)`).exec(app)?.[1]);
ok(num('minSdk') === 28 && num('targetSdk') === 35 && num('compileSdk') === 35, `app/build.gradle: minSdk 28, targetSdk 35, compileSdk 35 (${num('minSdk')}, ${num('targetSdk')}, ${num('compileSdk')})`);
ok(/namespace 'io\.sigelo\.app'/.test(app) && /applicationId 'io\.sigelo\.app'/.test(app), 'app/build.gradle: io.sigelo.app');
ok(!/\bdependencies\s*\{/.test(code(app)) && !/androidx|implementation|kotlin/i.test(code(app) + code(root)) && /android\.useAndroidX=false/.test(props), 'gradle: no dependency, no AndroidX, no Kotlin');
const release = /release\s*\{([^}]*)\}/.exec(code(app))?.[1] ?? '';
ok(/minifyEnabled false/.test(release) && !/signingConfig/.test(release), 'release: not minified (the bridge is called by name), no signing config (unsigned)');
ok(/storeType 'pkcs12'/.test(app) && /sigelo\.debugKeystore/.test(app) && /tasks\.named\('preBuild'\)/.test(app), 'debug: signed by a key given as properties (CI makes one per job); the build refuses an empty assets/web/');
{
  const w = read(HERE, 'gradle', 'wrapper', 'gradle-wrapper.properties');
  const jar = createHash('sha256').update(readFileSync(join(HERE, 'gradle', 'wrapper', 'gradle-wrapper.jar'))).digest('hex');
  ok(w.includes(`distributionUrl=https\\://services.gradle.org/distributions/gradle-${WRAPPER.version}-bin.zip`) && w.includes(`distributionSha256Sum=${WRAPPER.dist}`) && /validateDistributionUrl=true/.test(w),
    `wrapper: Gradle ${WRAPPER.version}, the distribution pinned by its SHA-256`);
  ok(jar === WRAPPER.jar, `wrapper: gradle-wrapper.jar is Gradle ${WRAPPER.version}'s (${jar})`);
  const gw = read(HERE, 'gradlew');
  ok(gw.startsWith('#!/bin/sh') && (statSync(join(HERE, 'gradlew')).mode & 0o111) !== 0 && gw.includes('gradle/wrapper/gradle-wrapper.jar'), 'gradlew: a POSIX script, executable, running the wrapper jar');
}

// ================================================================ Java
const java = Object.fromEntries(walk(JAVA).filter((f) => f.endsWith('.java')).map((f) => [f.slice(JAVA.length + 1), read(f)]));
ok(Object.keys(java).sort().join() === 'MainActivity.java,SigeloBridge.java', `java: MainActivity and SigeloBridge (${Object.keys(java)})`);
ok(Object.values(java).every((t) => balanced(code(t)) && /^package io\.sigelo\.app;$/m.test(t) && [...t.matchAll(/^import ([\w.]+);$/gm)].every((m) => /^(android|java|javax|org\.json)\./.test(m[1]))),
  'java: braces balanced, package io.sigelo.app, no import but the platform\'s (no AndroidX)');
const A = await import(pathToFileURL(join(REPO, 'apps', 'web', 'platform-android.mjs')).href).catch(() => null);
const ops = A?.OPS ?? ['https', 'tls', 'write', 'close', 'seal', 'open', 'mode', 'wiped'];
const cases = [...code(java['SigeloBridge.java']).matchAll(/case "\s*"/g)].length;
const caseNames = [...java['SigeloBridge.java'].matchAll(/case "([a-z]+)":/g)].map((m) => m[1]).sort();
ok(caseNames.join() === [...ops].sort().join() && cases === ops.length, `bridge: SigeloBridge answers exactly the operations platform-android.mjs sends (${caseNames} / ${ops})`);
const pa = read(REPO, 'apps', 'web', 'platform-android.mjs');
ok(['sigelo-shell/0', 'sigelo-bridge/0'].every((s) => java['SigeloBridge.java'].includes(`"${s}"`) && pa.includes(`'${s}'`)) && /"sigelo-app " \+ kind \+ "\/0"/.test(java['SigeloBridge.java']),
  'bridge: the same protocol names on both sides (sigelo-shell/0, sigelo-bridge/0), the AAD per kind');
const ji = [...java['SigeloBridge.java'].matchAll(/@JavascriptInterface\s+public (\w+) (\w+)\(/g)].map((m) => m[2]).sort();
ok(ji.join() === 'connect,info' && (java['MainActivity.java'].match(/@JavascriptInterface/g) ?? []).length === 0 && /addJavascriptInterface\(bridge\.shell\(\), "SigeloShell"\)/.test(java['MainActivity.java']),
  `bridge: the page sees SigeloShell.info() and connect() only (${ji})`);
const ma = java['MainActivity.java'];
ok(['setJavaScriptEnabled(true)', 'setAllowFileAccess(false)', 'MIXED_CONTENT_NEVER_ALLOW', 'setGeolocationEnabled(false)', 'setSupportMultipleWindows(false)'].every((s) => ma.includes(s)) && !/setAllowUniversalAccessFromFileURLs\(true|setAllowFileAccessFromFileURLs\(true/.test(ma),
  'WebView: JavaScript on, file access off, mixed content never, no geolocation, no new windows');
ok(/static final String HOST = "appassets\.androidplatform\.net"/.test(ma) && /shouldInterceptRequest[\s\S]*?return serve\(r\)/.test(ma) && /if \(!ours\(u\)\) return refuse\(404/.test(ma),
  'WebView: the page from https://appassets.androidplatform.net/ (intercepted), anything else refused, never fetched');
ok(/RESOURCE_VIDEO_CAPTURE\.equals\(res\[0\]\)/.test(ma) && /!video \|\| !ours\(req\.getOrigin\(\)\)/.test(ma) && /requestPermissions\(new String\[\] \{Manifest\.permission\.CAMERA\}/.test(ma), 'camera: video only, our origin only, CAMERA asked at the first request');
ok(/onShowFileChooser/.test(ma) && /ACTION_GET_CONTENT/.test(ma) && /FileChooserParams\.parseResult/.test(ma), 'files: a file input opens the system picker');
ok(/r\.hasGesture\(\)/.test(ma) && /ACTION_VIEW/.test(ma) && /CATEGORY_BROWSABLE/.test(ma), 'links: elsewhere opens in the browser, on a tap');
ok(/setEndpointIdentificationAlgorithm\("HTTPS"\)/.test(java['SigeloBridge.java']) && /getDefaultHostnameVerifier\(\)\.verify\(host/.test(java['SigeloBridge.java']) && /setInstanceFollowRedirects\(false\)/.test(java['SigeloBridge.java'])
  && !/TrustManager|setHostnameVerifier|ALLOW_ALL/.test(code(java['SigeloBridge.java'])), 'network: TLS names checked twice, no custom trust, no redirect followed');
ok(/setUserAuthenticationRequired\(true\)/.test(java['SigeloBridge.java']) && /BLOCK_MODE_GCM/.test(java['SigeloBridge.java']) && /setKeySize\(256\)/.test(java['SigeloBridge.java']) && /"AndroidKeyStore"/.test(java['SigeloBridge.java']),
  'keystore: AES-256-GCM in AndroidKeyStore; FULL under the screen lock');
{
  const types = [...ma.matchAll(/TYPES\.put\("(\w+)"/g)].map((m) => m[1]);
  const AS = await import(pathToFileURL(join(HERE, 'assets.mjs')).href);
  const exts = [...new Set((await AS.files()).map(([p]) => p.split('.').at(-1)))];
  ok(exts.every((x) => types.includes(x)) && (await AS.files()).every(([p]) => /^[A-Za-z0-9._@/-]{1,200}$/.test(p) && !p.includes('..')), `assets: every file of the page has a type MainActivity serves, and a name it accepts (${exts})`);
  if (existsSync(AS.OUT)) {
    let out = '';
    try { out = execFileSync(process.execPath, [join(HERE, 'assets.mjs'), '--check'], { encoding: 'utf8' }); } catch (e) { out = String(e.stdout); }
    ok(/^ok /m.test(out), `assets/web/: as assets.mjs writes it (${out.trim().split('\n').at(-1)})`);
  } else console.log('note: assets/web/ not there yet (node apps/android/assets.mjs); not compared');
}

// Where an android.jar is at hand (SIGELO_ANDROID_JAR; a JDK's javac on PATH or in JAVA_HOME): the Java
// compiled against it, with R and the lambda bootstrap stubbed (D8 desugars lambdas in a real build).
// Against platform 35 it must compile clean; against 28 (minSdk) only version-guarded calls may miss.
if (process.env.SIGELO_ANDROID_JAR) {
  const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const javac = process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin', 'javac') : 'javac';
  const t = mkdtempSync(join(tmpdir(), 'sigelo-javac-'));
  try {
    const names = [...read(MAIN, 'res', 'values', 'strings.xml').matchAll(/<string name="(\w+)"/g)].map((m) => m[1]);
    mkdirSync(join(t, 'src', 'java', 'lang', 'invoke'), { recursive: true });
    writeFileSync(join(t, 'src', 'R.java'), `package io.sigelo.app;\npublic final class R { public static final class string {\n${names.map((n, i) => `public static final int ${n} = ${0x7f0f0000 + i};`).join('\n')}\n} }\n`);
    writeFileSync(join(t, 'src', 'java', 'lang', 'invoke', 'LambdaMetafactory.java'), 'package java.lang.invoke;\npublic final class LambdaMetafactory { public static CallSite metafactory(MethodHandles.Lookup c, String n, MethodType t, MethodType s, MethodHandle i, MethodType r) { return null; } }\n');
    let out = '';
    try {
      out = execFileSync(javac, ['-Xlint:all', '-Xlint:-options', '-Xlint:-deprecation', '-source', '8', '-target', '8', '-bootclasspath', process.env.SIGELO_ANDROID_JAR, '-d', join(t, 'out'),
        join(t, 'src', 'R.java'), join(t, 'src', 'java', 'lang', 'invoke', 'LambdaMetafactory.java'), ...Object.keys(java).map((f) => join(JAVA, f))], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) { out = `${e.stdout ?? ''}${e.stderr ?? e.message}`; }
    const errors = [...out.matchAll(/^(\S+\.java):(\d+): error: (.*)$/gm)];
    const guarded = errors.every(([, f, l]) => /SDK_INT >= Build\.VERSION_CODES\.\w+\)/.test(read(f).split('\n')[Number(l) - 1]));
    ok(!/warning|error/.test(out) || (errors.length > 0 && guarded && !/warning/.test(out)), `javac against ${rel(process.env.SIGELO_ANDROID_JAR)}: ${errors.length ? `${errors.length} missing, each behind an SDK_INT check` : 'clean'} (${out.trim().split('\n').slice(0, 3).join(' | ')})`);
  } finally { rmSync(t, { recursive: true, force: true }); }
}

// ================================================================ the workflow
{
  const wf = read(REPO, '.github', 'workflows', 'android.yml');
  const uses = [...wf.matchAll(/^\s*-?\s*uses:\s*(\S+)(.*)$/gm)];
  ok(uses.length >= 4 && uses.every((u) => /^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/.test(u[1]) && /# v\d/.test(u[2])), `workflow: every action pinned by a commit SHA, its version in a comment (${uses.map((u) => u[1].split('@')[0])})`);
  ok(!/\bsecrets\./.test(wf) && !/pull_request_target|workflow_run/.test(wf) && /^permissions:\s*\n\s+contents: read\s*$/m.test(wf), 'workflow: no secret, no privileged trigger, contents: read only');
  ok(/runs-on: ubuntu-24\.04/.test(wf) && /gradle\/actions\/wrapper-validation@/.test(wf) && /java-version: '17'/.test(wf), 'workflow: ubuntu-24.04, JDK 17, the wrapper validated');
  ok(/keytool -genkeypair/.test(wf) && /assembleRelease/.test(wf) && /assembleDebug/.test(wf) && /sha256sum/.test(wf) && /SHA256SUMS/.test(wf) && /actions\/upload-artifact@/.test(wf) && /apksigner"? verify/.test(wf),
    'workflow: an ephemeral debug key (keytool), the unsigned release and the debug build, their SHA-256, uploaded');
  ok(/node apps\/android\/assets\.mjs/.test(wf) && /node apps\/android\/check\.mjs/.test(wf) && /test-shell\.mjs/.test(wf), 'workflow: the page copied in, this check and the page\'s tests before the build');
  ok(!/\t/.test(wf) && !/\$\{\{\s*github\.event\./.test(wf), 'workflow: no tab; no event text in a script');
  // A strict YAML parse where Python has PyYAML (CI's runner does): duplicate keys refused.
  let parsed = null;
  try {
    parsed = execFileSync('python3', ['-c', `import sys,yaml
class L(yaml.SafeLoader): pass
def m(loader, node, deep=False):
    keys=[loader.construct_object(k, deep=deep) for k,_ in node.value]
    if len(keys)!=len(set(map(str,keys))): raise SystemExit('duplicate key in '+str(node.start_mark))
    return yaml.SafeLoader.construct_mapping(loader, node, deep)
L.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, m)
d=yaml.load(open(sys.argv[1]), Loader=L)
import json; print(json.dumps({'jobs': list(d['jobs']), 'steps': len(d['jobs']['apk']['steps']), 'on': sorted(str(k) for k in d[True])}))`, join(REPO, '.github', 'workflows', 'android.yml')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) { parsed = e.code === 'ENOENT' || /No module named/.test(String(e.stderr)) ? 'skip' : String(e.stderr || e.message); }
  if (parsed === 'skip') console.log('note: no python3 with PyYAML here: the workflow\'s YAML not parsed');
  else { let j = null; try { j = JSON.parse(parsed); } catch {} ok(j?.jobs?.join() === 'apk' && j.steps >= 8, `workflow: YAML parses strictly, one job (apk) (${typeof parsed === 'string' ? parsed.trim().slice(0, 200) : ''})`); }
}

for (const f of fails) console.log('FAIL ' + f);
if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
console.log(`ALL PASS (${count})`);
