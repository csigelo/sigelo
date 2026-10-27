// SPDX-License-Identifier: MIT
// The Android project checked without the SDK (design/apps.md §8): what can be known of it on a
// machine with Node alone. The build itself runs on CI (.github/workflows/android.yml).
//   node apps/android/check.mjs     → ALL PASS (n)
// The manifest and resources (well-formed, two permissions, no backup, references resolve, the
// icon from assets/brand/app-icon.svg), the Gradle files (AGP pinned, minSdk 28, targetSdk 35, no
// dependency, braces balanced), the wrapper (its jar by SHA-256, the distribution pinned), the Java
// (the bridge's operations as platform-android.mjs sends them, the WebView's settings, every asset
// type served), the F-Droid listing, icon and draft recipe (FDROID.md), the workflow (actions
// pinned by SHA, no secret, the outputs), and assets/web/ as assets.mjs writes it when it is there.
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
const AGP = '8.8.2';
// The APK signing certificate (release/apk-ceremony.md; public: each release.json with an APK names it).
const APK_CERT = '0e2f720cc60ca706adf97fd724e478c3601fb6ee8c35d4ed63973236f5994b21';

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
  // The icon: assets/brand/app-icon.svg (the seal) in the adaptive icon's 108 dp, the SVG's 512 square as
  // the full 108 dp (the mark sits in the 66 dp safe circle), paper behind, the same foreground as the themed layer.
  const { shapes, vector, polygons } = await import('./icon.mjs');
  const s = shapes(), vec = read(MAIN, 'res', 'drawable', 'ic_launcher_foreground.xml'), launcher = read(MAIN, 'res', 'mipmap-anydpi', 'ic_launcher.xml');
  ok(vec === vector(s) && vec.includes(`android:pathData="${s.d}"`) && vec.includes('android:fillType="evenOdd"') && vec.includes(`android:scaleX="${Math.round(s.scale * 1.5 * 1e4) / 1e4}"`),
    'icon: the foreground is app-icon.svg\'s seal path (evenodd), its transform x 1.5 in the 768 viewport (icon.mjs vector())');
  ok(read(MAIN, 'res', 'values', 'colors.xml').toUpperCase().includes(`<COLOR NAME="SIGELO_PAPER">#FF${s.paper.toUpperCase()}</COLOR>`) && launcher.includes('<background android:drawable="@color/sigelo_paper" />')
    && launcher.includes('<foreground android:drawable="@drawable/ic_launcher_foreground" />') && launcher.includes('<monochrome android:drawable="@drawable/ic_launcher_foreground" />'),
    'icon: adaptive, paper background (app-icon.svg\'s square), the seal as foreground and monochrome');
  // Inside the safe zone: every point of the mark within 33 dp of the centre (of 108), i.e. 33/108 × 512 px of the SVG.
  const far = Math.max(...polygons(s.d).flat().map(([x, y]) => Math.hypot(s.tx + x * s.scale - 256, s.ty + y * s.scale - 256)));
  ok(far <= (33 / 108) * 512, `icon: the whole mark (pixels and flying squares) inside the 66 dp safe circle (${(far / 512 * 108).toFixed(1)} dp ≤ 33 from the centre)`);
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
// The module needs the page's import map to load in Node; without it, its OPS line read as text.
const ops = A?.OPS ?? JSON.parse((/export const OPS = Object\.freeze\((\[[^\]]*\])\)/.exec(read(REPO, 'apps', 'web', 'platform-android.mjs'))?.[1] ?? '[]').replace(/'/g, '"'));
const cases = [...code(java['SigeloBridge.java']).matchAll(/case "\s*"/g)].length;
const caseNames = [...java['SigeloBridge.java'].matchAll(/case "([a-z-]+)":/g)].map((m) => m[1]).sort();
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

// ================================================================ F-Droid (FDROID.md)
// The store listing F-Droid reads from <subdir>/fastlane (subdir: apps/android/app, so its version
// check finds app/build.gradle), the icon it cannot take from our XML-only launcher icon, and the
// draft recipe for fdroiddata: what it builds is what CI builds, without the relay or the tests.
{
  const FL = join(HERE, 'app', 'fastlane', 'metadata', 'android', 'en-US');
  const txt = (f) => (existsSync(join(FL, f)) ? read(FL, f) : '');
  const len = (s) => [...s.trimEnd()].length;
  ok(len(txt('title.txt')) > 0 && len(txt('title.txt')) <= 50 && len(txt('short_description.txt')) > 0 && len(txt('short_description.txt')) <= 80
    && len(txt('full_description.txt')) > 0 && len(txt('full_description.txt')) <= 4000,
    `fastlane: title ≤ 50, short ≤ 80, full ≤ 4000 characters (${len(txt('title.txt'))}, ${len(txt('short_description.txt'))}, ${len(txt('full_description.txt'))})`);
  const logs = existsSync(join(FL, 'changelogs')) ? readdirSync(join(FL, 'changelogs')) : [];
  ok(logs.length > 0 && logs.every((f) => /^[1-9]\d*\.txt$/.test(f) && len(txt(`changelogs/${f}`)) > 0 && len(txt(`changelogs/${f}`)) <= 500), `fastlane: changelogs/<versionCode>.txt, each ≤ 500 characters (${logs})`);
  ok(!/A2A|\bTODO\b/i.test(['title.txt', 'short_description.txt', 'full_description.txt', ...logs.map((f) => `changelogs/${f}`)].map(txt).join('\n')), 'fastlane: no placeholder, no protocol jargon in the listing');
  let icon = '';
  try { icon = execFileSync(process.execPath, [join(HERE, 'icon.mjs'), '--check'], { encoding: 'utf8' }); } catch (e) { icon = String(e.stdout); }
  ok(/^ok /m.test(icon), `fastlane: images/icon.png is assets/brand/app-icon.svg as icon.mjs draws it (${icon.trim()})`);

  const yml = join(HERE, 'fdroid', 'io.sigelo.app.yml');
  let d = null, why = '';
  try {
    d = JSON.parse(execFileSync('python3', ['-c', `import sys,yaml,json
class L(yaml.SafeLoader): pass
def m(loader, node, deep=False):
    keys=[loader.construct_object(k, deep=deep) for k,_ in node.value]
    if len(keys)!=len(set(map(str,keys))): raise SystemExit('duplicate key in '+str(node.start_mark))
    return yaml.SafeLoader.construct_mapping(loader, node, deep)
L.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, m)
print(json.dumps(yaml.load(open(sys.argv[1]), Loader=L)))`, yml], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
  } catch (e) { why = e.code === 'ENOENT' || /No module named/.test(String(e.stderr)) ? 'skip' : String(e.stderr || e.message); }
  if (why === 'skip') console.log('note: no python3 with PyYAML here: the F-Droid draft not parsed');
  else {
    const app = read(MAIN, '..', '..', 'build.gradle'), code = Number(/versionCode (\d+)/.exec(app)?.[1]), b = d?.Builds?.at(-1) ?? {};
    const steps = [...(b.sudo ?? []), ...(b.prebuild ?? []), ...(b.build ?? [])].join('\n');
    ok(d !== null && /applicationId 'io\.sigelo\.app'/.test(app) && d.License === 'MIT' && /^MIT License/.test(read(REPO, 'LICENSE')) && d.RepoType === 'git'
      && d.Repo === 'https://github.com/csigelo/sigelo.git' && d.SourceCode === 'https://github.com/csigelo/sigelo', `fdroid draft: io.sigelo.app, MIT, the public repository (${why.trim().slice(0, 200)})`);
    // fdroiddata wants the tag's full commit hash, not the tag (its merge request checklist).
    ok(b.subdir === 'apps/android/app' && /^[0-9a-f]{40}$/.test(b.commit ?? '') && Number.isInteger(b.versionCode) && b.versionCode >= code
      && d.CurrentVersion === b.versionName && d.CurrentVersionCode === b.versionCode && logs.includes(`${b.versionCode}.txt`) && d.AuthorName === 'sigelo',
      `fdroid draft: subdir app, the tag's full commit hash, versionCode ≥ build.gradle's (${b.versionCode} ≥ ${code}), current = last build, its changelog there, AuthorName`);
    ok(d.AutoUpdateMode === 'Version' && /^Tags \^v/.test(d.UpdateCheckMode ?? '') && JSON.stringify(b.gradle) === '[true]' && !b.output && !b.scanignore && !b.scandelete && !b.srclibs,
      'fdroid draft: Tags update check, auto-update on Version; the default flavour and output; no scanignore, scandelete or srclib');
    const node = /N=node-v(\d+)\.(\d+)\.(\d+)-linux-x64\.tar\.xz/.exec(steps), wf = read(REPO, '.github', 'workflows', 'android.yml');
    ok(node && new RegExp(`nodejs\\.org/dist/v${node[1]}\\.${node[2]}\\.${node[3]}/\\$N`).test(steps) && /H=[0-9a-f]{64}\n/.test(steps) && /sha256sum -c -/.test(steps)
      && wf.includes(`node-version: '${node[1]}'`), `fdroid draft: Node pinned by SHA-256, the major CI uses (${node?.[1]})`);
    ok((b.prebuild ?? []).every((s) => /^(cd [./a-z]+|npm ci --ignore-scripts)$/.test(s)) && /npx tsc/.test(steps) && /node apps\/android\/assets\.mjs/.test(steps)
      && !/relay|adapters|test-|curl .*(npmjs|github)|git clone/.test(steps.replace(/nodejs\.org/, '')), 'fdroid draft: prebuild only fetches (npm ci, no script); build runs tsc and assets.mjs; no relay, adapter or test');
    const mr = existsSync(join(HERE, 'fdroid', 'MR.md')) ? read(HERE, 'fdroid', 'MR.md') : '';
    ok(/^## Title\n\nNew app: sigelo$/m.test(mr) && /\/label ~"New App"/.test(mr) && /fdroid build --on-server -v -l io\.sigelo\.app/.test(mr) && !/A2A|\bTODO\b/.test(mr),
      'fdroid MR.md: "New app: sigelo", the template\'s label, the local fdroid build step; no jargon, no placeholder left but the run URL');
    // Route B (FDROID.md): F-Droid builds, then publishes our signed APK only if it matches.
    ok(d.Binaries === 'https://github.com/csigelo/sigelo/releases/download/v%v/sigelo-%v.apk' && d.AllowedAPKSigningKeys === APK_CERT,
      `fdroid draft: Binaries is the release's sigelo-<v>.apk, AllowedAPKSigningKeys our certificate (${d.AllowedAPKSigningKeys})`);
    const jdk = /java-version: '(\d+)'/.exec(wf)?.[1], J = `/usr/lib/jvm/java-${jdk}-openjdk-amd64/bin`;
    ok(jdk && (b.sudo ?? []).includes(`J=${J}`) && (b.sudo ?? []).some((c) => c.includes(`openjdk-${jdk}-jdk-headless`))
      && ['java', 'javac'].every((t) => (b.sudo ?? []).includes(`update-alternatives --set ${t} $J/${t}`)) && /sourceCompatibility JavaVersion\.VERSION_17/.test(app),
      `fdroid draft: F-Droid's java and javac set to the JDK major CI builds with (${jdk}); class files for 17 on both`);
  }
}

// ================================================================ reproducible: the ceremony and the compare run
// The signed APK must be CI's unsigned one plus the signature block, nothing else moved: apksigner
// realigns stored entries unless told not to, and then F-Droid's signature copy fails (v0.1.10).
{
  const cer = read(REPO, 'release', 'apk-ceremony.md');
  ok(/apksigner sign [^`]*--alignment-preserved/.test(cer.replace(/\\\n\s*/g, ' ')) && /s\[:cd\]==u\[:cd\]/.test(cer),
    'apk-ceremony: apksigner sign --alignment-preserved, then the signed APK checked to begin with the unsigned one');
  const rp = join(REPO, '.github', 'workflows', 'android-reproduce.yml'), r = existsSync(rp) ? read(rp) : '';
  const ru = [...r.matchAll(/^\s*-?\s*uses:\s*(\S+)(.*)$/gm)];
  let y = null;
  try {
    y = JSON.parse(execFileSync('python3', ['-c', `import sys,yaml,json
d=yaml.safe_load(open(sys.argv[1]))
print(json.dumps({'on': sorted(str(k) for k in d[True]), 'jobs': {k: {'coe': v.get('continue-on-error'), 'steps': [s.get('continue-on-error') for s in v['steps']]} for k, v in d['jobs'].items()}}))`, rp], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
  } catch (e) { y = e.code === 'ENOENT' || /No module named/.test(String(e.stderr)) ? 'skip' : null; }
  ok(r && ru.length >= 5 && ru.every((u) => /^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/.test(u[1]) && /# v\d/.test(u[2])) && !/\bsecrets\./.test(r)
    && /^permissions:\s*\n\s+contents: read\s*$/m.test(r) && !/\$\{\{\s*(github\.event|inputs)\.[^}]*\}\}/.test(r.split('\n').filter((l) => !/^\s*(ref|REF|EXPECT):/.test(l)).join('\n'))
    && (y === 'skip' || (y?.on?.join() === 'workflow_dispatch' && Object.values(y.jobs).every((j) => j.coe === true && j.steps.every((c) => c === true)))),
    'android-reproduce: dispatch only, every job and step continue-on-error (a report, never a red run); actions pinned; no secret; inputs only through env');
  ok(/exit 0\s*$/.test(r.trimEnd() + '\n') && /temurin-17, temurin-21, debian-21, debian-17/.test(r) && /apksigcopier"? compare --unsigned/.test(r) && /--alignment-preserved/.test(r),
    'android-reproduce: four JDKs, the F-Droid signature copy, a verdict that always ends the run');
}

// ================================================================ the workflow
{
  const wf = read(REPO, '.github', 'workflows', 'android.yml');
  const uses = [...wf.matchAll(/^\s*-?\s*uses:\s*(\S+)(.*)$/gm)];
  ok(uses.length >= 4 && uses.every((u) => /^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/.test(u[1]) && /# v\d/.test(u[2])), `workflow: every action pinned by a commit SHA, its version in a comment (${uses.map((u) => u[1].split('@')[0])})`);
  ok(!/\bsecrets\./.test(wf) && !/pull_request_target|workflow_run/.test(wf) && /^permissions:\s*\n\s+contents: read\s*$/m.test(wf), 'workflow: no secret, no privileged trigger, contents: read only');
  ok(/runs-on: ubuntu-24\.04/.test(wf) && /gradle\/actions\/wrapper-validation@/.test(wf) && /java-version: '21'/.test(wf), 'workflow: ubuntu-24.04, JDK 21 (F-Droid\'s), the wrapper validated');
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
