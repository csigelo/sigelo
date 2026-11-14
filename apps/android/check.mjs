// SPDX-License-Identifier: MIT
// The Android project checked without the SDK (design/apps.md §8): what can be known of it on a
// machine with Node alone. The build itself runs on CI (.github/workflows/android.yml).
//   node apps/android/check.mjs     → ALL PASS (n)
// The manifest and resources (well-formed, four permissions (storage on Android 9 only), one provider not exported, no backup, references resolve, the
// icon from assets/brand/app-icon.svg), the Gradle files (AGP pinned, minSdk 28, targetSdk 35, no
// dependency, braces balanced), the wrapper (its jar by SHA-256, the distribution pinned), the Java
// (the bridge's operations as platform-android.mjs sends them, the WebView's settings, every asset
// type served; the app lock, notifications and their open event), the version (one source), the F-Droid
// listing, icon and draft recipe (FDROID.md; its steps walked over this tree), the workflow (actions
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
  ok(perms.join() === 'android.permission.CAMERA,android.permission.INTERNET,android.permission.POST_NOTIFICATIONS,android.permission.WRITE_EXTERNAL_STORAGE', `manifest: INTERNET, CAMERA, POST_NOTIFICATIONS and WRITE_EXTERNAL_STORAGE only (${perms})`);
  const wes = all(man, 'uses-permission').find((p) => p.attrs['android:name'] === 'android.permission.WRITE_EXTERNAL_STORAGE');
  ok(wes?.attrs['android:maxSdkVersion'] === '28' && all(man, 'uses-permission').filter((p) => p !== wes).every((p) => p.attrs['android:maxSdkVersion'] === undefined),
    'manifest: the shared storage only up to Android 9 (maxSdkVersion 28: Downloads through MediaStore after, no permission)');
  ok(all(man, 'uses-sdk').length === 0 && man.attrs.package === undefined, 'manifest: no uses-sdk, no package (minSdk, targetSdk and the namespace are in app/build.gradle)');
  const app = all(man, 'application')[0]?.attrs ?? {};
  ok(app['android:allowBackup'] === 'false' && app['android:dataExtractionRules'] === '@xml/data_extraction_rules' && app['android:debuggable'] === undefined && app['android:usesCleartextTraffic'] === undefined,
    'manifest: no backup, no transfer (data extraction rules), not debuggable by the manifest');
  const acts = all(man, 'activity');
  ok(acts.length === 1 && acts[0].attrs['android:name'] === '.MainActivity' && acts[0].attrs['android:exported'] === 'true'
    && all(acts[0], 'action').some((a) => a.attrs['android:name'] === 'android.intent.action.MAIN') && all(acts[0], 'category').some((a) => a.attrs['android:name'] === 'android.intent.category.LAUNCHER'),
  'manifest: one activity, MainActivity, exported for the launcher only');
  ok(all(man, 'service').length + all(man, 'receiver').length === 0 && all(acts[0], 'data').length === 0, 'manifest: no service, receiver or URL handler');
  const pv = all(man, 'provider');
  ok(pv.length === 1 && pv[0].attrs['android:name'] === '.PhotoProvider' && pv[0].attrs['android:authorities'] === 'io.sigelo.app.photos' && pv[0].attrs['android:exported'] === 'false'
    && pv[0].attrs['android:grantUriPermissions'] === 'true' && all(pv[0], 'grant-uri-permission').length === 0 && all(pv[0], 'meta-data').length === 0,
    'manifest: one provider, PhotoProvider (io.sigelo.app.photos), not exported, reached only through the camera intent\'s grant');
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
  ok(missing.length === 0 && refs.size > 8, `resources: every reference resolves (${refs.size}; missing ${missing})`);
  {
    // No action bar (2026-11-14): the page's own top bar; the system bars in its paper, dark icons, until the page names its background.
    const th = read(MAIN, 'res', 'values', 'themes.xml'), th35 = read(MAIN, 'res', 'values-v35', 'themes.xml');
    const item = (n, v) => th.includes(`<item name="android:${n}">${v}</item>`);
    ok(th.includes('parent="@android:style/Theme.Material.Light.NoActionBar"') && !/ActionBar"|DarkActionBar/.test(th.replace('Light.NoActionBar"', '')) && !/DarkActionBar/.test(th35)
      && ['windowBackground', 'statusBarColor', 'navigationBarColor'].every((n) => item(n, '@color/sigelo_paper')) && item('windowLightStatusBar', 'true') && item('windowLightNavigationBar', 'true')
      && th35.includes('<style name="Theme.Sigelo" parent="Base.Sigelo">') && th35.includes('<item name="android:windowOptOutEdgeToEdgeEnforcement">true</item>'),
      'theme: the platform\'s Material without an action bar (no AndroidX), the system bars and the window in paper with dark icons; Android 15 not edge to edge (the WebView below the status bar)');
  }
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
ok(Object.keys(java).sort().join() === 'BigFiles.java,MainActivity.java,PhotoProvider.java,SigeloBridge.java', `java: MainActivity, SigeloBridge, BigFiles and PhotoProvider (${Object.keys(java)})`);
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
const jbl = java['SigeloBridge.java'];
ok(/private boolean locked = true;/.test(ma) && /protected void onStart\(\) \{[\s\S]*?SystemClock\.elapsedRealtime\(\) - awayAt >= bridge\.lockAfter\(\) \* 60_000L\) locked = true;[\s\S]*?if \(locked && afterAuth == null\) lockNow\(\);/.test(ma)
  && /protected void onStop\(\) \{\s*if \(afterAuth == null\) awayAt = SystemClock\.elapsedRealtime\(\);/.test(ma) && /if \(bridge == null \|\| !bridge\.lockOn\(\) \|\| bridge\.mode\(\) == null \|\| km == null \|\| !km\.isDeviceSecure\(\)\) \{\s*showPage\(\);/.test(ma)
  && /setVisibility\(View\.INVISIBLE\)/.test(ma) && !/LOCK_AFTER_MS/.test(ma)
  && /void unlock\(Runnable ok, Runnable no, boolean force\) \{[\s\S]*?boolean recent = !force && unlockedAt >= 0 && SystemClock\.elapsedRealtime\(\) - unlockedAt < CONFIRMED_MS;/.test(ma) && /static final long CONFIRMED_MS = 60_000;/.test(ma)
  && /if \(afterAuth != null\) \{/.test(ma) && !/authCancelled\.run\(\);/.test(ma)
  && /activity\.unlock\([^;]*m\.optBoolean\("force", false\)\);/.test(jbl) && /prefs\.getBoolean\("lock_on", true\)/.test(jbl) && /prefs\.getInt\("lock_after", 1\)/.test(jbl)
  && /static final int\[\] LOCK_AFTER = \{1, 5, 15, 60\};/.test(jbl) && JSON.stringify(A?.LOCK_AFTER ?? [1, 5, 15, 60]) === '[1,5,15,60]'
  && /boolean weaker = \(lockOn\(\) && !on1\) \|\| after1 > lockAfter\(\);\s*if \(weaker\) activity\.unlock\(save,/.test(jbl) && /\.put\("secure", km != null && km\.isDeviceSecure\(\)\)/.test(jbl),
  'app lock: the screen lock at a start and at a return after the set minutes (1, 5, 15, 60; default 1), none when off (default on), the page hidden until confirmed; '
  + 'the page\'s own asks always (a minute\'s window, force skips it); a weaker setting asks the lock first; a second ask joins the prompt up, never cancels it');
{
  // Notifications: only what the page gives, its name kept off the lock screen, the tap's intent immutable and ours, the tag checked.
  const nb = /private void notification\(WebMessagePort to, int id, JSONObject m\) \{([\s\S]*?)\n    \}\n/.exec(jbl)?.[1] ?? '';
  const strings = read(MAIN, 'res', 'values', 'strings.xml');
  const tagJ = /static final Pattern TAG = Pattern\.compile\("([^"]+)"\);/.exec(jbl)?.[1]?.replace(/\\\\/g, '\\');
  ok(nb && (nb.match(/setContentTitle\(/g) ?? []).length === 2 && (nb.match(/setContentText\(/g) ?? []).length === 2 && /\.setContentTitle\(title\)\s*\.setContentText\(text\)/.test(nb)
    && /String title = line\(m, "title"\), text = line\(m, "text"\);/.test(nb) && !/setStyle|setTicker|setSubText|addAction|setLargeIcon|setContentInfo|MessagingStyle|BigTextStyle/.test(nb),
    'notify: the title and text the page gives, nothing else (no style, ticker, subtext, action)');
  ok(/\.setContentTitle\(activity\.getString\(R\.string\.app_name\)\)\s*\.setContentText\(activity\.getString\(R\.string\.notify_public\)\)/.test(nb) && /\.setVisibility\(Notification\.VISIBILITY_PRIVATE\)\s*\.setPublicVersion\(shown\)/.test(nb)
    && strings.includes('<string name="app_name">sigelo</string>') && strings.includes('<string name="notify_public">New message</string>') && /<string name="notify_channel">[^<]+<\/string>/.test(strings),
    'notify: private on the lock screen, its public version "sigelo" / "New message" (no name)');
  ok(/PendingIntent\.getActivity\(activity, tag\.hashCode\(\), open, PendingIntent\.FLAG_IMMUTABLE \| PendingIntent\.FLAG_UPDATE_CURRENT\)/.test(nb) && !/FLAG_MUTABLE|getBroadcast|getService/.test(code(jbl))
    && /new Intent\(activity, MainActivity\.class\)\.setAction\(OPEN\)\.putExtra\(EXTRA_OPEN, tag\)\s*\.addFlags\(Intent\.FLAG_ACTIVITY_SINGLE_TOP \| Intent\.FLAG_ACTIVITY_CLEAR_TOP\)/.test(nb)
    && /\.setAutoCancel\(true\)/.test(nb) && /\.setCategory\(Notification\.CATEGORY_MESSAGE\)/.test(nb) && /nm\.notify\(tag, tag\.hashCode\(\), n\);/.test(nb) && /nm\.cancel\(tag, tag\.hashCode\(\)\);/.test(nb),
    'notify: the tap an immutable PendingIntent to MainActivity (explicit, action io.sigelo.app.OPEN, the tag), auto-cancelled, category message, the tag its tag and id');
  ok(tagJ && A?.TAG ? tagJ === A.TAG.source : tagJ === '^(chat|group|pay):[A-Za-z0-9:._-]{1,200}$', `notify: the same tag pattern both sides (${tagJ})`);
  ok(/if \(!\(t instanceof String\) \|\| !TAG\.matcher\(\(String\) t\)\.matches\(\)\) \{\s*fail\(to, id, "notify",/.test(nb) && nb.indexOf('TAG.matcher') < nb.indexOf('nm.cancel') && nb.indexOf('activity.notificationsAllowed()') < nb.indexOf('nm.notify')
    && /fail\(to, id, "notify_permission",/.test(nb) && /void opened\(String tag\) \{\s*if \(tag == null \|\| !TAG\.matcher\(tag\)\.matches\(\)\) return;/.test(jbl) && /private static final int NOTE_MAX = 100;/.test(jbl),
    'notify: the tag checked before a notification or its removal, title and text 1 to 100 characters, refused notify_permission when not allowed; a tapped tag checked again');
  ok(/requestPermissions\(new String\[\] \{POST_NOTIFICATIONS\}, REQ_NOTIFY\)/.test(ma) && /if \(req == REQ_NOTIFY\) \{/.test(ma) && /if \(req != REQ_CAMERA\) \{\s*super\.onRequestPermissionsResult/.test(ma) && /Build\.VERSION\.SDK_INT < 33 \|\| checkSelfPermission\(POST_NOTIFICATIONS\)/.test(ma),
    'notify: POST_NOTIFICATIONS asked when the page asks (Android 13+), its own request code; the camera\'s path as before');
  ok(/protected void onNewIntent\(Intent i\) \{\s*super\.onNewIntent\(i\);\s*setIntent\(i\);\s*opened\(i\);/.test(ma) && /if \(saved == null\) opened\(getIntent\(\)\);/.test(ma) && /SigeloBridge\.OPEN\.equals\(i\.getAction\(\)\)/.test(ma)
    && /if \(port != null\) postOpen\(port, tag\);\s*else pendingOpen = tag;/.test(jbl) && /if \(pendingOpen != null\) \{\s*String tag = pendingOpen;\s*pendingOpen = null;\s*postOpen\(mine, tag\);/.test(jbl) && /put\("ev", "open"\)\.put\("tag", tag\)/.test(jbl)
    && /if \(typeof m\?\.ev === 'string'\) \{[^\n]*return; \}\n\s*const w = waiting\.get\(m\?\.id\);/.test(pa),
    'open event: a tap (onNewIntent, or the start\'s intent) posts {ev:"open", tag}, kept until the page\'s port is open and posted once; the page routes ev messages to their listeners, never to a request waiting');
}
ok(!/onCreateOptionsMenu|onOptionsItemSelected|M_RELOAD|android\.view\.Menu|getActionBar/.test(code(ma)) && /void reload\(\) \{\s*if \(web != null\) web\.loadUrl\(START\);/.test(ma)
  && /case "reload":\s*\/\/[^\n]*\n\s*post\(to, ok\(id\)\);\s*main\.post\(activity::reload\);/.test(jbl)
  && /if \(!COLOUR\.matcher\(c\)\.matches\(\)\) \{\s*fail\(to, id, "bars",/.test(jbl) && /Pattern\.compile\("\^#\[0-9a-fA-F\]\{6\}\$"\)/.test(jbl)
  && /w\.setStatusBarColor\(colour\);\s*w\.setNavigationBarColor\(colour\);/.test(ma) && /SYSTEM_UI_FLAG_LIGHT_STATUS_BAR \| View\.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR/.test(ma)
  && /if \(Build\.VERSION\.SDK_INT >= Build\.VERSION_CODES\.R && w\.getInsetsController\(\) != null\) w\.getInsetsController\(\)\.setSystemBarsAppearance\(light \? LIGHT_BARS : 0, LIGHT_BARS\);/.test(ma),
  'no action bar: no menu; Reload is the page\'s (bridge "reload": answered, then the start loaded); the system bars in the page\'s background (bridge "bars", #rrggbb checked), the icons light or dark to match, Android 11+ through the insets controller too');
ok(/onShowFileChooser/.test(ma) && /ACTION_GET_CONTENT/.test(ma) && /FileChooserParams\.parseResult/.test(ma), 'files: a file input opens the system picker');
{
  // Big files (design/transfer.md §10): BigFiles and PhotoProvider.
  const bf = java['BigFiles.java'], pp = java['PhotoProvider.java'];
  ok(/path\.startsWith\("\/\.big\/"\) && bridge != null\) return bridge\.big\.range\(u, r\.getRequestHeaders\(\), HEADERS\);/.test(ma) && ma.indexOf('bridge.big.range') < ma.indexOf('SAFE_PATH.matcher(path)')
    && /if \(!String\.valueOf\(st\[0\]\)\.equals\(u\.getQueryParameter\("size"\)\) \|\| !String\.valueOf\(st\[1\]\)\.equals\(u\.getQueryParameter\("mtime"\)\)\) return empty\(409/.test(bf)
    && /to - from \+ 1 > CHUNK\) return empty\(416/.test(bf) && /docOf\(profile == null \? "p1" : profileChecked\(profile\), doc\)/.test(bf),
    'big files: a range of a doc this profile picked or took, at most 1 MiB, 409 once its size or time moved; before the page\'s own files');
  ok(/COLUMN_LAST_MODIFIED\)/.test(bf) && /c\.getLong\(di\) \* 1000/.test(bf) && /MediaStore\.MediaColumns\.DATE_MODIFIED/.test(bf),
    'big files: a doc\'s time is its last-modified, else the media store\'s DATE_MODIFIED (an edit seen on a resume: file_changed)');
  ok(/MediaStore\.Downloads\.EXTERNAL_CONTENT_URI/.test(bf) && /IS_PENDING, 1\)/.test(bf) && /IS_PENDING, 0\)/.test(bf) && /static final int CHUNK = 1 << 20;/.test(bf) && /byte\[\] buf = new byte\[CHUNK\];\s*for \(int k; \(k = in\.read\(buf\)\) > 0; \) out\.write\(buf, 0, k\);/.test(bf)
    && /getNoBackupFilesDir\(\), "transfer"\), profile\)/.test(bf) && /r\.no\("land", "the copy into Downloads failed/.test(bf) && /Manifest\.permission\.WRITE_EXTERNAL_STORAGE\}, REQ_STORAGE/.test(bf),
    'big files: partials in private no-backup storage per profile; landed in Downloads through MediaStore, pending until whole, a 1 MiB buffer; Android 9 asks the storage permission; a failure said (land)');
  ok(/MediaStore\.ACTION_IMAGE_CAPTURE\)\.putExtra\(MediaStore\.EXTRA_OUTPUT, out\)/.test(bf) && /PhotoProvider\.uriOf\(f\.getName\(\)\)/.test(bf) && /requestPermissions\(new String\[\] \{Manifest\.permission\.CAMERA\}, REQ_CAMERA_PHOTO\)/.test(bf)
    && /if \(!keep\) stripLocation\(f\);/.test(bf) && /import android\.media\.ExifInterface;/.test(bf) && /TAG_GPS_LATITUDE/.test(bf) && /x\.saveAttributes\(\)/.test(bf)
    && /takePersistableUriPermission\(u, Intent\.FLAG_GRANT_READ_URI_PERMISSION\)/.test(bf) && /ACTION_OPEN_DOCUMENT/.test(bf),
    'big files: the system camera into the cache through PhotoProvider, CAMERA asked at the first photo, location tags removed unless kept (the platform\'s ExifInterface); the picker\'s read grant kept');
  ok(/Pattern\.compile\("\^\[0-9a-f\]\{32\}\\\\\.jpg\$"\)/.test(pp) && /getPathSegments\(\)\.size\(\) != 1/.test(pp) && /getCacheDir\(\), "photos"\)/.test(pp) && (pp.match(/throw new UnsupportedOperationException/g) ?? []).length === 3,
    'PhotoProvider: one name shape (32 hex .jpg) in cache/photos, nothing else; no insert, delete or update');
  ok(/FLAG_KEEP_SCREEN_ON/.test(bf) && /if \(bridge != null && bridge\.big\.permission\(req, grants\)\) return;/.test(ma) && /if \(bridge != null && bridge\.bigResult\(req, result, data\)\) return;/.test(ma),
    'big files: the screen kept on while a transfer moves; the picker\'s, camera\'s and permissions\' answers routed to BigFiles');
}
ok(/r\.hasGesture\(\)/.test(ma) && /ACTION_VIEW/.test(ma) && /CATEGORY_BROWSABLE/.test(ma), 'links: elsewhere opens in the browser, on a tap');
ok(/setEndpointIdentificationAlgorithm\("HTTPS"\)/.test(java['SigeloBridge.java']) && /getDefaultHostnameVerifier\(\)\.verify\(host/.test(java['SigeloBridge.java']) && /setInstanceFollowRedirects\(false\)/.test(java['SigeloBridge.java'])
  && !/TrustManager|setHostnameVerifier|ALLOW_ALL/.test(code(java['SigeloBridge.java'])), 'network: TLS names checked twice, no custom trust, no redirect followed');
// Review 2026-10-28 (LOW), now per profile (design/profiles.md §4): removing a profile deletes all three of its
// aliases (a remote profile seals its control identity under alias 0 as well as its text under alias 2); the
// menu's form switch, which erased everything, is gone.
const jb = java['SigeloBridge.java'];
const forgetBody = /static void forgetProfile\(String profile\) \{([\s\S]*?)\n    \}/.exec(jb)?.[1] ?? '';
ok(/for \(int a = 0; a < ALIASES\.length; a\+\+\) deleteKey\(alias\(profile, a\)\);/.test(forgetBody) && !/switchTo|WebStorage|M_SWITCH|M_FORGET/.test(code(jb) + code(java['MainActivity.java'])),
  'forget-profile: every alias of that profile deleted; no form switch erasing all profiles');
ok(/P1\.equals\(profile\) \? ALIASES\[a\] : "sigelo-" \+ profile \+ SUFFIXES\[a\]/.test(jb) && /\{"-identity", "-identity-full", "-control"\}/.test(jb) && /"\^p\[1-9\]\[0-9\]\{0,2\}\$"/.test(jb)
  && /m\.optString\("profile", P1\)/.test(jb), 'keystore: p1 keeps the three aliases of before; profile <id> sigelo-<id>-identity, -identity-full, -control; the profile id checked, p1 when none is named');
ok(/out\[0\] = \(byte\) \(name\.length == 0 \? 1 : 2\);/.test(jb) && /if \(!P1\.equals\(profile\)\) throw new Refused\("sealed", "sealed for another profile"\);/.test(jb)
  && /if \(!owner\.equals\(profile\) && !owner\.startsWith\(profile \+ ":"\)\) throw new Refused\("sealed", "sealed for another profile"\);/.test(jb) && /\(P1\.equals\(profile\) \? "" : " " \+ profile\)/.test(jb),
  'keystore: blob version 1 for p1 (as before), version 2 naming the profile for the others, the AAD naming it; a blob opens in its own profile only');
// design/profiles.md P2: several computers in a profile, one blob each under the profile's aliases (no alias per computer).
ok(/"\^c\[1-9\]\[0-9\]\{0,2\}\$"/.test(jb) && /m\.optString\("computer", C1\)/.test(jb) && /String owner = C1\.equals\(computer\) \? \(P1\.equals\(profile\) \? "" : profile\) : profile \+ ":" \+ computer;/.test(jb)
  && /seal\(kind, m\.optBoolean\("full", false\), profile, computer, data\) : open\(kind, profile, computer, data\)/.test(jb) && /: " " \+ profile \+ " " \+ computer;/.test(jb),
  'keystore (computers): the computer id checked, c1 when none is named; another computer\'s blob version 2 naming "<profile>:<computer>", the AAD naming it; no alias per computer');
ok(!/now != null && !now\.equals\(want\)/.test(jb) && /if \(!want\.equals\(mode\(\)\)\) prefs\.edit\(\)\.putString\("mode", want\)\.commit\(\);/.test(jb), 'mode: set by each profile\'s first run (no refusal of the other form)');
ok(/setUserAuthenticationRequired\(true\)/.test(java['SigeloBridge.java']) && /BLOCK_MODE_GCM/.test(java['SigeloBridge.java']) && /setKeySize\(256\)/.test(java['SigeloBridge.java']) && /"AndroidKeyStore"/.test(java['SigeloBridge.java']),
  'keystore: AES-256-GCM in AndroidKeyStore; FULL under the screen lock');
{
  const types = [...ma.matchAll(/TYPES\.put\("(\w+)"/g)].map((m) => m[1]);
  const AS = await import(pathToFileURL(join(HERE, 'assets.mjs')).href);
  const exts = [...new Set((await AS.files()).map(([p]) => p.split('.').at(-1)))];
  ok(exts.every((x) => types.includes(x)) && (await AS.files()).every(([p]) => /^[A-Za-z0-9._@/-]{1,200}$/.test(p) && !p.includes('..')), `assets: every file of the page has a type MainActivity serves, and a name it accepts (${exts})`);
  // One source of every file: copy.mjs's walk (assets.mjs names no repository path of its own), and a graph that does not
  // resolve stops the copy.
  const asText = read(HERE, 'assets.mjs').replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, ' ');
  ok(!/\bts\/|contact\/|node_modules|agent\//.test(asText) && /C\.walk\(map \?\? C\.importMap\(\)\)/.test(asText), 'assets.mjs: every source from copy.mjs\'s walk; no repository path of its own (ts/, contact/, agent/, node_modules)');
  const C = await import(pathToFileURL(join(REPO, 'apps', 'web', 'copy.mjs')).href);
  let thrown = '';
  try { await AS.files(C.importMap('<script type="importmap">{"imports":{}}</script>')); } catch (e) { thrown = e.message; }
  ok(/the page's import graph does not resolve: .*sigelo/.test(thrown), `assets.mjs: a file missing from the import graph stops it (${thrown.slice(0, 120)})`);
  // The version (one source): apps/agent/package.json, vendored as vendor/package.json (About reads it), is build.gradle's versionName.
  const agentPkg = join(REPO, 'apps', 'agent', 'package.json'), agentV = JSON.parse(read(agentPkg)).version, gradleV = /versionName '([^']+)'/.exec(read(HERE, 'app', 'build.gradle'))?.[1];
  const shipped = (await AS.files()).find(([p]) => p === 'vendor/package.json');
  ok(gradleV === agentV && shipped && C.sourceOf('vendor/package.json') === agentPkg && (!existsSync(shipped[1]) || readFileSync(shipped[1]).equals(readFileSync(agentPkg))),
    `version: app/build.gradle's versionName is apps/agent/package.json's (${gradleV} / ${agentV}); the page ships vendor/package.json from it, byte for byte`);
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
    const drawables = readdirSync(join(MAIN, 'res', 'drawable')).map((f) => f.replace(/\.xml$/, ''));
    writeFileSync(join(t, 'src', 'R.java'), `package io.sigelo.app;\npublic final class R { public static final class string {\n${names.map((n, i) => `public static final int ${n} = ${0x7f0f0000 + i};`).join('\n')}\n}\npublic static final class drawable {\n${drawables.map((n, i) => `public static final int ${n} = ${0x7f080000 + i};`).join('\n')}\n} }\n`);
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
    {
      // The recipe's steps walked over this tree from the subdir (each block starts there, its commands joined):
      // each cd lands on a directory, npm ci where a package.json and its lockfile are, tsc where a tsconfig.json is,
      // assets.mjs the file it names; and every directory copy.mjs reads from (node_modules, dist) made by one of them.
      const problems = [], made = new Set();
      for (const block of [b.prebuild ?? [], b.build ?? []]) {
        let cwd = join(REPO, b.subdir ?? '');
        for (const step of block) {
          let m;
          if ((m = /^cd (\S+)$/.exec(step))) { cwd = join(cwd, m[1]); if (!existsSync(cwd) || !statSync(cwd).isDirectory()) problems.push(`${step}: ${rel(cwd)} is not a directory`); }
          else if (step === 'npm ci --ignore-scripts') { if (!['package.json', 'package-lock.json'].every((f) => existsSync(join(cwd, f)))) problems.push(`${step} in ${rel(cwd)}: no package.json and package-lock.json`); made.add(rel(join(cwd, 'node_modules'))); }
          else if (step === 'npx tsc') {
            const tc = join(cwd, 'tsconfig.json');
            if (!existsSync(tc)) problems.push(`${step} in ${rel(cwd)}: no tsconfig.json`);
            else made.add(rel(join(cwd, /"outDir"\s*:\s*"([^"]+)"/.exec(read(tc))?.[1] ?? '.')));
          } else if ((m = /^node (\S+\.mjs)$/.exec(step))) { if (join(cwd, m[1]) !== join(HERE, 'assets.mjs')) problems.push(`${step} in ${rel(cwd)}: not apps/android/assets.mjs`); }
          else problems.push(`${step}: not a step this check knows`);
        }
      }
      const froms = [...read(REPO, 'apps', 'web', 'copy.mjs').matchAll(/\['vendor\/[^']*', '([^']+)'\]/g)].map((x) => x[1]);
      const roots = [...new Set(froms.map((f) => /^(.*?\/(?:node_modules|dist))\//.exec(f)?.[1]).filter(Boolean))];
      for (const r of roots) if (!made.has(r)) problems.push(`${r}: copy.mjs reads it, no step of the recipe makes it`);
      ok(problems.length === 0 && roots.length >= 3 && froms.length >= 8,
        `fdroid draft: its prebuild and build steps walk this tree from ${b.subdir} (cd, npm ci, tsc, assets.mjs); copy.mjs's ${roots.join(', ')} each made by a step (${problems.join('; ')})`);
    }
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
    && /^permissions:\s*\{\}\s*$/m.test(r) && [...r.matchAll(/^\s+permissions:(.*)$/gm)].every((m) => /^\s*\{\s*contents: read\s*\}\s*$/.test(m[1])) && !/\$\{\{\s*(github\.event|inputs)\.[^}]*\}\}/.test(r.split('\n').filter((l) => !/^\s*(ref|REF|EXPECT):/.test(l)).join('\n'))
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
  ok(!/\bsecrets\./.test(wf) && !/pull_request_target|workflow_run/.test(wf) && /^permissions:\s*\{\}\s*$/m.test(wf) && [...wf.matchAll(/^\s+permissions:(.*)$/gm)].every((m) => /^\s*\{\s*contents: read\s*\}\s*$/.test(m[1])), 'workflow: no secret, no privileged trigger, permissions {} on top, contents: read per job');
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
import json; print(json.dumps({'jobs': list(d['jobs']), 'steps': len(d['jobs']['build']['steps']), 'builders': d['jobs']['build']['strategy']['matrix']['builder'], 'needs': d['jobs']['apk']['needs'], 'on': sorted(str(k) for k in d[True])}))`, join(REPO, '.github', 'workflows', 'android.yml')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) { parsed = e.code === 'ENOENT' || /No module named/.test(String(e.stderr)) ? 'skip' : String(e.stderr || e.message); }
  if (parsed === 'skip') console.log('note: no python3 with PyYAML here: the workflow\'s YAML not parsed');
  else { let j = null; try { j = JSON.parse(parsed); } catch {} ok(j?.jobs?.join() === 'build,apk' && j.steps >= 8 && j.builders?.length === 2 && j.needs === 'build', `workflow: YAML parses strictly, build twice (matrix of 2) then apk compares (${typeof parsed === 'string' ? parsed.trim().slice(0, 200) : ''})`); }
}

// Where `java` runs a source file (JDK 11+, no Android SDK needed): SigeloBridge.java's keystore methods as they
// are in the file (aad, profileOf, alias, forgetProfile, seal, open), with a software AES key store in place of
// AndroidKeyStore, run on the profiles' cases (design/profiles.md §4). Its other code needs the platform: not run.
{
  const jb = java['SigeloBridge.java'];
  const grab = (a, b) => { const i = jb.indexOf(a), j = jb.indexOf(b, i); return i < 0 || j < 0 ? null : jb.slice(i, j); };
  const parts = [grab('    private static final String[] ALIASES', '    private static final int HTTP_MAX'), grab('    /**\n     * p1 (or none given)', '    @SuppressWarnings("deprecation")   // setUserAuthenticationValidityDurationSeconds'),
    grab('    /** A profile\'s removal', '    private void keystore(')];
  let probe = null;
  try { probe = execFileSync('java', ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch {}
  if (!probe) console.log('note: no java here: the keystore methods not run');
  else {
    const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const t = mkdtempSync(join(tmpdir(), 'sigelo-ks-'));
    try {
      writeFileSync(join(t, 'KS.java'), `import java.nio.charset.StandardCharsets; import java.security.*; import java.io.IOException; import java.util.*; import java.util.regex.Pattern;
import javax.crypto.*; import javax.crypto.spec.GCMParameterSpec;
public class KS {
  static final class Refused extends Exception { final String check; Refused(String c, String m) { super(m); check = c; } }
  static final class JSONObject { final Map<String, String> m = new HashMap<>(); JSONObject put(String k, String v) { m.put(k, v); return this; } String optString(String k, String f) { return m.getOrDefault(k, f); } }
  static final Map<String, SecretKey> STORE = new HashMap<>();
${parts.join('')}
  static SecretKey key(String profile, int a, boolean make) throws GeneralSecurityException { String al = alias(profile, a); if (STORE.containsKey(al)) return STORE.get(al); if (!make) return null; KeyGenerator g = KeyGenerator.getInstance("AES"); g.init(256); STORE.put(al, g.generateKey()); return STORE.get(al); }
  static void deleteKey(String alias) { STORE.remove(alias); }
  interface X { Object run() throws Exception; }
  static String t(X x) { try { Object o = x.run(); return o instanceof byte[] ? new String((byte[]) o, StandardCharsets.UTF_8) : String.valueOf(o); } catch (Refused e) { return "refused " + e.check; } catch (Exception e) { return "error " + e.getClass().getSimpleName(); } }
  public static void main(String[] a) throws Exception {
    byte[] m = "secret".getBytes(StandardCharsets.UTF_8);
    byte[] b1 = seal("identity", false, "p1", "c1", m), b2 = seal("identity", true, "p2", "c1", m), k2 = seal("keeper", true, "p2", "c1", m);
    byte[] forged = b2.clone(); forged[4] = '3';
    System.out.println(String.join("|", "v" + b1[0] + " a" + b1[1] + " " + b1.length, "v" + b2[0] + " a" + b2[1] + " " + new String(b2, 3, b2[2], StandardCharsets.US_ASCII) + " " + b2.length,
      t(() -> open("identity", "p1", "c1", b1)), t(() -> open("identity", "p2", "c1", b1)), t(() -> open("identity", "p2", "c1", b2)), t(() -> open("identity", "p1", "c1", b2)), t(() -> open("identity", "p3", "c1", b2)),
      t(() -> open("identity", "p2", "c1", k2)), t(() -> open("keeper", "p2", "c1", k2)), t(() -> open("identity", "p3", "c1", forged)), t(() -> open("identity", "p2", "c1", new byte[] {2, 0, 2, 'p', '2'})),
      t(() -> profileOf(new JSONObject())), t(() -> profileOf(new JSONObject().put("profile", "p0"))), t(() -> profileOf(new JSONObject().put("profile", "p1/x"))), t(() -> profileOf(new JSONObject().put("profile", "p999"))),
      String.valueOf(new TreeSet<>(STORE.keySet()))));
    // P2: a computer's blob under its profile's aliases, naming the computer; it opens as that computer of that profile only.
    byte[] c12 = seal("control", false, "p1", "c2", m), c22 = seal("control", false, "p2", "c2", m), c21 = seal("control", false, "p2", "c1", m);
    byte[] relabel = c22.clone(); relabel[7] = '3';
    System.out.println(String.join("|", "v" + c12[0] + " a" + c12[1] + " " + new String(c12, 3, c12[2], StandardCharsets.US_ASCII), "v" + c22[0] + " " + new String(c22, 3, c22[2], StandardCharsets.US_ASCII), "v" + c21[0] + " " + new String(c21, 3, c21[2], StandardCharsets.US_ASCII),
      t(() -> open("control", "p1", "c2", c12)), t(() -> open("control", "p1", "c1", c12)), t(() -> open("control", "p1", "c3", c12)), t(() -> open("control", "p2", "c2", c12)),
      t(() -> open("control", "p2", "c2", c22)), t(() -> open("control", "p2", "c1", c22)), t(() -> open("control", "p2", "c1", c21)), t(() -> open("control", "p2", "c2", c21)), t(() -> open("control", "p2", "c3", relabel)),
      t(() -> open("identity", "p2", "c2", c22)), t(() -> computerOf(new JSONObject())), t(() -> computerOf(new JSONObject().put("computer", "c0"))), t(() -> computerOf(new JSONObject().put("computer", "p2"))), t(() -> computerOf(new JSONObject().put("computer", "c999"))),
      String.valueOf(new TreeSet<>(STORE.keySet()))));
    forgetProfile("p2");
    System.out.println(String.join("|", String.valueOf(new TreeSet<>(STORE.keySet())), t(() -> open("identity", "p2", "c1", b2)), t(() -> open("identity", "p1", "c1", b1)), t(() -> open("control", "p2", "c2", c22)), t(() -> open("control", "p1", "c2", c12))));
    // The kept words (kind "words"): under the FULL alias, their own AAD; never opened as another kind, nor another kind as them.
    byte[] w1 = seal("words", false, "p1", "c1", m), w3 = seal("words", true, "p3", "c1", m), k3 = seal("keeper", true, "p3", "c1", m);
    System.out.println(String.join("|", "v" + w1[0] + " a" + w1[1], "v" + w3[0] + " a" + w3[1], t(() -> open("words", "p1", "c1", w1)), t(() -> open("words", "p3", "c1", w3)), t(() -> open("keeper", "p3", "c1", w3)),
      t(() -> open("identity", "p3", "c1", w3)), t(() -> open("words", "p3", "c1", k3)), t(() -> open("words", "p1", "c1", w3)), t(() -> open("words", "p2", "c1", w3)), t(() -> seal("seed", true, "p1", "c1", m))));
    forgetProfile("p3");
    System.out.println(String.join("|", String.valueOf(new TreeSet<>(STORE.keySet())), t(() -> open("words", "p3", "c1", w3)), t(() -> open("words", "p1", "c1", w1))));
  }
}
`);
      let out = '';
      try { out = execFileSync('java', [join(t, 'KS.java')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], cwd: t }); } catch (e) { out = `${e.stdout ?? ''}${e.stderr ?? e.message}`; }
      const want = ['v1 a0 36|v2 a1 p2 39|secret|refused sealed|secret|refused sealed|refused sealed|error AEADBadTagException|secret|refused sealed|refused sealed|p1|refused profile|refused profile|p999|[sigelo-identity, sigelo-p2-identity-full]',
        'v2 a2 p1:c2|v2 p2:c2|v2 p2|secret|refused sealed|refused sealed|refused sealed|secret|refused sealed|secret|refused sealed|error AEADBadTagException|refused sealed|c1|refused computer|refused computer|c999|[sigelo-control, sigelo-identity, sigelo-p2-control, sigelo-p2-identity-full]',
        '[sigelo-control, sigelo-identity]|refused sealed|secret|refused sealed|secret',
        'v1 a1|v2 a1|secret|secret|error AEADBadTagException|error AEADBadTagException|error AEADBadTagException|refused sealed|refused sealed|refused kind',
        '[sigelo-control, sigelo-identity, sigelo-identity-full]|refused sealed|secret'];
      ok(parts.every(Boolean) && out.trim().split('\n').join('\n') === want.join('\n'),
        `keystore (SigeloBridge.java's own methods under java): p1 blob version 1 under the aliases of before; p2 version 2 naming it, its own alias; each opens in its own profile only (a relabelled header, a keeper as an identity, a short blob refused); profile ids checked; the kept words (kind words) under the FULL alias with their own AAD, never opened as a keeper or identity nor a keeper as them, an unknown kind refused, gone with forget-profile; computers (P2): another computer's blob version 2 naming profile and computer, under the profile's control alias, opening as that computer only (a relabelled owner refused by its AAD), computer ids checked; forget-profile erases p2's aliases (its computers' blobs too), p1 kept (${out.trim().split('\n').join(' / ').slice(0, 400)})`);
    } finally { rmSync(t, { recursive: true, force: true }); }
  }
}

for (const f of fails) console.log('FAIL ' + f);
if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
console.log(`ALL PASS (${count})`);
