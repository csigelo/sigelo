// SPDX-License-Identifier: MIT
// The Android project checked without the SDK (design/apps.md §8): what can be known of it on a
// machine with Node alone. The build itself runs on CI (.github/workflows/android.yml).
//   node apps/android/check.mjs     → ALL PASS (n)
// The manifest and resources (well-formed, fourteen permissions (storage on Android 9 only; the microphone for voice messages and calls; a call's
// foreground service, audio, proximity lock and ring vibration; boot for Built in push), one provider not exported, four services (Stay
// connected, Built in push, the push connector's raise, a call), two receivers (the push app's, Built in push's boot), no backup, references resolve, the
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
  ok(perms.join() === 'android.permission.ACCESS_NETWORK_STATE,android.permission.CAMERA,android.permission.FOREGROUND_SERVICE,android.permission.FOREGROUND_SERVICE_MICROPHONE,android.permission.FOREGROUND_SERVICE_SPECIAL_USE,android.permission.INTERNET,android.permission.MODIFY_AUDIO_SETTINGS,android.permission.POST_NOTIFICATIONS,android.permission.RECEIVE_BOOT_COMPLETED,android.permission.RECORD_AUDIO,android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,android.permission.VIBRATE,android.permission.WAKE_LOCK,android.permission.WRITE_EXTERNAL_STORAGE',
    `manifest: INTERNET, CAMERA, POST_NOTIFICATIONS, RECORD_AUDIO (voice messages, calls), WRITE_EXTERNAL_STORAGE; for Stay connected FOREGROUND_SERVICE, FOREGROUND_SERVICE_SPECIAL_USE, REQUEST_IGNORE_BATTERY_OPTIMIZATIONS; for calls FOREGROUND_SERVICE_MICROPHONE, MODIFY_AUDIO_SETTINGS, WAKE_LOCK, VIBRATE, ACCESS_NETWORK_STATE; for Built in push RECEIVE_BOOT_COMPLETED only (no USE_FULL_SCREEN_INTENT, no READ_PHONE_STATE, no MANAGE_OWN_CALLS) (${perms})`);
  ok(all(man, 'uses-feature').some((f) => f.attrs['android:name'] === 'android.hardware.microphone' && f.attrs['android:required'] === 'false'), 'manifest: a microphone not required (a phone without one still installs it)');
  const wes = all(man, 'uses-permission').find((p) => p.attrs['android:name'] === 'android.permission.WRITE_EXTERNAL_STORAGE');
  ok(wes?.attrs['android:maxSdkVersion'] === '28' && all(man, 'uses-permission').filter((p) => p !== wes).every((p) => p.attrs['android:maxSdkVersion'] === undefined),
    'manifest: the shared storage only up to Android 9 (maxSdkVersion 28: Downloads through MediaStore after, no permission)');
  ok(all(man, 'uses-sdk').length === 0 && man.attrs.package === undefined, 'manifest: no uses-sdk, no package (minSdk, targetSdk and the namespace are in app/build.gradle)');
  const app = all(man, 'application')[0]?.attrs ?? {};
  ok(app['android:allowBackup'] === 'false' && app['android:dataExtractionRules'] === '@xml/data_extraction_rules' && app['android:debuggable'] === undefined && app['android:usesCleartextTraffic'] === undefined,
    'manifest: no backup, no transfer (data extraction rules), not debuggable by the manifest');
  const acts = all(man, 'activity');
  // Two filters: the launcher's, and share into sigelo (0.1.20: ACTION_SEND alone, text, pictures, any file; no SEND_MULTIPLE).
  const filters = acts.length === 1 ? all(acts[0], 'intent-filter') : [];
  const names = (f, k) => all(f, k).map((a) => a.attrs['android:name']).join();
  ok(acts.length === 1 && acts[0].attrs['android:name'] === '.MainActivity' && acts[0].attrs['android:exported'] === 'true' && filters.length === 2
    && names(filters[0], 'action') === 'android.intent.action.MAIN' && names(filters[0], 'category') === 'android.intent.category.LAUNCHER' && all(filters[0], 'data').length === 0,
  'manifest: one activity, MainActivity, exported: the launcher\'s filter and the share filter only');
  const send = filters[1] ?? { kids: [] };
  ok(names(send, 'action') === 'android.intent.action.SEND' && names(send, 'category') === 'android.intent.category.DEFAULT'
    && all(send, 'data').map((d) => Object.keys(d.attrs).join() + '=' + d.attrs['android:mimeType']).join() === 'android:mimeType=text/plain,android:mimeType=image/*,android:mimeType=*/*',
  'manifest: share into sigelo: ACTION_SEND (not SEND_MULTIPLE), category DEFAULT, mime types text/plain, image/*, */* only (no scheme, host or path)');
  // Push (UnifiedPush.java, design/push.md §1 B): the distributor's five connector actions and nothing else; exported, since the
  // distributor is another app. Built in push (PushClient, §6): its boot receiver, BOOT_COMPLETED and MY_PACKAGE_REPLACED only (both
  // protected: only the system sends them).
  const rc = all(man, 'receiver'), up = 'org.unifiedpush.android.connector.';
  const rcUp = rc.find((r) => r.attrs['android:name'] === '.UnifiedPush'), rcBoot = rc.find((r) => r.attrs['android:name'] === '.PushClient$Boot');
  ok(rc.length === 2 && rcUp && rcUp.attrs['android:exported'] === 'true' && all(rcUp, 'intent-filter').length === 1
    && all(rcUp, 'action').map((a) => a.attrs['android:name']).join() === ['NEW_ENDPOINT', 'REGISTRATION_FAILED', 'UNREGISTERED', 'TEMP_UNAVAILABLE', 'MESSAGE'].map((x) => up + x).join()
    && rcBoot && all(rcBoot, 'intent-filter').length === 1 && all(rcBoot, 'action').map((a) => a.attrs['android:name']).join() === 'android.intent.action.BOOT_COMPLETED,android.intent.action.MY_PACKAGE_REPLACED'
    && all(rcBoot, 'data').length === 0 && all(man, 'data').every((d) => Object.keys(d.attrs).join() === 'android:mimeType'),
  'manifest: two receivers: UnifiedPush (the five connector actions only) and PushClient$Boot (BOOT_COMPLETED, MY_PACKAGE_REPLACED only); no URL handler (no data but mime types)');
  // Stay connected (StayConnected.java): a foreground service of type specialUse, its subtype said, not exported, ending with the task;
  // the push connector's RAISE_TO_FOREGROUND, exported, no type (it does nothing but be bound); and a call's (below).
  const svAll = all(man, 'service'), sv = svAll.filter((x) => x.attrs['android:name'] === '.StayConnected'), prop = sv.length === 1 ? all(sv[0], 'property') : [];
  const raise = svAll.filter((x) => x.attrs['android:name'] === '.UnifiedPush$Raise');
  ok(svAll.length === 4 && raise.length === 1 && raise[0].attrs['android:exported'] === 'true' && raise[0].attrs['android:foregroundServiceType'] === undefined
    && all(raise[0], 'action').map((a) => a.attrs['android:name']).join() === up + 'RAISE_TO_FOREGROUND',
  'manifest: four services: StayConnected, PushClient, CallService and UnifiedPush$Raise (RAISE_TO_FOREGROUND, exported, no foreground type)');
  const pc = svAll.find((x) => x.attrs['android:name'] === '.PushClient'), pcProp = pc ? all(pc, 'property') : [];
  ok(pc && pc.attrs['android:exported'] === 'false' && pc.attrs['android:foregroundServiceType'] === 'specialUse' && pc.attrs['android:stopWithTask'] === 'false'
    && pcProp.length === 1 && pcProp[0].attrs['android:name'] === 'android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE' && /own push server/.test(pcProp[0].attrs['android:value'] ?? '') && all(pc, 'intent-filter').length === 0,
    'manifest: PushClient (Built in push): not exported, specialUse with its subtype, not ended by a swipe-away (stopWithTask false), no intent filter');
  ok(sv.length === 1 && sv[0].attrs['android:name'] === '.StayConnected' && sv[0].attrs['android:exported'] === 'false' && sv[0].attrs['android:foregroundServiceType'] === 'specialUse'
    && sv[0].attrs['android:stopWithTask'] === 'true' && prop.length === 1 && prop[0].attrs['android:name'] === 'android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE'
    && /end-to-end messaging connection open/.test(prop[0].attrs['android:value'] ?? '') && all(sv[0], 'intent-filter').length === 0,
    'manifest: StayConnected: not exported, foregroundServiceType specialUse with its PROPERTY_SPECIAL_USE_FGS_SUBTYPE, stopWithTask, no intent filter');
  // A call (CallService.java, design/calls.md §4): of type microphone, not exported, ending with the task, no filter.
  const cs = all(man, 'service').find((x) => x.attrs['android:name'] === '.CallService');
  ok(cs && cs.attrs['android:exported'] === 'false' && cs.attrs['android:foregroundServiceType'] === 'microphone' && cs.attrs['android:stopWithTask'] === 'true' && all(cs, 'intent-filter').length === 0 && all(cs, 'property').length === 0,
    'manifest: CallService: not exported, foregroundServiceType microphone, stopWithTask, no intent filter');
  const pv = all(man, 'provider');
  ok(pv.length === 1 && pv[0].attrs['android:name'] === '.PhotoProvider' && pv[0].attrs['android:authorities'] === 'io.sigelo.app.photos' && pv[0].attrs['android:exported'] === 'false'
    && pv[0].attrs['android:grantUriPermissions'] === 'true' && all(pv[0], 'grant-uri-permission').length === 0 && all(pv[0], 'meta-data').length === 0,
    'manifest: one provider, PhotoProvider (io.sigelo.app.photos), not exported, reached only through the camera intent\'s grant');
  // Android 11+ package visibility: the camera intent declared, so resolveActivity sees a camera app (BigFiles cameraApp).
  const qs = all(man, 'queries');
  ok(qs.length === 1 && all(qs[0], 'intent').length === 2 && all(qs[0], 'action').map((a) => a.attrs['android:name']).join() === 'android.media.action.IMAGE_CAPTURE,org.unifiedpush.android.distributor.REGISTER' && all(qs[0], 'package').length === 0 && all(qs[0], 'provider').length === 0,
    'manifest: <queries> names the camera intent and UnifiedPush\'s REGISTER (the distributors) only (no package, no provider)');
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
ok(/include ':app'/.test(settings) && /FAIL_ON_PROJECT_REPOS/.test(settings) && !/maven\s*\{/.test(code(settings)) && !/jcenter/.test(settings), 'settings.gradle: one module; repositories google() and mavenCentral() only, none per project (F-Droid\'s scanner rejects another maven repo: CI\'s Central mirror is an init script, android.yml)');
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
ok(Object.keys(java).sort().join() === 'BigFiles.java,CallService.java,MainActivity.java,Ntfy.java,PhotoProvider.java,PushClient.java,SigeloBridge.java,StayConnected.java,UnifiedPush.java,WebPush.java', `java: MainActivity, SigeloBridge, BigFiles, PhotoProvider, StayConnected, CallService, UnifiedPush, WebPush, PushClient and Ntfy (${Object.keys(java)})`);
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
// The microphone (voice messages): the WebView's ask granted at once for audio only, our origin only, when RECORD_AUDIO is
// granted, else denied without a prompt (the page asked through the bridge first: one dialog, not two).
ok(/boolean audio = res\.length == 1 && PermissionRequest\.RESOURCE_AUDIO_CAPTURE\.equals\(res\[0\]\);\s*if \(audio && ours\(req\.getOrigin\(\)\)\) \{\s*if \(checkSelfPermission\(Manifest\.permission\.RECORD_AUDIO\) == PackageManager\.PERMISSION_GRANTED\) req\.grant\(res\);\s*else req\.deny\(\);/.test(ma)
  && !/RECORD_AUDIO\}, REQ_/.test(ma),
  'microphone: the WebView granted audio capture only, for our origin only, once RECORD_AUDIO is; never a second prompt from the WebView');
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
    && strings.includes('<string name="app_name">Sigelo</string>') && strings.includes('<string name="notify_public">New message</string>') && /<string name="notify_channel">[^<]+<\/string>/.test(strings),
    'notify: private on the lock screen, its public version "Sigelo" / "New message" (no name)');
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
    && /if \(typeof m\?\.ev === 'string'\) \{[\s\S]{0,400}?return;\n\s*\}\n\s*const w = waiting\.get\(m\?\.id\);/.test(pa),
    'open event: a tap (onNewIntent, or the start\'s intent) posts {ev:"open", tag}, kept until the page\'s port is open and posted once; the page routes ev messages to their listeners, never to a request waiting');
}
{
  // Share into sigelo (0.1.20): ACTION_SEND at a start or onNewIntent to the bridge; a file another app's content URI only (never
  // file://, never this app's own authorities: it would send the app's private files); one held, the latest wins; told to every new port.
  const bf = java['BigFiles.java'];
  ok(/setIntent\(i\);\s*opened\(i\);\s*shared\(i\);/.test(ma) && /if \(saved == null\) shared\(getIntent\(\)\);/.test(ma) && /Intent\.ACTION_SEND\.equals\(i\.getAction\(\)\)/.test(ma)
    && /FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY\) != 0\) return;/.test(ma) && !/ACTION_SEND_MULTIPLE/.test(code(ma) + code(jbl)),
    'share: ACTION_SEND handed to the bridge at a start (not a restart, not from the recent apps) and onNewIntent; SEND_MULTIPLE nowhere');
  ok(/return "content"\.equals\(u\.getScheme\(\)\) && a != null && !a\.equals\(PhotoProvider\.AUTHORITY\) && !a\.equals\(pkg\) && !a\.startsWith\(pkg \+ "\."\);/.test(jbl)
    && /if \(!foreign\(u\)\) \{\s*holdShare\(seq, null, null, null, refusedShare\(/.test(jbl) && /if \(seq != shareSeq\) return;/.test(jbl)
    && /if \(shareEv != null\) \{\s*post\(mine, shareEv\);/.test(jbl) && /static final int SHARE_TEXT_MAX = 100_000;/.test(jbl) && /TEXT_MAX = 100_000/.test(read(REPO, 'apps', 'contact', 'page.mjs'))
    && /JSONObject shared\(String profile, Uri u\)[\s\S]*?keepDoc\(profile, doc, "u:" \+ u\);\s*return describe\(profile, doc, "u:" \+ u\);/.test(bf)
    && /case "share-take":\s*shareTake\(to, id, m\);/.test(jbl) && /if \(text == null && u == null\) \{\s*fail\(to, id, "share", "nothing shared"\);/.test(jbl),
    'share: a file only another app\'s content URI (file:// and the app\'s own authorities refused), the latest share wins, told again to each new page; a text at most the page\'s TEXT_MAX; share-take makes the URI a doc of the profile named (as big-pick), refused "share" when nothing is held');
}
{
  // Stay connected (StayConnected.java; design/push.md §A): the process kept, not a socket of its own; no wake lock, no exact alarm, no boot start.
  const sc = java['StayConnected.java'], scc = code(sc), strings = read(MAIN, 'res', 'values', 'strings.xml');
  ok(/startForeground\(NOTE, n, ServiceInfo\.FOREGROUND_SERVICE_TYPE_SPECIAL_USE\); else startForeground\(NOTE, n\);/.test(sc) && /return START_NOT_STICKY;/.test(sc)
    && !/WakeLock|newWakeLock|setExact|setAlarmClock|SCHEDULE_EXACT_ALARM|BOOT_COMPLETED|Socket/.test(scc),
    'stay: startForeground with type specialUse (Android 14+), not sticky; no wake lock, no exact alarm, no boot start, no socket of its own');
  ok(/am\.setAndAllowWhileIdle\(AlarmManager\.ELAPSED_REALTIME_WAKEUP, SystemClock\.elapsedRealtime\(\) \+ NUDGE_MS, alarm\(\)\)/.test(sc) && /NUDGE_MS = 15 \* 60_000L;/.test(sc) && /am\.cancel\(alarm\(\)\);/.test(sc)
    && /PendingIntent\.getService\(this, 0, new Intent\(this, StayConnected\.class\)\.setAction\(NUDGE\), PendingIntent\.FLAG_IMMUTABLE/.test(sc)
    && /ACTION_DEVICE_IDLE_MODE_CHANGED/.test(sc) && /!pm\.isDeviceIdleMode\(\)\) nudge\(\);/.test(sc) && /unregisterReceiver\(idle\);/.test(sc),
    'stay: an inexact alarm every 15 minutes (setAndAllowWhileIdle, immutable, explicit), cancelled at the end; the end of Doze nudges too');
  ok(/NotificationManager\.IMPORTANCE_LOW\)/.test(sc) && /\.setContentTitle\(getString\(R\.string\.stay_title\)\)/.test(sc) && !/setContentText|addAction|setStyle/.test(scc)
    && strings.includes('<string name="stay_title">Sigelo · connected</string>') && /PendingIntent\.getActivity\(this, 0, open, PendingIntent\.FLAG_IMMUTABLE/.test(sc) && /\.setOngoing\(true\)/.test(sc),
    'stay: the notification "sigelo · connected", low importance, no text, no action; a tap opens the app (immutable)');
  ok(/prefs\(c\)\.getBoolean\(ON, false\)/.test(sc) && /if \(m\.has\(k\) && !\(m\.opt\(k\) instanceof Boolean\)\) throw new SigeloBridge\.Refused\("stay",/.test(sc)
    && /!open\(a, new Intent\(Settings\.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri\.parse\("package:" \+ a\.getPackageName\(\)\)\)\)\) \{\s*open\(a, new Intent\(Settings\.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS\)\);/.test(sc)
    && /if \(!blocked\(a\)\) \{[\s\S]{0,120}?a\.askNotifications\(/.test(sc) && /&& !a\.shouldShowRequestPermissionRationale\(POST_NOTIFICATIONS\);/.test(sc) && /Settings\.ACTION_APP_NOTIFICATION_SETTINGS/.test(sc),
    'stay: the switch off by default (Built in push keeps the process now), booleans only (refused "stay"); a refusal never final: the battery prompt at each tap, POST_NOTIFICATIONS while Android shows it, then the app\'s settings page');
  ok(/StayConnected\.follow\(this, StayConnected\.on\(this\)\);\s*super\.onPause\(\);/.test(ma) && /if \(isFinishing\(\)\) StayConnected\.follow\(this, false\);/.test(ma)
    && /if \(StayConnected\.on\(this\) \|\| UnifiedPush\.BUILTIN\.equals\(UnifiedPush\.mode\(this\)\)\) moveTaskToBack\(true\);\s*else super\.onBackPressed\(\);/.test(ma) && !/StayConnected/.test(code(ma).replace(/[\s\S]*?protected void onCreate/, '').split('onBackPressed')[0]),
    'stay: started as the app leaves the screen (onPause), stopped when it finishes; Back on the first screen minimises while it or Built in push is on (the page and its connection kept)');
  ok(/StayConnected\.page = this;/.test(jbl) && /if \(StayConnected\.page == this\) StayConnected\.page = null;/.test(jbl) && /put\("ev", "nudge"\)/.test(jbl) && /case "stay":\s*try \{\s*StayConnected\.op\(activity, m,/.test(jbl),
    'stay: the bridge answers "stay" through StayConnected.op and posts {ev:"nudge"} to the page; registered while open');
}
{
  const strings = read(MAIN, 'res', 'values', 'strings.xml');
  // Push (UnifiedPush.java, WebPush.java; design/push.md §1 B): the connector hand-rolled against AND_3, platform crypto only.
  const u = java['UnifiedPush.java'], uc = code(u), w = java['WebPush.java'], sc = java['StayConnected.java'];
  ok(![...w.matchAll(/^import ([\w.]+);$/gm)].some((m) => !/^(java|javax)\./.test(m[1])) && /"sigelo-push\/0 wake"/.test(w) && /Arrays\.copyOf\("sigelo-push\/0 wake"\.getBytes\(StandardCharsets\.UTF_8\), 32\)/.test(w)
    && /KeyAgreement\.getInstance\("ECDH"\)/.test(w) && /Mac\.getInstance\("HmacSHA256"\)/.test(w) && /Cipher\.getInstance\("AES\/GCM\/NoPadding"\)/.test(w) && /"WebPush: info"/.test(w)
    && /"Content-Encoding: aes128gcm"/.test(w) && /"Content-Encoding: nonce"/.test(w) && existsSync(join(HERE, 'test', 'WebPushTest.java')),
  'push: WebPush is RFC 8291 in java.* and javax.* only (no Android import: test/WebPushTest.java runs its vectors on a JVM); WAKE is relay/push.mjs\'s 32 bytes');
  ok(/if \(action == null \|\| token == null \|\| !token\.equals\(mine\)\) return;/.test(u) && uc.indexOf('!token.equals(mine)') < uc.indexOf('case NEW_ENDPOINT')
    && /e == null \|\| !e\.startsWith\("https:\/\/"\) \|\| e\.length\(\) > ENDPOINT_MAX/.test(u)
    && /new Intent\(ACK\)\.setPackage\(dist\)/.test(u) && /if \(APP\.equals\(mode\(c\)\) && isWake\(c, i\.getByteArrayExtra\("bytesMessage"\)\)\) wake\(c\);/.test(u)
    && /return body != null && k != null && pub != null && WebPush\.isWake\(body, \(ECPrivateKey\) k\[0\], pub, \(byte\[\]\) k\[1\]\);/.test(u),
  'push: every distributor broadcast must name our token first; an endpoint https only; a MESSAGE acknowledged, a wake only in mode app and when it opens to WAKE under our keys');
  ok([...uc.matchAll(/c\.sendBroadcast\(new Intent\((\w+)\)\.setPackage\((\w+)\)/g)].map((m) => m[1]).sort().join() === 'ACK,REGISTER,UNREGISTER' && (uc.match(/sendBroadcast\(/g) ?? []).length === 3
    && /PendingIntent\.getBroadcast\(c, 0, new Intent\("org\.unifiedpush\.register\.dummy_app"\), PendingIntent\.FLAG_IMMUTABLE\)/.test(u)
    && /queryBroadcastReceivers\(new Intent\(REGISTER\), 0\)/.test(u) && /UUID\.randomUUID\(\)/.test(u),
  'push: REGISTER, UNREGISTER and MESSAGE_ACK only, each explicit to the distributor\'s package; pi immutable; distributors found by REGISTER receivers; a random token');
  ok(/ALIAS = "sigelo-push"/.test(u) && /KeyGenerator\.getInstance\(KeyProperties\.KEY_ALGORITHM_AES, KEYSTORE\)/.test(u) && !/setUserAuthenticationRequired/.test(uc) && /ci\.updateAAD\(ALIAS/.test(u)
    && /putString\(KEYS, b64\(blob\)\)/.test(u) && /\.remove\(KEYS\)\.remove\(PUB\)/.test(u) && /ks\.deleteEntry\(ALIAS\)/.test(u),
  'push: the private key and auth sealed under keystore "sigelo-push" (AES-GCM, no user auth: a wake opens while locked); erased when push is turned off');
  ok(/if \(b != null\) \{\s*if \(!BUILTIN\.equals\(mode\(c\)\)\) StayConnected\.wake\(c\);\s*if \(b\.wake\(\)\) return;\s*\}/.test(u) && /\.setContentText\(c\.getString\(R\.string\.push_wake\)\)/.test(u) && !/setContentText\((?!c\.getString\(R\.string\.push_wake\))/.test(uc)
    && strings.includes('<string name="push_wake">New activity</string>') && /nm\.cancel\(WAKE_TAG, WAKE_TAG\.hashCode\(\)\)/.test(u),
  'push: a wake with the page alive → the wake window (push app; Built in keeps the process itself) and {ev:"wake"}; else one notification "New activity" (no name, no count), cancelled when the app opens');
  ok(/static final String WAKE = "io\.sigelo\.app\.WAKE";/.test(sc) && /WAKE_MS = 60_000L;/.test(sc) && /if \(!on\(this\)\) stopSelf\(\);/.test(sc) && /later\.postDelayed\(windowOver, WAKE_MS\);/.test(sc)
    && /later\.removeCallbacks\(windowOver\);\s*AlarmManager am/.test(sc) && /c\.startForegroundService\(new Intent\(c, StayConnected\.class\)\.setAction\(WAKE\)\)/.test(sc),
  'push: the wake window is StayConnected started with WAKE, stopped after 60 s unless the switch is on');
  ok(/case "push":\s*try \{\s*post\(to, UnifiedPush\.op\(activity, m\)\.put\("id", id\)\);/.test(jbl) && /put\("ev", "wake"\)/.test(jbl) && /post\(port, state\.put\("ev", "push"\)\)/.test(jbl)
    && /UnifiedPush\.refresh\(this\);/.test(ma) && /UnifiedPush\.seen\(this\);/.test(ma)
    && /if \(m\.has\("mode"\) && !\(BUILTIN\.equals\(mo\) \|\| APP\.equals\(mo\) \|\| OFF\.equals\(mo\)\)\) throw new SigeloBridge\.Refused\("push",/.test(u),
  'push: the bridge answers "push" through UnifiedPush.op (a mode of three and a package name only, refused "push"), posts {ev:"wake"} and {ev:"push"}; started or registered again at each start');
  // Built in push (PushClient.java, Ntfy.java; design/push.md §6): the ntfy JSON stream held as the ntfy app holds it.
  const pcj = java['PushClient.java'], pcc = code(pcj), nt = java['Ntfy.java'];
  ok(![...nt.matchAll(/^import ([\w.]+);$/gm)].some((m) => !/^java\./.test(m[1])) && /BASE = "https:\/\/push\.sigelo\.ai"/.test(nt) && /Pattern\.compile\("\^up\[A-Za-z0-9\]\{12\}\$"\)/.test(nt)
    && /RETRY_S = \{5, 10, 15, 20, 30, 45, 60, 120\};/.test(nt) && /READ_MS = 90_000/.test(nt) && /return BASE \+ "\/" \+ topic \+ "\?up=1";/.test(nt) && existsSync(join(HERE, 'test', 'NtfyTest.java')),
    'push (built in): Ntfy in java.* only (test/NtfyTest.java runs it on a JVM); push.sigelo.ai; a topic "up" + 12 of [A-Za-z0-9] (ntfy\'s isUnifiedPushTopic); the ntfy app\'s retry table; endpoint ?up=1');
  ok(/startForeground\(NOTE, n, ServiceInfo\.FOREGROUND_SERVICE_TYPE_SPECIAL_USE\); else startForeground\(NOTE, n\);/.test(pcj) && /return START_STICKY;/.test(pcj)
    && /PendingIntent\.getForegroundService\(this, 0, new Intent\(this, PushClient\.class\)\.setAction\(RESTART\), PendingIntent\.FLAG_IMMUTABLE/.test(pcj) && /am\.set\(AlarmManager\.ELAPSED_REALTIME, SystemClock\.elapsedRealtime\(\) \+ 1000, again\)/.test(pcj)
    && /cm\.registerDefaultNetworkCallback\(net\)/.test(pcj) && /cm\.unregisterNetworkCallback\(net\)/.test(pcj) && !/setExact|setAlarmClock|SCHEDULE_EXACT_ALARM|WifiLock/.test(pcc)
    && /\.acquire\(WAKE_LOCK_MS\)/.test(pcj) && !/\.acquire\(\)/.test(pcc) && /WAKE_LOCK_MS = 30_000L;/.test(pcj),
    'push (built in): specialUse foreground (Android 14+), sticky, a 1 s restart alarm at a swipe-away (immutable, inexact), the default network watched; a wake lock only for 30 s at a wake; no exact alarm');
  ok(/new URL\(Ntfy\.stream\(topic, prefs\(this\)\.getString\(SINCE, null\)\)\)\.openConnection\(\)/.test(pcj) && /\(HttpsURLConnection\)/.test(pcj) && /c\.setInstanceFollowRedirects\(false\);/.test(pcj)
    && /c\.setReadTimeout\(Ntfy\.READ_MS\);/.test(pcj) && /if \(body != null && UnifiedPush\.isWake\(this, body\)\) woken\(\);/.test(pcj) && /if \("open"\.equals\(e\.event\)\) \{\s*opened = true;\s*ready\(\);/.test(pcj)
    && /main\.post\(\(\) -> UnifiedPush\.wake\(this\)\);/.test(pcj),
    'push (built in): https only, no redirect, a 90 s read timeout; ready (the endpoint given) at the stream\'s open; a wake only when a message opens to WAKE under our keys, then as a push app\'s');
  ok(/NotificationManager\.IMPORTANCE_LOW\)/.test(pcj) && /\.setContentTitle\(getString\(R\.string\.push_title\)\)/.test(pcj) && !/setContentText|addAction|setStyle/.test(pcc)
    && strings.includes('<string name="push_title">Sigelo · ready for messages</string>') && /\.setOngoing\(true\)/.test(pcj),
    'push (built in): one notification "Sigelo · ready for messages", low importance, no text, no action');
  ok(/if \(!Intent\.ACTION_BOOT_COMPLETED\.equals\(a\) && !Intent\.ACTION_MY_PACKAGE_REPLACED\.equals\(a\)\) return;\s*if \(UnifiedPush\.BUILTIN\.equals\(UnifiedPush\.mode\(c\)\)\) start\(c\);/.test(pcj)
    && /m = p\.getBoolean\(ON, false\) \? APP : p\.getBoolean\(StayConnected\.ON, true\) \? BUILTIN : OFF;/.test(u),
    'push (built in): started at boot and after an update only when the mode is Built in; the mode from before: Push → Push app, Stay connected (the old default) → Built in, else Off');
  // Voice calls (CallService.java; design/calls.md §4, §5): the call's foreground service of type microphone, its ongoing-call
  // notification, the audio mode and focus, the earpiece and the speaker, the proximity lock, the ring; nothing when closed (B1).
  const cs = java['CallService.java'], csc = code(cs);
  ok(/if \(Build\.VERSION\.SDK_INT >= 30\) startForeground\(NOTE_CALL, n, ServiceInfo\.FOREGROUND_SERVICE_TYPE_MICROPHONE\);\s*else startForeground\(NOTE_CALL, n\);/.test(cs) && /return START_NOT_STICKY;/.test(cs)
    && /if \(c\.checkSelfPermission\(Manifest\.permission\.RECORD_AUDIO\) != PackageManager\.PERMISSION_GRANTED\) throw new SigeloBridge\.Refused\("mic_permission",/.test(cs)
    && /app\.startForegroundService\(new Intent\(app, CallService\.class\)/.test(cs) && !/BOOT_COMPLETED|Socket|setExact/.test(csc),
    'call: a foreground service of type microphone (Android 11+), started only once RECORD_AUDIO is granted, not sticky; no socket, no boot start');
  ok(/b\.setStyle\(Notification\.CallStyle\.forOngoingCall\(new Person\.Builder\(\)\.setName\(who\)\.build\(\), hangUp\)\)/.test(cs) && /else b\.addAction\(new Notification\.Action\.Builder\(null, getString\(R\.string\.call_hangup\), hangUp\)\.build\(\)\);/.test(cs)
    && /PendingIntent\.getService\(this, NOTE_CALL, new Intent\(this, CallService\.class\)\.setAction\(ACTION_HANGUP\), PendingIntent\.FLAG_IMMUTABLE/.test(cs)
    && /\.setUsesChronometer\(true\)/.test(cs) && /\.setOngoing\(true\)/.test(cs) && /\.setVisibility\(Notification\.VISIBILITY_PRIVATE\)/.test(cs),
    'call: the ongoing-call notification (CallStyle on Android 12+: the name, a timer, Hang up; an action before), private on the lock screen; Hang up an immutable explicit intent to this service');
  ok(/am\.setMode\(AudioManager\.MODE_IN_COMMUNICATION\);/.test(cs) && /setUsage\(AudioAttributes\.USAGE_VOICE_COMMUNICATION\)/.test(cs) && /am\.requestAudioFocus\(focus\);/.test(cs)
    && /am\.abandonAudioFocusRequest\(focus\);/.test(cs) && /am\.setMode\(modeBefore\);/.test(cs) && /on = true;\s*route\(app, false\);/.test(cs),
    'call: audio mode IN_COMMUNICATION and voice-communication focus while it lasts, both given back at the end; the earpiece by default');
  ok(/TYPE_BUILTIN_SPEAKER : AudioDeviceInfo\.TYPE_BUILTIN_EARPIECE/.test(cs) && /am\.setCommunicationDevice\(d\)/.test(cs) && /am\.setSpeakerphoneOn\(loud\);/.test(cs) && /am\.clearCommunicationDevice\(\);/.test(cs)
    && /newWakeLock\(PowerManager\.PROXIMITY_SCREEN_OFF_WAKE_LOCK, "sigelo:call"\)/.test(cs) && /proximity\.release\(PowerManager\.RELEASE_FLAG_WAIT_FOR_NO_PROXIMITY\)/.test(cs) && /hold\(app, !loud\);/.test(cs)
    && !/PARTIAL_WAKE_LOCK|FULL_WAKE_LOCK|SCREEN_BRIGHT_WAKE_LOCK/.test(csc),
    'call: the speaker toggle (setCommunicationDevice on Android 12+, setSpeakerphoneOn before); the proximity lock at the ear only (let go on the speaker and at the end); no other wake lock');
  ok(/if \(mode == AudioManager\.RINGER_MODE_NORMAL\) \{/.test(cs) && /if \(mode != AudioManager\.RINGER_MODE_SILENT && app\.checkSelfPermission\(Manifest\.permission\.VIBRATE\)/.test(cs) && /r\.setLooping\(true\);/.test(cs)
    && /setUsage\(AudioAttributes\.USAGE_NOTIFICATION_RINGTONE\)/.test(cs) && /NotificationManager\.IMPORTANCE_HIGH\)/.test(cs) && /ch\.setSound\(null, null\);/.test(cs) && /\.setCategory\(Notification\.CATEGORY_CALL\)/.test(cs)
    && /\.setPublicVersion\(shown\)/.test(cs) && !/setFullScreenIntent|USE_FULL_SCREEN_INTENT/.test(csc) && /ring\(app, false, null\);\s*app\.startForegroundService/.test(cs),
    'call-ring: the ringtone in normal mode only, the vibration unless silent, a heads-up (high, category call; the lock screen without the name); no full-screen intent (the app closed rings nothing: B1); stopped once the call starts');
  ok(/case "call":\s*case "call-speaker":\s*case "call-ring":\s*callOp\(to, id, m, op\);/.test(jbl) && /if \(!\(v instanceof Boolean\)\) \{\s*fail\(to, id, "call", "on: true or false"\);/.test(jbl)
    && /put\("ev", "hangup"\)/.test(jbl) && /CallService\.ring\(activity, false, null\);\s*CallService\.call\(activity, false, null\);/.test(jbl)
    && /SigeloBridge b = StayConnected\.page;\s*if \(b != null\) b\.hangup\(\);/.test(cs) && /'call', 'call-speaker', 'call-ring'/.test(read(REPO, 'apps', 'web', 'platform-android.mjs')),
    'call: the bridge answers call, call-speaker, call-ring (booleans only, refused "call"), posts {ev:"hangup"} from the notification\'s Hang up, and turns both off when the page goes');
  ok(/MAIN\.removeCallbacks\(RING_OVER\);/.test(cs) && /MAIN\.postDelayed\(RING_OVER, RING_MAX_MS\);/.test(cs) && /RING_MAX_MS = 75_000L/.test(cs)
    && /if \(port != null\) \{\s*try \{\s*CallService\.ring\(activity, false, null\);\s*CallService\.call\(activity, false, null\);/.test(jbl),
    'call-ring: stops by itself after 75 s (a ring lives 60 s); a reload of the page stops its ring and its call\'s audio');
  ok(['call_channel', 'call_ring_channel', 'call_incoming', 'call_ongoing', 'call_hangup'].every((k) => strings.includes(`<string name="${k}">`)) && /\.onEvent\(\(\) => \{ try \{ void router\?\.page\?\.line\?\.hangup\?\.\(\)/.test(read(REPO, 'apps', 'web', 'boot.mjs')),
    'call: its strings; the page ends the live call at {ev:"hangup"} (boot.mjs → the Line)');
  ok(/cm\.registerDefaultNetworkCallback\(watch\);/.test(cs) && /cm\.unregisterNetworkCallback\(watch\);/.test(cs) && /boolean changed = lastNet != null && !lastNet\.equals\(n\);/.test(cs)
    && /roam\(app, true\);/.test(cs) && /roam\(app, false\);/.test(cs) && /put\("ev", "network"\)/.test(jbl) && /onNetwork\(fn\)/.test(read(REPO, 'apps', 'web', 'boot.mjs')) && /LOCAL\?\.onNetwork\?\.\(\(\) => \{ CALL\.phone\?\.networkChanged\(\); \}\);/.test(read(REPO, 'apps', 'agent', 'ui.js')),
    'call: the default network watched only while a call lasts; a change (not the first network) → {ev:"network"} → the page\'s Phone restarts ICE at once');
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
  ok(/path\.startsWith\("\/\.big\/"\) && bridge != null\) return bridge\.big\.range\(u, HEADERS\);/.test(ma) && ma.indexOf('bridge.big.range') < ma.indexOf('SAFE_PATH.matcher(path)')
    && /if \(!String\.valueOf\(st\[0\]\)\.equals\(u\.getQueryParameter\("size"\)\) \|\| !String\.valueOf\(st\[1\]\)\.equals\(u\.getQueryParameter\("mtime"\)\)\) return empty\(409/.test(bf)
    && /to - from \+ 1 > CHUNK\) return empty\(416/.test(bf) && /u\.getQueryParameter\(\"from\"\)/.test(bf) && !/\"range\"\.equalsIgnoreCase/.test(bf) && /docOf\(profile == null \? "p1" : profileChecked\(profile\), doc\)/.test(bf),
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
  ok(/new Intent\(MediaStore\.ACTION_IMAGE_CAPTURE\)\.resolveActivity\(activity\.getPackageManager\(\)\) != null/.test(bf) && /if \(!cameraApp\(\)\) throw new SigeloBridge\.Refused\("no_camera", /.test(bf)
    && bf.indexOf('if (!cameraApp())') < bf.indexOf('requestPermissions(new String[] {Manifest.permission.CAMERA}, REQ_CAMERA_PHOTO)') && /r\.no\("no_camera", /.test(bf) && !/no_camera_app/.test(bf),
    'big files: no app answers the camera intent → refused no_camera before CAMERA is asked (and if the start still finds none)');
  ok(/setType\(m\.optBoolean\("images", false\) \? "image\/\*" : "\*\/\*"\)/.test(bf), 'big files: the picker for pictures only when the page asks images (the composer\'s Photo), any file otherwise');
  ok(/putExtra\(Intent\.EXTRA_ALLOW_MULTIPLE, pendingPickMultiple\)/.test(bf) && /getClipData\(\)/.test(bf) && /put\("docs", a\)\.put\("picked", picked\)/.test(bf) && /PICK_MAX = 16/.test(bf),
    'big files: several picked at once when the page asks multiple (EXTRA_ALLOW_MULTIPLE, the ClipData\'s items in order, at most 16) → {docs, picked}');
  ok(/MediaStore\.Downloads\.EXTERNAL_CONTENT_URI/.test(bf) && /RELATIVE_PATH, Environment\.DIRECTORY_DOWNLOADS/.test(bf) && /IS_PENDING, 1/.test(bf),
    'big files: a file landed or saved (Save to Downloads) goes into Downloads through MediaStore, pending until whole (no storage permission from Android 10)');
  ok(/Pattern\.compile\("\^\[0-9a-f\]\{32\}\\\\\.jpg\$"\)/.test(pp) && /getPathSegments\(\)\.size\(\) != 1/.test(pp) && /getCacheDir\(\), "photos"\)/.test(pp) && (pp.match(/throw new UnsupportedOperationException/g) ?? []).length === 3,
    'PhotoProvider: one name shape (32 hex .jpg) in cache/photos, nothing else; no insert, delete or update');
  ok(/requestPermissions\(new String\[\] \{Manifest\.permission\.RECORD_AUDIO\}, REQ_MIC\)/.test(bf) && /shouldShowRequestPermissionRationale\(Manifest\.permission\.RECORD_AUDIO\)/.test(bf) && /r\.no\("mic_blocked", MIC_BLOCKED\)/.test(bf)
    && /r\.no\("mic_permission", MIC_OFF\)/.test(bf) && /ACTION_APPLICATION_DETAILS_SETTINGS, Uri\.fromParts\("package", activity\.getPackageName\(\), null\)/.test(bf)
    && /if \(!s\.startsWith\("content:\/\/media\/"\)\) throw new SigeloBridge\.Refused\("big", "uri: a file that landed in Downloads"\);/.test(bf),
    'voice: RECORD_AUDIO asked at a tap (mic), asked again after a refusal while Android shows its dialog, then mic_blocked; app-settings opens the app\'s settings page; big-url takes landed files only');
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
