// SPDX-License-Identifier: MIT
package io.sigelo.app;

import android.Manifest;
import android.app.Activity;
import android.app.KeyguardManager;
import android.app.NotificationManager;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.webkit.PermissionRequest;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * sigelo for Android (design/apps.md §8): one WebView showing the page of apps/web, served from the
 * APK's assets at https://appassets.androidplatform.net/ (the host Android reserves for this; nothing
 * is fetched from the network), and SigeloBridge for what a page cannot do: the relay's HTTPS and
 * TLS without an Origin header, a computer on the LAN, and a key in AndroidKeyStore.
 *
 * Rules: JavaScript on; file access off; mixed content never; no other origin is ever loaded (a
 * link elsewhere opens in the browser, on a tap); the camera is granted to this origin only, for
 * video only, after Android's CAMERA permission is asked at the first scan; the image picker for a
 * file input. Profiles (several identities, each its own storage and keystore aliases) are the page's
 * (apps/web/profiles.mjs): removing one erases its keys (SigeloBridge forget-profile). The menu: Reload.
 *
 * The app lock: once a form is set and the phone has a screen lock, the screen lock is asked at a
 * start and at a return after the set minutes away (SigeloBridge "lock": 1, 5, 15 or 60; off: neither),
 * and by the page before a screen that shows or spends the identity (SigeloBridge "unlock": the 25
 * words, a profile switch, a payment above the limit; asked whether the lock is on or off; within
 * CONFIRMED_MS of the last confirmation not again, unless forced). The page is hidden until it is
 * confirmed; not confirmed, the app goes to the background, locked. The FULL key's own window in
 * AndroidKeyStore (SigeloBridge.AUTH_SECONDS) stays the inner guard.
 *
 * Big files (SigeloBridge "big-*", BigFiles, design/transfer.md §10): the system's picker and camera answer
 * here (onActivityResult, the camera's and the storage permission's results); a file the page reads is
 * served by range at ORIGIN/.big/<doc> (serve), never from anywhere else; the screen kept on while a
 * transfer moves.
 *
 * Notifications (SigeloBridge "notify"): a tap opens this activity with action io.sigelo.app.OPEN and
 * the tag; the tag goes to the page as {ev:"open", tag} (onNewIntent; a start by the tap: once the
 * page's port is open). POST_NOTIFICATIONS is asked when the page asks (Android 13+).
 */
public final class MainActivity extends Activity {
    static final String HOST = "appassets.androidplatform.net";
    static final String ORIGIN = "https://" + HOST;
    static final String START = ORIGIN + "/index.html";

    private static final int REQ_FILE = 1, REQ_CAMERA = 2, REQ_AUTH = 3, REQ_NOTIFY = 4;
    private static final int M_RELOAD = 1;
    /** The page's asks (SigeloBridge "unlock"): not asked again within this long of the last confirmation (elapsed time, ms). */
    static final long CONFIRMED_MS = 60_000;
    private static final String POST_NOTIFICATIONS = "android.permission.POST_NOTIFICATIONS";   // Manifest.permission's, API 33
    /** The page's files by name: letters, digits and . _ @ - / only (vendor/@noble/...). */
    private static final Pattern SAFE_PATH = Pattern.compile("^/[A-Za-z0-9._@/-]{1,200}$");
    private static final Map<String, String> TYPES = new HashMap<>();
    static {
        TYPES.put("html", "text/html");
        TYPES.put("mjs", "text/javascript");
        TYPES.put("js", "text/javascript");
        TYPES.put("css", "text/css");
        TYPES.put("svg", "image/svg+xml");
        TYPES.put("json", "application/json");
        TYPES.put("png", "image/png");
    }
    /** Beside the page's own CSP (index.html): no connection anywhere but this origin (the bridge carries the network). */
    private static final Map<String, String> HEADERS;
    static {
        Map<String, String> h = new HashMap<>();
        h.put("Content-Security-Policy", "connect-src 'self'; object-src 'none'; frame-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'");
        h.put("Cache-Control", "no-store");
        h.put("X-Content-Type-Options", "nosniff");
        h.put("Referrer-Policy", "no-referrer");
        HEADERS = Collections.unmodifiableMap(h);
    }

    private WebView web;
    private SigeloBridge bridge;
    private ValueCallback<Uri[]> pendingFiles;
    private PermissionRequest pendingCamera;
    private Runnable afterAuth, authCancelled;
    private final List<Consumer<Boolean>> pendingNotify = new ArrayList<>();
    /** elapsedRealtime: when the app left the screen (-1: it has not), when the screen lock was last confirmed (-1: never). */
    private long awayAt = -1, unlockedAt = -1;
    /** The page hidden until the screen lock is confirmed. */
    private boolean locked = true;

    static boolean ours(Uri u) {
        return u != null && "https".equals(u.getScheme()) && HOST.equals(u.getHost()) && u.getPort() == -1;
    }

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        WebView.setWebContentsDebuggingEnabled((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);
        web = new WebView(this);
        setContentView(web);
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        s.setGeolocationEnabled(false);
        s.setSupportMultipleWindows(false);
        s.setJavaScriptCanOpenWindowsAutomatically(false);
        s.setMediaPlaybackRequiresUserGesture(false);   // the camera preview of a scan
        bridge = new SigeloBridge(this, web);
        web.addJavascriptInterface(bridge.shell(), "SigeloShell");
        web.setWebViewClient(new Client());
        web.setWebChromeClient(new Chrome());
        web.loadUrl(START);
        // Started by a tap on one of our notifications (not a restart that brings back the same intent).
        if (saved == null) opened(getIntent());
    }

    @Override
    protected void onNewIntent(Intent i) {
        super.onNewIntent(i);
        setIntent(i);
        opened(i);
    }

    /** A notification's tap: its tag (checked: this activity is the launcher's, any app can start it) to the page, once. */
    private void opened(Intent i) {
        if (i == null || !SigeloBridge.OPEN.equals(i.getAction()) || bridge == null) return;
        String tag = i.getStringExtra(SigeloBridge.EXTRA_OPEN);
        i.removeExtra(SigeloBridge.EXTRA_OPEN);
        bridge.opened(tag);
    }

    /** Set by the bridge (secure, door) while a new identity's words are on screen: Back does nothing then. Else Back is the page's. */
    volatile boolean door;

    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        if (door) return;
        // The page keeps one history entry per screen (welcome.mjs, ui.js): Back goes one screen back,
        // and leaves the app only from the first one.
        if (web != null && web.canGoBack()) {
            web.goBack();
            return;
        }
        super.onBackPressed();
    }

    @Override
    protected void onStart() {
        super.onStart();
        if (awayAt >= 0 && bridge != null && SystemClock.elapsedRealtime() - awayAt >= bridge.lockAfter() * 60_000L) locked = true;
        awayAt = -1;
        // Our own prompt in front (afterAuth set) hid this activity: its answer comes in onActivityResult.
        if (locked && afterAuth == null) lockNow();
    }

    @Override
    protected void onStop() {
        if (afterAuth == null) awayAt = SystemClock.elapsedRealtime();
        super.onStop();
    }

    /** The page hidden and the screen lock asked. Nothing to ask (the lock off, no form yet, no screen lock on this phone): open. */
    private void lockNow() {
        KeyguardManager km = getSystemService(KeyguardManager.class);
        if (bridge == null || !bridge.lockOn() || bridge.mode() == null || km == null || !km.isDeviceSecure()) {
            showPage();
            return;
        }
        locked = true;
        if (web != null) web.setVisibility(View.INVISIBLE);
        // Not confirmed: to the background, still locked; asked again when it comes back (onStart).
        confirmCredential(this::showPage, () -> moveTaskToBack(true));
    }

    private void showPage() {
        locked = false;
        if (web != null) web.setVisibility(View.VISIBLE);
    }

    /**
     * The page's ask (SigeloBridge "unlock"), on this thread: ok at once when confirmed within CONFIRMED_MS (not when
     * forced: a payment above the pay limit) or no screen lock is set. Asked whether the app lock is on or off.
     */
    void unlock(Runnable ok, Runnable no, boolean force) {
        KeyguardManager km = getSystemService(KeyguardManager.class);
        boolean recent = !force && unlockedAt >= 0 && SystemClock.elapsedRealtime() - unlockedAt < CONFIRMED_MS;
        if (recent || km == null || !km.isDeviceSecure()) ok.run();
        else confirmCredential(ok, no);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (web != null) web.onResume();
    }

    @Override
    protected void onPause() {
        if (web != null) web.onPause();   // animations only: the page's JavaScript (the carrier) runs on
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        if (bridge != null) bridge.close();
        if (web != null) web.destroy();
        web = null;
        super.onDestroy();
    }

    // ---------------------------------------------------------------- the page's files

    /** A request of the page: a file of assets/web/ when it is ours, else an empty refusal (nothing reaches the network). */
    WebResourceResponse serve(WebResourceRequest r) {
        Uri u = r.getUrl();
        if (!ours(u)) return refuse(404, "Not Found");
        if (!"GET".equals(r.getMethod())) return refuse(405, "Method Not Allowed");
        String path = u.getPath();
        // A file the page sends, by range (BigFiles: the doc a pick or a photo gave; 409 once it changed).
        if (path != null && path.startsWith("/.big/") && bridge != null) return bridge.big.range(u, r.getRequestHeaders(), HEADERS);
        if (path == null || path.equals("/")) path = "/index.html";
        if (!SAFE_PATH.matcher(path).matches() || path.contains("..") || path.contains("//")) return refuse(404, "Not Found");
        int dot = path.lastIndexOf('.');
        String type = dot < 0 ? null : TYPES.get(path.substring(dot + 1).toLowerCase(Locale.ROOT));
        if (type == null) return refuse(404, "Not Found");
        InputStream in;
        try {
            in = getAssets().open("web" + path);
        } catch (IOException e) {
            return refuse(404, "Not Found");
        }
        String charset = type.startsWith("text/") || type.endsWith("json") || type.endsWith("xml") ? "utf-8" : null;
        return new WebResourceResponse(type, charset, 200, "OK", HEADERS, in);
    }

    private static WebResourceResponse refuse(int status, String reason) {
        return new WebResourceResponse("text/plain", "utf-8", status, reason, HEADERS, new ByteArrayInputStream(new byte[0]));
    }

    private final class Client extends WebViewClient {
        @Override
        public WebResourceResponse shouldInterceptRequest(WebView v, WebResourceRequest r) {
            return serve(r);
        }

        @Override
        public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest r) {
            Uri u = r.getUrl();
            if (ours(u)) return false;
            String scheme = u.getScheme();
            // A link elsewhere: to the browser, when the user tapped it; never in this WebView.
            if (r.isForMainFrame() && r.hasGesture() && ("https".equals(scheme) || "http".equals(scheme))) {
                try {
                    startActivity(new Intent(Intent.ACTION_VIEW, u).addCategory(Intent.CATEGORY_BROWSABLE));
                } catch (ActivityNotFoundException e) {
                    // no browser: nothing opens
                }
            }
            return true;
        }

        @Override
        public boolean onRenderProcessGone(WebView v, RenderProcessGoneDetail d) {
            // The page's process ended (killed for memory, or crashed): a new WebView, not a crash of the app.
            if (v == web) {
                bridge.close();
                web = null;
                v.destroy();
                recreate();
            }
            return true;
        }
    }

    // ---------------------------------------------------------------- camera, files, the screen lock

    private final class Chrome extends WebChromeClient {
        @Override
        public void onPermissionRequest(PermissionRequest req) {
            String[] res = req.getResources();
            boolean video = res.length == 1 && PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(res[0]);
            if (!video || !ours(req.getOrigin())) {
                req.deny();
                return;
            }
            if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                req.grant(res);
                return;
            }
            if (pendingCamera != null) pendingCamera.deny();
            pendingCamera = req;
            requestPermissions(new String[] {Manifest.permission.CAMERA}, REQ_CAMERA);
        }

        @Override
        public void onPermissionRequestCanceled(PermissionRequest req) {
            if (pendingCamera == req) pendingCamera = null;
        }

        @Override
        public boolean onShowFileChooser(WebView v, ValueCallback<Uri[]> cb, FileChooserParams p) {
            if (pendingFiles != null) pendingFiles.onReceiveValue(null);
            pendingFiles = cb;
            Intent i = new Intent(Intent.ACTION_GET_CONTENT).addCategory(Intent.CATEGORY_OPENABLE);
            String[] types = mimeTypes(p.getAcceptTypes());
            if (types.length == 1) {
                i.setType(types[0]);
            } else {
                i.setType("*/*");
                if (types.length > 1) i.putExtra(Intent.EXTRA_MIME_TYPES, types);
            }
            try {
                startActivityForResult(i, REQ_FILE);
            } catch (ActivityNotFoundException e) {
                pendingFiles = null;
                cb.onReceiveValue(null);
            }
            return true;
        }
    }

    /**
     * The picker's types from a file input's accept list: MIME types as they are; an extension
     * (".json") means any type, since what a document provider calls a .json file varies.
     */
    static String[] mimeTypes(String[] accept) {
        List<String> out = new ArrayList<>();
        if (accept != null) {
            for (String a : accept) {
                if (a == null) continue;
                for (String t : a.split(",")) {
                    t = t.trim().toLowerCase(Locale.ROOT);
                    if (t.isEmpty()) continue;
                    if (t.startsWith(".")) return new String[0];
                    if (t.contains("/") && !out.contains(t)) out.add(t);
                }
            }
        }
        return out.toArray(new String[0]);
    }

    /** Notifications may be shown: POST_NOTIFICATIONS granted (Android 13+) and not turned off in the system's settings. */
    boolean notificationsAllowed() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        boolean granted = Build.VERSION.SDK_INT < 33 || checkSelfPermission(POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED;
        return granted && nm != null && nm.areNotificationsEnabled();
    }

    /** The page's ask for notifications: POST_NOTIFICATIONS requested when not granted (Android 13+); answer(allowed), on this thread. */
    void askNotifications(Consumer<Boolean> answer) {
        if (Build.VERSION.SDK_INT < 33 || checkSelfPermission(POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
            answer.accept(notificationsAllowed());
            return;
        }
        pendingNotify.add(answer);
        // One request up at a time: a second ask waits for its answer.
        if (pendingNotify.size() == 1) requestPermissions(new String[] {POST_NOTIFICATIONS}, REQ_NOTIFY);
    }

    @Override
    public void onRequestPermissionsResult(int req, String[] perms, int[] grants) {
        if (bridge != null && bridge.big.permission(req, grants)) return;
        if (req == REQ_NOTIFY) {
            List<Consumer<Boolean>> waiting = new ArrayList<>(pendingNotify);
            pendingNotify.clear();
            boolean granted = grants.length == 1 && grants[0] == PackageManager.PERMISSION_GRANTED && notificationsAllowed();
            for (Consumer<Boolean> a : waiting) a.accept(granted);
            return;
        }
        if (req != REQ_CAMERA) {
            super.onRequestPermissionsResult(req, perms, grants);
            return;
        }
        PermissionRequest p = pendingCamera;
        pendingCamera = null;
        if (p == null) return;
        if (grants.length == 1 && grants[0] == PackageManager.PERMISSION_GRANTED) p.grant(new String[] {PermissionRequest.RESOURCE_VIDEO_CAPTURE});
        else p.deny();
    }

    /** The screen lock, for the FULL identity's key (valid 5 minutes after): ok or no runs on this thread. */
    @SuppressWarnings("deprecation")   // createConfirmDeviceCredentialIntent: the one prompt API 28 to 35 share without AndroidX
    void confirmCredential(Runnable ok, Runnable no) {
        KeyguardManager km = getSystemService(KeyguardManager.class);
        Intent i = km == null ? null : km.createConfirmDeviceCredentialIntent(getString(R.string.app_name), getString(R.string.unlock_identity));
        if (i == null) {
            no.run();
            return;
        }
        // A prompt up already (the lock's, say, while the page asks for a key): its one answer serves both.
        if (afterAuth != null) {
            Runnable ok0 = afterAuth, no0 = authCancelled;
            afterAuth = () -> {
                ok0.run();
                ok.run();
            };
            authCancelled = () -> {
                no0.run();
                no.run();
            };
            return;
        }
        afterAuth = ok;
        authCancelled = no;
        try {
            startActivityForResult(i, REQ_AUTH);
        } catch (ActivityNotFoundException e) {
            afterAuth = authCancelled = null;
            no.run();
        }
    }

    @Override
    protected void onActivityResult(int req, int result, Intent data) {
        if (req == REQ_FILE) {
            ValueCallback<Uri[]> cb = pendingFiles;
            pendingFiles = null;
            if (cb != null) cb.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(result, data));
            return;
        }
        if (bridge != null && bridge.bigResult(req, result, data)) return;
        if (req == REQ_AUTH) {
            Runnable ok = afterAuth, no = authCancelled;
            afterAuth = authCancelled = null;
            if (result == RESULT_OK) unlockedAt = SystemClock.elapsedRealtime();
            if (result == RESULT_OK && ok != null) ok.run();
            else if (no != null) no.run();
            return;
        }
        super.onActivityResult(req, result, data);
    }

    // ---------------------------------------------------------------- the menu

    @Override
    public boolean onCreateOptionsMenu(Menu m) {
        m.add(Menu.NONE, M_RELOAD, 1, R.string.reload);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == M_RELOAD) {
            if (web != null) web.loadUrl(START);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    void modeChanged() {
        // The first run's screens are behind it now: Back must not walk into them after the reload.
        if (web != null) web.clearHistory();
    }
}
