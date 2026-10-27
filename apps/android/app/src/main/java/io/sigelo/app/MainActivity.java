// SPDX-License-Identifier: MIT
package io.sigelo.app;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
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
 * file input. The menu switches between the two forms (this phone's identity, a computer's page):
 * after a confirmation the other form's storage and keys are erased.
 */
public final class MainActivity extends Activity {
    static final String HOST = "appassets.androidplatform.net";
    static final String ORIGIN = "https://" + HOST;
    static final String START = ORIGIN + "/index.html";

    private static final int REQ_FILE = 1, REQ_CAMERA = 2, REQ_AUTH = 3;
    private static final int M_RELOAD = 1, M_SWITCH = 2, M_FORGET = 3;
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
    }

    /** Set by the bridge (secure, door) while a new identity's words are on screen: Back does nothing then. */
    volatile boolean door;

    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        if (door) return;
        super.onBackPressed();
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

    @Override
    public void onRequestPermissionsResult(int req, String[] perms, int[] grants) {
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
        if (authCancelled != null) authCancelled.run();
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
        if (req == REQ_AUTH) {
            Runnable ok = afterAuth, no = authCancelled;
            afterAuth = authCancelled = null;
            if (result == RESULT_OK && ok != null) ok.run();
            else if (no != null) no.run();
            return;
        }
        super.onActivityResult(req, result, data);
    }

    // ---------------------------------------------------------------- the menu: the two forms

    @Override
    public boolean onCreateOptionsMenu(Menu m) {
        return onPrepareOptionsMenu(m);
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu m) {
        m.clear();
        String mode = bridge.mode();
        if ("self".equals(mode)) m.add(Menu.NONE, M_SWITCH, 1, R.string.switch_to_remote);
        if ("remote".equals(mode)) {
            m.add(Menu.NONE, M_FORGET, 1, R.string.forget_computer);
            m.add(Menu.NONE, M_SWITCH, 2, R.string.switch_to_self);
        }
        m.add(Menu.NONE, M_RELOAD, 3, R.string.reload);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        String mode = bridge.mode();
        switch (item.getItemId()) {
            case M_RELOAD:
                if (web != null) web.loadUrl(START);
                return true;
            case M_SWITCH:
                confirmErase("self".equals(mode) ? R.string.switch_from_self : R.string.switch_from_remote, R.string.erase_and_switch,
                        "self".equals(mode) ? "remote" : "self");
                return true;
            case M_FORGET:
                confirmErase(R.string.switch_from_remote, R.string.forget, "remote");
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    /** Asks; on yes, the current form's keys and the page's storage are erased and the page starts in `to`. */
    private void confirmErase(int message, int yes, String to) {
        new AlertDialog.Builder(this)
                .setTitle(R.string.switch_title)
                .setMessage(message)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(yes, (d, w) -> {
                    bridge.switchTo(to);
                    invalidateOptionsMenu();
                    if (web != null) {
                        web.clearCache(true);
                        web.loadUrl(START);
                    }
                })
                .show();
    }

    void modeChanged() {
        invalidateOptionsMenu();
    }
}
