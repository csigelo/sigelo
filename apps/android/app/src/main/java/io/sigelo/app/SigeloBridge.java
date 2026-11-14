// SPDX-License-Identifier: MIT
package io.sigelo.app;

import android.app.KeyguardManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Base64;
import android.view.WindowManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebMessage;
import android.webkit.WebMessagePort;
import android.webkit.WebView;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * What the page asks of the phone (design/apps.md §4.3, §5), protocol sigelo-bridge/0, the page's
 * side in apps/web/platform-android.mjs (its header lists the messages; test-shell.mjs runs the same
 * protocol in Node). The page sees one object, SigeloShell: info() and connect(); connect() posts a
 * WebMessagePort to this origin only, and every request goes over it as JSON text, bytes as base64.
 *
 *   https  an HTTP request: https:// to any host, http:// only to a private IPv4 address (a computer's
 *          `ui --remote` on the LAN, sealed in the page). No proxy, no redirect followed, no cookie,
 *          no Origin; the body read up to 1 MiB.
 *   tls    a TLS stream to host:port (the relay's MQTT on 8883, its WebSocket on 443): the system's
 *          certificate authorities, the host name checked; then data both ways until either closes.
 *   seal / open   AES-256-GCM under a key made in AndroidKeyStore that never leaves it: the identity
 *          (SAFE; FULL under a key that needs the screen lock, valid 5 minutes), the keeper root of a
 *          restore from seed (under the FULL key, its own AAD), the kept words (kind "words": the 25 words
 *          already encrypted under the words password, apps/web/words.mjs; the FULL key, its own AAD) or a
 *          computer's text. Per profile
 *          (apps/web/profiles.mjs, design/profiles.md §4): p1 under the three aliases of before, blob
 *          version 1 as before (nothing resealed at the upgrade); another profile under its own three
 *          aliases, blob version 2 naming it, the AAD naming kind and profile: no blob opens elsewhere.
 *          Several computers in a profile (design/profiles.md P2): one blob each under the profile's aliases,
 *          the first as above, another version 2 naming profile and computer, its AAD too.
 *   forget-profile  a profile's three aliases deleted (its removal: whatever copy of its blobs is left
 *          never opens again).
 *   mode / wiped  the active profile's form, set once its first run commits (it turns the app lock on);
 *          wiped: the page cleared its storage after a switch of an older version (wipe).
 *   secure        FLAG_SECURE on the window while a seed screen is up (no screenshot, no recents
 *          thumbnail, no screen recording of the 25 words); off again after. door: while on, the system
 *          Back does nothing (a new identity's words: the review screen's one button is the only way on).
 *   clip-clear    the system clipboard emptied (the page asks after the words were pasted).
 *   share         the system's share sheet (ACTION_SEND, text/plain) with a message the page wrote: a code and how to use it.
 *   bars          the status and navigation bars (and the window behind the page) in the page's background,
 *          #rrggbb: dark icons on a light colour, light ones on a dark colour (MainActivity.bars; no action bar).
 *   reload        the page loaded again from its start (MainActivity.reload): Settings → About's "Reload the app".
 *   clip-copy     text on the clipboard marked sensitive (no preview; stagenet words only), emptied
 *          after `clear` seconds (1 to 300) unless something else was copied since.
 *   unlock        the screen lock, before a screen that shows or spends the identity (MainActivity.unlock:
 *          not again within a minute of the last confirmation unless force, a payment above the pay limit;
 *          none set on the phone: ok).
 *   lock          the app lock's settings, kept here (SharedPreferences "lock_on", default true; "lock_after",
 *          minutes, 1, 5, 15 or 60, default 1): MainActivity asks the screen lock at a start and at a return
 *          after that long away, or not at all when off. A weaker setting asks the screen lock first. The
 *          answer names them and secure (the phone has a screen lock).
 *   notify        a system notification on one channel ("messages"): the title and text the page gives (a name
 *          and a generic line, never a message's text), the lock screen's public version only "sigelo" and
 *          "New message"; the tag (chat:, group: or pay:, TAG) is its notification tag and id, and comes back
 *          when it is tapped. cancel: removed. ask: POST_NOTIFICATIONS asked (Android 13+) → granted.
 *          Not allowed: refused "notify_permission".
 *   big-pick, big-photo, big-hash, big-stat, big-write, big-flush, big-digest, big-drop, big-free, big-land, big-open,
 *   big-awake   big files (BigFiles: the system's picker and camera, ranges read from the file itself, partials
 *          written at offsets, Downloads; design/transfer.md §10). Every one names its profile.
 *   The shell's own event, no id: {ev:"open", tag} when one of our notifications is tapped (MainActivity
 *          onNewIntent; at a start by the tap, kept until the page's port is open, then posted once).
 */
public final class SigeloBridge {
    static final String SHELL = "sigelo-shell/0", PORT_MESSAGE = "sigelo-bridge/0";
    private static final String KEYSTORE = "AndroidKeyStore", CLIP_LABEL = "sigelo stagenet words";
    // Aliases by the byte that starts a sealed blob after its version: 0 SAFE identity, 1 FULL identity, 2 a computer's text.
    // Profile p1 keeps these; profile <id> has "sigelo-<id>" + the suffix of the same index.
    private static final String[] ALIASES = {"sigelo-identity", "sigelo-identity-full", "sigelo-control"};
    private static final String[] SUFFIXES = {"-identity", "-identity-full", "-control"};
    private static final String P1 = "p1";
    private static final Pattern PROFILE = Pattern.compile("^p[1-9][0-9]{0,2}$");
    private static final String C1 = "c1";
    private static final Pattern COMPUTER = Pattern.compile("^c[1-9][0-9]{0,2}$");
    private static final int HTTP_MAX = 1 << 20, CHUNK = 16384, TIMEOUT_MS = 20000, MAX_STREAMS = 16, AUTH_SECONDS = 300;
    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern HOSTNAME = Pattern.compile("^[A-Za-z0-9.-]{1,253}$");
    /** The page's background for the system bars: #rrggbb, opaque. */
    private static final Pattern COLOUR = Pattern.compile("^#[0-9a-fA-F]{6}$");
    /** A notification's tag: what it is about (a chat, a group, a payment request), given back when it is tapped. */
    static final Pattern TAG = Pattern.compile("^(chat|group|pay):[A-Za-z0-9:._-]{1,200}$");
    static final String CHANNEL = "messages", OPEN = "io.sigelo.app.OPEN", EXTRA_OPEN = "open";
    private static final int NOTE_MAX = 100;
    /** The app lock's choices: minutes away before the screen lock is asked again at a return. */
    static final int[] LOCK_AFTER = {1, 5, 15, 60};

    private final MainActivity activity;
    private final WebView web;
    private final SharedPreferences prefs;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService io = Executors.newCachedThreadPool();
    private final Map<Integer, Conn> streams = new ConcurrentHashMap<>();
    private final AtomicInteger nextStream = new AtomicInteger();
    final BigFiles big;
    private WebMessagePort port;   // the main thread's: the page's current port
    private String pendingOpen;    // the main thread's: a tapped notification's tag waiting for the page's port

    SigeloBridge(MainActivity activity, WebView web) {
        this.activity = activity;
        this.web = web;
        this.prefs = activity.getSharedPreferences("sigelo", Context.MODE_PRIVATE);
        this.big = new BigFiles(activity, prefs);
    }

    /** A refusal the page reads as {check, message}. */
    static final class Refused extends Exception {
        private static final long serialVersionUID = 1L;
        final String check;

        Refused(String check, String message) {
            super(message);
            this.check = check;
        }
    }

    // ---------------------------------------------------------------- what the page sees

    Object shell() {
        return new Shell();
    }

    /** SigeloShell: two methods, called on the WebView's bridge thread. */
    public final class Shell {
        @JavascriptInterface
        public String info() {
            JSONObject o = new JSONObject();
            try {
                String mode = mode();
                o.put("v", SHELL).put("mode", mode == null ? JSONObject.NULL : mode).put("wipe", prefs.getBoolean("wipe", false)).put("version", version());
            } catch (JSONException e) {
                return "{}";
            }
            return o.toString();
        }

        @JavascriptInterface
        public void connect() {
            main.post(SigeloBridge.this::openPort);
        }
    }

    private String version() {
        try {
            return activity.getPackageManager().getPackageInfo(activity.getPackageName(), 0).versionName;
        } catch (PackageManager.NameNotFoundException e) {
            return "";
        }
    }

    /** A new port for the page now shown (a load or a reload): the old one and its streams end. */
    private void openPort() {
        String url = web.getUrl();
        if (url == null || !MainActivity.ours(Uri.parse(url))) return;
        closePort();
        WebMessagePort[] ch = web.createWebMessageChannel();
        final WebMessagePort mine = ch[0];
        port = mine;
        mine.setWebMessageCallback(new WebMessagePort.WebMessageCallback() {
            @Override
            public void onMessage(WebMessagePort p, WebMessage m) {
                if (mine == port && m != null && m.getData() != null) handle(mine, m.getData());
            }
        }, main);
        web.postWebMessage(new WebMessage(PORT_MESSAGE, new WebMessagePort[] {ch[1]}), Uri.parse(MainActivity.ORIGIN));
        // A start by a tap on a notification: its tag once the page's port is open, once.
        if (pendingOpen != null) {
            String tag = pendingOpen;
            pendingOpen = null;
            postOpen(mine, tag);
        }
    }

    /** A notification of ours tapped (MainActivity, main thread): to the page now, or once its port is open. */
    void opened(String tag) {
        if (tag == null || !TAG.matcher(tag).matches()) return;
        if (port != null) postOpen(port, tag);
        else pendingOpen = tag;
    }

    private void postOpen(WebMessagePort to, String tag) {
        try {
            post(to, new JSONObject().put("ev", "open").put("tag", tag));
        } catch (JSONException e) {
            // nothing to say it with
        }
    }

    private void closePort() {
        for (Conn c : streams.values()) c.close();
        streams.clear();
        if (port != null) port.close();
        port = null;
    }

    /** The app ends: every stream closed, no thread left. */
    void close() {
        closePort();
        big.close();
        io.shutdownNow();
    }

    /** One message to the page, in order, on the main thread; dropped once that page is gone. */
    private void post(WebMessagePort to, JSONObject o) {
        final String text = o.toString();
        main.post(() -> {
            if (to == port && to != null) to.postMessage(new WebMessage(text));
        });
    }

    private static JSONObject ok(int id) {
        try {
            return new JSONObject().put("id", id);
        } catch (JSONException e) {
            throw new IllegalStateException(e);
        }
    }

    private void fail(WebMessagePort to, int id, String check, String message) {
        try {
            post(to, new JSONObject().put("id", id).put("error", new JSONObject().put("check", check).put("message", message == null ? check : message)));
        } catch (JSONException e) {
            // nothing to say it with
        }
    }

    private interface Work {
        JSONObject run() throws Exception;
    }

    /** Off the main thread (no network there: Android refuses it); nothing once the app is ending. */
    private void spawn(Runnable r) {
        try {
            io.execute(r);
        } catch (RejectedExecutionException e) {
            // the bridge is closed
        }
    }

    /** Work off the main thread, its answer (or its refusal) posted back. */
    private void answer(WebMessagePort to, int id, Work w) {
        spawn(() -> {
            try {
                post(to, w.run());
            } catch (Refused e) {
                fail(to, id, e.check, e.getMessage());
            } catch (Exception e) {
                fail(to, id, "connect", String.valueOf(e.getMessage()));
            }
        });
    }

    // ---------------------------------------------------------------- the messages (main thread)

    private void handle(WebMessagePort to, String data) {
        final JSONObject m;
        try {
            m = new JSONObject(data);
        } catch (JSONException e) {
            return;
        }
        final String op = m.optString("op");
        final int id = m.optInt("id", -1);
        switch (op) {
            case "https":
                answer(to, id, () -> https(m).put("id", id));
                break;
            case "tls":
                openTls(to, id, m);
                break;
            case "write": {
                Conn c = streams.get(m.optInt("s", -1));
                byte[] bytes;
                try {
                    bytes = Base64.decode(m.optString("data"), Base64.NO_WRAP);
                } catch (IllegalArgumentException e) {
                    fail(to, id, "stream", "not base64");
                    break;
                }
                if (c == null) fail(to, id, "stream", "no such stream (closed)");
                else c.write(id, bytes);
                break;
            }
            case "close": {
                Conn c = streams.remove(m.optInt("s", -1));
                if (c != null) c.close();
                break;
            }
            case "seal":
            case "open":
                keystore(to, id, m, op.equals("seal"), false);
                break;
            case "forget-profile":
                answer(to, id, () -> {
                    forgetProfile(profileOf(m));
                    big.forget(profileOf(m));
                    return ok(id);
                });
                break;
            case "mode":
                setMode(to, id, m.optString("mode"));
                break;
            case "wiped":
                prefs.edit().putBoolean("wipe", false).apply();
                post(to, ok(id));
                break;
            case "secure": {
                boolean on = m.optBoolean("on", false);
                if (on) activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
                else activity.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
                activity.door = on && m.optBoolean("door", false);
                post(to, ok(id));
                break;
            }
            case "clip-clear": {
                ClipboardManager cm = activity.getSystemService(ClipboardManager.class);
                if (cm != null) cm.clearPrimaryClip();
                post(to, ok(id));
                break;
            }
            case "clip-copy": {
                ClipboardManager cm = activity.getSystemService(ClipboardManager.class);
                if (cm == null) {
                    fail(to, id, "clip", "no clipboard");
                    break;
                }
                ClipData clip = ClipData.newPlainText(CLIP_LABEL, m.optString("text"));
                PersistableBundle extras = new PersistableBundle();
                extras.putBoolean("android.content.extra.IS_SENSITIVE", true);   // ClipDescription.EXTRA_IS_SENSITIVE (API 33): no preview
                clip.getDescription().setExtras(extras);
                cm.setPrimaryClip(clip);
                int clear = Math.max(1, Math.min(300, m.optInt("clear", 60)));
                main.postDelayed(() -> {
                    // Ours still, or unreadable (the app in the background): emptied. Another app's copy since: kept.
                    ClipDescription d = cm.getPrimaryClipDescription();
                    if (d == null || CLIP_LABEL.contentEquals(d.getLabel() == null ? "" : d.getLabel())) cm.clearPrimaryClip();
                }, clear * 1000L);
                post(to, ok(id));
                break;
            }
            case "share": {
                // A ready-to-send message (a code and its instructions link) through the system's share sheet.
                String text = m.optString("text");
                if (text.isEmpty() || text.length() > 2000) {
                    fail(to, id, "share", "a message of 1 to 2000 characters");
                    break;
                }
                Intent send = new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text);
                activity.startActivity(Intent.createChooser(send, null));
                post(to, ok(id));
                break;
            }
            case "bars": {
                String c = m.optString("colour");
                if (!COLOUR.matcher(c).matches()) {
                    fail(to, id, "bars", "a colour #rrggbb");
                    break;
                }
                activity.bars(0xFF000000 | Integer.parseInt(c.substring(1), 16));
                post(to, ok(id));
                break;
            }
            case "reload":
                // Answered first: the reload ends this page and its port (a new one for the page loaded).
                post(to, ok(id));
                main.post(activity::reload);
                break;
            case "unlock":
                activity.unlock(() -> post(to, ok(id)), () -> fail(to, id, "cancelled", "the screen lock was not confirmed"), m.optBoolean("force", false));
                break;
            case "lock":
                lock(to, id, m);
                break;
            case "notify":
                notification(to, id, m);
                break;
            case "big-pick":
            case "big-photo":
            case "big-land":
            case "big-open":
                bigAsync(to, id, m, op);
                break;
            case "big-hash":
                answer(to, id, () -> big.hash(m).put("id", id));
                break;
            case "big-stat":
                answer(to, id, () -> big.stat(m).put("id", id));
                break;
            case "big-write":
                answer(to, id, () -> big.write(m).put("id", id));
                break;
            case "big-flush":
                answer(to, id, () -> big.flush(m).put("id", id));
                break;
            case "big-digest":
                answer(to, id, () -> big.sha(m).put("id", id));
                break;
            case "big-drop":
                answer(to, id, () -> big.drop(m).put("id", id));
                break;
            case "big-free":
                answer(to, id, () -> big.free(m).put("id", id));
                break;
            case "big-awake":
                big.awake(m.optBoolean("on", false));
                post(to, ok(id));
                break;
            default:
                fail(to, id, "op", "no operation " + op);
        }
    }

    // ---------------------------------------------------------------- big files (BigFiles)

    /** The big-file asks that wait for another activity or a permission: the answer posted when it comes. */
    private void bigAsync(WebMessagePort to, int id, JSONObject m, String op) {
        BigFiles.Reply r = new BigFiles.Reply() {
            @Override
            public void ok(JSONObject o) {
                try {
                    post(to, o.put("id", id));
                } catch (JSONException e) {
                    fail(to, id, "big", "unreadable");
                }
            }

            @Override
            public void no(String check, String message) {
                fail(to, id, check, message);
            }
        };
        try {
            if (op.equals("big-pick")) big.pick(m, r);
            else if (op.equals("big-photo")) big.photo(m, r);
            else if (op.equals("big-land")) big.land(m, r, this::spawn);
            else big.openFile(m, r);
        } catch (Refused e) {
            fail(to, id, e.check, e.getMessage());
        }
    }

    /** MainActivity's: a pick or a photo came back. */
    boolean bigResult(int req, int code, Intent data) {
        return big.result(req, code, data, this::spawn);
    }

    // ---------------------------------------------------------------- the app lock's settings

    boolean lockOn() {
        return prefs.getBoolean("lock_on", true);
    }

    /** Minutes away before the screen lock is asked again at a return (one of LOCK_AFTER; 1 when none is set). */
    int lockAfter() {
        int a = prefs.getInt("lock_after", 1);
        for (int x : LOCK_AFTER) if (x == a) return a;
        return 1;
    }

    private void lock(WebMessagePort to, int id, JSONObject m) {
        boolean on = lockOn();
        int after = lockAfter();
        if (m.has("on")) {
            Object v = m.opt("on");
            if (!(v instanceof Boolean)) {
                fail(to, id, "lock", "on: true or false");
                return;
            }
            on = (Boolean) v;
        }
        if (m.has("after")) {
            Object v = m.opt("after");
            int a = v instanceof Integer ? (Integer) v : -1;
            boolean known = false;
            for (int x : LOCK_AFTER) known |= x == a;
            if (!known) {
                fail(to, id, "lock", "after: 1, 5, 15 or 60 minutes");
                return;
            }
            after = a;
        }
        final boolean on1 = on;
        final int after1 = after;
        Runnable save = () -> {
            prefs.edit().putBoolean("lock_on", on1).putInt("lock_after", after1).apply();
            KeyguardManager km = activity.getSystemService(KeyguardManager.class);
            try {
                post(to, ok(id).put("on", on1).put("after", after1).put("secure", km != null && km.isDeviceSecure()));
            } catch (JSONException e) {
                fail(to, id, "lock", "no answer");
            }
        };
        // Weaker (off, or longer away): the screen lock first.
        boolean weaker = (lockOn() && !on1) || after1 > lockAfter();
        if (weaker) activity.unlock(save, () -> fail(to, id, "cancelled", "the screen lock was not confirmed"), false);
        else save.run();
    }

    // ---------------------------------------------------------------- notifications

    /** A string field of 1 to NOTE_MAX characters, else null. */
    private static String line(JSONObject m, String k) {
        Object v = m.opt(k);
        return v instanceof String && !((String) v).isEmpty() && ((String) v).length() <= NOTE_MAX ? (String) v : null;
    }

    private void notification(WebMessagePort to, int id, JSONObject m) {
        NotificationManager nm = activity.getSystemService(NotificationManager.class);
        if (nm == null) {
            fail(to, id, "notify", "no notifications on this phone");
            return;
        }
        if (m.optBoolean("ask", false)) {
            activity.askNotifications(granted -> {
                try {
                    post(to, ok(id).put("granted", granted));
                } catch (JSONException e) {
                    fail(to, id, "notify", "no answer");
                }
            });
            return;
        }
        Object t = m.opt("tag");
        if (!(t instanceof String) || !TAG.matcher((String) t).matches()) {
            fail(to, id, "notify", "tag: chat:, group: or pay: and up to 200 letters, digits or : . _ -");
            return;
        }
        String tag = (String) t;
        if (m.optBoolean("cancel", false)) {
            nm.cancel(tag, tag.hashCode());
            post(to, ok(id));
            return;
        }
        String title = line(m, "title"), text = line(m, "text");
        if (title == null || text == null) {
            fail(to, id, "notify", "title and text: 1 to " + NOTE_MAX + " characters");
            return;
        }
        if (!activity.notificationsAllowed()) {
            fail(to, id, "notify_permission", "notifications are not allowed for this app");
            return;
        }
        nm.createNotificationChannel(new NotificationChannel(CHANNEL, activity.getString(R.string.notify_channel), NotificationManager.IMPORTANCE_DEFAULT));
        // The lock screen's version: no name, no line of the page's.
        Notification shown = new Notification.Builder(activity, CHANNEL)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle(activity.getString(R.string.app_name))
                .setContentText(activity.getString(R.string.notify_public))
                .setCategory(Notification.CATEGORY_MESSAGE)
                .build();
        Intent open = new Intent(activity, MainActivity.class).setAction(OPEN).putExtra(EXTRA_OPEN, tag)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent tap = PendingIntent.getActivity(activity, tag.hashCode(), open, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification n = new Notification.Builder(activity, CHANNEL)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle(title)
                .setContentText(text)
                .setCategory(Notification.CATEGORY_MESSAGE)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .setPublicVersion(shown)
                .setAutoCancel(true)
                .setContentIntent(tap)
                .build();
        nm.notify(tag, tag.hashCode(), n);
        post(to, ok(id));
    }

    // ---------------------------------------------------------------- https

    /** A private IPv4 address (or this phone's loopback): where a computer's `ui --remote` listens. */
    static boolean lan(String host) {
        Matcher m = IPV4.matcher(host);
        if (!m.matches()) return false;
        int[] b = new int[4];
        for (int i = 0; i < 4; i++) {
            b[i] = Integer.parseInt(m.group(i + 1));
            if (b[i] > 255) return false;
        }
        return b[0] == 10 || b[0] == 127 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
    }

    private JSONObject https(JSONObject m) throws Exception {
        URL url;
        try {
            url = new URL(m.getString("url"));
        } catch (MalformedURLException e) {
            throw new Refused("connect", "not a URL");
        }
        String proto = url.getProtocol(), method = m.optString("method", "GET");
        boolean allowed = "https".equals(proto) || ("http".equals(proto) && lan(url.getHost()));
        if (!allowed || url.getUserInfo() != null) throw new Refused("connect", proto + "://" + url.getHost() + ": https, or http to an address of this network only");
        if (!method.equals("GET") && !method.equals("POST")) throw new Refused("connect", "GET or POST only");
        HttpURLConnection c = (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
        try {
            c.setInstanceFollowRedirects(false);
            c.setUseCaches(false);
            c.setConnectTimeout(TIMEOUT_MS);
            c.setReadTimeout(TIMEOUT_MS);
            c.setRequestMethod(method);
            c.setRequestProperty("User-Agent", "sigelo-app");
            c.setRequestProperty("Accept-Encoding", "identity");
            if (m.has("body")) {
                byte[] body = Base64.decode(m.getString("body"), Base64.NO_WRAP);
                c.setDoOutput(true);
                c.setFixedLengthStreamingMode(body.length);
                c.setRequestProperty("Content-Type", m.optString("type", "text/plain;charset=UTF-8"));
                try (OutputStream out = c.getOutputStream()) {
                    out.write(body);
                }
            }
            int status = c.getResponseCode();
            InputStream in = status >= 400 ? c.getErrorStream() : c.getInputStream();
            byte[] body = in == null ? new byte[0] : readUpTo(in, HTTP_MAX);
            JSONObject h = new JSONObject();
            for (String k : new String[] {"date", "content-length", "retry-after", "content-type"}) {
                String v = c.getHeaderField(k);
                if (v != null) h.put(k, v);
            }
            return new JSONObject().put("status", status).put("headers", h).put("body", Base64.encodeToString(body, Base64.NO_WRAP));
        } finally {
            c.disconnect();
        }
    }

    private static byte[] readUpTo(InputStream in, int max) throws IOException, Refused {
        try (InputStream s = in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] b = new byte[CHUNK];
            for (int n; (n = s.read(b)) >= 0; ) {
                out.write(b, 0, n);
                if (out.size() > max) throw new Refused("connect", "an answer over " + max + " bytes");
            }
            return out.toByteArray();
        }
    }

    // ---------------------------------------------------------------- tls streams

    /** Connects, answers {id, stream}, and only then starts reading: the page knows the stream before its first bytes. */
    private void openTls(WebMessagePort to, int id, JSONObject m) {
        spawn(() -> {
            Conn c;
            try {
                c = connectTls(to, m);
            } catch (Refused e) {
                fail(to, id, e.check, e.getMessage());
                return;
            } catch (Exception e) {
                fail(to, id, "connect", String.valueOf(e.getMessage()));
                return;
            }
            try {
                post(to, ok(id).put("stream", c.id));
            } catch (JSONException e) {
                c.close();
                return;
            }
            c.startReading();
        });
    }

    private Conn connectTls(WebMessagePort to, JSONObject m) throws Exception {
        String host = m.optString("host");
        int p = m.optInt("port", -1);
        if (p < 1 || p > 65535 || !HOSTNAME.matcher(host).matches()) throw new Refused("connect", "a host name and a port");
        if (streams.size() >= MAX_STREAMS) throw new Refused("connect", "too many streams open");
        Socket raw = new Socket(Proxy.NO_PROXY);
        SSLSocket s = null;
        try {
            raw.setTcpNoDelay(true);
            raw.connect(new InetSocketAddress(host, p), TIMEOUT_MS);
            s = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, host, p, true);
            SSLParameters sp = s.getSSLParameters();
            sp.setEndpointIdentificationAlgorithm("HTTPS");
            if (!IPV4.matcher(host).matches()) sp.setServerNames(Collections.singletonList(new SNIHostName(host)));
            s.setSSLParameters(sp);
            s.setSoTimeout(TIMEOUT_MS);
            s.startHandshake();
            // An SSLSocket does not check the name by itself on every version: checked here, as Android's documentation asks.
            if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, s.getSession())) throw new SSLPeerUnverifiedException("the certificate does not name " + host);
            s.setSoTimeout(0);   // from here MQTT's keepalive notices a dead connection
        } catch (Exception e) {
            try {
                if (s != null) s.close();
                else raw.close();
            } catch (IOException x) {
                // closing
            }
            throw e;
        }
        Conn c = new Conn(nextStream.incrementAndGet(), s, to);
        streams.put(c.id, c);
        return c;
    }

    /** One TLS stream: a reader thread posting what arrives, one writer thread so writes keep their order. */
    private final class Conn {
        final int id;
        final SSLSocket s;
        final WebMessagePort to;
        final ExecutorService out = Executors.newSingleThreadExecutor();
        volatile boolean closed;

        Conn(int id, SSLSocket s, WebMessagePort to) {
            this.id = id;
            this.s = s;
            this.to = to;
        }

        void startReading() {
            spawn(() -> {
                String error = null;
                byte[] b = new byte[CHUNK];
                try {
                    InputStream in = s.getInputStream();
                    for (int n; (n = in.read(b)) >= 0; ) {
                        if (n > 0) post(to, new JSONObject().put("s", id).put("data", Base64.encodeToString(b, 0, n, Base64.NO_WRAP)));
                    }
                } catch (IOException | JSONException e) {
                    if (!closed) error = String.valueOf(e.getMessage());
                }
                streams.remove(id);
                close();
                try {
                    JSONObject end = new JSONObject().put("s", id).put("end", true);
                    if (error != null) end.put("error", error);
                    post(to, end);
                } catch (JSONException e) {
                    // the page sees no end; its MQTT keepalive will
                }
            });
        }

        void write(int reqId, byte[] data) {
            try {
                out.execute(() -> {
                    try {
                        OutputStream o = s.getOutputStream();
                        o.write(data);
                        o.flush();
                        post(to, ok(reqId));
                    } catch (IOException | RuntimeException e) {
                        fail(to, reqId, "stream", String.valueOf(e.getMessage()));
                        close();
                    }
                });
            } catch (RuntimeException e) {   // the writer is shut down: the stream closed
                fail(to, reqId, "stream", "the stream is closed");
            }
        }

        /** Closed on a thread of its own: closing TLS writes (close_notify), which the main thread may not. */
        void close() {
            if (closed) return;
            closed = true;
            out.shutdown();
            new Thread(() -> {
                try {
                    s.close();
                } catch (IOException e) {
                    // closing
                }
            }, "sigelo-close").start();
        }
    }

    // ---------------------------------------------------------------- the keystore

    /**
     * p1 (or none given): the kind alone, as before profiles; another profile: the kind and the profile; a computer
     * other than a profile's first (design/profiles.md P2): the kind, the profile and the computer.
     */
    private static byte[] aad(String kind, String profile, String computer) {
        String who = C1.equals(computer) ? (P1.equals(profile) ? "" : " " + profile) : " " + profile + " " + computer;
        return ("sigelo-app " + kind + "/0" + who).getBytes(StandardCharsets.UTF_8);
    }

    /** The request's profile: "p1" when it names none (a page of before profiles). */
    static String profileOf(JSONObject m) throws Refused {
        String p = m.optString("profile", P1);
        if (!PROFILE.matcher(p).matches()) throw new Refused("profile", "a profile id: p1, p2, ...");
        return p;
    }

    /** The request's computer of its profile: "c1" when it names none (the first, or a page of before P2). */
    static String computerOf(JSONObject m) throws Refused {
        String c = m.optString("computer", C1);
        if (!COMPUTER.matcher(c).matches()) throw new Refused("computer", "a computer id: c1, c2, ...");
        return c;
    }

    static String alias(String profile, int a) {
        return P1.equals(profile) ? ALIASES[a] : "sigelo-" + profile + SUFFIXES[a];
    }

    @SuppressWarnings("deprecation")   // setUserAuthenticationValidityDurationSeconds: API 28 and 29 only
    private static SecretKey key(String profile, int a, boolean make) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        Key k = ks.getKey(alias(profile, a), null);
        if (k instanceof SecretKey) return (SecretKey) k;
        if (!make) return null;
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias(profile, a), KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true);
        if (a == 1) {
            b.setUserAuthenticationRequired(true);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) b.setUserAuthenticationParameters(AUTH_SECONDS, KeyProperties.AUTH_DEVICE_CREDENTIAL | KeyProperties.AUTH_BIOMETRIC_STRONG);
            else b.setUserAuthenticationValidityDurationSeconds(AUTH_SECONDS);
        }
        KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        g.init(b.build());
        return g.generateKey();
    }

    private static void deleteKey(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE);
            ks.load(null);
            ks.deleteEntry(alias);
        } catch (GeneralSecurityException | IOException e) {
            // gone already, or no keystore: nothing to erase
        }
    }

    /** A profile's removal: its three aliases deleted, so its blobs never open again (crypto-erase). */
    static void forgetProfile(String profile) {
        for (int a = 0; a < ALIASES.length; a++) deleteKey(alias(profile, a));
    }

    /**
     * p1: [1][alias][IV 12][ciphertext ‖ tag 16], as before profiles. Another profile: [2][alias][n][its id, n
     * bytes][IV 12][ciphertext ‖ tag 16]. A computer other than the first (P2: one blob per computer under the
     * profile's aliases): version 2, the n bytes "<profile>:<computer>". The AAD names the kind (and the profile,
     * and the computer), so one kind's blob never opens as another's, nor one profile's or computer's in another.
     */
    static byte[] seal(String kind, boolean full, String profile, String computer, byte[] plain) throws GeneralSecurityException, IOException, Refused {
        int a = "identity".equals(kind) ? (full ? 1 : 0) : "keeper".equals(kind) || "words".equals(kind) ? 1 : "control".equals(kind) ? 2 : -1;
        if (a < 0) throw new Refused("kind", "identity, keeper, words or control");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key(profile, a, true));
        c.updateAAD(aad(kind, profile, computer));
        byte[] ct = c.doFinal(plain), iv = c.getIV();
        if (iv == null || iv.length != 12) throw new GeneralSecurityException("an IV of " + (iv == null ? 0 : iv.length) + " bytes");
        String owner = C1.equals(computer) ? (P1.equals(profile) ? "" : profile) : profile + ":" + computer;
        byte[] name = owner.getBytes(StandardCharsets.US_ASCII);
        int at = name.length == 0 ? 2 : 3 + name.length;
        byte[] out = new byte[at + 12 + ct.length];
        out[0] = (byte) (name.length == 0 ? 1 : 2);
        out[1] = (byte) a;
        if (name.length > 0) {
            out[2] = (byte) name.length;
            System.arraycopy(name, 0, out, 3, name.length);
        }
        System.arraycopy(iv, 0, out, at, 12);
        System.arraycopy(ct, 0, out, at + 12, ct.length);
        return out;
    }

    static byte[] open(String kind, String profile, String computer, byte[] blob) throws GeneralSecurityException, IOException, Refused {
        if (blob.length < 2) throw new Refused("sealed", "not sealed by this app");
        int at;   // where the IV starts
        if (blob[0] == 1) {
            if (!P1.equals(profile)) throw new Refused("sealed", "sealed for another profile");
            if (!C1.equals(computer)) throw new Refused("sealed", "sealed for another computer");
            at = 2;
        } else if (blob[0] == 2) {
            int n = blob.length > 2 ? blob[2] : -1;
            if (n < 2 || n > 9 || blob.length < 3 + n) throw new Refused("sealed", "not sealed by this app");
            String owner = new String(blob, 3, n, StandardCharsets.US_ASCII);
            String want = C1.equals(computer) ? profile : profile + ":" + computer;
            if (!owner.equals(profile) && !owner.startsWith(profile + ":")) throw new Refused("sealed", "sealed for another profile");
            if ((P1.equals(profile) && C1.equals(computer)) || !owner.equals(want)) throw new Refused("sealed", "sealed for another computer");
            at = 3 + n;
        } else {
            throw new Refused("sealed", "not sealed by this app");
        }
        if (blob.length < at + 12 + 16) throw new Refused("sealed", "not sealed by this app");
        int a = blob[1];
        boolean fits = "identity".equals(kind) ? (a == 0 || a == 1) : "keeper".equals(kind) || "words".equals(kind) ? a == 1 : "control".equals(kind) && a == 2;
        if (!fits) throw new Refused("sealed", "sealed as something else");
        SecretKey k = key(profile, a, false);
        if (k == null) throw new Refused("sealed", "its key is gone from this phone's keystore");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, blob, at, 12));
        c.updateAAD(aad(kind, profile, computer));
        return c.doFinal(blob, at + 12, blob.length - at - 12);
    }

    private void keystore(WebMessagePort to, int id, JSONObject m, boolean sealing, boolean retried) {
        spawn(() -> {
            try {
                String kind = m.optString("kind"), profile = profileOf(m), computer = computerOf(m);
                byte[] data = Base64.decode(m.optString("data"), Base64.NO_WRAP);
                byte[] out = sealing ? seal(kind, m.optBoolean("full", false), profile, computer, data) : open(kind, profile, computer, data);
                post(to, ok(id).put("data", Base64.encodeToString(out, Base64.NO_WRAP)));
            } catch (UserNotAuthenticatedException e) {
                // The FULL key: the screen lock first, then once more.
                if (retried) {
                    fail(to, id, "cancelled", "the screen lock was not confirmed");
                    return;
                }
                main.post(() -> activity.confirmCredential(() -> keystore(to, id, m, sealing, true),
                        () -> fail(to, id, "cancelled", "the screen lock was not confirmed")));
            } catch (KeyPermanentlyInvalidatedException e) {
                fail(to, id, "sealed", "the key was invalidated (the screen lock was removed or changed): import the identity again, or restore it from your 25 words");
            } catch (Refused e) {
                fail(to, id, e.check, e.getMessage());
            } catch (IllegalStateException e) {
                // A key that needs the screen lock, on a phone without one.
                fail(to, id, "locked", "set a screen lock (PIN, pattern or password) first: a FULL identity is sealed under it");
            } catch (GeneralSecurityException | IOException | JSONException | RuntimeException e) {
                fail(to, id, "sealed", String.valueOf(e.getMessage()));
            }
        });
    }

    // ---------------------------------------------------------------- the form

    String mode() {
        return prefs.getString("mode", null);
    }

    /**
     * The page sets the form when a profile's first run commits; each profile has its own (the page's
     * registry), so a change is no refusal. Set at all: the app lock is on.
     */
    private void setMode(WebMessagePort to, int id, String want) {
        if (!"self".equals(want) && !"remote".equals(want)) {
            fail(to, id, "mode", "self or remote");
            return;
        }
        if (!want.equals(mode())) prefs.edit().putString("mode", want).commit();
        activity.modeChanged();
        try {
            post(to, ok(id).put("mode", want));
        } catch (JSONException e) {
            // unreachable: a string
        }
    }
}
