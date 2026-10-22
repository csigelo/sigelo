// SPDX-License-Identifier: MIT
package io.sigelo.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Base64;
import android.webkit.JavascriptInterface;
import android.webkit.WebMessage;
import android.webkit.WebMessagePort;
import android.webkit.WebStorage;
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
 *          (SAFE; FULL under a key that needs the screen lock, valid 5 minutes) or a computer's text.
 *   mode / wiped  the form picked at first start; a switch (the menu) erases the other's storage.
 */
public final class SigeloBridge {
    static final String SHELL = "sigelo-shell/0", PORT_MESSAGE = "sigelo-bridge/0";
    private static final String KEYSTORE = "AndroidKeyStore";
    // Aliases by the byte that starts a sealed blob after its version: 0 SAFE identity, 1 FULL identity, 2 a computer's text.
    private static final String[] ALIASES = {"sigelo-identity", "sigelo-identity-full", "sigelo-control"};
    private static final int HTTP_MAX = 1 << 20, CHUNK = 16384, TIMEOUT_MS = 20000, MAX_STREAMS = 16, AUTH_SECONDS = 300;
    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern HOSTNAME = Pattern.compile("^[A-Za-z0-9.-]{1,253}$");

    private final MainActivity activity;
    private final WebView web;
    private final SharedPreferences prefs;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService io = Executors.newCachedThreadPool();
    private final Map<Integer, Conn> streams = new ConcurrentHashMap<>();
    private final AtomicInteger nextStream = new AtomicInteger();
    private WebMessagePort port;   // the main thread's: the page's current port

    SigeloBridge(MainActivity activity, WebView web) {
        this.activity = activity;
        this.web = web;
        this.prefs = activity.getSharedPreferences("sigelo", Context.MODE_PRIVATE);
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
            case "mode":
                setMode(to, id, m.optString("mode"));
                break;
            case "wiped":
                prefs.edit().putBoolean("wipe", false).apply();
                post(to, ok(id));
                break;
            default:
                fail(to, id, "op", "no operation " + op);
        }
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

    private static byte[] aad(String kind) {
        return ("sigelo-app " + kind + "/0").getBytes(StandardCharsets.UTF_8);
    }

    @SuppressWarnings("deprecation")   // setUserAuthenticationValidityDurationSeconds: API 28 and 29 only
    private static SecretKey key(int a, boolean make) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        Key k = ks.getKey(ALIASES[a], null);
        if (k instanceof SecretKey) return (SecretKey) k;
        if (!make) return null;
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(ALIASES[a], KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
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

    private static void deleteKey(int a) {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE);
            ks.load(null);
            ks.deleteEntry(ALIASES[a]);
        } catch (GeneralSecurityException | IOException e) {
            // gone already, or no keystore: nothing to erase
        }
    }

    /** [1][alias][IV 12][ciphertext ‖ tag 16]; the AAD names the kind, so one kind's blob never opens as another's. */
    static byte[] seal(String kind, boolean full, byte[] plain) throws GeneralSecurityException, IOException, Refused {
        int a = "identity".equals(kind) ? (full ? 1 : 0) : "control".equals(kind) ? 2 : -1;
        if (a < 0) throw new Refused("kind", "identity or control");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key(a, true));
        c.updateAAD(aad(kind));
        byte[] ct = c.doFinal(plain), iv = c.getIV();
        if (iv == null || iv.length != 12) throw new GeneralSecurityException("an IV of " + (iv == null ? 0 : iv.length) + " bytes");
        byte[] out = new byte[2 + 12 + ct.length];
        out[0] = 1;
        out[1] = (byte) a;
        System.arraycopy(iv, 0, out, 2, 12);
        System.arraycopy(ct, 0, out, 14, ct.length);
        return out;
    }

    static byte[] open(String kind, byte[] blob) throws GeneralSecurityException, IOException, Refused {
        if (blob.length < 2 + 12 + 16 || blob[0] != 1) throw new Refused("sealed", "not sealed by this app");
        int a = blob[1];
        boolean fits = "identity".equals(kind) ? (a == 0 || a == 1) : "control".equals(kind) && a == 2;
        if (!fits) throw new Refused("sealed", "sealed as something else");
        SecretKey k = key(a, false);
        if (k == null) throw new Refused("sealed", "its key is gone from this phone's keystore");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, blob, 2, 12));
        c.updateAAD(aad(kind));
        return c.doFinal(blob, 14, blob.length - 14);
    }

    private void keystore(WebMessagePort to, int id, JSONObject m, boolean sealing, boolean retried) {
        spawn(() -> {
            try {
                String kind = m.optString("kind");
                byte[] data = Base64.decode(m.optString("data"), Base64.NO_WRAP);
                byte[] out = sealing ? seal(kind, m.optBoolean("full", false), data) : open(kind, data);
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
                fail(to, id, "sealed", "the key was invalidated (the screen lock was removed or changed): import the identity again");
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

    // ---------------------------------------------------------------- the two forms

    String mode() {
        return prefs.getString("mode", null);
    }

    /** At first start the page sets the form; after that only the menu changes it (switchTo, after a confirmation). */
    private void setMode(WebMessagePort to, int id, String want) {
        if (!"self".equals(want) && !"remote".equals(want)) {
            fail(to, id, "mode", "self or remote");
            return;
        }
        String now = mode();
        if (now != null && !now.equals(want)) {
            fail(to, id, "mode", "switch from the app's menu: it asks first, then erases the other form");
            return;
        }
        if (now == null) {
            prefs.edit().putString("mode", want).commit();
            activity.modeChanged();
        }
        try {
            post(to, ok(id).put("mode", want));
        } catch (JSONException e) {
            // unreachable: a string
        }
    }

    /**
     * The user confirmed: the form now in use is erased (its keys deleted from the keystore, the
     * page's storage cleared here and, at its next load, by the page itself: wipe), then `to` starts.
     */
    void switchTo(String to) {
        String from = mode();
        if ("self".equals(from)) {
            deleteKey(0);
            deleteKey(1);
        }
        if ("remote".equals(from)) deleteKey(2);
        closePort();
        WebStorage.getInstance().deleteAllData();
        prefs.edit().putString("mode", to).putBoolean("wipe", true).commit();
    }
}
