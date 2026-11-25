// SPDX-License-Identifier: MIT
package io.sigelo.app;

import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;
import android.os.SystemClock;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.net.ssl.HttpsURLConnection;

/**
 * The built-in push client (design/push.md §6): one HTTPS stream to push.sigelo.ai, the ntfy JSON stream of this phone's
 * topic, held by a foreground service of type specialUse while the push mode is Built in (UnifiedPush.mode). It goes on
 * after the app is swiped away (stopWithTask false, START_STICKY, a 1 s restart alarm at onTaskRemoved, as the ntfy app's
 * SubscriberService), and starts at boot and after an update (Boot, below). Force-stopped: nothing until the app is opened.
 *
 * The stream: GET https://push.sigelo.ai/<topic>/json?since=<the last message id>. Its first "open" makes the push
 * ready: the endpoint (Ntfy.endpoint) goes to the page, then to the relay (sigelo-push/0); before a subscriber, ntfy
 * refuses the relay's publish (507). A "message" is base64 (a binary UnifiedPush body); one that opens to WebPush.WAKE
 * under our keys is a wake, handled as a distributor's MESSAGE (UnifiedPush.wake), with a 30 s partial wake lock for the
 * page to log in and fetch. Anything else is dropped. No wake lock while waiting.
 *
 * Reconnects: the ntfy app's table (Ntfy.retryMs: 5 s … 120 s), reset by a stream that opened; a new default network
 * drops the stream and reconnects at once with the table reset; the end of Doze ends a wait and nudges the page. The read
 * times out after 90 s with no line (the server sends a keepalive every 45 s).
 *
 * One silent notification ("Sigelo · ready for messages") on the Connection channel at low importance, no text, no action;
 * a tap opens the app. Notifications denied: it runs all the same (Android 13+ shows it in the Task Manager only).
 *
 * SharedPreferences "sigelo": push_topic, push_since (the last message id), push_ready (the stream has opened once for
 * this topic), push_state (UnifiedPush's: registering, ok, unavailable).
 */
public final class PushClient extends Service {
    static final String TOPIC = "push_topic", SINCE = "push_since", READY = "push_ready";
    private static final String RESTART = "io.sigelo.app.PUSH_RESTART";
    private static final int NOTE = 3;
    private static final long WAKE_LOCK_MS = 30_000L;

    private final Handler main = new Handler(Looper.getMainLooper());
    private final Object gate = new Object();
    private volatile boolean running;
    private volatile boolean kicked;
    private volatile HttpURLConnection conn;
    private Thread loop;
    private ConnectivityManager.NetworkCallback net;

    private static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("sigelo", Context.MODE_PRIVATE);
    }

    /** This phone's topic, made at the first use (a new one is a new capability: the relay is told again). */
    static String topic(Context c) {
        SharedPreferences p = prefs(c);
        String t = p.getString(TOPIC, null);
        if (Ntfy.topic(t)) return t;
        t = Ntfy.newTopic(new SecureRandom());
        p.edit().putString(TOPIC, t).remove(SINCE).putBoolean(READY, false).commit();
        return t;
    }

    /** The topic forgotten (push off, or the push app chosen): the next Built in makes a new one. */
    static void forget(Context c) {
        prefs(c).edit().remove(TOPIC).remove(SINCE).remove(READY).apply();
    }

    /** Started (allowed: the app in front, a boot, an update, the alarm of a restart). Refused by Android: the next start of the app. */
    static void start(Context c) {
        try {
            c.startForegroundService(new Intent(c, PushClient.class));
        } catch (IllegalStateException | SecurityException e) {
            // not allowed now (Android 12+ in the background)
        }
    }

    static void stop(Context c) {
        c.stopService(new Intent(c, PushClient.class));
    }

    /** At boot and after an update: started when the mode is Built in. BOOT_COMPLETED and MY_PACKAGE_REPLACED only (both protected). */
    public static final class Boot extends BroadcastReceiver {
        @Override
        public void onReceive(Context c, Intent i) {
            String a = i.getAction();
            if (!Intent.ACTION_BOOT_COMPLETED.equals(a) && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(a)) return;
            if (UnifiedPush.BUILTIN.equals(UnifiedPush.mode(c))) start(c);
        }
    }

    private final BroadcastReceiver idle = new BroadcastReceiver() {
        @Override
        public void onReceive(Context c, Intent i) {
            PowerManager pm = getSystemService(PowerManager.class);
            if (pm == null || pm.isDeviceIdleMode()) return;
            synchronized (gate) {   // Doze over: a wait ends now
                gate.notifyAll();
            }
            SigeloBridge b = StayConnected.page;
            if (b != null) b.nudge();
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        IntentFilter f = new IntentFilter(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) registerReceiver(idle, f, Context.RECEIVER_NOT_EXPORTED); else registerReceiver(idle, f);
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        if (cm != null) {
            net = new ConnectivityManager.NetworkCallback() {
                private boolean first = true;

                @Override
                public void onAvailable(Network n) {
                    if (first) {   // the network there at the start: no reconnect for it
                        first = false;
                        return;
                    }
                    kick();
                }
            };
            try {
                cm.registerDefaultNetworkCallback(net);
            } catch (RuntimeException e) {
                net = null;
            }
        }
        running = true;
        loop = new Thread(this::run, "sigelo-push");
        loop.start();
    }

    @Override
    public int onStartCommand(Intent i, int flags, int startId) {
        Notification n = note();
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) startForeground(NOTE, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE); else startForeground(NOTE, n);
        } catch (RuntimeException e) {
            // Android refused the foreground (a restart it does not allow now): stopped; the next start of the app starts it
            stopSelf();
            return START_NOT_STICKY;
        }
        if (!UnifiedPush.BUILTIN.equals(UnifiedPush.mode(this))) {
            stopSelf();
            return START_NOT_STICKY;
        }
        return START_STICKY;
    }

    /** Swiped away from the recent apps: the service goes on (stopWithTask false); a restart in 1 s in case the vendor ends it. */
    @Override
    public void onTaskRemoved(Intent root) {
        AlarmManager am = getSystemService(AlarmManager.class);
        PendingIntent again = PendingIntent.getForegroundService(this, 0, new Intent(this, PushClient.class).setAction(RESTART), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        if (am != null) am.set(AlarmManager.ELAPSED_REALTIME, SystemClock.elapsedRealtime() + 1000, again);
        super.onTaskRemoved(root);
    }

    @Override
    public void onDestroy() {
        running = false;
        kick();
        if (loop != null) loop.interrupt();
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        if (cm != null && net != null) {
            try {
                cm.unregisterNetworkCallback(net);
            } catch (RuntimeException e) {
                // not registered
            }
        }
        unregisterReceiver(idle);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent i) {
        return null;
    }

    /** Now: the stream dropped (a new network) or the wait ended, the table reset. The socket closed off the main thread. */
    private void kick() {
        kicked = true;
        HttpURLConnection c = conn;
        if (c != null) new Thread(c::disconnect, "sigelo-push-close").start();
        synchronized (gate) {
            gate.notifyAll();
        }
    }

    // ---------------------------------------------------------------- the stream

    private void run() {
        int failures = 0;
        while (running && builtin()) {
            kicked = false;
            boolean opened = false;
            try {
                opened = stream(topic(this));
            } catch (IOException | RuntimeException e) {
                // the network, a refusal, a timeout: below
            }
            if (!running) break;
            if (opened) failures = 0;
            failures++;
            state(prefs(this).getBoolean(READY, false) ? "unavailable" : "registering");
            if (kicked) {
                failures = 0;
                continue;
            }
            long until = SystemClock.elapsedRealtime() + Ntfy.retryMs(failures);
            synchronized (gate) {   // the wait; kick() and the end of Doze end it early
                long left = until - SystemClock.elapsedRealtime();
                if (running && !kicked && left > 0) {
                    try {
                        gate.wait(left);
                    } catch (InterruptedException e) {
                        // onDestroy
                    }
                }
            }
            if (kicked) failures = 0;
        }
    }

    /** One stream until it ends. → it opened. */
    private boolean stream(String topic) throws IOException {
        HttpsURLConnection c = (HttpsURLConnection) new URL(Ntfy.stream(topic, prefs(this).getString(SINCE, null))).openConnection();
        conn = c;
        boolean opened = false;
        try {
            c.setConnectTimeout(Ntfy.CONNECT_MS);
            c.setReadTimeout(Ntfy.READ_MS);
            c.setInstanceFollowRedirects(false);
            c.setUseCaches(false);
            c.setRequestProperty("Accept", "application/x-ndjson");
            if (!running || kicked) return false;
            if (c.getResponseCode() != 200) throw new IOException("push server: HTTP " + c.getResponseCode());
            try (InputStream in = c.getInputStream(); Reader r = new InputStreamReader(in, StandardCharsets.UTF_8)) {
                String line;
                while (running && (line = line(r)) != null) {
                    Ntfy.Event e = Ntfy.parse(line);
                    if (e == null) continue;
                    if ("open".equals(e.event)) {
                        opened = true;
                        ready();
                    } else if ("message".equals(e.event)) {
                        if (e.id != null) prefs(this).edit().putString(SINCE, e.id).apply();
                        byte[] body = e.body();
                        if (body != null && UnifiedPush.isWake(this, body)) woken();
                    }
                }
            }
            return opened;
        } finally {
            conn = null;
            c.disconnect();
        }
    }

    /** One line of at most Ntfy.LINE_MAX characters; a longer one is read to its end and given as "" (no event). Null: the end. */
    private static String line(Reader r) throws IOException {
        StringBuilder b = new StringBuilder();
        int ch;
        boolean over = false, any = false;
        while ((ch = r.read()) != -1) {
            any = true;
            if (ch == '\n') return over ? "" : b.toString();
            if (b.length() < Ntfy.LINE_MAX) b.append((char) ch); else over = true;
        }
        return !any ? null : over ? "" : b.toString();
    }

    /** The stream is open: push ready (the page then registers the endpoint at its relay). */
    private void ready() {
        if (!builtin()) return;
        prefs(this).edit().putBoolean(READY, true).apply();
        state("ok");
    }

    /** Still Built in (the mode moved on before onDestroy came: nothing more is written). */
    private boolean builtin() {
        return running && UnifiedPush.BUILTIN.equals(UnifiedPush.mode(this));
    }

    /** push_state kept and told to the page when it changes (Built in only). */
    private void state(String s) {
        if (!builtin()) return;
        SharedPreferences p = prefs(this);
        if (s.equals(p.getString(UnifiedPush.STATE, null))) return;
        p.edit().putString(UnifiedPush.STATE, s).remove(UnifiedPush.REASON).apply();
        main.post(() -> UnifiedPush.tell(this));
    }

    private void woken() {
        PowerManager pm = getSystemService(PowerManager.class);
        if (pm != null) pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "sigelo:push").acquire(WAKE_LOCK_MS);
        main.post(() -> UnifiedPush.wake(this));
    }

    /** "Sigelo · ready for messages": the Connection channel, low importance (no sound, no badge), no text, a tap opens the app. */
    private Notification note() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        NotificationChannel ch = new NotificationChannel(StayConnected.CHANNEL, getString(R.string.stay_channel), NotificationManager.IMPORTANCE_LOW);
        ch.setShowBadge(false);
        if (nm != null) nm.createNotificationChannel(ch);
        Intent open = new Intent(this, MainActivity.class).setAction(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        PendingIntent tap = PendingIntent.getActivity(this, NOTE, open, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this, StayConnected.CHANNEL)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle(getString(R.string.push_title))
                .setCategory(Notification.CATEGORY_SERVICE)
                .setOngoing(true)
                .setShowWhen(false)
                .setContentIntent(tap)
                .build();
    }
}
