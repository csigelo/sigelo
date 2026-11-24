// SPDX-License-Identifier: MIT
package io.sigelo.app;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.ActivityNotFoundException;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;
import android.os.SystemClock;
import android.provider.Settings;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Stay connected (design/push.md §A, ROADMAP B1): a foreground service of type specialUse while the switch is on
 * (SigeloBridge "stay", SharedPreferences "stay_on", default on: one setting for the phone, not per profile).
 *
 * It owns no socket. The relay's connection is the page's: the carrier (MQTT, its keepalive and backoff) runs in
 * MainActivity's WebView, and its TLS stream is SigeloBridge's, both in this process. The service keeps the process
 * at foreground priority, so Android neither freezes nor kills it once the app is minimised, and its network stays
 * open under Doze (a packet wakes the phone). The WebView stays the Activity's: rotation and the like do not recreate
 * it (configChanges), Back on the first screen moves the task back instead of finishing it while this is on.
 * Removed from the recent apps, the task and its page end: the service stops with it (stopWithTask), since a
 * "connected" with no page would be false. Not started at boot, for the same reason.
 *
 * One silent notification ("sigelo · connected", low importance, no action), a tap opens the app. No wake lock.
 * An inexact alarm at most every 15 minutes (setAndAllowWhileIdle: Doze lets one through about that often) and
 * the end of Doze nudge the page ({ev:"nudge"}): its carrier reconnects, with its own backoff, when the connection
 * is down. The two asks (notifications, the battery exemption) come when the user turns the switch on or taps
 * Settings' row, one at a time, each after the page's one line why; never at a start. A refusal is never final: the
 * next tap asks again while Android still shows the prompt, after that it opens the app's page in the system's settings. Notifications denied: the service runs all the same; Android 13+ then shows its
 * notification nowhere but in the quick settings' list of active apps.
 *
 * The wake window (design/push.md §1 B, UnifiedPush): a push wake with the page alive starts this service with WAKE,
 * allowed from the background while the distributor holds UnifiedPush.Raise bound; it keeps the process in front for
 * WAKE_MS while the page's carrier logs in and fetches, then stops, unless the switch is on (then it runs on as above).
 */
public final class StayConnected extends Service {
    static final String CHANNEL = "connection", ON = "stay_on", ASKED = "stay_battery_asked", NOTIFY_ASKED = "stay_notify_asked";
    private static final String POST_NOTIFICATIONS = "android.permission.POST_NOTIFICATIONS";   // Manifest.permission's, API 33
    private static final String NUDGE = "io.sigelo.app.NUDGE";
    static final String WAKE = "io.sigelo.app.WAKE";
    static final long WAKE_MS = 60_000L;
    private final Handler later = new Handler(Looper.getMainLooper());
    private final Runnable windowOver = () -> {
        if (!on(this)) stopSelf();
    };
    private static final int NOTE = 1;
    private static final long NUDGE_MS = 15 * 60_000L;

    /** The page's bridge while it is open (SigeloBridge sets and clears it, main thread): where a nudge goes. */
    static volatile SigeloBridge page;

    private static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("sigelo", Context.MODE_PRIVATE);
    }

    /** The switch (default on). */
    static boolean on(Context c) {
        return prefs(c).getBoolean(ON, true);
    }

    /** A push wake (UnifiedPush): the service for the wake window. Refused by Android (no Raise binding): the page's own nudge only. */
    static void wake(Context c) {
        try {
            c.startForegroundService(new Intent(c, StayConnected.class).setAction(WAKE));
        } catch (IllegalStateException | SecurityException e) {
            // not allowed now: the page still gets its wake
        }
    }

    /** The service started (on) or stopped (off). Started while the app is in front (onPause, the switch): allowed then. */
    static void follow(Context c, boolean on) {
        Intent i = new Intent(c, StayConnected.class);
        if (!on) {
            c.stopService(i);
            return;
        }
        try {
            c.startForegroundService(i);
        } catch (IllegalStateException | SecurityException e) {
            // not allowed now (Android 12+ in the background): the next time the app is left
        }
    }

    private static boolean exempt(Context c) {
        PowerManager pm = c.getSystemService(PowerManager.class);
        return pm != null && pm.isIgnoringBatteryOptimizations(c.getPackageName());
    }

    /** The answer to "stay" (main thread). */
    interface Answer {
        void give(JSONObject o);
    }

    private static JSONObject state(MainActivity a) throws JSONException {
        SharedPreferences p = prefs(a);
        return new JSONObject().put("on", on(a)).put("exempt", exempt(a)).put("asked", p.getBoolean(ASKED, false))
                .put("notify", a.notificationsAllowed()).put("notifyAsked", p.getBoolean(NOTIFY_ASKED, false)).put("notifyBlocked", blocked(a));
    }

    /**
     * Android will not show the notifications prompt (again): before 13 there is none; granted but turned off in the
     * system's settings; or asked before and refused for good (two refusals, "don't ask again": no rationale then).
     */
    private static boolean blocked(MainActivity a) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true;
        if (a.checkSelfPermission(POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return true;
        return prefs(a).getBoolean(NOTIFY_ASKED, false) && !a.shouldShowRequestPermissionRationale(POST_NOTIFICATIONS);
    }

    /**
     * SigeloBridge "stay" (main thread): {on?: boolean, battery?: boolean, notifications?: boolean} → {on, exempt, asked,
     * notify, notifyAsked, notifyBlocked}. on: kept, the service follows at once. The asks come from a tap (the switch
     * turned on, Settings' row), never at a start, and a refusal is never final: battery true shows the system's "ignore
     * battery optimisations" prompt each time (its list when that screen is missing); notifications true asks
     * POST_NOTIFICATIONS while Android still shows the prompt, after that opens the app's notification settings. false:
     * the page's one-line why was declined, only remembered. The answer once the prompt is answered (notifications) or at once.
     */
    @SuppressLint("BatteryLife")   // asked on the user's tap only, never at a start
    static void op(MainActivity a, JSONObject m, Answer answer) throws SigeloBridge.Refused, JSONException {
        SharedPreferences p = prefs(a);
        for (String k : new String[] {"on", "battery", "notifications"}) {
            if (m.has(k) && !(m.opt(k) instanceof Boolean)) throw new SigeloBridge.Refused("stay", k + ": true or false");
        }
        if (m.has("on")) {
            boolean on = m.getBoolean("on");
            p.edit().putBoolean(ON, on).apply();
            follow(a, on);
        }
        if (m.has("battery") && !exempt(a)) {
            p.edit().putBoolean(ASKED, true).apply();
            if (m.getBoolean("battery") && !open(a, new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:" + a.getPackageName())))) {
                open(a, new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
            }
        }
        if (m.has("notifications") && !a.notificationsAllowed() && m.getBoolean("notifications")) {
            if (!blocked(a)) {
                p.edit().putBoolean(NOTIFY_ASKED, true).apply();
                a.askNotifications(granted -> {
                    try {
                        answer.give(state(a));
                    } catch (JSONException e) {
                        // nothing to say it with
                    }
                });
                return;
            }
            open(a, new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, a.getPackageName()));
        }
        answer.give(state(a));
    }

    /** A system screen; false when this phone has none. */
    private static boolean open(Activity a, Intent i) {
        try {
            a.startActivity(i);
            return true;
        } catch (ActivityNotFoundException e) {
            return false;
        }
    }

    private final BroadcastReceiver idle = new BroadcastReceiver() {
        @Override
        public void onReceive(Context c, Intent i) {
            PowerManager pm = getSystemService(PowerManager.class);
            if (pm != null && !pm.isDeviceIdleMode()) nudge();   // Doze over: the network is back in full
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        IntentFilter f = new IntentFilter(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) registerReceiver(idle, f, Context.RECEIVER_NOT_EXPORTED); else registerReceiver(idle, f);
    }

    @Override
    public int onStartCommand(Intent i, int flags, int startId) {
        Notification n = note();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) startForeground(NOTE, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE); else startForeground(NOTE, n);
        if (i != null && NUDGE.equals(i.getAction())) nudge();
        if (i != null && WAKE.equals(i.getAction())) {
            later.removeCallbacks(windowOver);
            later.postDelayed(windowOver, WAKE_MS);
        }
        AlarmManager am = getSystemService(AlarmManager.class);
        if (am != null) am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + NUDGE_MS, alarm());
        // Killed: not restarted by the system, which would bring the notification back without the page.
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        later.removeCallbacks(windowOver);
        AlarmManager am = getSystemService(AlarmManager.class);
        if (am != null) am.cancel(alarm());
        unregisterReceiver(idle);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent i) {
        return null;
    }

    private void nudge() {
        SigeloBridge b = page;
        if (b != null) b.nudge();
    }

    /** The alarm: this service again with NUDGE (explicit, not exported); one at a time, each start moves it on. */
    private PendingIntent alarm() {
        return PendingIntent.getService(this, 0, new Intent(this, StayConnected.class).setAction(NUDGE), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    /** "sigelo · connected": its own channel at low importance (no sound, no badge), no content, a tap opens the app. */
    private Notification note() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        NotificationChannel ch = new NotificationChannel(CHANNEL, getString(R.string.stay_channel), NotificationManager.IMPORTANCE_LOW);
        ch.setShowBadge(false);
        if (nm != null) nm.createNotificationChannel(ch);
        Intent open = new Intent(this, MainActivity.class).setAction(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        PendingIntent tap = PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle(getString(R.string.stay_title))
                .setCategory(Notification.CATEGORY_SERVICE)
                .setOngoing(true)
                .setShowWhen(false)
                .setContentIntent(tap)
                .build();
    }
}
