// SPDX-License-Identifier: MIT
package io.sigelo.app;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Person;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.media.AudioAttributes;
import android.net.ConnectivityManager;
import android.net.Network;
import android.media.AudioDeviceInfo;
import android.media.AudioFocusRequest;
import android.media.AudioManager;
import android.media.Ringtone;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.IBinder;
import android.os.PowerManager;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.os.VibratorManager;

/**
 * A voice call's audio (design/calls.md §4, §5; apps/contact/call.mjs; the page's side apps/web/platform-android.mjs
 * callAudio). The media itself is the WebView's own RTCPeerConnection: this class only holds what Android needs around it.
 * Three bridge operations (SigeloBridge "call", "call-speaker", "call-ring"), all on the main thread:
 *
 *   call {on, name}   on: this service in the foreground, type microphone, started while the activity is on the screen (the
 *          page asks at Call or Accept, a tap), so the microphone stays allowed with the screen locked or another app in
 *          front (Android 11+ allows background capture only so); its ongoing-call notification (Android 12+: CallStyle,
 *          the name, a timer, Hang up; before: the same as an ordinary ongoing notification); audio mode IN_COMMUNICATION,
 *          voice-call focus, the earpiece; the proximity lock blanks the screen at the ear. off: all of it undone, stopped.
 *   call-speaker {on}  the loudspeaker (the proximity lock let go) or the earpiece again.
 *   call-ring {on, name}  a call coming while the app runs (on the screen, or kept by Stay connected): the default ringtone
 *          and a repeating vibration as the ringer mode allows (silent: neither; vibrate: the vibration only), and a heads-up
 *          notification (channel "calls", the caller's name; the lock screen's version says only "Incoming call"), whose
 *          tap opens the app on the call screen. off: both stop (by themselves after 75 s, a page that never said off). The app closed: nothing rings (design §5): the push build
 *          (design/push.md) adds a full-screen ring here (USE_FULL_SCREEN_INTENT), Accept opening the activity before this
 *          service starts, as Android 14 requires.
 *
 * Roaming (2026-11-24): while a call lasts, the default network is watched (registerDefaultNetworkCallback,
 * ACCESS_NETWORK_STATE, no prompt); a change (Wi-Fi to mobile data, a new network) goes to the page as {ev:"network"}, and
 * the caller's page restarts ICE at once instead of waiting for the old path to time out.
 *
 * Hang up in the notification comes back here (ACTION_HANGUP) and goes to the page as {ev:"hangup"}: its Line ends the
 * call as the page's Hang up does. Nothing is recorded; Bluetooth headsets follow the system (switching later).
 */
public final class CallService extends Service {
    static final String CHANNEL_CALL = "call", CHANNEL_RING = "calls", ACTION_HANGUP = "io.sigelo.app.HANGUP", EXTRA_NAME = "name";
    private static final int NOTE_CALL = 2, NOTE_RING = 3;
    private static final long[] BUZZ = {0, 800, 1200};
    /** A ring lives at most this long (call.mjs EXP_S, 60 s, and a margin): stopped here even if the page never says off. */
    private static final long RING_MAX_MS = 75_000L;
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static Context appContext;
    private static final Runnable RING_OVER = () -> ring(appContext, false, null);

    private static AudioFocusRequest focus;
    private static PowerManager.WakeLock proximity;
    private static Ringtone tone;
    private static Vibrator buzz;
    private static boolean on, speakerOn;
    private static int modeBefore = AudioManager.MODE_NORMAL;
    private static ConnectivityManager.NetworkCallback watch;
    private static Network lastNet;

    // ---------------------------------------------------------------- the bridge's operations

    /** The call's audio on (name: the contact's, as the page gives it) or off. */
    static void call(Context c, boolean want, String name) throws SigeloBridge.Refused {
        Context app = c.getApplicationContext();
        if (want) {
            if (c.checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) throw new SigeloBridge.Refused("mic_permission", "the microphone is not allowed for sigelo");
            ring(app, false, null);
            app.startForegroundService(new Intent(app, CallService.class).putExtra(EXTRA_NAME, name == null ? "" : name));
            audioOn(app);
        } else {
            audioOff(app);
            app.stopService(new Intent(app, CallService.class));
        }
    }

    /** The loudspeaker on, or the earpiece. */
    static void speaker(Context c, boolean want) throws SigeloBridge.Refused {
        Context app = c.getApplicationContext();
        if (!on) throw new SigeloBridge.Refused("call_state", "no call going on");
        route(app, want);
    }

    /** The ring here (a call coming while the app runs), or its end. */
    @SuppressWarnings("deprecation")   // vibrate(effect, attributes): the one form API 28 to 35 share
    static void ring(Context c, boolean want, String name) {
        Context app = c.getApplicationContext();
        NotificationManager nm = app.getSystemService(NotificationManager.class);
        MAIN.removeCallbacks(RING_OVER);
        if (tone != null) { tone.stop(); tone = null; }
        if (buzz != null) { buzz.cancel(); buzz = null; }
        if (nm != null) nm.cancel(NOTE_RING);
        if (!want) return;
        appContext = app;
        MAIN.postDelayed(RING_OVER, RING_MAX_MS);
        AudioManager am = app.getSystemService(AudioManager.class);
        int mode = am == null ? AudioManager.RINGER_MODE_NORMAL : am.getRingerMode();
        AudioAttributes ringing = new AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE).setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build();
        if (mode == AudioManager.RINGER_MODE_NORMAL) {
            Uri u = RingtoneManager.getActualDefaultRingtoneUri(app, RingtoneManager.TYPE_RINGTONE);
            Ringtone r = u == null ? null : RingtoneManager.getRingtone(app, u);
            if (r != null) {
                r.setAudioAttributes(ringing);
                r.setLooping(true);
                r.play();
                tone = r;
            }
        }
        if (mode != AudioManager.RINGER_MODE_SILENT && app.checkSelfPermission(Manifest.permission.VIBRATE) == PackageManager.PERMISSION_GRANTED) {
            Vibrator v = Build.VERSION.SDK_INT >= 31 ? app.getSystemService(VibratorManager.class).getDefaultVibrator() : app.getSystemService(Vibrator.class);
            if (v != null && v.hasVibrator()) {
                v.vibrate(VibrationEffect.createWaveform(BUZZ, 1), ringing);
                buzz = v;
            }
        }
        if (nm == null || !nm.areNotificationsEnabled()) return;
        NotificationChannel ch = new NotificationChannel(CHANNEL_RING, app.getString(R.string.call_ring_channel), NotificationManager.IMPORTANCE_HIGH);
        ch.setSound(null, null);   // the ringtone above, as the ringer mode allows: not the channel's
        ch.enableVibration(false);
        nm.createNotificationChannel(ch);
        Notification shown = new Notification.Builder(app, CHANNEL_RING)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle(app.getString(R.string.app_name))
                .setContentText(app.getString(R.string.call_incoming))
                .setCategory(Notification.CATEGORY_CALL)
                .build();
        Notification n = new Notification.Builder(app, CHANNEL_RING)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle(name == null || name.isEmpty() ? app.getString(R.string.app_name) : name)
                .setContentText(app.getString(R.string.call_incoming))
                .setCategory(Notification.CATEGORY_CALL)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .setPublicVersion(shown)
                .setOngoing(true)
                .setContentIntent(openApp(app))
                .build();
        nm.notify(NOTE_RING, n);
    }

    // ---------------------------------------------------------------- the audio around a call

    private static void audioOn(Context app) {
        AudioManager am = app.getSystemService(AudioManager.class);
        if (am != null) {
            if (!on) modeBefore = am.getMode();
            am.setMode(AudioManager.MODE_IN_COMMUNICATION);
            if (focus == null) {
                focus = new AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN_TRANSIENT)
                        .setAudioAttributes(new AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION).setContentType(AudioAttributes.CONTENT_TYPE_SPEECH).build())
                        .build();
                am.requestAudioFocus(focus);
            }
        }
        on = true;
        route(app, false);
        roam(app, true);
    }

    /** The default network watched while a call lasts: a change → {ev:"network"} to the page (main thread). */
    private static void roam(Context app, boolean want) {
        ConnectivityManager cm = app.getSystemService(ConnectivityManager.class);
        if (cm == null) return;
        if (!want) {
            if (watch != null) { try { cm.unregisterNetworkCallback(watch); } catch (IllegalArgumentException e) { /* not registered */ } }
            watch = null;
            lastNet = null;
            return;
        }
        if (watch != null) return;
        Handler main = new Handler(Looper.getMainLooper());
        watch = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network n) {
                main.post(() -> {
                    // The first call is the network in use at registration: not a change.
                    boolean changed = lastNet != null && !lastNet.equals(n);
                    lastNet = n;
                    SigeloBridge b = StayConnected.page;
                    if (changed && b != null) b.network();
                });
            }
        };
        try { cm.registerDefaultNetworkCallback(watch); } catch (RuntimeException e) { watch = null; }
    }

    @SuppressWarnings("deprecation")   // setSpeakerphoneOn: before Android 12 only
    private static void audioOff(Context app) {
        AudioManager am = app.getSystemService(AudioManager.class);
        if (am != null && on) {
            if (Build.VERSION.SDK_INT >= 31) am.clearCommunicationDevice();
            else am.setSpeakerphoneOn(false);
            if (focus != null) am.abandonAudioFocusRequest(focus);
            am.setMode(modeBefore);
        }
        focus = null;
        on = false;
        speakerOn = false;
        hold(app, false);
        roam(app, false);
    }

    /** The speaker or the earpiece; the proximity lock only at the ear. */
    @SuppressWarnings("deprecation")
    private static void route(Context app, boolean loud) {
        AudioManager am = app.getSystemService(AudioManager.class);
        if (am != null) {
            if (Build.VERSION.SDK_INT >= 31) {
                int want = loud ? AudioDeviceInfo.TYPE_BUILTIN_SPEAKER : AudioDeviceInfo.TYPE_BUILTIN_EARPIECE;
                for (AudioDeviceInfo d : am.getAvailableCommunicationDevices()) {
                    if (d.getType() == want) { am.setCommunicationDevice(d); break; }
                }
            } else {
                am.setSpeakerphoneOn(loud);
            }
        }
        speakerOn = loud;
        hold(app, !loud);
    }

    /** The proximity wake lock: the screen off at the ear (no stray touches), back on once the phone leaves it. */
    private static void hold(Context app, boolean want) {
        PowerManager pm = app.getSystemService(PowerManager.class);
        if (want && proximity == null && pm != null && pm.isWakeLockLevelSupported(PowerManager.PROXIMITY_SCREEN_OFF_WAKE_LOCK)) {
            proximity = pm.newWakeLock(PowerManager.PROXIMITY_SCREEN_OFF_WAKE_LOCK, "sigelo:call");
            proximity.setReferenceCounted(false);
            proximity.acquire(4 * 60 * 60 * 1000L);   // a bound for a call left on; let go at its end
        } else if (!want && proximity != null) {
            if (proximity.isHeld()) proximity.release(PowerManager.RELEASE_FLAG_WAIT_FOR_NO_PROXIMITY);
            proximity = null;
        }
    }

    private static PendingIntent openApp(Context app) {
        Intent i = new Intent(app, MainActivity.class).setAction(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        return PendingIntent.getActivity(app, NOTE_CALL, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    // ---------------------------------------------------------------- the service: the foreground, its notification

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_HANGUP.equals(intent.getAction())) {
            // The notification's Hang up: the page's Line ends the call (and turns this off through "call").
            SigeloBridge b = StayConnected.page;
            if (b != null) b.hangup();
            else { audioOff(getApplicationContext()); stopSelf(); }
            return START_NOT_STICKY;
        }
        String name = intent == null ? "" : intent.getStringExtra(EXTRA_NAME);
        NotificationManager nm = getSystemService(NotificationManager.class);
        NotificationChannel ch = new NotificationChannel(CHANNEL_CALL, getString(R.string.call_channel), NotificationManager.IMPORTANCE_LOW);
        ch.setSound(null, null);
        if (nm != null) nm.createNotificationChannel(ch);
        PendingIntent hangUp = PendingIntent.getService(this, NOTE_CALL, new Intent(this, CallService.class).setAction(ACTION_HANGUP), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        String who = name == null || name.isEmpty() ? getString(R.string.app_name) : name;
        Notification.Builder b = new Notification.Builder(this, CHANNEL_CALL)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle(who)
                .setContentText(getString(R.string.call_ongoing))
                .setCategory(Notification.CATEGORY_CALL)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .setPublicVersion(new Notification.Builder(this, CHANNEL_CALL).setSmallIcon(R.drawable.ic_launcher_foreground)
                        .setContentTitle(getString(R.string.app_name)).setContentText(getString(R.string.call_ongoing)).build())
                .setOngoing(true)
                .setUsesChronometer(true)
                .setWhen(System.currentTimeMillis())
                .setContentIntent(openApp(this));
        if (Build.VERSION.SDK_INT >= 31) b.setStyle(Notification.CallStyle.forOngoingCall(new Person.Builder().setName(who).build(), hangUp));
        else b.addAction(new Notification.Action.Builder(null, getString(R.string.call_hangup), hangUp).build());
        Notification n = b.build();
        if (Build.VERSION.SDK_INT >= 30) startForeground(NOTE_CALL, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE);
        else startForeground(NOTE_CALL, n);
        return START_NOT_STICKY;
    }

    @Override
    public void onTaskRemoved(Intent root) {
        // The app swiped away: its page (and the call) are gone; nothing to hold.
        audioOff(getApplicationContext());
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent i) {
        return null;
    }
}
