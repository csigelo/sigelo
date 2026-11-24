// SPDX-License-Identifier: MIT
package io.sigelo.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Push (design/push.md §1 B, path B): a UnifiedPush connector written against the spec (AND_3), no library, no AndroidX,
 * no Kotlin. The user's distributor (ntfy, NextPush, Sunup, Conversations…) holds the one connection; the relay
 * (relay/push.mjs) POSTs a 32-byte encrypted wake to the endpoint it gave us when mail waits and no session is open.
 *
 * Connector, app → distributor (explicit broadcasts to the distributor's package):
 *   org.unifiedpush.android.distributor.REGISTER     token, application, message, pi (a PendingIntent: who we are)
 *   org.unifiedpush.android.distributor.UNREGISTER   token, application, pi
 *   org.unifiedpush.android.distributor.MESSAGE_ACK  token, id
 * Distributor → app (this receiver, exported; every one must name our token, which only we and the distributor know):
 *   org.unifiedpush.android.connector.NEW_ENDPOINT        token, endpoint   (https only, else ignored)
 *   org.unifiedpush.android.connector.REGISTRATION_FAILED token, reason
 *   org.unifiedpush.android.connector.UNREGISTERED        token
 *   org.unifiedpush.android.connector.TEMP_UNAVAILABLE    token
 *   org.unifiedpush.android.connector.MESSAGE             token, bytesMessage, id
 * and the service org.unifiedpush.android.connector.RAISE_TO_FOREGROUND (Raise, below) the distributor binds before a
 * MESSAGE, which lets this app start its foreground service from the background for a few seconds.
 *
 * A distributor is any package with a receiver for REGISTER (the manifest's queries entry lets us see them); none:
 * state "none", the page says so once and offers Stay connected. Several: the user picks (state "pick").
 *
 * The keys: a P-256 pair and a 16-byte auth secret (WebPush), made at the first registration; the private key and
 * the secret sealed under the keystore key "sigelo-push" (AES-256-GCM, no user authentication: a wake must open while
 * the phone is locked), the public half in the clear. They are given to the page (p256dh, auth) with the endpoint,
 * and the page's carrier gives all three to its relay over its signed session (sigelo-push/0).
 *
 * A MESSAGE that opens to WebPush.WAKE: acknowledged, then, when the page is alive (minimised, its process kept),
 * StayConnected for the wake window and {ev:"wake"} to the page, whose carrier logs in at once and fetches; its own
 * notifications follow. With no page (the app swiped away, or never opened since the phone started): one
 * notification "sigelo · New activity", no name, no count; a tap opens the app, which connects and fetches. Anything
 * else: acknowledged and dropped.
 *
 * SharedPreferences "sigelo" (one setting for the phone, not per profile): push_on, push_dist, push_token,
 * push_endpoint, push_state, push_reason, push_pub (base64url), push_keys (sealed).
 */
public final class UnifiedPush extends BroadcastReceiver {
    static final String DIST = "org.unifiedpush.android.distributor.", CONN = "org.unifiedpush.android.connector.";
    static final String REGISTER = DIST + "REGISTER", UNREGISTER = DIST + "UNREGISTER", ACK = DIST + "MESSAGE_ACK";
    static final String NEW_ENDPOINT = CONN + "NEW_ENDPOINT", FAILED = CONN + "REGISTRATION_FAILED", UNREGISTERED = CONN + "UNREGISTERED",
            TEMP = CONN + "TEMP_UNAVAILABLE", MESSAGE = CONN + "MESSAGE";
    static final String ON = "push_on", DISTRIBUTOR = "push_dist", TOKEN = "push_token", ENDPOINT = "push_endpoint", STATE = "push_state",
            REASON = "push_reason", PUB = "push_pub", KEYS = "push_keys";
    private static final String KEYSTORE = "AndroidKeyStore", ALIAS = "sigelo-push", WAKE_TAG = "wake";
    private static final int ENDPOINT_MAX = 1024, REASON_MAX = 200;

    private static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("sigelo", Context.MODE_PRIVATE);
    }

    /** Push switched on (wake mode Push). */
    static boolean on(Context c) {
        return prefs(c).getBoolean(ON, false);
    }

    /** The distributors installed: package names (not this app). */
    static List<String> distributors(Context c) {
        List<String> out = new ArrayList<>();
        PackageManager pm = c.getPackageManager();
        for (ResolveInfo r : pm.queryBroadcastReceivers(new Intent(REGISTER), 0)) {
            String p = r.activityInfo == null ? null : r.activityInfo.packageName;
            if (p != null && !p.equals(c.getPackageName()) && !out.contains(p)) out.add(p);
        }
        return out;
    }

    private static String label(Context c, String pkg) {
        try {
            PackageManager pm = c.getPackageManager();
            return pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString();
        } catch (PackageManager.NameNotFoundException e) {
            return pkg;
        }
    }

    /** Who we are, for the distributor (AND_3): a PendingIntent whose creator is this package. */
    private static PendingIntent pi(Context c) {
        return PendingIntent.getBroadcast(c, 0, new Intent("org.unifiedpush.register.dummy_app"), PendingIntent.FLAG_IMMUTABLE);
    }

    // ---------------------------------------------------------------- the keys, sealed

    private static SecretKey sealKey(boolean make) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        Key k = ks.getKey(ALIAS, null);
        if (k instanceof SecretKey) return (SecretKey) k;
        if (!make) return null;
        KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        g.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setRandomizedEncryptionRequired(true).build());
        return g.generateKey();
    }

    private static String b64(byte[] b) {
        return Base64.encodeToString(b, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }

    private static byte[] unb64(String s) {
        try {
            return s == null ? null : Base64.decode(s, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** New push keys: the public half kept in the clear, the private key and auth sealed ([IV 12][ct ‖ tag], AAD the alias). */
    private static void makeKeys(Context c) throws GeneralSecurityException, IOException {
        KeyPair kp = WebPush.newKeys();
        byte[] auth = new byte[16];
        new java.security.SecureRandom().nextBytes(auth);
        byte[] priv = WebPush.encoded(kp.getPrivate()), plain = new byte[priv.length + 16];
        System.arraycopy(priv, 0, plain, 0, priv.length);
        System.arraycopy(auth, 0, plain, priv.length, 16);
        Cipher ci = Cipher.getInstance("AES/GCM/NoPadding");
        ci.init(Cipher.ENCRYPT_MODE, sealKey(true));
        ci.updateAAD(ALIAS.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        byte[] ct = ci.doFinal(plain), iv = ci.getIV(), blob = new byte[12 + ct.length];
        System.arraycopy(iv, 0, blob, 0, 12);
        System.arraycopy(ct, 0, blob, 12, ct.length);
        prefs(c).edit().putString(PUB, b64(WebPush.raw((ECPublicKey) kp.getPublic()))).putString(KEYS, b64(blob)).apply();
    }

    /** The keys kept: { private key, auth }, or null (none, or the keystore key gone). */
    private static Object[] keys(Context c) {
        byte[] blob = unb64(prefs(c).getString(KEYS, null));
        if (blob == null || blob.length < 12 + 16 + 16) return null;
        try {
            SecretKey k = sealKey(false);
            if (k == null) return null;
            Cipher ci = Cipher.getInstance("AES/GCM/NoPadding");
            ci.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, Arrays.copyOfRange(blob, 0, 12)));
            ci.updateAAD(ALIAS.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            byte[] plain = ci.doFinal(blob, 12, blob.length - 12);
            ECPrivateKey priv = WebPush.pkcs8(Arrays.copyOf(plain, plain.length - 16));
            return new Object[] {priv, Arrays.copyOfRange(plain, plain.length - 16, plain.length)};
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            return null;
        }
    }

    // ---------------------------------------------------------------- the page's op

    /** The state the page reads: {on, state, reason, distributors: [{id, name}], distributor, endpoint, p256dh, auth}. */
    static JSONObject state(Context c) throws JSONException {
        SharedPreferences p = prefs(c);
        JSONArray ds = new JSONArray();
        for (String d : distributors(c)) ds.put(new JSONObject().put("id", d).put("name", label(c, d)));
        String endpoint = p.getString(ENDPOINT, null), dist = p.getString(DISTRIBUTOR, null);
        Object[] k = endpoint == null ? null : keys(c);
        JSONObject o = new JSONObject().put("on", on(c)).put("state", p.getString(STATE, "off")).put("distributors", ds)
                .put("distributor", dist == null ? JSONObject.NULL : dist).put("reason", p.getString(REASON, null) == null ? JSONObject.NULL : p.getString(REASON, null));
        if (endpoint != null && k != null) o.put("endpoint", endpoint).put("p256dh", p.getString(PUB, "")).put("auth", b64((byte[]) k[1]));
        else o.put("endpoint", JSONObject.NULL).put("p256dh", JSONObject.NULL).put("auth", JSONObject.NULL);
        return o;
    }

    /**
     * SigeloBridge "push" (main thread): {on?: boolean, distributor?: string} → state(). on true registers with the
     * distributor asked for (it must be installed: else refused "push"), else the one kept, else the only one installed;
     * several and none picked: state "pick"; none installed: state "none". on false unregisters (the keys go too).
     * Neither: the state only.
     */
    static JSONObject op(Context c, JSONObject m) throws SigeloBridge.Refused, JSONException {
        if (m.has("on") && !(m.opt("on") instanceof Boolean)) throw new SigeloBridge.Refused("push", "on: true or false");
        if (m.has("distributor") && !(m.opt("distributor") instanceof String)) throw new SigeloBridge.Refused("push", "distributor: a package name");
        if (!m.has("on")) return state(c);
        SharedPreferences p = prefs(c);
        if (!m.getBoolean("on")) {
            off(c);
            return state(c);
        }
        List<String> ds = distributors(c);
        String want = m.has("distributor") ? m.getString("distributor") : p.getString(DISTRIBUTOR, null);
        if (m.has("distributor") && !ds.contains(want)) throw new SigeloBridge.Refused("push", "no such distributor installed: " + want);
        if (want == null || !ds.contains(want)) want = ds.size() == 1 ? ds.get(0) : null;
        p.edit().putBoolean(ON, true).apply();
        if (want == null) {
            p.edit().putString(STATE, ds.isEmpty() ? "none" : "pick").remove(REASON).apply();
            return state(c);
        }
        if (!want.equals(p.getString(DISTRIBUTOR, null))) unregisterAt(c);   // another distributor: the old one forgets us
        register(c, want);
        return state(c);
    }

    private static void register(Context c, String dist) {
        SharedPreferences p = prefs(c);
        try {
            if (keys(c) == null) makeKeys(c);
        } catch (GeneralSecurityException | IOException e) {
            p.edit().putString(STATE, "failed").putString(REASON, "the push keys could not be made").apply();
            return;
        }
        String token = p.getString(TOKEN, null);
        if (token == null) token = UUID.randomUUID().toString();
        p.edit().putString(DISTRIBUTOR, dist).putString(TOKEN, token).putString(STATE, p.getString(ENDPOINT, null) == null ? "registering" : "ok").remove(REASON).apply();
        c.sendBroadcast(new Intent(REGISTER).setPackage(dist).putExtra("token", token).putExtra("application", c.getPackageName())
                .putExtra("message", "sigelo").putExtra("pi", pi(c)));
    }

    /** The distributor told to forget us; token and endpoint gone here. */
    private static void unregisterAt(Context c) {
        SharedPreferences p = prefs(c);
        String dist = p.getString(DISTRIBUTOR, null), token = p.getString(TOKEN, null);
        if (dist != null && token != null) {
            c.sendBroadcast(new Intent(UNREGISTER).setPackage(dist).putExtra("token", token).putExtra("application", c.getPackageName()).putExtra("pi", pi(c)));
        }
        p.edit().remove(TOKEN).remove(ENDPOINT).apply();
    }

    /** Push off: unregistered, the keys erased (a new registration makes new ones). */
    static void off(Context c) {
        unregisterAt(c);
        prefs(c).edit().putBoolean(ON, false).putString(STATE, "off").remove(REASON).remove(KEYS).remove(PUB).remove(DISTRIBUTOR).apply();
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE);
            ks.load(null);
            ks.deleteEntry(ALIAS);
        } catch (GeneralSecurityException | IOException e) {
            // gone already
        }
    }

    /** The app starts with push on: registered again (a distributor may have lost us; NEW_ENDPOINT comes back the same or new). */
    static void refresh(Context c) {
        SharedPreferences p = prefs(c);
        String dist = p.getString(DISTRIBUTOR, null);
        if (on(c) && dist != null && distributors(c).contains(dist)) register(c, dist);
        else if (on(c) && dist != null) p.edit().putString(STATE, "unregistered").putString(REASON, "the push app was removed").remove(TOKEN).remove(ENDPOINT).apply();
    }

    // ---------------------------------------------------------------- from the distributor

    @Override
    public void onReceive(Context c, Intent i) {
        String action = i.getAction(), token = i.getStringExtra("token");
        SharedPreferences p = prefs(c);
        String mine = p.getString(TOKEN, null);
        if (action == null || token == null || !token.equals(mine)) return;   // not ours (or another app's forgery)
        switch (action) {
            case NEW_ENDPOINT: {
                String e = i.getStringExtra("endpoint");
                if (e == null || !e.startsWith("https://") || e.length() > ENDPOINT_MAX) {
                    p.edit().putString(STATE, "failed").putString(REASON, "the push app gave an endpoint that is not https").apply();
                } else {
                    p.edit().putString(ENDPOINT, e).putString(STATE, "ok").remove(REASON).apply();
                }
                tell(c);
                break;
            }
            case FAILED: {
                String why = i.getStringExtra("reason");
                p.edit().putString(STATE, "failed").putString(REASON, why == null ? "refused" : why.substring(0, Math.min(why.length(), REASON_MAX))).remove(ENDPOINT).apply();
                tell(c);
                break;
            }
            case UNREGISTERED:
                p.edit().putString(STATE, "unregistered").remove(REASON).remove(TOKEN).remove(ENDPOINT).apply();
                tell(c);
                break;
            case TEMP:
                p.edit().putString(STATE, "unavailable").apply();
                tell(c);
                break;
            case MESSAGE: {
                String id = i.getStringExtra("id"), dist = p.getString(DISTRIBUTOR, null);
                if (id != null && dist != null) c.sendBroadcast(new Intent(ACK).setPackage(dist).putExtra("token", token).putExtra("id", id));
                byte[] body = i.getByteArrayExtra("bytesMessage");
                Object[] k = keys(c);
                byte[] pub = unb64(p.getString(PUB, null));
                if (body != null && k != null && pub != null && WebPush.isWake(body, (ECPrivateKey) k[0], pub, (byte[]) k[1])) wake(c);
                break;
            }
            default:
                break;
        }
    }

    /** The page told the new state ({ev:"push", …state()}), when it is open. */
    private static void tell(Context c) {
        SigeloBridge b = StayConnected.page;
        if (b == null) return;
        try {
            b.pushChanged(state(c));
        } catch (JSONException e) {
            // nothing to say it with
        }
    }

    /** A wake: the page alive → the service for the wake window and {ev:"wake"}; else the one notification. */
    static void wake(Context c) {
        SigeloBridge b = StayConnected.page;
        if (b != null) {
            StayConnected.wake(c);
            if (b.wake()) return;
        }
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        boolean allowed = nm != null && nm.areNotificationsEnabled()
                && (Build.VERSION.SDK_INT < 33 || c.checkSelfPermission("android.permission.POST_NOTIFICATIONS") == PackageManager.PERMISSION_GRANTED);
        if (!allowed) return;
        nm.createNotificationChannel(new NotificationChannel(SigeloBridge.CHANNEL, c.getString(R.string.notify_channel), NotificationManager.IMPORTANCE_DEFAULT));
        Intent open = new Intent(c, MainActivity.class).setAction(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        PendingIntent tap = PendingIntent.getActivity(c, WAKE_TAG.hashCode(), open, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        nm.notify(WAKE_TAG, WAKE_TAG.hashCode(), new Notification.Builder(c, SigeloBridge.CHANNEL)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle(c.getString(R.string.app_name))
                .setContentText(c.getString(R.string.push_wake))
                .setCategory(Notification.CATEGORY_MESSAGE)
                .setVisibility(Notification.VISIBILITY_PUBLIC)
                .setAutoCancel(true)
                .setContentIntent(tap)
                .build());
    }

    /** The app is open again: the wake's notification has done its work. */
    static void seen(Context c) {
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        if (nm != null) nm.cancel(WAKE_TAG, WAKE_TAG.hashCode());
    }

    /**
     * RAISE_TO_FOREGROUND (AND_3): the distributor binds this before a MESSAGE; while bound, this app counts as in front, so
     * the receiver may start StayConnected. It does nothing else.
     */
    public static final class Raise extends Service {
        private final IBinder binder = new Binder();

        @Override
        public IBinder onBind(Intent i) {
            return binder;
        }
    }
}
