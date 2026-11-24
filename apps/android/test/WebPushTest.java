// SPDX-License-Identifier: MIT
package io.sigelo.app;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;

/**
 * WebPush.java on a desktop JVM (apps/android/test-push.mjs compiles and runs it when a JDK is there): RFC 8291 Appendix A
 * opened byte for byte, the sigelo wake vector of relay/test/push.mjs (WAKE_BODY: the RFC's keys and salt), and what must
 * not open. Prints "ALL PASS (n)" or the failures, exit 1.
 */
public final class WebPushTest {
    private static int n = 0, failed = 0;

    private static void ok(boolean cond, String what) {
        n++;
        if (!cond) {
            failed++;
            System.out.println("FAIL " + what);
        }
    }

    private static byte[] b(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    public static void main(String[] args) throws Exception {
        byte[] uaPrivate = b("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94");
        byte[] uaPublic = b("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
        byte[] auth = b("BTBZMqHH6r4Tts7J_aSIgg");
        byte[] rfcBody = b("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN");
        byte[] wakeBody = b("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_WltxQDr23ZlTPu6FJ-lJe9mCE1ds1aqnlkxh84dqQK5ZvIRol0qJAL4Pvsj2TZUMR");

        KeyPair fresh = WebPush.newKeys();
        ECPrivateKey ua = WebPush.scalar(uaPrivate, ((ECPublicKey) fresh.getPublic()).getParams());
        ok(Arrays.equals(WebPush.raw(WebPush.point(uaPublic, ua.getParams())), uaPublic), "raw(point(p256dh)): the RFC's user agent key round-trips");
        ok(new String(WebPush.open(rfcBody, ua, uaPublic, auth), StandardCharsets.UTF_8).equals("When I grow up, I want to be a watermelon"), "RFC 8291 Appendix A: the example opens to its message");
        ok(WebPush.WAKE.length == 32 && new String(WebPush.WAKE, 0, 18, StandardCharsets.UTF_8).equals("sigelo-push/0 wake"), "WAKE: 32 bytes, the label then zeros (relay/push.mjs)");
        ok(WebPush.isWake(wakeBody, ua, uaPublic, auth), "the sigelo wake vector (relay/test/push.mjs WAKE_BODY) is a wake");
        ok(!WebPush.isWake(rfcBody, ua, uaPublic, auth), "the RFC's message is not a wake (opens, but not to WAKE)");
        byte[] otherAuth = auth.clone();
        otherAuth[0] ^= 1;
        ok(!WebPush.isWake(wakeBody, ua, uaPublic, otherAuth), "another auth secret: not a wake");
        byte[] flipped = wakeBody.clone();
        flipped[flipped.length - 1] ^= 1;
        ok(!WebPush.isWake(flipped, ua, uaPublic, auth), "a flipped tag bit: not a wake");
        ok(!WebPush.isWake(Arrays.copyOf(wakeBody, 50), ua, uaPublic, auth) && !WebPush.isWake(null, ua, uaPublic, auth) && !WebPush.isWake(new byte[5000], ua, uaPublic, auth), "short, null, oversized: not a wake, no exception");
        ECPrivateKey kept = WebPush.pkcs8(WebPush.encoded(fresh.getPrivate()));
        ok(kept.getS().equals(((ECPrivateKey) fresh.getPrivate()).getS()) && WebPush.raw((ECPublicKey) fresh.getPublic()).length == 65, "a new key pair: PKCS#8 round-trip, a 65-byte p256dh");
        byte[] sixteen = WebPush.hkdf(new byte[16], new byte[32], new byte[0], 16);
        ok(sixteen.length == 16, "hkdf: one block, cut to the length asked");

        if (failed > 0) {
            System.out.println(failed + " FAILED, " + (n - failed) + " passed");
            System.exit(1);
        }
        System.out.println("ALL PASS (" + n + ")");
    }
}
