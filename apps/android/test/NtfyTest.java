// SPDX-License-Identifier: MIT
package io.sigelo.app;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/**
 * Ntfy.java on a desktop JVM (apps/android/test-push.mjs): the topic and endpoint, the stream's URL, the
 * JSON stream's lines as ntfy 2.38.2 writes them, the reconnect table, and the relay's wake carried as ntfy carries it (base64)
 * opening with WebPush. Prints "ALL PASS (n)" or the failures, exit 1.
 */
public final class NtfyTest {
    private static int n = 0, failed = 0;

    private static void ok(boolean cond, String what) {
        n++;
        if (!cond) {
            failed++;
            System.out.println("FAIL " + what);
        }
    }

    private static boolean throwsIae(Runnable r) {
        try {
            r.run();
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    public static void main(String[] args) throws Exception {
        // The topic: "up" + 12 of [A-Za-z0-9], 14 in all (ntfy's isUnifiedPushTopic); random, from the alphabet only.
        SecureRandom r = new SecureRandom();
        Set<String> seen = new HashSet<>();
        boolean shape = true;
        int[] counts = new int[128];
        for (int i = 0; i < 2000; i++) {
            String t = Ntfy.newTopic(r);
            shape &= t.length() == 14 && t.startsWith("up") && t.substring(2).chars().allMatch(c -> Ntfy.ALPHABET.indexOf(c) >= 0) && Ntfy.topic(t);
            seen.add(t);
            for (char c : t.substring(2).toCharArray()) counts[c]++;
        }
        ok(shape, "newTopic: up + 12 of [A-Za-z0-9], 14 characters, accepted by topic()");
        ok(seen.size() == 2000, "newTopic: 2000 draws, 2000 topics");
        long used = Ntfy.ALPHABET.chars().filter(c -> counts[c] > 0).count();
        ok(used == 62, "newTopic: every one of the 62 characters drawn over 24000 (" + used + ")");
        ok(!Ntfy.topic(null) && !Ntfy.topic("up") && !Ntfy.topic("upABCDEFGHIJK") && !Ntfy.topic("upABCDEFGHIJKLM") && !Ntfy.topic("xxABCDEFGHIJKL")
                && !Ntfy.topic("upABCDEFGHIJ-L") && !Ntfy.topic("upABCDEFGHIJ/L") && !Ntfy.topic("upABCDEFGHIJ\u00e9L") && Ntfy.topic("upABCDEFGHIJKL"),
                "topic(): exactly up + 12 alphanumerics; 13, 15, another prefix, '-', '/', a non-ASCII letter refused");

        // The endpoint (what the relay is given) and the stream (what the phone reads).
        ok(Ntfy.endpoint("upAbcdef012345").equals("https://push.sigelo.ai/upAbcdef012345?up=1"), "endpoint: https://push.sigelo.ai/<topic>?up=1 (the ntfy app's form)");
        ok(throwsIae(() -> Ntfy.endpoint("up/../x")) && throwsIae(() -> Ntfy.endpoint(null)) && throwsIae(() -> Ntfy.stream("news", null)), "endpoint, stream: refuse anything but a topic");
        ok(Ntfy.stream("upAbcdef012345", null).equals("https://push.sigelo.ai/upAbcdef012345/json"), "stream: no since at the first connect");
        ok(Ntfy.stream("upAbcdef012345", "Xy12AbCdEf34").equals("https://push.sigelo.ai/upAbcdef012345/json?since=Xy12AbCdEf34"), "stream: since the last message id");
        ok(Ntfy.stream("upAbcdef012345", "a&poll=1").equals("https://push.sigelo.ai/upAbcdef012345/json") && Ntfy.stream("upAbcdef012345", "").equals("https://push.sigelo.ai/upAbcdef012345/json"),
                "stream: a since that is not an id is dropped (no parameter injection)");

        // The stream's lines (ntfy 2.38.2's JSON stream).
        Ntfy.Event open = Ntfy.parse("{\"id\":\"T1lxGzAbcd12\",\"time\":1764072000,\"event\":\"open\",\"topic\":\"upAbcdef012345\"}");
        ok(open != null && open.event.equals("open") && open.id.equals("T1lxGzAbcd12") && open.message == null, "parse: open");
        Ntfy.Event ka = Ntfy.parse("{\"id\":\"k2\",\"time\":1764072045,\"event\":\"keepalive\",\"topic\":\"upAbcdef012345\"}");
        ok(ka != null && ka.event.equals("keepalive"), "parse: keepalive");
        Ntfy.Event txt = Ntfy.parse("{\"id\":\"m1\",\"time\":1,\"expires\":2,\"event\":\"message\",\"topic\":\"upAbcdef012345\",\"message\":\"h\\u00e9llo \\\"q\\\" \\ud83d\\ude00\",\"tags\":[\"a\",{\"b\":[1,-2.5e3,true,false,null]}],\"priority\":3}");
        ok(txt != null && txt.message.equals("h\u00e9llo \"q\" \ud83d\ude00") && Arrays.equals(txt.body(), txt.message.getBytes(StandardCharsets.UTF_8)), "parse: a text message, escapes and a surrogate pair; nested arrays and objects skipped");
        String[] bad = {"", " ", "not json", "[]", "\"open\"", "{\"event\":1}", "{}", "{\"event\":\"open\"", "{\"event\":\"open\"} x", "{\"event\":\"open\",\"event\":\"message\"}",
                "{\"event\":\"message\",\"id\":\"a/b\"}", "{\"event\":\"message\",\"message\":7}", "{\"event\":\"message\",\"encoding\":[]}", "{\"event\":\"open\",\"x\":01a}",
                "{\"event\":\"open\",\"x\":\"\\x\"}", "{\"event\":\"open\",\"x\":\"a\u0001\"}", "{\"event\":\"open\",\"x\":tru}", "{\"event\":\"open\",\"x\":-}", "{\"event\":\"open\",\"x\":1.}",
                "{\"event\":\"open\",\"x\":" + "[".repeat(40) + "]".repeat(40) + "}", "{\"event\":\"open\",\"x\":\"" + "a".repeat(Ntfy.LINE_MAX) + "\"}", null};
        int refused = 0;
        for (String b : bad) if (Ntfy.parse(b) == null) refused++;
        ok(refused == bad.length, "parse: " + refused + " of " + bad.length + " malformed lines refused (not an object, no event, duplicate key, bad id, bad types, bad escapes, control characters, too deep, too long)");
        Ntfy.Event unknown = Ntfy.parse("{\"event\":\"poll_request\",\"id\":\"p1\"}");
        ok(unknown != null && unknown.event.equals("poll_request") && unknown.body() == null, "parse: an event we do not use is read, carries no body");
        Ntfy.Event badB64 = Ntfy.parse("{\"event\":\"message\",\"id\":\"b1\",\"message\":\"!!notbase64\",\"encoding\":\"base64\"}");
        Ntfy.Event otherEnc = Ntfy.parse("{\"event\":\"message\",\"id\":\"b2\",\"message\":\"x\",\"encoding\":\"gzip\"}");
        ok(badB64 != null && badB64.body() == null && otherEnc != null && otherEnc.body() == null, "body: bad base64 and an unknown encoding give no body");

        // The relay's wake as ntfy carries it: the binary body base64 (server.go handleBodyAsMessageAutoDetect), opened with WebPush.
        byte[] uaPrivate = Base64.getUrlDecoder().decode("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94");
        byte[] uaPublic = Base64.getUrlDecoder().decode("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
        byte[] auth = Base64.getUrlDecoder().decode("BTBZMqHH6r4Tts7J_aSIgg");
        byte[] wakeBody = Base64.getUrlDecoder().decode("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_WltxQDr23ZlTPu6FJ-lJe9mCE1ds1aqnlkxh84dqQK5ZvIRol0qJAL4Pvsj2TZUMR");
        KeyPair fresh = WebPush.newKeys();
        ECPrivateKey ua = WebPush.scalar(uaPrivate, ((ECPublicKey) fresh.getPublic()).getParams());
        String line = "{\"id\":\"W4keUp000001\",\"time\":1764072100,\"expires\":1764115300,\"event\":\"message\",\"topic\":\"upAbcdef012345\",\"message\":\""
                + Base64.getEncoder().encodeToString(wakeBody) + "\",\"encoding\":\"base64\"}";
        Ntfy.Event wake = Ntfy.parse(line);
        ok(wake != null && wake.id.equals("W4keUp000001") && Arrays.equals(wake.body(), wakeBody) && WebPush.isWake(wake.body(), ua, uaPublic, auth),
                "a message carrying the relay's wake (relay/test/push.mjs WAKE_BODY, base64 as ntfy writes it) opens to WAKE; its id becomes since");
        byte[] other = wakeBody.clone();
        other[40] ^= 1;
        Ntfy.Event forged = Ntfy.parse("{\"event\":\"message\",\"id\":\"f1\",\"message\":\"" + Base64.getEncoder().encodeToString(other) + "\",\"encoding\":\"base64\"}");
        ok(forged != null && !WebPush.isWake(forged.body(), ua, uaPublic, auth) && !WebPush.isWake(txt.body(), ua, uaPublic, auth),
                "anyone may publish to the topic: a changed body or a text message is no wake");

        // Reconnect: the ntfy app's table, then its last value.
        long[] want = {5000, 10000, 15000, 20000, 30000, 45000, 60000, 120000, 120000, 120000};
        boolean table = true;
        for (int f = 1; f <= want.length; f++) table &= Ntfy.retryMs(f) == want[f - 1];
        ok(table && Ntfy.retryMs(1000) == 120000 && Ntfy.retryMs(0) == 5000 && Ntfy.retryMs(-3) == 5000, "retryMs: 5, 10, 15, 20, 30, 45, 60, 120 s, then 120 s; 0 or less as 1");

        if (failed > 0) {
            System.out.println(failed + " FAILED, " + (n - failed) + " passed");
            System.exit(1);
        }
        System.out.println("ALL PASS (" + n + ")");
    }
}
