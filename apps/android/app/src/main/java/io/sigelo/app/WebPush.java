// SPDX-License-Identifier: MIT
package io.sigelo.app;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC 8291 (Message Encryption for Web Push) with RFC 8188 aes128gcm, the receiving side, in platform crypto only: P-256
 * ECDH, HKDF over HMAC-SHA256, AES-128-GCM (design/push.md §1 B). No Android import: apps/android/test/WebPushTest.java runs
 * it on a desktop JVM against RFC 8291's Appendix A and the sigelo wake vector of relay/test/push.mjs.
 *
 * The relay (relay/push.mjs) sends one thing, WAKE: 32 bytes, the same for every cause. open() → the plaintext of a
 * one-record body; a wake is only a body whose plaintext is exactly WAKE.
 */
final class WebPush {
    private WebPush() {}

    /** relay/push.mjs WAKE: "sigelo-push/0 wake", then zeros, 32 bytes. */
    static final byte[] WAKE = Arrays.copyOf("sigelo-push/0 wake".getBytes(StandardCharsets.UTF_8), 32);
    /** The largest body taken: one record of the relay's 4096 (RFC 8188 rs). */
    static final int BODY_MAX = 4096;

    /** A new P-256 key pair: the push keys (p256dh is its public half, raw). */
    static KeyPair newKeys() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    /** The uncompressed point, 65 bytes: 0x04 ‖ X ‖ Y (p256dh). */
    static byte[] raw(ECPublicKey k) {
        byte[] out = new byte[65];
        out[0] = 4;
        fixed(k.getW().getAffineX(), out, 1);
        fixed(k.getW().getAffineY(), out, 33);
        return out;
    }

    private static void fixed(BigInteger v, byte[] out, int at) {
        byte[] b = v.toByteArray();
        int n = Math.min(b.length, 32);
        System.arraycopy(b, b.length - n, out, at + 32 - n, n);
    }

    /** An uncompressed point on the curve of params → its public key; throws for anything else. */
    static ECPublicKey point(byte[] raw, ECParameterSpec params) throws GeneralSecurityException {
        if (raw == null || raw.length != 65 || raw[0] != 4) throw new GeneralSecurityException("not an uncompressed P-256 point");
        ECPoint w = new ECPoint(new BigInteger(1, Arrays.copyOfRange(raw, 1, 33)), new BigInteger(1, Arrays.copyOfRange(raw, 33, 65)));
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, params));
    }

    /** A private key from its PKCS#8 encoding (as kept, sealed, by UnifiedPush). */
    static ECPrivateKey pkcs8(byte[] der) throws GeneralSecurityException {
        return (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    /** A private key from its 32-byte scalar on the curve of params (the test vectors give it so). */
    static ECPrivateKey scalar(byte[] d, ECParameterSpec params) throws GeneralSecurityException {
        return (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1, d), params));
    }

    /** HKDF-SHA256 (RFC 5869), extract then one block of expand: len ≤ 32. */
    static byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int len) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(info);
        mac.update((byte) 1);
        return Arrays.copyOf(mac.doFinal(), len);
    }

    private static byte[] cat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int at = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, at, p.length);
            at += p.length;
        }
        return out;
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * RFC 8291 §3.4 / RFC 8188 §2, one record: body = salt (16) ‖ rs (4) ‖ idlen (1) ‖ keyid (the sender's 65-byte public
     * key) ‖ ciphertext. key: the user agent's private key, p256dh its raw public half, auth the 16-byte secret.
     * → the plaintext; throws for any body that is not one whole last record under these keys.
     */
    static byte[] open(byte[] body, ECPrivateKey key, byte[] p256dh, byte[] auth) throws GeneralSecurityException {
        if (body == null || body.length < 21 + 65 + 17 || body.length > BODY_MAX) throw new GeneralSecurityException("not an aes128gcm body of one record");
        byte[] salt = Arrays.copyOfRange(body, 0, 16);
        long rs = ((body[16] & 0xFFL) << 24) | ((body[17] & 0xFF) << 16) | ((body[18] & 0xFF) << 8) | (body[19] & 0xFF);
        int idlen = body[20] & 0xFF;
        if (idlen != 65 || rs < 18 || body.length - 21 - idlen > rs) throw new GeneralSecurityException("not a P-256 keyid, or more than one record");
        byte[] asPublic = Arrays.copyOfRange(body, 21, 21 + idlen), ct = Arrays.copyOfRange(body, 21 + idlen, body.length);
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(key);
        ka.doPhase(point(asPublic, key.getParams()), true);
        byte[] secret = ka.generateSecret();
        byte[] ikm = hkdf(auth, secret, cat(ascii("WebPush: info"), new byte[] {0}, p256dh, asPublic), 32);
        byte[] cek = hkdf(salt, ikm, cat(ascii("Content-Encoding: aes128gcm"), new byte[] {0}), 16);
        byte[] nonce = hkdf(salt, ikm, cat(ascii("Content-Encoding: nonce"), new byte[] {0}), 12);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, nonce));
        byte[] rec = c.doFinal(ct);
        // Padding is zeros after the delimiter; the one record is the last: 0x02.
        int end = rec.length - 1;
        while (end >= 0 && rec[end] == 0) end--;
        if (end < 0 || rec[end] != 2) throw new GeneralSecurityException("not the last record");
        return Arrays.copyOf(rec, end);
    }

    /** Is this body the relay's wake for these keys? */
    static boolean isWake(byte[] body, ECPrivateKey key, byte[] p256dh, byte[] auth) {
        try {
            return Arrays.equals(open(body, key, p256dh, auth), WAKE);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** The private key's PKCS#8 bytes (kept sealed). */
    static byte[] encoded(PrivateKey k) {
        return k.getEncoded();
    }
}
