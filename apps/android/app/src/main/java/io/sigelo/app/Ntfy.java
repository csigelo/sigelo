// SPDX-License-Identifier: MIT
package io.sigelo.app;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The built-in push client's pure part (design/push.md §6): the topic, the endpoint, the stream's URL, one line of the
 * ntfy JSON stream read, the reconnect delays. java.* only: test/NtfyTest.java runs it on a desktop JVM (test-push.mjs).
 *
 * The topic is "up" and 12 characters of [A-Za-z0-9], as the ntfy app makes it (up/BroadcastReceiver.kt): ntfy 2.38.2
 * takes a topic as UnifiedPush only at exactly 14 characters (server_rate_visitor.go isUnifiedPushTopic), and the relay's
 * wake (Content-Encoding: aes128gcm) is a UnifiedPush publish, refused 507 for good on any other length. 12 of 62
 * characters: 71 bits; the endpoint URL is the capability.
 */
final class Ntfy {
    static final String BASE = "https://push.sigelo.ai";
    static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static final int TOPIC_RANDOM = 12;
    private static final Pattern TOPIC = Pattern.compile("^up[A-Za-z0-9]{12}$"), ID = Pattern.compile("^[A-Za-z0-9]{1,64}$");
    /** The ntfy app's reconnect table (service/JsonConnection.kt RETRY_SECONDS), then its last value. */
    static final int[] RETRY_S = {5, 10, 15, 20, 30, 45, 60, 120};
    /** Two of the server's 45 s keepalives; the connect itself 15 s. */
    static final int READ_MS = 90_000, CONNECT_MS = 15_000;
    /** A line longer than this is no message of ours (the server's limit is 4 KiB, base64 a third more). */
    static final int LINE_MAX = 16_384;

    private Ntfy() {
    }

    /** A new topic: "up" and 12 random characters of ALPHABET (SecureRandom.nextInt: uniform, no modulo bias). */
    static String newTopic(SecureRandom r) {
        StringBuilder s = new StringBuilder("up");
        for (int i = 0; i < TOPIC_RANDOM; i++) s.append(ALPHABET.charAt(r.nextInt(ALPHABET.length())));
        return s.toString();
    }

    static boolean topic(String t) {
        return t != null && TOPIC.matcher(t).matches();
    }

    /** The endpoint the relay posts its wake to: the form the ntfy app gives (Util.kt topicUrlUp). */
    static String endpoint(String topic) {
        if (!topic(topic)) throw new IllegalArgumentException("not a push topic");
        return BASE + "/" + topic + "?up=1";
    }

    /** The JSON stream of topic, from after message since (an id the server gave) or from now. */
    static String stream(String topic, String since) {
        if (!topic(topic)) throw new IllegalArgumentException("not a push topic");
        return BASE + "/" + topic + "/json" + (since != null && ID.matcher(since).matches() ? "?since=" + since : "");
    }

    /** The delay before attempt n + 1 after n failures in a row (n ≥ 1), in ms. */
    static long retryMs(int failures) {
        int i = Math.max(0, Math.min(failures, RETRY_S.length) - 1);
        return RETRY_S[i] * 1000L;
    }

    /** One event of the stream: open, keepalive, message, poll_request…; id, message and encoding when there. */
    static final class Event {
        final String event, id, message, encoding;

        Event(String event, String id, String message, String encoding) {
            this.event = event;
            this.id = id;
            this.message = message;
            this.encoding = encoding;
        }

        /** A message's body: base64 decoded when the server says so (a binary UnifiedPush body), else its UTF-8. Null: none or bad base64. */
        byte[] body() {
            if (message == null) return null;
            if ("base64".equals(encoding)) {
                try {
                    return Base64.getDecoder().decode(message);
                } catch (IllegalArgumentException e) {
                    return null;
                }
            }
            return encoding == null || encoding.isEmpty() ? message.getBytes(StandardCharsets.UTF_8) : null;
        }
    }

    /** One line of the stream → its event, or null (not one JSON object, no "event" string, an id or field of the wrong type). */
    static Event parse(String line) {
        if (line == null || line.length() > LINE_MAX) return null;
        Object v;
        try {
            Json j = new Json(line);
            v = j.value(0);
            j.space();
            if (j.i != line.length()) return null;
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (!(v instanceof Map)) return null;
        Map<?, ?> m = (Map<?, ?>) v;
        Object ev = m.get("event"), id = m.get("id"), msg = m.get("message"), enc = m.get("encoding");
        if (!(ev instanceof String)) return null;
        if (id != null && !(id instanceof String && ID.matcher((String) id).matches())) return null;
        if (msg != null && !(msg instanceof String) || enc != null && !(enc instanceof String)) return null;
        return new Event((String) ev, (String) id, (String) msg, (String) enc);
    }

    /** A JSON number, kept as its text (none is used; a type of its own so that it is never taken for a string). */
    private static final class Num {
        final String text;

        Num(String text) {
            this.text = text;
        }
    }

    /** A strict JSON reader for one line: objects (duplicate keys refused), arrays, strings, numbers (Num), literals; depth 16. */
    private static final class Json {
        final String s;
        int i;

        Json(String s) {
            this.s = s;
        }

        void space() {
            while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == '\t' || s.charAt(i) == '\r' || s.charAt(i) == '\n')) i++;
        }

        private IllegalArgumentException bad() {
            return new IllegalArgumentException("not JSON at " + i);
        }

        Object value(int depth) {
            if (depth > 16) throw bad();
            space();
            if (i >= s.length()) throw bad();
            char c = s.charAt(i);
            if (c == '{') return object(depth);
            if (c == '[') return array(depth);
            if (c == '"') return string();
            if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
            if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            if (s.startsWith("null", i)) { i += 4; return null; }
            return number();
        }

        private Map<String, Object> object(int depth) {
            Map<String, Object> m = new LinkedHashMap<>();
            i++;
            space();
            if (i < s.length() && s.charAt(i) == '}') { i++; return m; }
            while (true) {
                space();
                if (i >= s.length() || s.charAt(i) != '"') throw bad();
                String k = string();
                space();
                if (i >= s.length() || s.charAt(i) != ':') throw bad();
                i++;
                if (m.containsKey(k)) throw bad();
                m.put(k, value(depth + 1));
                space();
                if (i >= s.length()) throw bad();
                char c = s.charAt(i++);
                if (c == '}') return m;
                if (c != ',') throw bad();
            }
        }

        private List<Object> array(int depth) {
            List<Object> a = new ArrayList<>();
            i++;
            space();
            if (i < s.length() && s.charAt(i) == ']') { i++; return a; }
            while (true) {
                a.add(value(depth + 1));
                space();
                if (i >= s.length()) throw bad();
                char c = s.charAt(i++);
                if (c == ']') return a;
                if (c != ',') throw bad();
            }
        }

        private String string() {
            StringBuilder b = new StringBuilder();
            i++;
            while (true) {
                if (i >= s.length()) throw bad();
                char c = s.charAt(i++);
                if (c == '"') return b.toString();
                if (c < 0x20) throw bad();
                if (c != '\\') { b.append(c); continue; }
                if (i >= s.length()) throw bad();
                char e = s.charAt(i++);
                switch (e) {
                    case '"': case '\\': case '/': b.append(e); break;
                    case 'b': b.append('\b'); break;
                    case 'f': b.append('\f'); break;
                    case 'n': b.append('\n'); break;
                    case 'r': b.append('\r'); break;
                    case 't': b.append('\t'); break;
                    case 'u':
                        if (i + 4 > s.length()) throw bad();
                        try {
                            b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        } catch (NumberFormatException x) {
                            throw bad();
                        }
                        i += 4;
                        break;
                    default: throw bad();
                }
            }
        }

        private static boolean digit(char c) {
            return c >= '0' && c <= '9';
        }

        private Num number() {
            int start = i;
            if (i < s.length() && s.charAt(i) == '-') i++;
            int digits = i;
            while (i < s.length() && digit(s.charAt(i))) i++;
            if (i == digits) throw bad();
            if (i < s.length() && s.charAt(i) == '.') { i++; int f = i; while (i < s.length() && digit(s.charAt(i))) i++; if (i == f) throw bad(); }
            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                int e = i;
                while (i < s.length() && digit(s.charAt(i))) i++;
                if (i == e) throw bad();
            }
            return new Num(s.substring(start, i));
        }
    }
}
