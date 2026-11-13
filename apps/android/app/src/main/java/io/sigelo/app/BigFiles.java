// SPDX-License-Identifier: MIT
package io.sigelo.app;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.media.ExifInterface;
import android.media.MediaScannerConnection;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import android.provider.MediaStore;
import android.provider.OpenableColumns;
import android.util.Base64;
import android.view.WindowManager;
import android.webkit.MimeTypeMap;
import android.webkit.WebResourceResponse;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Big files for the page (design/transfer.md §10; the page's side: apps/web/platform-android.mjs "big-*",
 * apps/contact/transfer-web.mjs). The page never holds a file whole: it names one by a doc (a token this
 * class keeps, per profile) and reads it by byte range; it writes what it receives into a partial here
 * at offsets, then has the partial moved into the phone's Downloads.
 *
 *   big-pick   the system's document picker (ACTION_OPEN_DOCUMENT); the read grant kept (a resume after a
 *              restart still reads it) → {doc, name, size, mtime} | {cancelled}
 *   big-photo  the system's camera (ACTION_IMAGE_CAPTURE) into this app's cache through PhotoProvider; CAMERA
 *              asked at the first (declared for the scan, Android refuses the intent until it is granted);
 *              the location tags removed unless keepLocation → {doc, name, size, mtime} | {cancelled}
 *   big-hash   each 1 MiB chunk's SHA-256 and the whole file's, here (the page would take minutes) → {name, size, mtime, sha256, hashes}
 *   big-stat   {size, mtime}: the sender checks the file is still the one hashed
 *   a range    GET ORIGIN/.big/<doc>?size=&mtime= with Range (MainActivity.serve → range): 206 and those bytes,
 *              409 when size or mtime moved, 404 for any other doc. No base64: the page fetch()es them. No Range:
 *              the whole file, up to 64 MiB (a photo the page downscales for its preview).
 *   big-write  bytes at an offset of <part>.part in this profile's private storage; big-flush: on disk (fsync)
 *   big-digest the partial read back whole (SHA-256); big-drop: gone; big-free: bytes free here
 *   big-land   the partial moved into Downloads (MediaStore, IS_PENDING until the copy is whole, a 1 MiB
 *              buffer; Android 9: the public folder, WRITE_EXTERNAL_STORAGE asked at the first) → {uri, name};
 *              refused "land" with why (no permission, no room): the page says it, the partial kept
 *   big-open   a file that landed opened by the system's viewer (ACTION_VIEW, a read grant)
 *   big-awake  FLAG_KEEP_SCREEN_ON while a transfer moves
 * part: a transfer id (32 hex). doc: 32 hex. profile: as the keystore's (p1, p2…).
 */
final class BigFiles {
    static final int CHUNK = 1 << 20;
    static final int REQ_PICK = 5, REQ_PHOTO = 6, REQ_CAMERA_PHOTO = 7, REQ_STORAGE = 8;
    private static final Pattern HEX32 = Pattern.compile("^[0-9a-f]{32}$");
    private static final Pattern PROFILE = Pattern.compile("^p[1-9][0-9]{0,2}$");
    private static final Pattern SAFE_NAME = Pattern.compile("[\\\\/:*?\"<>|\\x00-\\x1f]");
    private static final int NAME_MAX = 200;
    /** A file read whole by the page (no Range: a photo it downscales for the preview): at most this. */
    private static final long PREVIEW_MAX = 64L << 20;

    /** An answer to the page, or a refusal (SigeloBridge.Refused), from any thread. */
    interface Reply {
        void ok(JSONObject o);

        void no(String check, String message);
    }

    private final MainActivity activity;
    private final SharedPreferences prefs;
    private final SecureRandom rng = new SecureRandom();
    private final Map<String, RandomAccessFile> open = new ConcurrentHashMap<>();
    private Reply pendingPick, pendingPhoto, pendingStorage;   // the main thread's
    private String pendingPickProfile, pendingPhotoProfile, pendingPhotoDoc;
    private boolean pendingKeepLocation;
    private Runnable afterStorage;

    BigFiles(MainActivity activity, SharedPreferences prefs) {
        this.activity = activity;
        this.prefs = prefs;
    }

    static String profileOf(JSONObject m) throws SigeloBridge.Refused {
        String p = m.optString("profile", "p1");
        if (!PROFILE.matcher(p).matches()) throw new SigeloBridge.Refused("profile", "not a profile id");
        return p;
    }

    private static String hex32(JSONObject m, String key) throws SigeloBridge.Refused {
        String v = m.optString(key);
        if (!HEX32.matcher(v).matches()) throw new SigeloBridge.Refused("big", key + ": 32 hex digits");
        return v;
    }

    private String newToken() {
        byte[] b = new byte[16];
        rng.nextBytes(b);
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format(Locale.ROOT, "%02x", x & 255));
        return s.toString();
    }

    // ---------------------------------------------------------------- docs: what the page may read

    /** A doc kept: "u:<content uri>" (picked) or "f:<file in the cache's photos>" (taken), per profile. */
    private void keepDoc(String profile, String doc, String where) {
        prefs.edit().putString("doc." + profile + "." + doc, where).apply();
    }

    private String docOf(String profile, String doc) throws SigeloBridge.Refused {
        String w = HEX32.matcher(doc).matches() ? prefs.getString("doc." + profile + "." + doc, null) : null;
        if (w == null) throw new SigeloBridge.Refused("file", "no such file here (pick it again)");
        return w;
    }

    static File photos(Activity a) {
        File d = new File(a.getCacheDir(), "photos");
        //noinspection ResultOfMethodCallIgnored
        d.mkdirs();
        return d;
    }

    private long[] statOf(String where) throws SigeloBridge.Refused {
        if (where.startsWith("f:")) {
            File f = new File(photos(activity), where.substring(2));
            if (!f.isFile()) throw new SigeloBridge.Refused("file_changed", "the photo is gone");
            return new long[] {f.length(), f.lastModified()};
        }
        Uri u = Uri.parse(where.substring(2));
        try (Cursor c = activity.getContentResolver().query(u, null, null, null, null)) {
            if (c == null || !c.moveToFirst()) throw new SigeloBridge.Refused("file_changed", "the file is gone");
            // The time: the document's (ms), else the media store's DATE_MODIFIED (s), so a resume still sees an edit.
            int si = c.getColumnIndex(OpenableColumns.SIZE), mi = c.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED);
            int di = c.getColumnIndex(MediaStore.MediaColumns.DATE_MODIFIED);
            long size = si >= 0 && !c.isNull(si) ? c.getLong(si) : -1;
            long mtime = mi >= 0 && !c.isNull(mi) ? c.getLong(mi) : di >= 0 && !c.isNull(di) ? c.getLong(di) * 1000 : 0;
            if (size < 0) throw new SigeloBridge.Refused("file", "the provider does not say the file's size");
            return new long[] {size, mtime};
        } catch (SecurityException e) {
            throw new SigeloBridge.Refused("file_changed", "the grant to read it is gone (pick it again)");
        }
    }

    private String nameOf(String where) {
        if (where.startsWith("f:")) return prefs.getString("name." + where.substring(2), where.substring(2));
        try (Cursor c = activity.getContentResolver().query(Uri.parse(where.substring(2)), new String[] {OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst() && !c.isNull(0)) return clean(c.getString(0));
        } catch (RuntimeException e) {
            // no name: the generic one
        }
        return "file";
    }

    static String clean(String name) {
        String n = SAFE_NAME.matcher(name == null ? "" : name).replaceAll("_").trim();
        if (n.isEmpty() || n.equals(".") || n.equals("..")) n = "file";
        return n.length() > NAME_MAX ? n.substring(n.length() - NAME_MAX) : n;
    }

    /** The file opened at offset for reading (a content URI through its descriptor, so it can seek). */
    private InputStream openAt(String where, long offset) throws IOException {
        FileInputStream in;
        if (where.startsWith("f:")) in = new FileInputStream(new File(photos(activity), where.substring(2)));
        else {
            ParcelFileDescriptor pfd = activity.getContentResolver().openFileDescriptor(Uri.parse(where.substring(2)), "r");
            if (pfd == null) throw new IOException("the provider gave no file");
            in = new ParcelFileDescriptor.AutoCloseInputStream(pfd);
        }
        try {
            in.getChannel().position(offset);
        } catch (IOException e) {
            long left = offset;
            while (left > 0) {
                long k = in.skip(left);
                if (k <= 0) throw new IOException("cannot reach the offset");
                left -= k;
            }
        }
        return in;
    }

    private JSONObject describe(String profile, String doc, String where) throws SigeloBridge.Refused, JSONException {
        long[] st = statOf(where);
        return new JSONObject().put("doc", doc).put("name", nameOf(where)).put("size", st[0]).put("mtime", st[1])
            .put("url", MainActivity.ORIGIN + "/.big/" + doc + "?size=" + st[0] + "&mtime=" + st[1] + "&profile=" + profile);
    }

    // ---------------------------------------------------------------- pick and photo (main thread)

    void pick(JSONObject m, Reply r) throws SigeloBridge.Refused {
        String profile = profileOf(m);
        if (pendingPick != null) pendingPick.no("cancelled", "another pick");
        pendingPick = r;
        pendingPickProfile = profile;
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        try {
            activity.startActivityForResult(i, REQ_PICK);
        } catch (ActivityNotFoundException e) {
            pendingPick = null;
            r.no("pick", "no file picker on this phone");
        }
    }

    void photo(JSONObject m, Reply r) throws SigeloBridge.Refused {
        String profile = profileOf(m);
        if (pendingPhoto != null) pendingPhoto.no("cancelled", "another photo");
        pendingPhoto = r;
        pendingPhotoProfile = profile;
        pendingKeepLocation = m.optBoolean("keepLocation", false);
        // CAMERA is declared (the scan): Android refuses ACTION_IMAGE_CAPTURE until it is granted. Asked here at the first.
        if (activity.checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            activity.requestPermissions(new String[] {Manifest.permission.CAMERA}, REQ_CAMERA_PHOTO);
            return;
        }
        shoot();
    }

    private void shoot() {
        Reply r = pendingPhoto;
        if (r == null) return;
        String doc = newToken();
        File f = new File(photos(activity), doc + ".jpg");
        Uri out = PhotoProvider.uriOf(f.getName());
        Intent i = new Intent(MediaStore.ACTION_IMAGE_CAPTURE).putExtra(MediaStore.EXTRA_OUTPUT, out)
            .addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_READ_URI_PERMISSION);
        pendingPhotoDoc = doc;
        try {
            activity.startActivityForResult(i, REQ_PHOTO);
        } catch (ActivityNotFoundException e) {
            pendingPhoto = null;
            r.no("no_camera_app", "no camera app on this phone");
        }
    }

    /** MainActivity.onRequestPermissionsResult for ours: true when it was ours. */
    boolean permission(int req, int[] grants) {
        boolean granted = grants.length == 1 && grants[0] == PackageManager.PERMISSION_GRANTED;
        if (req == REQ_CAMERA_PHOTO) {
            if (granted) shoot();
            else if (pendingPhoto != null) {
                Reply r = pendingPhoto;
                pendingPhoto = null;
                r.no("camera_permission", "the camera is not allowed for sigelo (Settings → Apps → sigelo → Permissions)");
            }
            return true;
        }
        if (req == REQ_STORAGE) {
            Runnable go = afterStorage;
            Reply r = pendingStorage;
            afterStorage = null;
            pendingStorage = null;
            if (granted && go != null) go.run();
            else if (r != null) r.no("land", "no permission to write to Downloads (Settings → Apps → sigelo → Permissions → Files)");
            return true;
        }
        return false;
    }

    /** MainActivity.onActivityResult for ours (a pick, a photo): true when it was ours. */
    boolean result(int req, int code, Intent data, java.util.concurrent.Executor io) {
        if (req == REQ_PICK) {
            Reply r = pendingPick;
            String profile = pendingPickProfile;
            pendingPick = null;
            if (r == null) return true;
            Uri u = data == null ? null : data.getData();
            if (code != Activity.RESULT_OK || u == null) {
                r.ok(cancelled());
                return true;
            }
            try {
                activity.getContentResolver().takePersistableUriPermission(u, Intent.FLAG_GRANT_READ_URI_PERMISSION);
            } catch (SecurityException e) {
                // not persistable: it reads until the app restarts
            }
            String doc = newToken();
            keepDoc(profile, doc, "u:" + u);
            io.execute(() -> {
                try {
                    r.ok(describe(profile, doc, "u:" + u));
                } catch (SigeloBridge.Refused e) {
                    r.no(e.check, e.getMessage());
                } catch (JSONException e) {
                    r.no("pick", "unreadable");
                }
            });
            return true;
        }
        if (req == REQ_PHOTO) {
            Reply r = pendingPhoto;
            String profile = pendingPhotoProfile, doc = pendingPhotoDoc;
            boolean keep = pendingKeepLocation;
            pendingPhoto = null;
            if (r == null || doc == null) return true;
            File f = new File(photos(activity), doc + ".jpg");
            if (code != Activity.RESULT_OK || !f.isFile() || f.length() == 0) {
                //noinspection ResultOfMethodCallIgnored
                f.delete();
                r.ok(cancelled());
                return true;
            }
            io.execute(() -> {
                try {
                    if (!keep) stripLocation(f);
                    String name = "IMG_" + new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.ROOT).format(new Date()) + ".jpg";
                    prefs.edit().putString("name." + f.getName(), name).apply();
                    keepDoc(profile, doc, "f:" + f.getName());
                    r.ok(describe(profile, doc, "f:" + f.getName()));
                } catch (IOException e) {
                    r.no("photo", "the photo could not be read: " + e.getMessage());
                } catch (SigeloBridge.Refused e) {
                    r.no(e.check, e.getMessage());
                } catch (JSONException e) {
                    r.no("photo", "unreadable");
                }
            });
            return true;
        }
        return false;
    }

    private static JSONObject cancelled() {
        try {
            return new JSONObject().put("cancelled", true);
        } catch (JSONException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The location a camera app wrote into the photo, removed (android.media.ExifInterface: the platform's, no dependency). */
    static void stripLocation(File f) throws IOException {
        ExifInterface x = new ExifInterface(f.getAbsolutePath());
        String[] tags = {ExifInterface.TAG_GPS_LATITUDE, ExifInterface.TAG_GPS_LATITUDE_REF, ExifInterface.TAG_GPS_LONGITUDE, ExifInterface.TAG_GPS_LONGITUDE_REF,
            ExifInterface.TAG_GPS_ALTITUDE, ExifInterface.TAG_GPS_ALTITUDE_REF, ExifInterface.TAG_GPS_TIMESTAMP, ExifInterface.TAG_GPS_DATESTAMP,
            ExifInterface.TAG_GPS_PROCESSING_METHOD, ExifInterface.TAG_GPS_SPEED, ExifInterface.TAG_GPS_SPEED_REF, ExifInterface.TAG_GPS_IMG_DIRECTION,
            ExifInterface.TAG_GPS_IMG_DIRECTION_REF, ExifInterface.TAG_GPS_DEST_LATITUDE, ExifInterface.TAG_GPS_DEST_LONGITUDE, ExifInterface.TAG_GPS_AREA_INFORMATION,
            ExifInterface.TAG_GPS_VERSION_ID, ExifInterface.TAG_GPS_MAP_DATUM, ExifInterface.TAG_GPS_SATELLITES, ExifInterface.TAG_GPS_STATUS, ExifInterface.TAG_GPS_MEASURE_MODE,
            ExifInterface.TAG_GPS_DOP, ExifInterface.TAG_GPS_TRACK, ExifInterface.TAG_GPS_TRACK_REF, ExifInterface.TAG_GPS_DIFFERENTIAL};
        boolean any = false;
        for (String t : tags) {
            if (x.getAttribute(t) != null) {
                x.setAttribute(t, null);
                any = true;
            }
        }
        if (any) x.saveAttributes();
    }

    // ---------------------------------------------------------------- the file sent (off the main thread)

    JSONObject hash(JSONObject m) throws Exception {
        String where = docOf(profileOf(m), hex32(m, "doc"));
        long[] st = statOf(where);
        long size = st[0];
        int n = (int) ((size + CHUNK - 1) / CHUNK);
        if (size > 16L * 1024 * 1024 * 1024) throw new SigeloBridge.Refused("transfer_too_large", "at most 16 GiB a file");
        byte[] hashes = new byte[n * 32], buf = new byte[CHUNK];
        MessageDigest whole = sha256();
        try (InputStream in = openAt(where, 0)) {
            for (int i = 0; i < n; i++) {
                int len = (int) Math.min(CHUNK, size - (long) i * CHUNK), got = 0;
                while (got < len) {
                    int k = in.read(buf, got, len - got);
                    if (k < 0) throw new SigeloBridge.Refused("file_changed", "the file is shorter than it says");
                    got += k;
                }
                MessageDigest d = sha256();
                d.update(buf, 0, len);
                System.arraycopy(d.digest(), 0, hashes, i * 32, 32);
                whole.update(buf, 0, len);
            }
        }
        long[] after = statOf(where);
        if (after[0] != st[0] || after[1] != st[1]) throw new SigeloBridge.Refused("file_changed", "the file changed while it was read: send it again");
        return new JSONObject().put("name", nameOf(where)).put("size", size).put("mtime", st[1]).put("sha256", hexOf(whole.digest())).put("hashes", Base64.encodeToString(hashes, Base64.NO_WRAP));
    }

    JSONObject stat(JSONObject m) throws Exception {
        long[] st = statOf(docOf(profileOf(m), hex32(m, "doc")));
        return new JSONObject().put("size", st[0]).put("mtime", st[1]);
    }

    /** GET ORIGIN/.big/<doc>?size=&mtime=&profile= with a Range header: those bytes (206), or a refusal. */
    WebResourceResponse range(Uri u, Map<String, String> headers, Map<String, String> base) {
        String path = u.getPath() == null ? "" : u.getPath(), doc = path.substring("/.big/".length());
        String where;
        long[] st;
        try {
            String profile = u.getQueryParameter("profile");
            where = docOf(profile == null ? "p1" : profileChecked(profile), doc);
            st = statOf(where);
        } catch (SigeloBridge.Refused e) {
            return empty(e.check.equals("file_changed") ? 409 : 404, e.check.equals("file_changed") ? "Conflict" : "Not Found", base);
        }
        if (!String.valueOf(st[0]).equals(u.getQueryParameter("size")) || !String.valueOf(st[1]).equals(u.getQueryParameter("mtime"))) return empty(409, "Conflict", base);
        long from = 0, to = st[0] - 1;
        String r = null;
        for (Map.Entry<String, String> h : headers.entrySet()) if ("range".equalsIgnoreCase(h.getKey())) r = h.getValue();
        if (r != null) {
            java.util.regex.Matcher mm = Pattern.compile("^bytes=(\\d+)-(\\d+)$").matcher(r.trim());
            if (!mm.matches()) return empty(416, "Range Not Satisfiable", base);
            from = Long.parseLong(mm.group(1));
            to = Math.min(Long.parseLong(mm.group(2)), st[0] - 1);
            if (from > to || to - from + 1 > CHUNK) return empty(416, "Range Not Satisfiable", base);
        } else if (st[0] > PREVIEW_MAX) {
            // Whole only for a picture the page shows or downscales (the preview); a bigger file goes by range.
            return empty(416, "Range Not Satisfiable", base);
        }
        byte[] out = new byte[(int) (to - from + 1)];
        try (InputStream in = openAt(where, from)) {
            int got = 0;
            while (got < out.length) {
                int k = in.read(out, got, out.length - got);
                if (k < 0) return empty(409, "Conflict", base);
                got += k;
            }
        } catch (IOException e) {
            return empty(409, "Conflict", base);
        }
        Map<String, String> h = new HashMap<>(base);
        h.put("Content-Range", "bytes " + from + "-" + to + "/" + st[0]);
        h.put("Content-Length", String.valueOf(out.length));
        String type = where.startsWith("f:") ? "image/jpeg" : "application/octet-stream";
        return new WebResourceResponse(type, null, r == null ? 200 : 206, r == null ? "OK" : "Partial Content", h, new ByteArrayInputStream(out));
    }

    private static String profileChecked(String p) throws SigeloBridge.Refused {
        if (!PROFILE.matcher(p).matches()) throw new SigeloBridge.Refused("profile", "not a profile id");
        return p;
    }

    private static WebResourceResponse empty(int status, String reason, Map<String, String> base) {
        return new WebResourceResponse("text/plain", "utf-8", status, reason, base, new ByteArrayInputStream(new byte[0]));
    }

    // ---------------------------------------------------------------- the file received (off the main thread)

    private File partDir(String profile) {
        File d = new File(new File(activity.getNoBackupFilesDir(), "transfer"), profile);
        //noinspection ResultOfMethodCallIgnored
        d.mkdirs();
        return d;
    }

    private File partOf(JSONObject m) throws SigeloBridge.Refused {
        return new File(partDir(profileOf(m)), hex32(m, "part") + ".part");
    }

    private RandomAccessFile raf(File f) throws IOException {
        RandomAccessFile x = open.get(f.getPath());
        if (x == null) {
            x = new RandomAccessFile(f, "rw");
            open.put(f.getPath(), x);
        }
        return x;
    }

    private void release(File f) {
        RandomAccessFile x = open.remove(f.getPath());
        if (x != null) {
            try {
                x.close();
            } catch (IOException e) {
                // gone already
            }
        }
    }

    JSONObject write(JSONObject m) throws Exception {
        File f = partOf(m);
        long offset = m.optLong("offset", -1);
        if (offset < 0) throw new SigeloBridge.Refused("big", "offset: bytes");
        byte[] b;
        try {
            b = Base64.decode(m.optString("data"), Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            throw new SigeloBridge.Refused("big", "data: base64");
        }
        if (b.length > CHUNK) throw new SigeloBridge.Refused("big", "at most 1 MiB a write");
        synchronized (this) {
            RandomAccessFile x = raf(f);
            x.seek(offset);
            x.write(b);
        }
        return new JSONObject();
    }

    JSONObject flush(JSONObject m) throws Exception {
        File f = partOf(m);
        synchronized (this) {
            RandomAccessFile x = open.get(f.getPath());
            if (x != null) x.getFD().sync();
        }
        return new JSONObject();
    }

    JSONObject sha(JSONObject m) throws Exception {
        File f = partOf(m);
        synchronized (this) {
            release(f);
        }
        MessageDigest d = sha256();
        byte[] buf = new byte[CHUNK];
        try (InputStream in = new FileInputStream(f)) {
            for (int k; (k = in.read(buf)) > 0; ) d.update(buf, 0, k);
        } catch (IOException e) {
            if (!f.exists()) return new JSONObject().put("sha256", hexOf(sha256().digest()));
            throw e;
        }
        return new JSONObject().put("sha256", hexOf(d.digest()));
    }

    JSONObject drop(JSONObject m) throws Exception {
        File f = partOf(m);
        synchronized (this) {
            release(f);
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
        return new JSONObject();
    }

    JSONObject free(JSONObject m) throws Exception {
        return new JSONObject().put("free", partDir(profileOf(m)).getUsableSpace());
    }

    /** The partial into Downloads, under its name (or name (2), …), its URI given back; the partial gone. */
    void land(JSONObject m, Reply r, java.util.concurrent.Executor io) throws SigeloBridge.Refused {
        File f = partOf(m);
        String name = clean(m.optString("name"));
        if (Build.VERSION.SDK_INT >= 29) {
            io.execute(() -> landQ(f, name, r));
            return;
        }
        // Android 9: the public folder needs WRITE_EXTERNAL_STORAGE (declared for API 28 only), asked at the first.
        Runnable go = () -> io.execute(() -> landLegacy(f, name, r));
        if (activity.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED) {
            go.run();
            return;
        }
        if (pendingStorage != null) pendingStorage.no("land", "another save waits for the permission");
        pendingStorage = r;
        afterStorage = go;
        activity.requestPermissions(new String[] {Manifest.permission.WRITE_EXTERNAL_STORAGE}, REQ_STORAGE);
    }

    private static String typeOf(String name) {
        int dot = name.lastIndexOf('.');
        String t = dot < 0 ? null : MimeTypeMap.getSingleton().getMimeTypeFromExtension(name.substring(dot + 1).toLowerCase(Locale.ROOT));
        return t == null ? "application/octet-stream" : t;
    }

    @TargetApi(29)
    private void landQ(File f, String name, Reply r) {
        synchronized (this) {
            release(f);
        }
        ContentResolver cr = activity.getContentResolver();
        ContentValues v = new ContentValues();
        v.put(MediaStore.MediaColumns.DISPLAY_NAME, name);
        v.put(MediaStore.MediaColumns.MIME_TYPE, typeOf(name));
        v.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
        v.put(MediaStore.MediaColumns.IS_PENDING, 1);
        Uri u;
        try {
            u = cr.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, v);
        } catch (RuntimeException e) {
            r.no("land", "Downloads refused the file: " + e.getMessage());
            return;
        }
        if (u == null) {
            r.no("land", "Downloads refused the file");
            return;
        }
        try (InputStream in = new FileInputStream(f); OutputStream out = cr.openOutputStream(u)) {
            if (out == null) throw new IOException("no stream into Downloads");
            copy(in, out);
        } catch (IOException | RuntimeException e) {
            cr.delete(u, null, null);
            r.no("land", "the copy into Downloads failed (" + e.getMessage() + "): is the phone full?");
            return;
        }
        v.clear();
        v.put(MediaStore.MediaColumns.IS_PENDING, 0);
        cr.update(u, v, null, null);
        //noinspection ResultOfMethodCallIgnored
        f.delete();
        landed(r, u, name);
    }

    private void landLegacy(File f, String name, Reply r) {
        synchronized (this) {
            release(f);
        }
        @SuppressWarnings("deprecation")
        File dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File to = new File(dir, name);
        int dot = name.lastIndexOf('.');
        for (int i = 2; to.exists() && i < 1000; i++) to = new File(dir, dot > 0 ? name.substring(0, dot) + " (" + i + ")" + name.substring(dot) : name + " (" + i + ")");
        File target = to;
        try (InputStream in = new FileInputStream(f); OutputStream out = new FileOutputStream(target)) {
            copy(in, out);
        } catch (IOException e) {
            //noinspection ResultOfMethodCallIgnored
            target.delete();
            r.no("land", "the copy into Downloads failed (" + e.getMessage() + "): is the phone full?");
            return;
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
        MediaScannerConnection.scanFile(activity, new String[] {target.getAbsolutePath()}, new String[] {typeOf(name)}, (p, u) -> {
            if (u == null) r.no("land", "saved in Downloads as " + target.getName() + ", but the media store did not list it");
            else landed(r, u, target.getName());
        });
    }

    private static void landed(Reply r, Uri u, String name) {
        try {
            r.ok(new JSONObject().put("uri", u.toString()).put("name", name));
        } catch (JSONException e) {
            r.no("land", "unreadable");
        }
    }

    private static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[CHUNK];
        for (int k; (k = in.read(buf)) > 0; ) out.write(buf, 0, k);
        out.flush();
    }

    /** A file that landed (a content URI of the media store), in the system's viewer. */
    void openFile(JSONObject m, Reply r) {
        String s = m.optString("uri");
        if (!s.startsWith("content://media/")) {
            r.no("big", "uri: a file that landed in Downloads");
            return;
        }
        Intent i = new Intent(Intent.ACTION_VIEW).setDataAndType(Uri.parse(s), typeOf(clean(m.optString("name")))).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try {
            activity.startActivity(Intent.createChooser(i, null));
            r.ok(new JSONObject());
        } catch (ActivityNotFoundException e) {
            r.no("open", "no app on this phone opens it");
        }
    }

    void awake(boolean on) {
        if (on) activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        else activity.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
    }

    /** A profile removed (forget-profile): its partials and the docs it may read, gone. */
    void forget(String profile) {
        synchronized (this) {
            for (String p : open.keySet()) if (p.startsWith(partDir(profile).getPath())) release(new File(p));
        }
        File[] fs = partDir(profile).listFiles();
        if (fs != null) for (File f : fs) {
            //noinspection ResultOfMethodCallIgnored
            f.delete();
        }
        SharedPreferences.Editor e = prefs.edit();
        for (String k : prefs.getAll().keySet()) if (k.startsWith("doc." + profile + ".")) e.remove(k);
        e.apply();
    }

    /** Every partial closed (the app ends). */
    void close() {
        synchronized (this) {
            for (String p : open.keySet()) release(new File(p));
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hexOf(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format(Locale.ROOT, "%02x", x & 255));
        return s.toString();
    }
}
