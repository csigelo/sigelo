// SPDX-License-Identifier: MIT
package io.sigelo.app;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.regex.Pattern;

/**
 * The one file a camera app may write (design/transfer.md §10.4): content://io.sigelo.app.photos/<32 hex>.jpg,
 * a file in this app's cache (cache/photos/), reached only through a grant the camera intent carries
 * (not exported, grantUriPermissions). androidx's FileProvider does the same but is a dependency; this app
 * has none. Nothing else is served: no other name, no directory, no query beyond name and size.
 */
public final class PhotoProvider extends ContentProvider {
    static final String AUTHORITY = "io.sigelo.app.photos";
    private static final Pattern NAME = Pattern.compile("^[0-9a-f]{32}\\.jpg$");

    static Uri uriOf(String name) {
        return new Uri.Builder().scheme("content").authority(AUTHORITY).appendPath(name).build();
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    private File fileOf(Uri u) throws FileNotFoundException {
        String n = u.getLastPathSegment();
        if (u.getPathSegments().size() != 1 || n == null || !NAME.matcher(n).matches() || getContext() == null) throw new FileNotFoundException("not ours");
        File d = new File(getContext().getCacheDir(), "photos");
        //noinspection ResultOfMethodCallIgnored
        d.mkdirs();
        return new File(d, n);
    }

    @Override
    public ParcelFileDescriptor openFile(Uri u, String mode) throws FileNotFoundException {
        return ParcelFileDescriptor.open(fileOf(u), ParcelFileDescriptor.parseMode(mode));
    }

    @Override
    public String getType(Uri u) {
        return "image/jpeg";
    }

    @Override
    public Cursor query(Uri u, String[] projection, String selection, String[] args, String order) {
        File f;
        try {
            f = fileOf(u);
        } catch (FileNotFoundException e) {
            return null;
        }
        MatrixCursor c = new MatrixCursor(new String[] {OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE});
        c.addRow(new Object[] {f.getName(), f.length()});
        return c;
    }

    @Override
    public Uri insert(Uri u, ContentValues v) {
        throw new UnsupportedOperationException("read and write of one file only");
    }

    @Override
    public int delete(Uri u, String selection, String[] args) {
        throw new UnsupportedOperationException("read and write of one file only");
    }

    @Override
    public int update(Uri u, ContentValues v, String selection, String[] args) {
        throw new UnsupportedOperationException("read and write of one file only");
    }
}
