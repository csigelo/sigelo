// SPDX-License-Identifier: MIT
// Transfers in a page that holds its own identity (the phone app, design/transfer.md §10): the io of
// transfer-engine.mjs over the platform's files (the records, the chunk bitmaps and lists: small) and
// the shell's big-file bridge (the bytes: never in the page's storage, never a Blob held whole).
//
//   const io = webIo({ files, big, base, profile })   files: the platform's (sync read/write/remove);
//                                                     big: platform.big (below); base: 'app/me.local'
//   const X = webTransfers(io)                        the verbs with { carrier } as transfer-node.mjs's take them
//
// big (apps/web/platform-android.mjs, SigeloBridge "big-*"): every call names this profile.
//   pick() → { doc, name, size, mtime } | null       the system's document picker; the grant kept (a resume after a restart reads it)
//   hash(doc) → { size, mtime, sha256, hashes }      in the shell (each 1 MiB chunk and the whole), hashes: bytes
//   stat(doc) → { size, mtime }                      read(doc, offset, length, { size, mtime }) → bytes (a range; file_changed when either moved)
//   write(part, offset, bytes); flush(part); sha256(part) → hex; drop(part); free() → bytes
//   land(part, name) → { uri, name }                 the partial moved into the phone's Downloads (MediaStore, pending until whole)
// part: the transfer id. Partials live in the app's private storage until they land.
import { CHUNK, chunkLength } from './transfer.mjs';
import { fail } from './kdf.mjs';
import * as E from './transfer-engine.mjs';

const enc = new TextEncoder(), dec = new TextDecoder();

export function webIo({ files, big, base = 'app/me.local', flushEach = 1 }) {
  const file = `${base}.transfers.json`, dir = `${base}.files/.transfer/`;
  let freeBytes = Infinity;
  const refresh = () => { void big.free().then((n) => { if (Number.isFinite(n)) freeBytes = n; }, () => {}); };
  refresh();
  return {
    flushEach,
    lock: (fn) => fn(),   // one owner per identity (platform.owner): this page alone writes it
    read: () => { const b = files.read(file); return b === null ? null : dec.decode(b); },
    write: (text) => files.write(file, enc.encode(text)),
    have: {
      read: (id) => files.read(`${dir}${id}.have`),
      write: (id, bits) => { if (bits === null) files.remove(`${dir}${id}.have`); else files.write(`${dir}${id}.have`, Uint8Array.from(bits)); },
    },
    list: {
      read: (id, side) => files.read(`${dir}${id}.${side}.list`),
      write: (id, side, bytes) => files.write(`${dir}${id}.${side}.list`, Uint8Array.from(bytes)),
      drop: (id, side) => files.remove(`${dir}${id}.${side}.list`),
    },
    part: {
      async open(id) {
        return { write: (b, pos) => big.write(id, pos, b), flush: () => big.flush(id), close: async () => { refresh(); } };
      },
      drop: (id) => { void big.drop(id).catch(() => {}); },
      sha256: (id) => big.sha256(id),
    },
    free: () => { refresh(); return freeBytes; },
    async land(r) { const x = await big.land(r.id, r.name); refresh(); return x.uri; },
    async prepare({ doc }) {
      if (typeof doc !== 'string' || doc === '') fail('usage', 'doc: a file picked on this phone');
      const h = await big.hash(doc);
      return { file: doc, name: h.name, size: h.size, mtimeMs: h.mtime, hashes: h.hashes, whole: h.sha256 };
    },
    async changed(r) { try { const s = await big.stat(r.file); return s.size !== r.size || s.mtime !== r.mtimeMs; } catch { return true; } },
    async source(r) {
      return {
        read: (i) => big.read(r.file, i * CHUNK, chunkLength(r.size, i), { size: r.size, mtime: r.mtimeMs }),
        close: async () => {},
      };
    },
    tor: null,   // no Tor on the phone (a later build: Orbot's SOCKS port)
  };
}

/** The verbs over io, taking what transfer-node.mjs's take (identity is ignored: the io names the files). */
export function webTransfers(io, { compared = () => false, rtc = null } = {}) {
  const w = (f) => (o) => f({ ...o, io });
  return {
    io,
    send: w(E.send), accept: w(E.accept), resume: w(E.accept), decline: w(E.decline), cancel: w(E.cancel), forget: w(E.forget),
    list: w(E.list), setDirect: w(E.setDirect), setAuto: w(E.setAuto), settings: ({ patch, now } = {}) => E.settings({ io, patch, ...(now !== undefined && { now }) }),
    prepare: w(E.prepare), sendTo: w(E.sendTo), fanOut: w(E.fanOut), contactOf: E.contactOf, trustOf: E.trustOf,
    intake: ({ carrier }) => E.intake({ carrier, io, compared }),
    torCaps: async () => ({ serve: false, connect: false }), torConfig: () => null,
    loadRtc: async () => rtc,
    Engine: E.Engine,
  };
}
