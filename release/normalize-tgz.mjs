#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Rewrites each .tgz in place as gzip of the same tar with STORED deflate blocks, mtime 0.
//
//   node release/normalize-tgz.mjs <file.tgz>...
//
// npm's tar is the same bytes across npm 10 and 11, but its gzip comes from the zlib bundled in
// node, whose compressed output differs between node versions (and SIMD paths). Stored blocks
// of 65 535 bytes are a function of the tar alone, so the tarball's hash no longer depends on
// the builder's node. Cost: the tarball is its tar's size (about 3x); any gunzip reads it.
import { readFileSync, writeFileSync } from 'node:fs';
import { crc32, gunzipSync } from 'node:zlib';

for (const f of process.argv.slice(2)) {
  const tar = gunzipSync(readFileSync(f));
  const parts = [Buffer.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff])]; // no name, mtime 0, OS unknown
  for (let i = 0; i === 0 || i < tar.length; i += 65535) {
    const chunk = tar.subarray(i, i + 65535);
    const head = Buffer.alloc(5);
    head[0] = i + 65535 >= tar.length ? 1 : 0; // BFINAL on the last block, BTYPE 00 (stored)
    head.writeUInt16LE(chunk.length, 1);
    head.writeUInt16LE(~chunk.length & 0xffff, 3);
    parts.push(head, chunk);
  }
  const tail = Buffer.alloc(8);
  tail.writeUInt32LE(crc32(tar) >>> 0, 0);
  tail.writeUInt32LE(tar.length >>> 0, 4);
  writeFileSync(f, Buffer.concat([...parts, tail]));
}
