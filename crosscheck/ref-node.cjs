// SPDX-License-Identifier: MIT
// Batch driver for the THIRD-PARTY oracle cyberphone/json-canonicalization node-es6/canonicalize.js
// (JSON.parse, then the reference canonicalizer). Same line protocol as the other drivers.
const path = require('node:path');
const canonicalize = require(path.join(__dirname, '.work/jcs-ref/node-es6/canonicalize.js'));
const rl = require('node:readline').createInterface({ input: process.stdin, crlfDelay: Infinity });
const out = [];
const flush = () => { if (out.length) process.stdout.write(out.join('\n') + '\n'); out.length = 0; };
rl.on('line', (line) => {
  const r = JSON.parse(line);
  let a;
  try {
    if (r.op === 'jcs') a = { ok: true, out: Buffer.from(canonicalize(JSON.parse(r.text)), 'utf8').toString('hex') };
    else if (r.op === 'num') a = { ok: true, out: canonicalize(Buffer.from(r.bits, 'hex').readDoubleBE(0)) };
    else a = { ok: false, err: 'unknown op' };
  } catch (e) { a = { ok: false, err: String(e.message) }; }
  out.push(JSON.stringify(a));
  if (out.length >= 1000) flush();
});
rl.on('close', flush);
