#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Verify any sigelo bundle offline (SPEC §9): `node verify.mjs < bundle.json` or `node verify.mjs bundle.json`.
// Prints the §9.1 result as JSON; exits 1 with the failing check on stderr if the identity is invalid.
// The input is read as BYTES and decoded fatally (parseBytes, SPEC §3): a 'utf8' string read
// turns invalid UTF-8 into U+FFFD and accepted bundles that sigelo-verify rejects.
// Relative import: works from the checkout, or through a symlink to this directory (node realpaths it).
import { readFileSync } from 'node:fs';
import { parseBytes, verify } from '../../../ts/dist/sigelo.js';
const fail = (why) => { console.error(`sigelo verify: ${why}`); process.exit(1); };
let bytes, doc;
try { bytes = readFileSync(process.argv[2] ?? 0); } catch (e) { fail(e instanceof Error ? e.message : e); }
try { doc = parseBytes(bytes); } catch (e) { fail(`parse: ${e instanceof Error ? e.message : e}`); } // as sigelo-verify says it
try {
  console.log(JSON.stringify(verify(doc, Math.floor(Date.now() / 1000)), null, 2));
} catch (e) { fail(e instanceof Error ? e.message : e); }
