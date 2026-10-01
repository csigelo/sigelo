// SPDX-License-Identifier: MIT
// node sim/verify-one.mjs <bundle.json> <now> — the ts side of one differential comparison:
// the file's BYTES through parseBytes (fatal UTF-8 decode, then the strict parser: duplicate
// keys, "__proto__" and nesting past 512 reject the document), verify() with no locally known
// issuers, and the §9.1 result as JCS (exit 0) or the rejection on stderr (exit 1), in the shape
// and words go/cmd/sigelo-verify prints: "REJECT: parse: <check>" for a document that does not
// parse, "REJECT: <check>" otherwise. Reading the file as a 'utf8' string instead turned invalid
// bytes into U+FFFD and accepted what Go rejects (differential D3; SPEC §3).
import { readFileSync } from 'node:fs';
import { parseBytes, verify, canonicalize } from '../ts/dist/sigelo.js';
const [file, now] = process.argv.slice(2);
if (!file || !/^\d+$/.test(now ?? '')) { console.error('usage: node sim/verify-one.mjs <bundle.json> <now>'); process.exit(2); }
let bytes, doc;
try { bytes = readFileSync(file); } catch (e) { console.error(`verify-one: ${e?.message ?? e}`); process.exit(2); }
try { doc = parseBytes(bytes); } catch (e) { console.error('REJECT: parse: ' + (e?.message ?? e)); process.exit(1); }
try { console.log(canonicalize(verify(doc, Number(now)))); }
catch (e) { console.error('REJECT: ' + (e?.message ?? e)); process.exit(1); }
