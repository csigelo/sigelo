#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Sign a prompt as the operator, for the sigelo provenance gate (gate/DESIGN.md).
//   node sign.mjs --to did:sigelo:z…AGENT [--ttl 600] [--tools Bash,Edit] [--allow-after-read[=Bash,Edit]]
//                 [--background-ok] < prompt.txt
//                                                                                        → signed prompt
//     --allow-after-read   claims.taint_ok: the grant survives reading files, searches, web, MCP and command
//                          output in this turn (all granted tools, or only the listed ones). Without it, the
//                          first read ends the grant for privileged tools (DESIGN §5).
//     --background-ok      claims.background_ok: with deny_background set, the turn may start processes that
//                          outlive it (nohup, `&`, Monitor, run_in_background; HARDENING.md §2).
//   node sign.mjs --genesis                                                                → your genesis, to pin
// The key is the operator's sigelo-agent store, named by $SIGELO_OPERATOR_IDENTITY: no default, so the
// agent's own identity file is never picked up. Run it where the agent cannot read that file.
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { attest, did, parseBytes } from '../../ts/dist/sigelo.js';
import { CTX, LINE, rtrim } from './gate.mjs';

const arg = (k) => { const i = process.argv.indexOf(k); return i < 0 ? undefined : process.argv[i + 1]; };
const die = (m) => { process.stderr.write(`sign: ${m}\n`); process.exit(1); };
if (!process.env.SIGELO_OPERATOR_IDENTITY) die('set SIGELO_OPERATOR_IDENTITY to the operator identity file');
// Hygiene, not a boundary: an agent running as the operator's user can still read the file and unset the variable.
if (process.env.CLAUDECODE) die('refusing to sign inside a Claude Code session: sign in a terminal the agent does not control');
if (statSync(process.env.SIGELO_OPERATOR_IDENTITY).mode & 0o077) die('the operator identity file is readable by others: chmod 600 it');
const s = parseBytes(readFileSync(process.env.SIGELO_OPERATOR_IDENTITY));
const head = s.rotations.length ? s.rotations.at(-1).next_genesis : s.genesis; // the CURRENT key's genesis
if (process.argv.includes('--genesis')) { console.log(JSON.stringify(head)); process.exit(0); }

const to = arg('--to'), ttl = Number(arg('--ttl') ?? 600), tools = arg('--tools');
const aar = process.argv.find((x) => x === '--allow-after-read' || x.startsWith('--allow-after-read='));
const taintOk = aar === undefined ? undefined : aar.includes('=') ? aar.split('=')[1].split(',').filter(Boolean) : true;
if (Array.isArray(taintOk) && !taintOk.length) die('--allow-after-read= needs tool names');
if (!to?.startsWith('did:sigelo:z')) die('--to <agent DID> is required');
if (!Number.isInteger(ttl) || ttl < 1) die('--ttl must be a positive integer (seconds)');
const text = rtrim(readFileSync(0, 'utf8'));
if (!text) die('empty prompt on stdin');
if (text.includes('\t')) process.stderr.write('sign: warning: the text has tabs; the interactive TUI turns pasted tabs into spaces, so it will verify only through claude -p\n');
const iat = Math.floor(Date.now() / 1000);
const a = attest({
  secret: Uint8Array.from(Buffer.from(s.secret, 'hex')), iss: did(head), sub: to, iat, exp: iat + ttl, ctx: CTX, admission: 'open',
  claims: { text_sha256: createHash('sha256').update(text, 'utf8').digest('hex'), nonce: randomBytes(16).toString('base64url'), ...(tools && { tools: tools.split(',') }), ...(taintOk !== undefined && { taint_ok: taintOk }), ...(process.argv.includes('--background-ok') && { background_ok: true }) },
});
process.stdout.write(`${text}\n\n${LINE}${Buffer.from(JSON.stringify(a)).toString('base64url')}\n`);
