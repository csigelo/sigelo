#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Sign a prompt as the operator, for the sigelo provenance gate (gate/DESIGN.md).
//   node sign.mjs --to did:sigelo:z…AGENT [--ttl 600] [--tools Bash,Edit] < prompt.txt   → signed prompt
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
if (!to?.startsWith('did:sigelo:z')) die('--to <agent DID> is required');
if (!Number.isInteger(ttl) || ttl < 1) die('--ttl must be a positive integer (seconds)');
const text = rtrim(readFileSync(0, 'utf8'));
if (!text) die('empty prompt on stdin');
const iat = Math.floor(Date.now() / 1000);
const a = attest({
  secret: Uint8Array.from(Buffer.from(s.secret, 'hex')), iss: did(head), sub: to, iat, exp: iat + ttl, ctx: CTX, admission: 'open',
  claims: { text_sha256: createHash('sha256').update(text, 'utf8').digest('hex'), nonce: randomBytes(16).toString('base64url'), ...(tools && { tools: tools.split(',') }) },
});
process.stdout.write(`${text}\n\n${LINE}${Buffer.from(JSON.stringify(a)).toString('base64url')}\n`);
