// SPDX-License-Identifier: MIT
// Who the operator is (review 2026-10-28, HIGH 1): an identity's operator is the issuer of an unexpired
// sigelo-relay/operator attestation on its chain, never issuers[0]. HOMEs as machines, one loopback
// relay in this process: a plain agent takes an ordinary attestation from a world, pairs with the
// world's agent as a friend, and the world sends device messages (renew, wipe) as an operator would.
// Each is refused (device_from): no tier own, no operator attestation filed, nothing deleted. The same
// world with an operator attestation the agent took on purpose is its operator: its renewal lands.
//   node test-operator.ts   → ALL PASS test-operator.ts (n ok)
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { attest, did, sign, type Genesis } from 'sigelo';
import { cliIn, done, hasRelay, NO_RELAY, ok, startTestRelay, tmpHome } from './test-helpers.ts';

if (!hasRelay()) {
  console.log(`SKIP who the operator is: ${NO_RELAY}`);
  done(import.meta.filename);
}
const D = tmpHome('operator'), relay = await startTestRelay(D);
const endpoints = JSON.stringify(relay.endpoints);
Object.assign(process.env, { SIGELO_RELAY: 'relay.test', SIGELO_RELAY_ENDPOINTS: endpoints, SIGELO_RELAY_REGISTRY: 'off', SIGELO_KEY_PROVIDER: 'file' });
const env = (home: string) => ({ PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: home, SIGELO_RELAY: 'relay.test', SIGELO_SHORT_RELAY: 'relay.test', SIGELO_RELAY_REGISTRY: 'off', SIGELO_RELAY_ENDPOINTS: endpoints });
const V = tmpHome('op-victim'), W = tmpHome('op-world');
const cv = cliIn(env(V), V), cw = cliIn(env(W), W);
const file = (h: string): string => join(h, '.config', 'moadim', 'sigelo.local.json');
const idOf = (h: string) => JSON.parse(readFileSync(file(h), 'utf8')) as { secret: string; genesis: Genesis; attestations: { body: { iss: string; ctx: string } }[] };
const t = (): number => Math.floor(Date.now() / 1000);
const { libs, carrierFor } = await import('./sigelo-agent-enrol.ts');
const { lib } = await libs(), dev = await import('sigelo-contact/device.mjs' as string) as { signList(l: object, s: (b: unknown) => string): object };
// The world's agent sends a sigelo-device/1 message the way an operator's does (the internal send).
async function fromWorld(content: object): Promise<void> {
  const c = carrierFor(lib, file(W)) as unknown as { send(to: string, c: object, o: object): Promise<{ status: string }>; stop(): Promise<void> };
  const l = lib as unknown as { DEVICE_LABEL: string; DEVICE_SEND: symbol };
  try { await c.send(vDid, content, { label: l.DEVICE_LABEL, internal: l.DEVICE_SEND }); } finally { await c.stop(); }
}
// The world as the agent's `contacts` lists it (its tier is worked out there, from the agent's operators).
const worldIn = async (): Promise<{ tier?: string; ours?: boolean } | undefined> => (JSON.parse((await cv('contacts')).stdout || '{}') as { contacts?: { did: string; tier: string; ours?: boolean }[] }).contacts?.find((c) => c.did === wDid);
const operatorCtx = (sub: string, exp: number) => attest({ secret: Buffer.from(idOf(W).secret, 'hex'), iss: wDid, sub, iat: t() - 5, exp, ctx: 'sigelo-relay/operator', admission: 'invite', admission_by: wDid, claims: { relay: 'relay.test' } });
let vDid = '', wDid = '';

try {
  ok('two plain identities: init --no-recovery', (await cv('init', '--no-recovery')).status === 0 && (await cw('init', '--no-recovery')).status === 0);
  vDid = did(idOf(V).genesis); wDid = did(idOf(W).genesis);
  // An ordinary attestation from the world (its issuer is issuers[0] of the agent's file).
  const member = attest({ secret: Buffer.from(idOf(W).secret, 'hex'), iss: wDid, sub: vDid, iat: t() - 5, exp: t() + 30 * 86400, ctx: 'acme-world/member', admission: 'open', claims: {} });
  ok('the agent files the world\'s genesis and its member attestation', (await cv('add-issuer', JSON.stringify(idOf(W).genesis))).status === 0 && (await cv('add-attestation', JSON.stringify(member))).status === 0);
  const code = (await cw('invite', '--long', '--name', 'agent')).stdout.trim();
  const [acc] = await Promise.all([cv('accept', code, '--name', 'world', '--wait', '30'), cw('inbox', '--wait', '20')]);
  await cv('inbox');
  ok('the agent pairs with the world\'s agent as a normal contact (friend)', acc.status === 0 && (await worldIn())?.tier === 'friend', acc.stderr + acc.stdout);

  // renew: an operator-ctx attestation by the world, sent as a device renewal.
  await fromWorld({ v: 'sigelo-device/1', typ: 'renew', attestation: operatorCtx(vDid, t() + 14 * 86400), issuer: idOf(W).genesis });
  const r1 = await cv('inbox', '--wait', '5');
  ok('a renewal from a contact that is only issuers[0]: refused device_from, not renewed', r1.stderr.includes('device_from') && !r1.stderr.includes('renewed'), r1.stderr);
  ok('…no operator attestation filed, the world not own', !idOf(V).attestations.some((a) => a.body.ctx === 'sigelo-relay/operator') && (await worldIn())?.tier === 'friend', JSON.stringify(await worldIn()));

  // wipe: a device list signed by the world's key marking the agent revoked.
  const list = dev.signList({ operator: wDid, seq: 1, iat: t(), devices: [{ name: 'agent', worker: 0, did: vDid, rank: 'safe', added: t() - 60, by: wDid, revoked: t() }] }, (b) => sign(Buffer.from(idOf(W).secret, 'hex'), b));
  await fromWorld({ v: 'sigelo-device/1', typ: 'wipe', devices: list });
  const r2 = await cv('inbox', '--wait', '5');
  ok('a wipe from a contact that is only issuers[0]: refused device_from; the identity file stays', r2.stderr.includes('device_from') && !r2.stderr.includes('revoked this device') && existsSync(file(V)), r2.stderr);

  // The same world as an operator the agent took on purpose: its renewal is taken.
  ok('the agent files an operator attestation from the world itself', (await cv('add-attestation', JSON.stringify(operatorCtx(vDid, t() + 3 * 86400)))).status === 0);
  const later = t() + 14 * 86400;
  await fromWorld({ v: 'sigelo-device/1', typ: 'renew', attestation: operatorCtx(vDid, later), issuer: idOf(W).genesis });
  const r3 = await cv('inbox', '--wait', '5');
  ok('…then the world is its operator: the renewal lands', r3.stderr.includes('renewed') && !r3.stderr.includes('device_from'), r3.stderr);
} finally {
  await relay.close?.();
}
done(import.meta.filename);
