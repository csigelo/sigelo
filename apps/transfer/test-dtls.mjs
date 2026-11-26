// SPDX-License-Identifier: MIT
// dtls-verify.mjs against werift's own DTLS client and server over an in-memory pipe (no network, no
// timers but werift's): an honest handshake passes; a peer that presents someone else's certificate
// (the fingerprint the SDP names) without its key is refused on either side; an RSA certificate is
// refused, not let through; a transcript that differs from the peer's fails at the Finished check on
// either side; a renegotiation after the handshake is refused; no application data is delivered before
// the checks passed. Each refusal sends the peer an alert.
import { createRequire } from 'node:module';
import { createHash, X509Certificate } from 'node:crypto';
import { harden, hardened } from './dtls-verify.mjs';

const H = harden();
let n = 0, bad = 0;
const ok = (c, what) => { n++; if (c) console.log(`ok   ${what}`); else { bad++; console.log(`FAIL ${what}`); } };
ok(H.ok && hardened(), `the checks are in place (${H.why})`);
const W = createRequire(import.meta.url)('werift');

const ECDSA = { hash: 4, signature: 3 }, RSA = { hash: 4, signature: 1 };
const cert = (sh = ECDSA) => W.CipherContext.createSelfSignedCertificateWithKey(sh);
const fp = (pem) => createHash('sha256').update(new X509Certificate(pem).raw).digest('hex');

/** Two in-memory DTLS transports; tap(dir, buf) may change or drop a datagram (→ null). Alerts are counted. */
function pipe(tap = (_d, b) => b) {
  const alerts = { toClient: 0, toServer: 0 };
  const end = () => ({ type: 'mem', address: {}, closed: false, onData: () => {}, close: async () => {} });
  const s = end(), c = end();
  const deliver = (to, dir) => async (buf) => {
    const b = tap(dir, Buffer.from(buf));
    if (!b) return;
    if (b[0] === 21) alerts[dir]++;
    setImmediate(() => to.onData(b, {}));
  };
  s.send = deliver(c, 'toClient'); c.send = deliver(s, 'toServer');
  return { s, c, alerts };
}

/** One handshake: → { result: 'connected' | the refusal's check, side, client, server, alerts }. */
async function shake({ server: so = {}, client: co = {}, tap, after } = {}) {
  const sc = so.cert ?? await cert(), cc = co.cert ?? await cert();
  const p = pipe(tap && ((dir, b) => tap(dir, b, ctx)));
  const server = new W.DtlsServer({ transport: p.s, cert: sc.certPem, key: so.key ?? sc.keyPem, signatureHash: sc.signatureHash, certificateRequest: so.certificateRequest ?? true, extendedMasterSecret: so.ems ?? true });
  const client = new W.DtlsClient({ transport: p.c, cert: cc.certPem, key: co.key ?? cc.keyPem, signatureHash: cc.signatureHash, extendedMasterSecret: co.ems ?? true });
  const ctx = { server, client };
  const result = await new Promise((r) => {
    let up = 0;
    const t = setTimeout(() => r({ result: 'timeout' }), 15000);
    const done = (x) => { clearTimeout(t); r(x); };
    client.onError.once((e) => done({ result: e.check ?? e.message, side: 'client' }));
    server.onError.once((e) => done({ result: e.check ?? e.message, side: 'server' }));
    const conn = () => { if (++up === 2) done({ result: 'connected' }); };
    client.onConnect.once(conn); server.onConnect.once(conn);
    client.connect().catch((e) => done({ result: e.check ?? e.message, side: 'client' }));
  });
  if (after && result.result === 'connected') Object.assign(result, await after(ctx, p));
  await new Promise((r) => setTimeout(r, 50));   // an alert sent with the refusal arrives
  return { ...result, ...ctx, alerts: p.alerts, sc, cc };
}

// 1. Honest: both sides check and connect; data both ways; the certificate each side holds is the peer's.
{
  const x = await shake({
    after: async ({ server, client }) => {
      const got = new Promise((r) => server.onData.once((b) => r(b.toString())));
      client.send(Buffer.from('hello'));
      return { got: await got };
    },
  });
  ok(x.result === 'connected' && x.got === 'hello', `honest handshake, client certificate requested: connected, data through (${x.result})`);
  ok(fp(new X509Certificate(x.client.remoteCertificate).toString()) === fp(x.sc.certPem) && fp(new X509Certificate(x.server.remoteCertificate).toString()) === fp(x.cc.certPem),
    'each side holds the other\'s certificate (the one its fingerprint names)');
  const y = await shake({ server: { certificateRequest: false }, client: {} });
  ok(y.result === 'connected', `honest handshake without a client certificate: connected (${y.result})`);
}

// 2. The server presents the victim's certificate (fingerprint right) and signs with its own key.
{
  const victim = await cert(), attacker = await cert();
  const x = await shake({ server: { cert: victim, key: attacker.keyPem } });
  ok(x.result === 'dtls_bad_signature' && x.side === 'client', `server without the certificate's key: client refuses, ${x.result} (${x.side})`);
  ok(x.alerts.toServer === 1 && x.client.connected !== true && x.server.connected !== true, 'one alert to the server, nobody connected');
}

// 3. The client presents the victim's certificate and signs its CertificateVerify with its own key.
{
  const victim = await cert(), attacker = await cert();
  const x = await shake({ client: { cert: victim, key: attacker.keyPem } });
  ok(x.result === 'dtls_bad_signature' && x.side === 'server', `client without the certificate's key: server refuses, ${x.result} (${x.side})`);
  ok(x.alerts.toClient === 1 && x.server.connected !== true, 'one alert to the client, the server not connected');
}

// 4. RSA certificates: refused, not passed unchecked.
{
  const a = await shake({ server: { cert: await cert(RSA) } });
  ok(a.result === 'dtls_unsupported' && a.side === 'client', `server with an RSA certificate: ${a.result} (${a.side})`);
  const b = await shake({ client: { cert: await cert(RSA) } });
  ok(b.result === 'dtls_unsupported' && b.side === 'server', `client with an RSA certificate: ${b.result} (${b.side})`);
}

// 5. Transcripts that differ, keys equal (no extended master secret): the Finished checks catch it.
// ServerHello's session id (one byte werift's client reads nothing from) changed on the way.
{
  const sid = (dir, b) => {
    // record header 13 bytes, handshake header 12; ServerHello: version 2, random 32, session id length 1 + id
    if (dir === 'toClient' && b[0] === 22 && b[13] === 2 && b[13 + 12 + 34] === 1) { b[13 + 12 + 35] ^= 1; }
    return b;
  };
  const x = await shake({ server: { certificateRequest: false, ems: false }, client: { ems: false }, tap: sid });
  ok(x.result === 'dtls_bad_finished' && x.side === 'server', `ServerHello changed on the path: the server refuses the client Finished, ${x.result} (${x.side})`);
  // The client's check: its cached copy of the ServerHello changed after its flight 5 left, before the server's Finished.
  const late = (dir, b, ctx) => {
    if (dir === 'toClient' && ctx.client.dtls.flight === 5) {
      const h = ctx.client.dtls.sortedHandshakeCache.find((m) => m.msg_type === 2);
      if (h && !h.touched) { h.fragment = Buffer.from(h.fragment); h.fragment[35] ^= 1; h.touched = true; }
    }
    return b;
  };
  const y = await shake({ server: { certificateRequest: false, ems: false }, client: { ems: false }, tap: late });
  ok(y.result === 'dtls_bad_finished' && y.side === 'client', `a transcript differing at the server Finished: the client refuses, ${y.result} (${y.side})`);
}

// 6. Renegotiation after the handshake (a new ClientHello into a connected server): refused.
{
  const x = await shake({
    after: async ({ server }, p) => {
      const err = new Promise((r) => server.onError.once((e) => r(e.check ?? e.message)));
      const cc = await cert();
      const q = { type: 'mem', address: {}, closed: false, onData: () => {}, close: async () => {}, send: async (b) => setImmediate(() => p.s.onData(Buffer.from(b), {})) };
      const evil = new W.DtlsClient({ transport: q, cert: cc.certPem, key: cc.keyPem, signatureHash: cc.signatureHash, extendedMasterSecret: true });
      evil.connect().catch(() => {});
      return { reneg: await Promise.race([err, new Promise((r) => setTimeout(() => r('none'), 5000))]) };
    },
  });
  ok(x.result === 'connected' && x.reneg === 'dtls_renegotiation', `a ClientHello after the handshake: ${x.reneg}`);
}

// 7. Application data before the handshake is checked: werift decrypts any record once it holds keys
// (the server from the client's key exchange on), so a client without the certificate's key could reach
// the data channel's SCTP before the CertificateVerify and Finished checks. Nothing is delivered until
// this side's checks passed: neither with the client Finished held back, nor after the refusal.
{
  const victim = await cert(), attacker = await cert();
  let early = 0, hold = true;
  const x = await shake({
    client: { cert: victim, key: attacker.keyPem },
    tap: (dir, b, ctx) => {
      // the client's Finished (handshake, epoch 1) held back while the client sends data with its new keys
      if (dir === 'toServer' && b[0] === 22 && b.readUInt16BE(3) === 1 && hold) {
        hold = false;
        ctx.server.onData.subscribe(() => { early++; });
        setTimeout(() => { ctx.client.send(Buffer.from('early')).catch(() => {}); }, 20);
        setTimeout(() => { ctx.server.transport.socket.onData(b, {}); }, 120);
        return null;
      }
      return b;
    },
  });
  await x.client.send(Buffer.from('late')).catch(() => {});
  await new Promise((r) => setTimeout(r, 100));
  ok(x.result === 'dtls_bad_signature' && x.side === 'server', `client without the certificate's key, its Finished late: ${x.result} (${x.side})`);
  ok(early === 0, `no application data reached the server before or after the refusal (${early} delivered)`);
  const y = await shake({ after: async ({ server, client }) => {
    const got = new Promise((r) => server.onData.once((b) => r(b.toString())));
    const back = new Promise((r) => client.onData.once((b) => r(b.toString())));
    client.send(Buffer.from('ping')); server.send(Buffer.from('pong'));
    return { got: await got, back: await back };
  } });
  ok(y.got === 'ping' && y.back === 'pong', 'an honest pair still exchanges data both ways after the checks');
}

console.log(bad ? `FAILED ${bad} of ${n}` : `ALL PASS (${n})`);
process.exit(bad ? 1 : 0);
