// SPDX-License-Identifier: MIT
// The handshake checks werift 0.26.0's DTLS leaves out, added in this process before any peer exists.
// werift compares the peer's certificate with the fingerprint in the SDP, but never checks that the
// peer holds that certificate's key: no signature over the ServerKeyExchange (client side, RFC 5246
// §7.4.3, RFC 8422 §5.4), none over the CertificateVerify (server side, RFC 5246 §7.4.8), and neither
// side's Finished (§7.4.9). The fingerprint is public (it rides the SDP), so anyone on the path could
// present the right certificate with a key of their own and read the channel. Here, on werift's
// CommonJS build (the ESM bundle hides these classes; rtc.mjs loads werift through require):
//   - client, before its flight 5: the ServerKeyExchange's signature, with the certificate's key, over
//     client_random + server_random + ServerECDHParams, in the hash and algorithm the message names;
//   - server, before its flight 6: the CertificateVerify's signature over the handshake so far, and the
//     client's Finished;
//   - client, on the server's Finished: its verify_data;
//   - both: a second certificate or key exchange different from the one checked is refused, and so is
//     renegotiation (a new handshake after the fingerprint check; WebRTC never renegotiates);
//   - both: no application data is delivered before this side's checks passed (werift decrypts any record
//     once it holds keys: the server from the client's key exchange on, before its Finished arrives).
// Only ECDSA with a P-256 certificate is verified (what werift and browsers make); anything else is
// refused with an alert, never let through. A refusal sends a fatal alert and fails the transport.
// harden() is idempotent and returns { ok, why }; ok only for the werift version it was written against
// and only when every hook is in place (hardened() checks the marks again).
import { createRequire } from 'node:module';
import { X509Certificate, verify, timingSafeEqual } from 'node:crypto';
import { dirname, join } from 'node:path';

export const WERIFT = '0.26.0';
const MARK = Symbol.for('sigelo.dtls-verify/1');
const CHECKED = Symbol('sigelo.dtls-checked');   // on a DtlsContext: { cert, ske } once the client checked them
const FAILED = Symbol('sigelo.dtls-failed');     // on a DtlsContext: the refusal, sticky
const VERIFIED = Symbol('sigelo.dtls-verified'); // on a DtlsContext: this side's checks all passed
const require = createRequire(import.meta.url);

// RFC 5246 §7.2 alert descriptions
const DECRYPT_ERROR = 51, ILLEGAL_PARAMETER = 47, UNSUPPORTED_CERTIFICATE = 43, HANDSHAKE_FAILURE = 40, NO_RENEGOTIATION = 100;
const HASH = { 4: 'sha256', 5: 'sha384', 6: 'sha512' };   // RFC 5246 §7.4.1.4.1 HashAlgorithm
let W = null, state = null;
/** Handshake checks passed in this process (tests read it: proof the checks ran, not only that they exist). */
export const passed = { serverKeyExchange: 0, certificateVerify: 0, clientFinished: 0, serverFinished: 0 };

class Refused extends Error {
  constructor(check, why, alert) { super(`${check}: ${why}`); this.check = check; this.alert = alert; }
}

function send(ctx, desc) {   // a fatal alert, best effort: the refusal stands whether it leaves or not
  try {
    const [p] = W.builder.createPlaintext(ctx.dtls)([{ type: 21, fragment: Buffer.from([2, desc]) }], ++ctx.dtls.recordSequenceNumber);
    const pkt = ctx.dtls.epoch > 0 && ctx.cipher?.cipher ? ctx.cipher.encryptPacket(p) : p;
    Promise.resolve(ctx.transport.send(pkt.serialize())).catch(() => {});
  } catch {}
}
function refuse(ctx, check, why, alert) {
  const e = new Refused(check, why, alert);
  if (!ctx.dtls[FAILED]) { ctx.dtls[FAILED] = e; send(ctx, alert); }
  throw ctx.dtls[FAILED];
}

// The peer's message of a type, by the flight werift files it under (4: the server's, on the client;
// 5: the client's, on the server). Each side's own Certificate has the same type in another flight.
const cached = (dtls, flight, type) => dtls.handshakeCache[flight]?.data.find((h) => h.msg_type === type);
const before = (dtls, h) => { const all = dtls.sortedHandshakeCache, i = all.indexOf(h); return Buffer.concat(all.slice(0, i).map((x) => x.serialize())); };
const all = (dtls) => Buffer.concat(dtls.sortedHandshakeCache.map((x) => x.serialize()));

/** The key to check a signature with, and the hash: the pair must be one werift offered and ECDSA; the key P-256. */
function keyFor(ctx, certDer, hashId, sigId) {
  if (sigId !== W.c.SignatureAlgorithm.ecdsa_3) refuse(ctx, 'dtls_unsupported', `signature algorithm ${sigId}: only ECDSA is verified here`, HANDSHAKE_FAILURE);
  if (!W.c.signatures.some((s) => s.hash === hashId && s.signature === sigId) || !HASH[hashId]) refuse(ctx, 'dtls_bad_algorithm', `hash ${hashId} with signature ${sigId} was not offered`, ILLEGAL_PARAMETER);
  let key;
  try { key = new X509Certificate(certDer).publicKey; } catch { refuse(ctx, 'dtls_bad_certificate', 'the peer certificate does not parse', UNSUPPORTED_CERTIFICATE); }
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    refuse(ctx, 'dtls_unsupported', `peer certificate key ${key.asymmetricKeyType}/${key.asymmetricKeyDetails?.namedCurve ?? '-'}: only ECDSA P-256 is verified here`, UNSUPPORTED_CERTIFICATE);
  }
  return { key, hash: HASH[hashId] };
}
const sigOk = (k, data, sig) => { try { return verify(k.hash, data, { key: k.key, dsaEncoding: 'der' }, sig); } catch { return false; } };
const same = (a, b) => Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length && timingSafeEqual(a, b);
const certOf = (h) => W.Certificate.deSerialize(h.fragment).certificateList[0];

/** A certificate or key exchange arriving again must be the one already taken (before the check: the
 *  one werift took; after it: the one checked). werift's handlers take the last, its cache the first. */
function guard(ctx, handshake) {
  if (ctx.dtls[FAILED]) throw ctx.dtls[FAILED];
  if (handshake.msg_type === 11 && ctx.cipher.remoteCertificate) {
    let c = null; try { c = certOf(handshake); } catch {}
    if (!same(Buffer.from(c ?? []), Buffer.from(ctx.cipher.remoteCertificate))) refuse(ctx, 'dtls_certificate_changed', 'a second, different peer certificate in one handshake', HANDSHAKE_FAILURE);
  }
  const ck = ctx.dtls[CHECKED];
  if (handshake.msg_type === 12 && ck && !same(handshake.fragment, ck.ske)) refuse(ctx, 'dtls_key_exchange_changed', 'a second, different ServerKeyExchange after the checked one', HANDSHAKE_FAILURE);
}

/** Client, before flight 5: the server holds the certificate's key (its ServerKeyExchange signature). */
function checkServer(ctx) {
  const { dtls, cipher } = ctx;
  const hc = cached(dtls, 4, 11), hk = cached(dtls, 4, 12);
  if (!hc || !hk) refuse(ctx, 'dtls_missing', 'no server Certificate or ServerKeyExchange', HANDSHAKE_FAILURE);
  const cert = certOf(hc);
  if (!same(Buffer.from(cert), Buffer.from(cipher.remoteCertificate ?? []))) refuse(ctx, 'dtls_certificate_changed', 'the certificate taken is not the one in the handshake', HANDSHAKE_FAILURE);
  const ske = W.ServerKeyExchange.deSerialize(hk.fragment);
  if (ske.ellipticCurveType !== 3 || ske.namedCurve !== cipher.remoteKeyPair?.curve || !same(ske.publicKey, cipher.remoteKeyPair?.publicKey)) {
    refuse(ctx, 'dtls_key_exchange_changed', 'the key exchange taken is not the one in the handshake', HANDSHAKE_FAILURE);
  }
  const k = keyFor(ctx, cert, ske.hashAlgorithm, ske.signatureAlgorithm);
  const params = Buffer.from([3, ske.namedCurve >> 8, ske.namedCurve & 255, ske.publicKey.length]);
  const signed = Buffer.concat([cipher.localRandom.serialize(), cipher.remoteRandom.serialize(), params, ske.publicKey]);
  if (!sigOk(k, signed, ske.signature)) refuse(ctx, 'dtls_bad_signature', 'the ServerKeyExchange signature does not verify with the certificate\'s key', DECRYPT_ERROR);
  dtls[CHECKED] = { cert, ske: Buffer.from(hk.fragment) };
  passed.serverKeyExchange++;
}

/** Server, before flight 6: the client holds the certificate's key (CertificateVerify), and its Finished is right. */
function checkClient(ctx) {
  const { dtls, cipher } = ctx;
  const hv = cached(dtls, 5, 15), hc = cached(dtls, 5, 11);
  if (dtls.options.certificateRequest || hv) {
    if (!hc || !hv) refuse(ctx, 'dtls_missing', 'no client Certificate or CertificateVerify', HANDSHAKE_FAILURE);
    const cert = certOf(hc);
    if (!same(Buffer.from(cert), Buffer.from(cipher.remoteCertificate ?? []))) refuse(ctx, 'dtls_certificate_changed', 'the certificate taken is not the one in the handshake', HANDSHAKE_FAILURE);
    const cv = W.CertificateVerify.deSerialize(hv.fragment);
    const k = keyFor(ctx, cert, cv.algorithm >> 8, cv.algorithm & 255);
    if (!sigOk(k, before(dtls, hv), cv.signature)) refuse(ctx, 'dtls_bad_signature', 'the CertificateVerify signature does not verify with the certificate\'s key', DECRYPT_ERROR);
    passed.certificateVerify++;
  }
  const hf = cached(dtls, 5, 20);
  if (!hf || !cipher.masterSecret) refuse(ctx, 'dtls_missing', 'no client Finished', HANDSHAKE_FAILURE);
  if (!same(W.Finished.deSerialize(hf.fragment).verifyData, W.prf.prfVerifyDataClient(cipher.masterSecret, before(dtls, hf)))) {
    refuse(ctx, 'dtls_bad_finished', 'the client Finished does not match the handshake', DECRYPT_ERROR);
  }
  passed.clientFinished++;
  dtls[VERIFIED] = true;
}

/** Client, on the server's Finished (not cached by werift): it follows a checked key exchange and matches. */
function checkServerFinished(ctx, fins) {
  if (!ctx.dtls[CHECKED] || !ctx.cipher.masterSecret) refuse(ctx, 'dtls_early_finished', 'a server Finished before the key exchange was checked', HANDSHAKE_FAILURE);
  const f = W.FragmentedHandshake.assemble(fins);
  if (!same(W.Finished.deSerialize(f.fragment).verifyData, W.prf.prfVerifyDataServer(ctx.cipher.masterSecret, all(ctx.dtls)))) {
    refuse(ctx, 'dtls_bad_finished', 'the server Finished does not match the handshake', DECRYPT_ERROR);
  }
  passed.serverFinished++;
  ctx.dtls[VERIFIED] = true;
}

function hook(proto, name, wrap) {
  const orig = proto[name];
  if (typeof orig !== 'function') throw new Error(`werift: ${name} is not a method here`);
  if (orig[MARK]) return;
  const f = wrap(orig);
  f[MARK] = true;
  proto[name] = f;
}

function load() {
  const entry = require.resolve('werift');                     // …/werift/lib/webrtc/src/index.js
  const root = join(dirname(entry), '..', '..', '..');
  const version = require(join(root, 'package.json')).version;
  if (version !== WERIFT) return { why: `werift ${version}: these checks are written for ${WERIFT} only` };
  const d = (p) => require(join(root, 'lib', 'dtls', 'src', p));
  const m = {
    version,
    Flight5: d('flight/client/flight5.js').Flight5,
    Flight6: d('flight/server/flight6.js').Flight6,
    DtlsSocket: d('socket.js').DtlsSocket,
    SessionType: d('cipher/suites/abstract.js').SessionType,
    ServerKeyExchange: d('handshake/message/server/keyExchange.js').ServerKeyExchange,
    CertificateVerify: d('handshake/message/client/certificateVerify.js').CertificateVerify,
    Certificate: d('handshake/message/certificate.js').Certificate,
    Finished: d('handshake/message/finished.js').Finished,
    FragmentedHandshake: d('record/message/fragment.js').FragmentedHandshake,
    prf: d('cipher/prf.js'),
    builder: d('record/builder.js'),
    receive: d('record/receive.js'),
    c: d('cipher/const.js'),
    werift: require('werift'),
  };
  // The classes hooked must be the ones werift's own RTCPeerConnection builds on.
  if (Object.getPrototypeOf(m.werift.DtlsClient?.prototype ?? {}) !== m.DtlsSocket.prototype || m.werift.DtlsServer?.prototype instanceof m.DtlsSocket !== true) {
    return { why: 'werift\'s DTLS classes are not the ones loaded here' };
  }
  return m;
}

/** Hooks the checks into werift once; → { ok, why }. */
export function harden() {
  if (state) return state;
  try {
    const m = load();
    if (!m.Flight5) return (state = { ok: false, why: m.why });
    W = m;
    hook(m.Flight5.prototype, 'handleHandshake', (orig) => function (h) { guard(this, h); return orig.call(this, h); });
    hook(m.Flight5.prototype, 'exec', (orig) => async function () {
      if (this.dtls[FAILED]) throw this.dtls[FAILED];
      if (this.dtls.flight !== 5) checkServer(this);
      return orig.call(this);
    });
    hook(m.Flight6.prototype, 'handleHandshake', (orig) => function (h) { guard(this, h); return orig.call(this, h); });
    hook(m.Flight6.prototype, 'exec', (orig) => async function () {
      if (this.dtls[FAILED]) throw this.dtls[FAILED];
      if (this.dtls.flight !== 6) checkClient(this);
      return orig.call(this);
    });
    hook(m.DtlsSocket.prototype, 'handleFragmentHandshake', (orig) => function (msgs) {
      const out = orig.call(this, msgs);
      if (this.sessionType !== m.SessionType.CLIENT || this.connected) return out;
      try {
        if (this.dtls[FAILED]) throw this.dtls[FAILED];
        const fins = out.filter((h) => h.msg_type === 20);
        if (fins.length) checkServerFinished(this, fins);
        return out;
      } catch (e) { this.onError.execute(e); return []; }   // nothing of it is handled; the transport fails
    });
    // socket.js calls receive.parsePlainText through the module object for every record: application data
    // before the checks passed (or after a refusal) is dropped there, before SCTP or SRTP sees it.
    hook(m.receive, 'parsePlainText', (orig) => function (dtls, cipher) {
      const parse = orig.call(this, dtls, cipher);
      return (plain) => (plain?.recordLayerHeader?.contentType === 23 && (!dtls?.[VERIFIED] || dtls[FAILED]) ? [] : parse(plain));
    });
    hook(m.DtlsSocket.prototype, 'renegotiation', () => function () {
      refuse(this, 'dtls_renegotiation', 'a new handshake on a connected DTLS session is refused', NO_RENEGOTIATION);
    });
    state = hardened() ? { ok: true, why: `werift ${m.version}: handshake signatures and Finished checked` } : { ok: false, why: 'a hook did not take' };
  } catch (e) { state = { ok: false, why: `werift could not be hardened: ${e.message}` }; }
  return state;
}

/** Every hook in place (the marks harden() leaves on werift's prototypes). */
export function hardened() {
  if (!W) return false;
  return [[W.Flight5.prototype, 'handleHandshake'], [W.Flight5.prototype, 'exec'], [W.Flight6.prototype, 'handleHandshake'], [W.Flight6.prototype, 'exec'],
    [W.DtlsSocket.prototype, 'handleFragmentHandshake'], [W.DtlsSocket.prototype, 'renegotiation'], [W.receive, 'parsePlainText']].every(([p, n]) => p[n]?.[MARK] === true);
}

/** werift's CommonJS build, the one the hooks are on (null when harden() did not succeed). */
export const werift = () => (state?.ok ? W.werift : null);
