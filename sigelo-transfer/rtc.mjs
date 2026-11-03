// SPDX-License-Identifier: MIT
// sigelo-transfer: the direct path of a transfer (design/transfer.md §2, §6), one WebRTC data channel
// between two agents, on werift (pure TypeScript: ICE, DTLS, SCTP; no native code, so the build stays
// reproducible). Kept in its own package so sigelo-contact's dependencies stay as they are;
// contact/transfer-node.mjs imports it only when a transfer starts, and goes without it (Tor only)
// when it is not installed.
//
//   const p = await peer({ stun, gatherMs })   one side of a pairing's transfer attempt
//   await p.offer(label)        → sdp: the receiver's (it pulls): a data channel named label, every candidate gathered
//   await p.answer(sdp, label)  → sdp: the sender's, for that offer; only a channel named label is taken
//   await p.accept(sdp)         the receiver sets the sender's answer
//   await p.open(ms)            → the channel (contact/transfer.mjs's: send, buffered, close, on) once DTLS is up, or throws ice_timeout
//   p.close()
//
// Candidates are gathered at once and sent whole (not trickled): gatherMs at most (3 s), so a
// transfer costs two relay messages per attempt. stun: ['host:port', …]; empty: host candidates
// only. The remote description loses any `.local` candidate first: resolving it would put a
// multicast DNS socket on the LAN. The SDP rides a signed envelope, so its ICE credentials and DTLS
// fingerprint are the contact's; werift checks the fingerprint at the handshake.
import { createSecretKey } from 'node:crypto';
import { RTCPeerConnection } from 'werift';

export const WERIFT = '0.26.0';
const LOW = 1 << 20;

const fail = (check, why) => { throw Object.assign(new Error(`${check}: ${why}`), { check }); };
const iceServers = (stun) => (stun.length ? [{ urls: stun.map((s) => `stun:${s}`) }] : []);
const noMdns = (sdp) => sdp.split(/\r?\n/).filter((l) => !/^a=candidate:.* [0-9a-f-]+\.local /i.test(l)).join('\r\n');

// werift creates a cipher for every DTLS record from the raw key bytes, and Node prepares that key
// again each time: a third of the CPU of a transfer. A KeyObject made once is taken as is (measured on
// the phone: 1.5 → 2.8 MB/s). Applied when the shape is the one this version has; otherwise nothing.
function fastKeys(pc) {
  const x = pc.sctpTransport?.dtlsTransport?.dtls?.cipher?.cipher;
  if (!x || !Buffer.isBuffer(x.clientWriteKey) || !Buffer.isBuffer(x.serverWriteKey)) return false;
  x.clientWriteKey = createSecretKey(x.clientWriteKey);
  x.serverWriteKey = createSecretKey(x.serverWriteKey);
  return true;
}

/** A werift data channel as contact/transfer.mjs's channel. */
export function channelOf(dc, pc) {
  const on = { frame: [], low: [], close: [] };
  let closed = false;
  const shut = () => { if (closed) return; closed = true; for (const f of on.close) { try { f(); } catch {} } };
  dc.bufferedAmountLowThreshold = LOW;
  dc.onMessage.subscribe((m) => { if (typeof m === 'string') return; const u = new Uint8Array(m.buffer, m.byteOffset, m.length); for (const f of on.frame) f(u); });
  dc.bufferedAmountLow.subscribe(() => { for (const f of on.low) f(); });
  dc.stateChanged.subscribe((s) => { if (s === 'closed' || s === 'closing') shut(); });
  pc.connectionStateChange.subscribe((s) => { if (s === 'failed' || s === 'closed' || s === 'disconnected') shut(); });
  return {
    send(f) { if (closed) throw new Error('closed'); dc.send(Buffer.from(f.buffer, f.byteOffset, f.length)); },
    buffered: () => dc.bufferedAmount,
    close() { try { dc.close(); } catch {} shut(); },
    on(e, fn) { on[e].push(fn); },
    get closed() { return closed; },
  };
}

export async function peer({ stun = [], gatherMs = 3000 } = {}) {
  const pc = new RTCPeerConnection({ iceServers: iceServers(stun), iceStunGatherTimeout: Math.max(1, Math.ceil(gatherMs / 1000)) });   // werift: seconds
  let dc = null, want = null, gotDc;
  const dcP = new Promise((r) => { gotDc = r; });
  pc.onDataChannel.subscribe((ch) => {
    // Only the channel this attempt named; any other is closed (design §3 "Binding").
    if (want === null || ch.label !== want || dc) { try { ch.close(); } catch {} return; }
    dc = ch; gotDc(ch);
  });
  const gathered = async () => {
    if (pc.iceGatheringState !== 'complete') {
      await new Promise((r) => {
        const t = setTimeout(r, gatherMs);
        pc.iceGatheringStateChange.subscribe((s) => { if (s === 'complete') { clearTimeout(t); r(); } });
      });
    }
    return pc.localDescription.sdp;
  };
  return {
    pc,
    async offer(label) {
      want = label;
      dc = pc.createDataChannel(label, { ordered: true });
      gotDc(dc);
      await pc.setLocalDescription(await pc.createOffer());
      return gathered();
    },
    async answer(sdp, label) {
      want = label;
      await pc.setRemoteDescription({ type: 'offer', sdp: noMdns(sdp) });
      await pc.setLocalDescription(await pc.createAnswer());
      return gathered();
    },
    async accept(sdp) { await pc.setRemoteDescription({ type: 'answer', sdp: noMdns(sdp) }); },
    /** The channel, open, within ms; else ice_timeout (no pair of candidates answered). */
    async open(ms) {
      let timer;
      const timeout = new Promise((_, no) => { timer = setTimeout(() => no(Object.assign(new Error(`ice_timeout: no direct path within ${ms / 1000} s`), { check: 'ice_timeout' })), ms); });
      try {
        const ch = await Promise.race([dcP, timeout]);
        if (ch.readyState !== 'open') {
          await Promise.race([new Promise((r, no) => ch.stateChanged.subscribe((s) => { if (s === 'open') r(); else if (s === 'closed') no(Object.assign(new Error('ice_timeout: the channel closed'), { check: 'ice_timeout' })); })), timeout]);
        }
        fastKeys(pc);
        return channelOf(ch, pc);
      } finally { clearTimeout(timer); }
    },
    close() { try { pc.close(); } catch {} },
  };
}

/** One loopback pair in this process, 2 MiB through it: → "n MB/s" (npm test). */
export async function selfTest() {
  const a = await peer(), b = await peer(), label = 'sigelo-transfer/0 self 1';
  const o = await a.offer(label), ans = await b.answer(o, label);
  await a.accept(ans);
  const [ca, cb] = await Promise.all([a.open(30000), b.open(30000)]);
  const total = 2 << 20, t0 = Date.now();
  let got = 0;
  const done = new Promise((r) => cb.on('frame', (f) => { got += f.length; if (got >= total) r(); }));
  for (let s = 0; s < total; s += 65536) ca.send(new Uint8Array(65536));
  await done;
  const rate = (total / 1e6 / ((Date.now() - t0) / 1000)).toFixed(1);
  a.close(); b.close();
  if (got !== total) fail('self_test', `${got} of ${total} bytes`);
  return `2 MiB over a loopback data channel, ${rate} MB/s`;
}
