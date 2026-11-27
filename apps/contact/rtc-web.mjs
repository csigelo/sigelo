// SPDX-License-Identifier: MIT
// The direct path of a transfer in a page (apps/agent/TRANSFER.md "The phone app"): the WebView's own RTCPeerConnection
// behind the interface of apps/transfer/rtc.mjs (werift, Node), so transfer-engine.mjs drives both alike
// and a phone talks to a Node agent or another phone over the same `sigelo-transfer/0` channel.
//
//   const p = await peer({ stun, turn, gatherMs, RTC, policy })   RTC: the constructor (default globalThis.RTCPeerConnection);
//                                                     turn: { urls, username, credential } (carrier.turnServer) or null;
//                                                     policy "relay" ("Always relay my media"): iceTransportPolicy relay, no
//                                                     STUN, relayed candidates only in what leaves (call.mjs relayOnly); refused
//                                                     relay_only without turn
//   await p.relayed() → the selected pair has a relayed candidate (true), none (false), not known (null): call.mjs relayedOf
//   await p.offer(label) → sdp; await p.answer(sdp, label) → sdp; await p.accept(sdp)
//   await p.open(ms) → the channel (transfer.mjs's: send, buffered, close, on) once it is open, or throws ice_timeout
//   p.close()
//
// Candidates gathered at once and sent whole (not trickled), gatherMs at most. A `.local` candidate in the
// remote description is dropped (resolving it would put a multicast DNS socket on the LAN); the WebView
// itself hides its LAN addresses behind such names, so two devices on one network meet at the public
// address. The send buffer: the engine pauses above 4 MiB (transfer.mjs HIGH) and goes on below 1 MiB
// (bufferedamountlow); a browser closes a channel whose buffer passes 16 MiB, so neither is raised.
import { LOW } from './transfer.mjs';
import { RELAY_ONLY, relayOnly, relayedOf } from './call.mjs';

const fail = (check, why) => { throw Object.assign(new Error(`${check}: ${why}`), { check }); };
/** STUN ['host:port', …] and TURN ({ urls, username, credential } from the relay, or null) → RTCIceServer[]. The policy stays
 *  "all": a direct pair is preferred, the relayed candidate is used only when none answers. */
/** Browser and WebView DTLS checks the handshake signatures: TURN allowed here (apps/transfer/rtc.mjs: only with dtls-verify.mjs's checks in place). */
export const TURN_OK = true;
export const iceServers = (stun, turn = null) => [...(stun.length ? [{ urls: stun.map((s) => `stun:${s}`) }] : []),
  ...(turn ? [{ urls: [...turn.urls], username: turn.username, credential: turn.credential }] : [])];
export const noMdns = (sdp) => sdp.split(/\r?\n/).filter((l) => !/^a=candidate:.* [0-9a-f-]+\.local /i.test(l)).join('\r\n');

/** An RTCDataChannel as transfer.mjs's channel. */
export function channelOf(dc, pc) {
  const on = { frame: [], low: [], close: [] };
  let closed = false;
  const shut = () => { if (closed) return; closed = true; for (const f of on.close) { try { f(); } catch {} } };
  dc.binaryType = 'arraybuffer';
  dc.bufferedAmountLowThreshold = LOW;
  dc.addEventListener('message', (m) => { if (typeof m.data === 'string') return; const u = new Uint8Array(m.data); for (const f of on.frame) f(u); });
  dc.addEventListener('bufferedamountlow', () => { for (const f of on.low) f(); });
  dc.addEventListener('close', shut);
  pc.addEventListener('connectionstatechange', () => { if (['failed', 'closed', 'disconnected'].includes(pc.connectionState)) shut(); });
  return {
    send(f) { if (closed || dc.readyState !== 'open') throw new Error('closed'); dc.send(f); },
    buffered: () => dc.bufferedAmount,
    close() { try { dc.close(); } catch {} shut(); },
    on(e, fn) { on[e].push(fn); },
    get closed() { return closed; },
  };
}

export async function peer({ stun = [], turn = null, gatherMs = 3000, RTC = globalThis.RTCPeerConnection, policy = 'all' } = {}) {
  if (typeof RTC !== 'function') fail('no_rtc', 'this page has no RTCPeerConnection');
  const relay = policy === 'relay';
  if (relay && !turn) throw Object.assign(new Error(RELAY_ONLY), { check: 'relay_only' });
  const pc = new RTC({ iceServers: iceServers(relay ? [] : stun, turn), ...(relay && { iceTransportPolicy: 'relay' }) });
  let dc = null, want = null, gotDc;
  const dcP = new Promise((r) => { gotDc = r; });
  pc.addEventListener('datachannel', (ev) => {
    const ch = ev.channel;
    // Only the channel this attempt named; any other is closed (the binding).
    if (want === null || ch.label !== want || dc) { try { ch.close(); } catch {} return; }
    dc = ch; gotDc(ch);
  });
  const gathered = async () => {
    if (pc.iceGatheringState !== 'complete') {
      await new Promise((r) => {
        const t = setTimeout(r, gatherMs);
        pc.addEventListener('icegatheringstatechange', () => { if (pc.iceGatheringState === 'complete') { clearTimeout(t); r(); } });
      });
    }
    return relay ? relayOnly(pc.localDescription.sdp) : pc.localDescription.sdp;
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
          await Promise.race([new Promise((r, no) => {
            ch.addEventListener('open', () => r());
            ch.addEventListener('close', () => no(Object.assign(new Error('ice_timeout: the channel closed'), { check: 'ice_timeout' })));
          }), timeout]);
        }
        return channelOf(ch, pc);
      } finally { clearTimeout(timer); }
    },
    async relayed() { try { return relayedOf(await pc.getStats()); } catch { return null; } },
    close() { try { pc.close(); } catch {} },
  };
}
