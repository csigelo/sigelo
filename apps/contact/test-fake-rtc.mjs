// SPDX-License-Identifier: MIT
// A fake RTCPeerConnection for the call tests (test-call.mjs, apps/web/test-web.mjs's two pages): what call.mjs's Phone
// uses, with the one property that matters for security modelled: two connections meet only when each one's remote
// description names the other's ICE credentials and the other's DTLS certificate fingerprint (a relay that swapped
// an SDP would hold a certificate that matches neither). Not shipped (package.json files), never in a page.
//
//   const net = fakeNet({ lateMs })  net.RTC (the constructor), net.media() (a stream with one audio track)
//   net.direct = false: no candidate pair answers (no_path); net.cut(): every connection disconnected, and with
//   net.blocked = true they stay so; net.fail(): every connection failed (a network change: the old path is gone); net.loss
//   (0 to 1) and net.rtt (s): what getStats() reports (the far end's RTCP, and this side's receive counters); a sender's
//   setParameters is kept (sender.bps); net.certs: certificates made; net.pcs: the open ones.
let seq = 0;
const rand = (n) => { const b = new Uint8Array(n); globalThis.crypto.getRandomValues(b); return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(''); };
const fpOf = () => rand(32).toUpperCase().match(/../g).join(':');

export function fakeNet({ lateMs = 60, connectMs = 15 } = {}) {
  const net = { direct: true, blocked: false, certs: 0, pcs: new Set(), made: 0, loss: 0, rtt: 0.05 };
  class Track { constructor() { this.kind = 'audio'; this.enabled = true; this.stopped = false; } stop() { this.stopped = true; } }
  class Stream { constructor() { this.id = `s${++seq}`; this.tracks = [new Track()]; } getAudioTracks() { return this.tracks; } getTracks() { return this.tracks; } }
  class PC {
    static async generateCertificate() { net.certs++; return { fp: fpOf() }; }
    constructor(cfg = {}) {
      net.made++;
      this.cfg = cfg; this.cert = cfg.certificates?.[0] ?? { fp: fpOf() }; this.ufrag = rand(4); this.pwd = rand(12);
      this.localDescription = null; this.remoteDescription = null; this.iceGatheringState = 'new'; this.iceConnectionState = 'new';
      this.l = {}; this.senders = []; this.found = []; this.got = []; this.tracked = false; this.closed = false;
      net.pcs.add(this);
    }
    addEventListener(t, f) { (this.l[t] ??= []).push(f); }
    emit(t, ev = {}) { for (const f of this.l[t] ?? []) f(ev); }
    addTrack(t, s) {
      const snd = { track: t, stream: s, p: { encodings: [{}] }, bps: null, getParameters() { return JSON.parse(JSON.stringify(this.p)); }, async setParameters(p) { this.p = p; this.bps = p.encodings?.[0]?.maxBitrate ?? null; } };
      this.senders.push(snd);
      return snd;
    }
    getSenders() { return this.senders; }
    async getStats() {
      // 50 packets a second each way; the share net.loss of them lost.
      this.rx = (this.rx ?? { recv: 0, lost: 0 });
      const n = 150, lost = Math.round(n * net.loss);
      this.rx.recv += n - lost; this.rx.lost += lost;
      return new Map([['r1', { type: 'remote-inbound-rtp', kind: 'audio', fractionLost: net.loss, roundTripTime: net.rtt }], ['i1', { type: 'inbound-rtp', kind: 'audio', packetsLost: this.rx.lost, packetsReceived: this.rx.recv }]]);
    }
    sdp(type) {
      return ['v=0', `o=- ${seq} 2 IN IP4 127.0.0.1`, 's=-', 't=0 0', 'a=group:BUNDLE 0', 'm=audio 9 UDP/TLS/RTP/SAVPF 111', 'c=IN IP4 0.0.0.0', 'a=mid:0',
        'a=rtpmap:111 opus/48000/2', 'a=fmtp:111 minptime=10;useinbandfec=1', `a=ice-ufrag:${this.ufrag}`, `a=ice-pwd:${this.pwd}`,
        `a=fingerprint:sha-256 ${this.cert.fp}`, `a=setup:${type === 'offer' ? 'actpass' : 'active'}`, 'a=sendrecv', ...this.found.map((c) => `a=${c}`)].join('\r\n') + '\r\n';
    }
    async createOffer(o = {}) { if (o.iceRestart) { this.ufrag = rand(4); this.pwd = rand(12); } return { type: 'offer', sdp: this.sdp('offer') }; }
    async createAnswer() { return { type: 'answer', sdp: this.sdp('answer') }; }
    async setLocalDescription(d) {
      this.type = d.type; this.found = [];
      this.localDescription = { type: d.type, sdp: this.sdp(d.type) };
      this.iceGatheringState = 'gathering'; this.emit('icegatheringstatechange');
      const n = ++seq;
      setTimeout(() => { if (this.closed) return; this.found.push(`candidate:${n} 1 udp 2122260223 192.0.2.${n % 250} ${5000 + (n % 1000)} typ host`); this.localDescription = { type: this.type, sdp: this.sdp(this.type) }; this.emit('icecandidate', { candidate: {} }); }, 5);
      setTimeout(() => {
        if (this.closed) return;
        this.found.push(`candidate:${n + 1} 1 udp 1686052607 203.0.113.${n % 250} ${6000 + (n % 1000)} typ srflx raddr 0.0.0.0 rport 0`);
        this.localDescription = { type: this.type, sdp: this.sdp(this.type) };
        this.iceGatheringState = 'complete'; this.emit('icecandidate', { candidate: null }); this.emit('icegatheringstatechange');
        this.try();
      }, lateMs);
      this.try();
    }
    async setRemoteDescription(d) {
      if (!/^a=fingerprint:sha-256 /m.test(d.sdp)) throw new Error('no fingerprint');
      const uf = /^a=ice-ufrag:(\S+)/m.exec(d.sdp)[1];
      // An ICE restart offer from the far end: this side's credentials change too.
      if (d.type === 'offer' && this.remoteDescription && this.remoteUfrag !== uf) { this.ufrag = rand(4); this.pwd = rand(12); }
      this.remoteDescription = d; this.remoteUfrag = uf; this.remoteFp = /^a=fingerprint:sha-256 (\S+)/m.exec(d.sdp)[1];
      this.tuned = d.sdp;
      this.try();
    }
    async addIceCandidate(c) { if (!this.remoteDescription) throw new Error('no remote description'); this.got.push(c.candidate); this.try(); }
    peer() { return [...net.pcs].find((p) => p !== this && p.ufrag === this.remoteUfrag && p.remoteUfrag === this.ufrag) ?? null; }
    state(s) { if (this.iceConnectionState === s || this.closed) return; this.iceConnectionState = s; this.emit('iceconnectionstatechange'); }
    try() {
      if (this.closed || !this.localDescription || !this.remoteDescription) return;
      const p = this.peer();
      if (!p || !p.localDescription || !p.remoteDescription) return;
      // DTLS: each side's certificate must be the one the other was told of.
      if (this.remoteFp !== p.cert.fp || p.remoteFp !== this.cert.fp) { this.state('failed'); p.state('failed'); return; }
      if (!net.direct || net.blocked) { this.state('checking'); p.state('checking'); return; }
      setTimeout(() => {
        if (this.closed || p.closed || !net.direct || net.blocked) return;
        for (const x of [this, p]) {
          x.state('connected');
          if (!x.tracked) { x.tracked = true; x.emit('track', { streams: [{ id: `remote-${x === this ? p.ufrag : this.ufrag}` }] }); }
        }
      }, connectMs);
    }
    close() { this.closed = true; this.iceConnectionState = 'closed'; net.pcs.delete(this); }
  }
  net.RTC = PC;
  net.media = async () => new Stream();
  net.cut = () => { for (const p of net.pcs) p.state('disconnected'); };
  net.fail = () => { for (const p of net.pcs) p.state('failed'); };
  net.heal = () => { net.blocked = false; for (const p of net.pcs) p.try(); };
  return net;
}
