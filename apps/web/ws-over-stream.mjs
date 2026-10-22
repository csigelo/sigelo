// SPDX-License-Identifier: MIT
// The relay's socket in the Android app (design/apps.md §4.3): the shell gives a TLS byte stream
// (SigeloBridge tls(host, port)), and MQTT.js's browser build wants a WebSocket. Two shapes of one:
//
//   wsOverStream(connecting, { url, protocols, maxPayload })   RFC 6455 client framing over the stream
//                                                              (MQTT over WebSocket, wss on 443)
//   streamSocket(connecting)                                   the stream itself, no framing (mqtts on 8883)
//
// connecting: a Promise of a stream { write(bytes) → Promise, close(), ondata(bytes), onclose(error | null) }.
// Each returns what MQTT.js's browser build reads of a WebSocket (createWebsocket): readyState and
// its constants, binaryType ("arraybuffer"), bufferedAmount, protocol, send(), close(), and the
// onopen, onmessage ({ data: ArrayBuffer | string }), onerror, onclose ({ code, reason, wasClean }).
//
// The handshake sends Host, Upgrade, Connection, Sec-WebSocket-Key/-Version/-Protocol and nothing
// else: no Origin (the relay refuses a page's requests on purpose; the app is not a page of
// anyone's), no cookie, no extension (no compression). Frames out are masked with a fresh key each
// (§5.3); frames in must be unmasked, RSV 0, control frames whole and at most 125 bytes, a message at
// most maxPayload; anything else fails the connection (close 1002, 1007 or 1009, then close event
// 1006). Ping is answered with pong; a close is answered with the same code, then the stream ends.
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const HEAD_MAX = 16384;
const enc = new TextEncoder();
const utf8 = new TextDecoder('utf-8', { fatal: true });
const b64 = (b) => { let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000)); return btoa(s); };
const concat = (a, b) => { if (a.length === 0) return b; const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
const bytesOf = (d) => (typeof d === 'string' ? enc.encode(d) : d instanceof ArrayBuffer ? new Uint8Array(d) : ArrayBuffer.isView(d) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength) : null);
const asBuffer = (b) => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
const STATES = { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 };

/** What both shapes share: the states, the events (on* properties), bufferedAmount over the stream's writes. */
class Socket {
  constructor(url) {
    Object.assign(this, STATES, { url, readyState: 0, binaryType: 'arraybuffer', bufferedAmount: 0, protocol: '', extensions: '' });
    this.onopen = this.onmessage = this.onerror = this.onclose = null;
    this.stream = null;
    this.ended = false;
  }
  emit(type, ev = {}) { const f = this[`on${type}`]; if (typeof f === 'function') f.call(this, { type, target: this, ...ev }); }
  attach(connecting, onData, onGone) {
    Promise.resolve(connecting).then((s) => {
      if (this.readyState === 3) { s.close(); return; }
      this.stream = s;
      s.ondata = (b) => { if (!this.ended) onData(b); };
      s.onclose = (e) => onGone(e ?? null);
      this.ready();
    }, (e) => this.finish(1006, String(e?.message ?? e), false, true));
  }
  ready() {}
  write(bytes) {
    const n = bytes.length;
    this.bufferedAmount += n;
    Promise.resolve().then(() => this.stream.write(bytes)).then(() => { this.bufferedAmount -= n; }, (e) => { this.bufferedAmount -= n; this.fail(1006, `write: ${e?.message ?? e}`); });
  }
  /** The end: the stream closed, the close event once (error first when the connection failed). */
  finish(code, reason, wasClean, failed = false) {
    if (this.readyState === 3) return;
    this.readyState = 3; this.ended = true;
    clearTimeout(this.timer);
    try { this.stream?.close(); } catch {}
    if (failed) this.emit('error', { message: reason });
    this.emit('close', { code, reason, wasClean });
  }
  fail(_code, why) { this.finish(1006, why, false, true); }
}

/** A WebSocket client (RFC 6455) over a byte stream. url: ws:// or wss:// (Host and the path come from it). */
export function wsOverStream(connecting, { url, protocols = [], maxPayload = 64 * 1024 * 1024, closeMs = 5000, random = (n) => crypto.getRandomValues(new Uint8Array(n)) } = {}) {
  return new WsSocket(url, [protocols].flat(), connecting, { maxPayload, closeMs, random });
}

class WsSocket extends Socket {
  #o; #asked; #key = ''; #accept = null; #head = new Uint8Array(0); #buf = new Uint8Array(0); #shook = false;
  #msg = null; #msgOp = 0; #msgLen = 0; #sentClose = false; #gotClose = null;
  constructor(url, protocols, connecting, o) {
    super(url);
    const u = new URL(url), refuse = (why) => { Promise.resolve(connecting).then((s) => s.close(), () => {}); throw new SyntaxError(`wsOverStream: ${why}`); };
    if (u.protocol !== 'wss:' && u.protocol !== 'ws:') refuse(`${u.protocol}// is not a WebSocket URL`);
    if (protocols.some((p) => !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(p))) refuse('a subprotocol is a token');
    this.#o = o; this.#asked = protocols;
    const port = u.port && u.port !== (u.protocol === 'wss:' ? '443' : '80') ? `:${u.port}` : '';
    this.host = u.hostname + port; this.path = (u.pathname || '/') + u.search;
    this.#key = b64(o.random(16));
    // The answer the server must give (§4.2.2): base64(SHA-1(key ‖ GUID)), computed before anything is sent.
    const accept = crypto.subtle.digest('SHA-1', enc.encode(this.#key + GUID)).then((d) => b64(new Uint8Array(d)));
    this.attach(Promise.all([connecting, accept]).then(([s, a]) => { this.#accept = a; return s; }), (b) => this.#in(b), (e) => this.#gone(e));
  }
  ready() {
    const lines = [`GET ${this.path} HTTP/1.1`, `Host: ${this.host}`, 'Upgrade: websocket', 'Connection: Upgrade',
      `Sec-WebSocket-Key: ${this.#key}`, 'Sec-WebSocket-Version: 13', ...(this.#asked.length ? [`Sec-WebSocket-Protocol: ${this.#asked.join(', ')}`] : [])];
    this.write(enc.encode(lines.join('\r\n') + '\r\n\r\n'));
  }
  #in(b) {
    if (!this.#shook) {
      this.#head = concat(this.#head, b);
      let end = -1;
      for (let i = 3; i < this.#head.length; i++) if (this.#head[i] === 10 && this.#head[i - 1] === 13 && this.#head[i - 2] === 10 && this.#head[i - 3] === 13) { end = i + 1; break; }
      if (end < 0) { if (this.#head.length > HEAD_MAX) this.fail(1002, 'the handshake answer is too long'); return; }
      const why = this.#answer(new TextDecoder().decode(this.#head.subarray(0, end)));
      if (why) { this.fail(1002, why); return; }
      const rest = this.#head.subarray(end);
      this.#shook = true; this.#head = new Uint8Array(0);
      this.readyState = 1;
      this.emit('open');
      if (rest.length === 0 || this.readyState !== 1) return;
      b = rest;
    }
    this.#buf = concat(this.#buf, b);
    while (!this.ended && this.#frame()) { /* one frame each */ }
  }
  /** The server's handshake answer (§4.2.2, §4.1): → null when it is a WebSocket, else why not. */
  #answer(text) {
    const [status, ...rest] = text.split('\r\n'), h = new Map();
    for (const l of rest) { const i = l.indexOf(':'); if (i > 0) h.set(l.slice(0, i).trim().toLowerCase(), l.slice(i + 1).trim()); }
    const m = /^HTTP\/1\.1 (\d{3})/.exec(status);
    if (!m || m[1] !== '101') return `the server answered ${m ? m[1] : 'not HTTP/1.1'}, not 101 Switching Protocols`;
    if ((h.get('upgrade') ?? '').toLowerCase() !== 'websocket') return 'no Upgrade: websocket in the answer';
    if (!(h.get('connection') ?? '').toLowerCase().split(/\s*,\s*/).includes('upgrade')) return 'no Connection: Upgrade in the answer';
    if (h.get('sec-websocket-accept') !== this.#accept) return 'Sec-WebSocket-Accept does not match the key sent';
    if (h.has('sec-websocket-extensions')) return 'the server chose an extension none was asked for';
    const p = h.get('sec-websocket-protocol');
    if (p !== undefined && !this.#asked.includes(p)) return `the server chose subprotocol ${p}, not one asked for`;
    this.protocol = p ?? '';
    return null;
  }
  /** One frame off the buffer, if whole: → true when one was taken. */
  #frame() {
    const b = this.#buf;
    if (b.length < 2) return false;
    const fin = (b[0] & 0x80) !== 0, op = b[0] & 0x0f, masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f, at = 2;
    if (b[0] & 0x70) return this.fail(1002, 'a frame with RSV bits set (no extension was agreed)'), false;
    if (masked) return this.fail(1002, 'a masked frame from the server'), false;
    if (len === 126) { if (b.length < 4) return false; len = (b[2] << 8) | b[3]; at = 4; }
    else if (len === 127) {
      if (b.length < 10) return false;
      const hi = ((b[2] << 24) >>> 0) + (b[3] << 16) + (b[4] << 8) + b[5];
      if (hi !== 0 || b[6] & 0x80) return this.fail(1009, 'a frame longer than this client takes'), false;
      len = ((b[6] << 24) >>> 0) + (b[7] << 16) + (b[8] << 8) + b[9]; at = 10;
    }
    const control = op >= 8;
    if (control && (!fin || len > 125)) return this.fail(1002, 'a control frame fragmented or over 125 bytes'), false;
    if (!control && (op === 0 ? this.#msg === null : this.#msg !== null)) return this.fail(1002, op === 0 ? 'a continuation with no message begun' : 'a new message inside a fragmented one'), false;
    if (!control && (op === 0 ? this.#msgLen : 0) + len > this.#o.maxPayload) return this.fail(1009, `a message over ${this.#o.maxPayload} bytes`), false;
    if (b.length < at + len) return false;
    const payload = b.slice(at, at + len);
    this.#buf = b.subarray(at + len);
    if (op === 0x1 || op === 0x2 || op === 0x0) {
      if (op !== 0) { this.#msg = []; this.#msgOp = op; this.#msgLen = 0; }
      this.#msg.push(payload); this.#msgLen += len;
      if (fin) {
        let whole = new Uint8Array(this.#msgLen), o = 0;
        for (const p of this.#msg) { whole.set(p, o); o += p.length; }
        const text = this.#msgOp === 1;
        this.#msg = null; this.#msgLen = 0;
        if (this.readyState !== 1) return true;   // closing: data after our close is dropped (§5.5.1)
        if (text) { try { whole = utf8.decode(whole); } catch { return this.fail(1007, 'a text message that is not UTF-8'), false; } }
        this.emit('message', { data: text ? whole : asBuffer(whole) });
      }
      return true;
    }
    if (op === 0x9) { if (this.readyState === 1) this.#send(0xa, payload); return true; }
    if (op === 0xa) return true;
    if (op === 0x8) return this.#closeIn(payload), true;
    return this.fail(1002, `opcode ${op} is reserved`), false;
  }
  #last = null;   // the last frame's write: the end waits for it
  #closeIn(p) {
    if (p.length === 1) return this.fail(1002, 'a close frame of 1 byte');
    let code = 1005, reason = '';
    if (p.length >= 2) {
      code = (p[0] << 8) | p[1];
      if (!((code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1011) || (code >= 3000 && code <= 4999))) return this.fail(1002, `close code ${code} is not one a peer may send`);
      try { reason = utf8.decode(p.subarray(2)); } catch { return this.fail(1007, 'a close reason that is not UTF-8'); }
    }
    this.#gotClose = { code, reason };
    // Answered with the same code (§5.5.1), then the stream ends: the server closes TCP first,
    // but a stream of the shell is ours to close once both close frames have passed.
    if (!this.#sentClose) this.#send(0x8, p.length >= 2 ? p.subarray(0, 2) : new Uint8Array(0));
    this.readyState = 2;
    Promise.resolve(this.#last).finally(() => this.finish(code, reason, true));
  }
  /** One frame out, masked (§5.3). */
  #send(op, payload, fin = true) {
    const n = payload.length, ext = n < 126 ? 0 : n < 65536 ? 2 : 8, f = new Uint8Array(2 + ext + 4 + n);
    f[0] = (fin ? 0x80 : 0) | op;
    f[1] = 0x80 | (ext === 0 ? n : ext === 2 ? 126 : 127);
    if (ext === 2) { f[2] = n >> 8; f[3] = n & 0xff; }
    if (ext === 8) { const hi = Math.floor(n / 2 ** 32); f[2] = hi >>> 24; f[3] = (hi >> 16) & 0xff; f[4] = (hi >> 8) & 0xff; f[5] = hi & 0xff; f[6] = n >>> 24; f[7] = (n >> 16) & 0xff; f[8] = (n >> 8) & 0xff; f[9] = n & 0xff; }
    const at = 2 + ext, mask = this.#o.random(4);
    f.set(mask, at);
    for (let i = 0; i < n; i++) f[at + 4 + i] = payload[i] ^ mask[i & 3];
    if (op === 0x8) this.#sentClose = true;
    this.bufferedAmount += n;
    this.#last = Promise.resolve().then(() => this.stream.write(f)).then(() => { this.bufferedAmount -= n; }, (e) => { this.bufferedAmount -= n; if (!this.ended && op !== 0x8) this.fail(1006, `write: ${e?.message ?? e}`); });
  }
  send(data, { frameMax = Infinity } = {}) {
    if (this.readyState === 0) throw Object.assign(new Error('the WebSocket is not open yet'), { name: 'InvalidStateError' });
    const b = bytesOf(data);
    if (b === null) throw new TypeError('send: a string, an ArrayBuffer or a view of one');
    if (this.readyState !== 1) return;
    const op = typeof data === 'string' ? 0x1 : 0x2;
    if (b.length <= frameMax) { this.#send(op, b); return; }
    for (let i = 0; i < b.length; i += frameMax) this.#send(i === 0 ? op : 0x0, b.subarray(i, i + frameMax), i + frameMax >= b.length);
  }
  close(code, reason = '') {
    if (code !== undefined && code !== 1000 && !(code >= 3000 && code <= 4999)) throw Object.assign(new Error(`close: code ${code}`), { name: 'InvalidAccessError' });
    const r = enc.encode(reason);
    if (r.length > 123) throw new SyntaxError('close: a reason of at most 123 bytes');
    if (this.readyState >= 2) return;
    if (this.readyState === 0) { this.finish(1006, 'closed before it opened', false, true); return; }
    this.readyState = 2;
    const p = code === undefined ? new Uint8Array(0) : concat(Uint8Array.of(code >> 8, code & 0xff), r);
    this.#send(0x8, p);
    // The server's close frame ends it; without one in closeMs, the stream is closed anyway.
    this.timer = setTimeout(() => this.finish(1006, 'no close frame from the server', false), this.#o.closeMs);
  }
  fail(code, why) {
    // "Fail the WebSocket connection" (§7.1.7): a close frame with the reason when open, then the end.
    if (this.readyState === 1 && !this.#sentClose) this.#send(0x8, Uint8Array.of(code >> 8, code & 0xff));
    Promise.resolve(this.#last).finally(() => this.finish(1006, why, false, true));
  }
  #gone(e) {
    if (this.#gotClose) return this.finish(this.#gotClose.code, this.#gotClose.reason, true);
    if (!this.#shook) return this.finish(1006, e ? `the stream failed: ${e.message ?? e}` : 'the stream ended before the handshake', false, true);
    this.finish(1006, e ? `the stream failed: ${e.message ?? e}` : 'the stream ended with no close frame', false);
  }
}

/** The stream as a socket with no framing: each chunk read is a message, each send written as it is. */
export function streamSocket(connecting, { url = 'tls://' } = {}) {
  const s = new Socket(url);
  s.ready = () => { s.readyState = 1; s.emit('open'); };
  s.attach(connecting, (b) => s.emit('message', { data: asBuffer(b) }), (e) => (e ? s.finish(1006, `the stream failed: ${e.message ?? e}`, false, true) : s.finish(1000, 'the stream ended', true)));
  s.send = (data) => {
    if (s.readyState === 0) throw Object.assign(new Error('the socket is not open yet'), { name: 'InvalidStateError' });
    const b = bytesOf(data);
    if (b === null) throw new TypeError('send: a string, an ArrayBuffer or a view of one');
    if (s.readyState === 1) s.write(b.slice());
  };
  s.close = () => { if (s.readyState < 2) s.finish(1000, '', true); };
  return s;
}
