// Batch driver for sigelo's TypeScript implementation: one JSON request per stdin line, one JSON
// answer per stdout line, in order (the same protocol as go-driver/main.go). It imports the ts/
// sources compiled into .work/ts-dist by run.sh and calls only sigelo's own entry points; the
// raw Ed25519 check is the exact @noble call sigelo.ts makes (zip215:false), minus the wrapper.
import { createInterface } from 'node:readline';
const W = new URL('./.work/', import.meta.url);
const S = await import(new URL('ts-dist/sigelo.js', W));
const M = await import(new URL('ts-dist/monero.js', W));
const K = await import(new URL('ts-dist/keys.js', W));
const ed = await import(new URL('node_modules/@noble/ed25519/index.js', W));

const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (s) => Uint8Array.from(Buffer.from(s ?? '', 'hex'));
const err = (e) => ({ ok: false, err: String(e?.message ?? e) });


function run(r) {
  switch (r.op) {
    case 'jcs': {
      let v;
      try { v = S.parseBytes(new TextEncoder().encode(r.text)); } catch (e) { return { ...err(e), stage: 'parse' }; }
      try { return { ok: true, out: hex(new TextEncoder().encode(S.canonicalize(v))) }; } catch (e) { return { ...err(e), stage: 'canonicalize' }; }
    }
    case 'b58enc': return { ok: true, out: M.moneroBase58Encode(unhex(r.hex)) };
    case 'b58dec': try { return { ok: true, out: hex(M.moneroBase58Decode(r.s)) }; } catch (e) { return err(e); }
    case 'addr': try {
      const a = M.decodeAddress(r.s);
      return { ok: true, net: a.net, kind: a.kind, spend: hex(a.spend), view: hex(a.view), pid: a.paymentId ? hex(a.paymentId) : '' };
    } catch (e) { return err(e); }
    case 'addrenc': try {
      return { ok: true, out: M.encodeAddress({ net: r.net, kind: r.kind, spend: unhex(r.a), view: unhex(r.B), ...(r.kind === 'integrated' ? { paymentId: unhex(r.hex) } : {}) }) };
    } catch (e) { return err(e); }
    case 'wenc': try { return { ok: true, out: K.encodeMoneroWords(unhex(r.hex)) }; } catch (e) { return err(e); }
    case 'wdec': try { return { ok: true, out: hex(K.decodeMoneroWords(r.s)) }; } catch (e) { return err(e); }
    case 'wallet': try {
      const k = M.keysFromSpend(unhex(r.hex));
      return { ok: true, b: hex(k.b), a: hex(k.a), out: M.encodeAddress({ net: r.net, kind: 'standard', spend: k.B, view: k.A }) };
    } catch (e) { return err(e); }
    case 'subaddr': try {
      return { ok: true, out: M.subaddress({ a: unhex(r.a), B: unhex(r.B), major: r.major, minor: r.minor, net: r.net }) };
    } catch (e) { return err(e); }
    case 'edraw': try { return { ok: ed.verify(unhex(r.sig), unhex(r.msg), unhex(r.pub), { zip215: false }) }; } catch { return { ok: false }; }
    case 'edpub': return { ok: true, out: S.encodeKey(ed.getPublicKey(unhex(r.hex))) };
    case 'edsign': try { return { ok: true, out: S.sign(unhex(r.hex), S.parse(r.text)) }; } catch (e) { return err(e); }
    case 'edverify': try { return { ok: S.verifySig(r.key, S.parse(r.text), r.sig) }; } catch (e) { return err(e); }
    case 'siginput': try { return { ok: true, out: hex(S.signingInput(S.parse(r.text))) }; } catch (e) { return err(e); }
    case 'mbenc': return { ok: true, out: S.multibase(unhex(r.hex)) };
    case 'keydec': try { return { ok: true, out: hex(S.decodeKey(r.s)) }; } catch (e) { return err(e); }
  }
  return { ok: false, err: 'unknown op ' + r.op };
}

const out = [];
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  let r;
  try { r = JSON.parse(line); } catch (e) { out.push(JSON.stringify(err('driver: ' + e.message))); continue; }
  out.push(JSON.stringify(run(r)));
  if (out.length >= 1000) { process.stdout.write(out.join('\n') + '\n'); out.length = 0; }
}
if (out.length) process.stdout.write(out.join('\n') + '\n');
