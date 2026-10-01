// SPDX-License-Identifier: MIT
// A monero-wallet-rpc stand-in for sim/keeper-swarm.mjs. It grew out of the mock in
// spend/test.ts (same methods, same `sign` keys) but, unlike that one, it KEEPS BOOKS: every
// account has a balance, `transfer` refuses what the account cannot afford, `relay_tx` debits
// amount + fee and credits any destination that is one of this wallet's own (i, 0)
// addresses, `sweep_all` empties an account. Everything that would have left the wallet is in
// `moved`, which is the ground truth the swarm checks the keeper's spend.log against.
//
// Chaos is optional and seeded: latency, a wallet-side build error, a relay that fails (money
// stayed home), and a relay whose reply is garbage although the transaction went out (the
// dangerous case the keeper must log as relay_failed and keep debited).
//
// Loopback only, on the port asked for (≥ 39000 in the swarm). Never a real wallet.
import { createServer } from 'node:http';
import { walletFromRoot } from '../ts/dist/keys.js';
import { hashToScalar, signMessage, subaddress, subaddressKeys } from '../ts/dist/monero.js';

const L25519 = 2n ** 252n + 27742317777372353535851937790883648493n;
const leNum = (b) => b.reduceRight((n, x) => (n << 8n) | BigInt(x), 0n);
const leBytes = (n, len = 32) => Uint8Array.from({ length: len }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));

/**
 * @param {object} o
 * @param {string} o.net
 * @param {Uint8Array} o.root         seed of the keeper's wallet (walletFromRoot(root, 'allowance'))
 * @param {Record<number, bigint>} o.balances  initial balance per account index
 * @param {number} o.nextAccount     the index `create_account` hands out first
 * @param {() => number} o.rand      seeded PRNG in [0, 1)
 * @param {{ latencyMs?: number, buildError?: number, relayError?: number, relayGarbage?: number, fee?: bigint }} [o.chaos]
 * @param {number} [o.port]
 */
export async function startMockWallet(o) {
  const w = walletFromRoot(o.root, 'allowance', o.net);
  const chaos = { latencyMs: 0, buildError: 0, relayError: 0, relayGarbage: 0, fee: 30480000n, ...(o.chaos ?? {}) };
  const bal = new Map(Object.entries(o.balances).map(([k, v]) => [Number(k), BigInt(v)]));
  let nextAccount = o.nextAccount;
  let n = 0;
  const minors = new Map(); // account -> last minor handed out
  const labels = new Map(); // "major/minor" -> label
  const own = new Map(); // address -> { major, minor }
  const addrOf = (major, minor) => {
    const a = major === 0 && minor === 0 ? w.address : subaddress({ a: w.a, B: w.B, major, minor, net: o.net });
    own.set(a, { major, minor });
    return a;
  };
  for (const k of bal.keys()) addrOf(k, 0);
  const built = new Map(); // metadata -> { txid, account, dest, amount, fee, kind }
  const relayAttempts = new Map(); // metadata -> count
  const moved = []; // { txid, account, dest, amount, fee, kind, at }
  const incoming = new Map(); // account -> [{ ... }]
  const calls = new Map(); // method -> count
  const anomalies = []; // things a correct keeper never makes the wallet do
  const injected = { build_error: 0, relay_error: 0, relay_garbage_after_move: 0 };

  function signKeys(major, minor) {
    if (major === 0 && minor === 0) return { spend: w.b, view: w.a, spendPub: w.B, viewPub: w.A };
    const m = hashToScalar(Uint8Array.from('SubAddr\0', (c) => c.charCodeAt(0)), w.a, leBytes(BigInt(major), 4), leBytes(BigInt(minor), 4));
    const d = (leNum(w.b) + leNum(m)) % L25519;
    const { C, D } = subaddressKeys({ a: w.a, B: w.B, major, minor });
    return { spend: leBytes(d), view: leBytes((leNum(w.a) * d) % L25519), spendPub: D, viewPub: C };
  }
  const txid = () => (++n).toString(16).padStart(64, '0');
  const debit = (t) => {
    const b = bal.get(t.account) ?? 0n;
    bal.set(t.account, b - t.amount - t.fee);
    if (b - t.amount - t.fee < 0n) anomalies.push(`account ${t.account} overdrawn by ${t.txid}`);
    const to = own.get(t.dest);
    if (to !== undefined) {
      bal.set(to.major, (bal.get(to.major) ?? 0n) + t.amount);
      const list = incoming.get(to.major) ?? [];
      list.push({ amount: Number(t.amount), txid: t.txid, address: t.dest, subaddr_index: { major: to.major, minor: to.minor }, timestamp: Math.floor(Date.now() / 1000), confirmations: 20, locked: false });
      incoming.set(to.major, list);
    }
    moved.push({ ...t, at: Date.now() });
  };

  const server = createServer((rq, rs) => {
    let raw = '';
    rq.setEncoding('utf-8');
    rq.on('data', (c) => { raw += c; });
    rq.on('end', () => {
      let call;
      try { call = JSON.parse(raw); } catch { rs.writeHead(400); rs.end(); return; }
      calls.set(call.method, (calls.get(call.method) ?? 0) + 1);
      const delay = chaos.latencyMs > 0 ? Math.floor(o.rand() * chaos.latencyMs) : 0;
      const send = (body) => setTimeout(() => { if (!rs.destroyed) { rs.writeHead(200, { 'Content-Type': 'application/json' }); rs.end(body); } }, delay);
      const answer = (result) => send(JSON.stringify({ jsonrpc: '2.0', id: '0', result }));
      const error = (code, message) => send(JSON.stringify({ jsonrpc: '2.0', id: '0', error: { code, message } }));
      const p = call.params ?? {};
      switch (call.method) {
        case 'get_height': return answer({ height: 2209681 + n });
        case 'get_balance': {
          const b = bal.get(p.account_index) ?? 0n;
          return answer({ balance: Number(b), unlocked_balance: Number(b), blocks_to_unlock: 0 });
        }
        case 'create_address': {
          const major = p.account_index, minor = (minors.get(major) ?? 0) + 1;
          minors.set(major, minor);
          labels.set(`${major}/${minor}`, String(p.label ?? ''));
          return answer({ address: addrOf(major, minor), address_index: minor });
        }
        case 'get_address': {
          const major = p.account_index;
          const addresses = [...labels].filter(([k]) => k.startsWith(`${major}/`)).map(([k, label]) => ({ address_index: Number(k.split('/')[1]), label }));
          return answer({ address: addrOf(major, 0), addresses });
        }
        case 'get_transfers': return answer({ in: incoming.get(p.account_index) ?? [] });
        case 'create_account': {
          const major = nextAccount++;
          bal.set(major, bal.get(major) ?? 0n);
          return answer({ account_index: major, address: addrOf(major, 0) });
        }
        case 'sign': {
          const k = signKeys(Number(p.account_index ?? 0), Number(p.address_index ?? 0));
          const spend = p.signature_type === 'spend';
          return answer({ signature: signMessage({ message: String(p.data), mode: spend ? 'spend' : 'view', secret: spend ? k.spend : k.view, spendPub: k.spendPub, viewPub: k.viewPub }) });
        }
        case 'transfer': {
          if (p.do_not_relay !== true) anomalies.push('transfer without do_not_relay (one-phase spend)');
          if (!Array.isArray(p.destinations) || p.destinations.length !== 1) return error(-2, 'destinations');
          if (p.subaddr_indices !== undefined) anomalies.push('transfer with subaddr_indices (README: never set)');
          if (o.rand() < chaos.buildError) return injected.build_error++, error(-4, 'internal error: simulated build failure');
          const amount = BigInt(p.destinations[0].amount), fee = chaos.fee;
          const account = p.account_index;
          if ((bal.get(account) ?? 0n) < amount + fee) return error(-17, 'not enough money');
          const t = { txid: txid(), account, dest: p.destinations[0].address, amount, fee, kind: 'transfer' };
          const metadata = `meta-${t.txid}`;
          built.set(metadata, t);
          return answer({ tx_hash: t.txid, fee: Number(fee), amount: Number(amount), tx_metadata: metadata, tx_key: 'k'.repeat(64) });
        }
        case 'sweep_all': {
          const account = p.account_index, b = bal.get(account) ?? 0n, fee = chaos.fee;
          if (b === 0n) return error(-37, 'No unlocked balance in the specified account');
          if (p.do_not_relay !== true) anomalies.push('sweep_all without do_not_relay');
          const t = { txid: txid(), account, dest: p.address, amount: b > fee ? b - fee : 0n, fee: b > fee ? fee : b, kind: 'sweep' };
          const metadata = `meta-${t.txid}`;
          built.set(metadata, t);
          return answer({ tx_hash_list: [t.txid], fee_list: [Number(t.fee)], amount_list: [Number(t.amount)], tx_metadata_list: [metadata] });
        }
        case 'relay_tx': {
          const t = built.get(String(p.hex));
          relayAttempts.set(p.hex, (relayAttempts.get(p.hex) ?? 0) + 1);
          if (t === undefined) return error(-1, 'Failed to parse tx metadata');
          if (t.relayed) { anomalies.push(`relay_tx twice for ${t.txid}`); return error(-1, 'Failed to commit tx: already relayed'); }
          // The account may have been drained since this was built (a sweep, another relay).
          if ((bal.get(t.account) ?? 0n) < t.amount + t.fee) { t.dead = true; return error(-1, 'Failed to commit tx: double spend (inputs already spent)'); }
          const r = o.rand();
          if (r < chaos.relayError) { t.dead = true; injected.relay_error++; return error(-1, 'Failed to commit tx: simulated'); }
          t.relayed = true;
          debit(t);
          if (r < chaos.relayError + chaos.relayGarbage) return injected.relay_garbage_after_move++, send('<html>502 simulated garbage after relay</html>');
          return answer({ tx_hash: t.txid });
        }
        default: return error(-32601, `no method ${call.method}`);
      }
    });
  });
  await new Promise((resolve, reject) => { server.on('error', reject); server.listen(o.port ?? 0, '127.0.0.1', resolve); });
  const a = server.address();
  return {
    port: typeof a === 'object' && a !== null ? a.port : 0,
    moved, calls, anomalies, injected, relayAttempts, balances: bal, addrOf, own, chaos,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }),
  };
}
