#!/usr/bin/env node
// One JSON-RPC call to a soak wallet-rpc, with the RPC login from its 0600 --config-file (HTTP
// digest, the keeper's own client: spend/dist/service.js walletRpc). Prints the result as JSON.
//   node wallet-rpc.mjs [--password-file F] <url> <wallet-rpc.conf | -> <method> [<params JSON>]
// --password-file sets params.password from F (create_wallet, open_wallet): never on argv.
// e.g. node wallet-rpc.mjs http://127.0.0.1:38093/json_rpc ~/.local/share/sigelo-soak-019/keeper/wallet-rpc.conf get_address '{"account_index":0}'
// setup.sh uses it to create a side-by-side soak's wallet; by hand it shows the address to fund.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const { walletRpc } = await import(pathToFileURL(join(HERE, '..', 'dist', 'service.js')).href);
const argv = process.argv.slice(2);
const pwAt = argv.indexOf('--password-file');
const pwFile = pwAt < 0 ? undefined : argv.splice(pwAt, 2)[1];
const [url, conf, method, params] = argv;
if (!url || !conf || !method) { console.error('usage: wallet-rpc.mjs <url> <wallet-rpc.conf | -> <method> [<params JSON>]'); process.exit(2); }
const login = conf === '-' ? undefined : /^rpc-login=(\S+)$/m.exec(readFileSync(conf, 'utf-8'))?.[1];
if (conf !== '-' && login === undefined) { console.error(`wallet-rpc.mjs: ${conf} has no rpc-login=`); process.exit(2); }
try {
  const r = await walletRpc({ wallet: { rpc: url, ...(login !== undefined && { login }) } }, method, { ...(params ? JSON.parse(params) : {}), ...(pwFile !== undefined && { password: readFileSync(pwFile, 'utf-8') }) }, Number(process.env.SIGELO_SOAK_RPC_TIMEOUT_MS ?? 120_000));
  console.log(JSON.stringify(r));
} catch (e) { console.error(`wallet-rpc.mjs: ${e instanceof Error ? e.message : String(e)}`); process.exit(1); }
