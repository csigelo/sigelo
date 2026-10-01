// SPDX-License-Identifier: MIT
// sim/1f916/world.mjs — adapters/1f916/sigelo.ts as a world of the simulation.
//
// The adapter is imported as it is shipped: copied beside four stand-ins for the 1F916 modules it
// imports (society, keys, checkpoint, attestations — this directory) into sim/out/1f916/, and
// loaded with node's type stripping. Its database is an in-memory stand-in for the two statements
// it runs. `route()` is the part of the router patch.diff adds (src/index.ts): every object the
// router answers gets `now`/`now_utc` stamped into it (upstream json()), which is why commit
// 1dfec57 serves the genesis and the attestation NESTED. `bare: true` replays the bug that
// commit fixed: the documents served at the top level, clock included.
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = dirname(dirname(HERE));

export async function load1f916(out) {
  const dir = join(out, '1f916', 'src');
  mkdirSync(dir, { recursive: true });
  copyFileSync(join(ROOT, 'adapters', '1f916', 'sigelo.ts'), join(dir, 'sigelo.ts'));
  for (const f of ['society.ts', 'keys.ts', 'checkpoint.ts', 'attestations.ts']) copyFileSync(join(HERE, f), join(dir, f));
  const w = process.emitWarning; process.emitWarning = () => {}; // the type-stripping notice
  try { return await import(pathToFileURL(join(dir, 'sigelo.ts')).href); } finally { process.emitWarning = w; }
}

/** One 1F916 deployment: its env (registry seed, OAUTH_KEY, a stateful DB) and its four routes. */
export function world1f916(A, { seed, pub, oauthKey }) {
  const citizens = new Map(); // id -> { sigelo_did }
  const DB = {
    prepare(sql) {
      return { bind(...args) { return {
        async first() {
          if (sql.includes('sigelo_did FROM citizens')) return { sigelo_did: citizens.get(args[0])?.sigelo_did ?? null };
          return { posts: args[0] % 7, comments: (args[0] * 3) % 11 };
        },
        async run() {
          if (!sql.startsWith('UPDATE citizens SET sigelo_did')) throw new Error(`unexpected statement ${sql}`);
          const [did, id] = args;
          for (const [k, c] of citizens) if (k !== id && c.sigelo_did === did) throw new Error('UNIQUE constraint failed: citizens.sigelo_did');
          citizens.set(id, { sigelo_did: did });
          return { meta: { changes: 1 } };
        },
      }; } };
    },
  };
  const env = { REGISTRY_SEED: `${Buffer.from(seed).toString('base64url')}.${Buffer.from(pub).toString('base64url')}`, OAUTH_KEY: oauthKey, DB };
  const clock = (ms) => ({ now: ms, now_utc: new Date(ms).toISOString() });
  // What the router answers, as the bytes an agent receives. Nested (1dfec57) or bare (the bug).
  const answer = (doc, key, ms, bare) => JSON.stringify(bare ? { ...doc, ...clock(ms) } : { [key]: doc, ...clock(ms) });
  return {
    env,
    genesis: async (ms, bare = false) => answer(await A.worldGenesis(env), 'genesis', ms, bare),
    challenge: async (citizen, ms) => JSON.stringify({ ...(await A.sigeloChallenge(env, citizen, ms)), ...clock(ms) }),
    verify: async (citizen, body, ms) => JSON.stringify({ ...(await A.sigeloVerify(env, citizen, body, ms)), ...clock(ms) }),
    attestation: async (citizen, ms, bare = false) => answer(await A.sigeloAttestation(env, citizen, ms), 'attestation', ms, bare),
  };
}

/** What an agent following INTEGRATION.md keeps from an answer: the nested document if there is one, else the whole object. */
export const take = (text, key) => { const o = JSON.parse(text); return Object.hasOwn(o, key) ? o[key] : o; };
