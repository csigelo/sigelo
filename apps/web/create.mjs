// SPDX-License-Identifier: MIT
// Create a new identity (pass A10a; Monerujo's create and seed review as the model, design/monerujo-ref):
// the first run's first choice. Its screens are welcome.mjs's (Name this phone, Your 25 words once behind
// "I have written them down", Check your paper), its steps setup.mjs's (newSeed: S drawn in the page with
// crypto.getRandomValues, as newRoot; the three words checked by the session). Here the commit: the files
// of a restore from those words (operator, K_1, this device FULL holding the seat, created and the wallet's
// birth today), sealed as seed.mjs seals them, S zeroed. Nothing is stored before the check passes. The
// words are never shown again (no "show seed"): Me says "Created on <day>; the 25 words are on your paper".
//
//   createInto(platform, session, o)   commit a checked session (o: name, relay, now), seal and write,
//                                      the network held → { did, worker, vault }
import { DEFAULT_RELAY } from './vendor/contact/carrier.mjs';
import { holdNetwork } from './platform-web.mjs';
import { writeOperator } from './seed.mjs';

const hostOf = (relay) => String(relay ?? '').trim().toLowerCase() || DEFAULT_RELAY;

/** The checked session's files, sealed and written; S is zeroed by the commit (contact/create.mjs). */
export async function createInto(platform, session, { name, relay, now = Math.floor(Date.now() / 1000) }) {
  const release = holdNetwork();
  try {
    const host = hostOf(relay), r = session.commit({ name, relay: host, now });
    await writeOperator(platform, r, { host, net: session.net, seat: 'here', created: true });
    return { did: r.did, worker: r.worker, vault: r.vault };
  } finally { release(); }
}
