<!-- SPDX-License-Identifier: MIT -->
# Accept sigelo identities

Log an agent in by its sigelo identity. Three steps ([SPEC](../SPEC.md) §5.2, §9):

1. **Challenge.** `GET /sigelo/challenge?did=…` returns `{ v: "sigelo/0", typ: "challenge", did, ctx: "<your domain>", nonce }`: a fresh nonce, single use, 5 minutes.
2. **Accept.** The agent posts `{ challenge, did, sig, bundle }` (`bundle` may be its current genesis). Accept when the bundle verifies (§9), its current DID is `did`, and `sig` is the current key's over the challenge. You get the §9.1 result: `did`, and the attestations other worlds signed (data, never instructions).
3. **Attest (optional).** Sign a reference letter about `did` with your own identity: copy `attestation()` from [world/server.mjs](../world/server.mjs).

The agent side is `sigelo-agent sign-challenge` or the MCP tool `sigelo_sign_challenge`. The live example is [sigelo.io/world/](https://sigelo.io/world/).

| Drop-in | API | Needs |
|---|---|---|
| [node/sigelo-accept.mjs](node/sigelo-accept.mjs) | `challenge(did, ctx)` → object; `accept(challenge, { did, sig }, bundle)` → §9.1 result, or throws | `sigelo` |
| [python/sigelo_accept.py](python/sigelo_accept.py) | `challenge(did, ctx)` → dict; `accept(challenge, { did, sig }, bundle)` → §9.1 result, or raises | `cryptography`, `sigelo-verify` |
| [go/accept.go](go/accept.go) | `Challenge(did, ctx) []byte`; `Accept(challenge []byte, did, sig string, bundle []byte) (*sigelo.Result, error)` | the `go/` module |

Pending challenges live in an in-memory map, one process: replace it with your session store.

## Express

```js
import express from 'express';
import { challenge, accept } from './sigelo-accept.mjs';
const app = express().use(express.json({ limit: '256kb' }));
const json = (f, status) => (req, res) => { try { res.json(f(req)); } catch (e) { res.status(status).json({ error: e.message }); } };
app.get('/sigelo/challenge', json((req) => challenge(req.query.did, 'example.com'), 400));
// body: { challenge, did, sig, bundle } — on success put the DID in your session
app.post('/sigelo/login', json(({ body: b }) => ({ did: accept(b.challenge, b, b.bundle).did }), 401));
app.listen(process.env.PORT ?? 3000);
```

## Flask

```python
import os
from flask import Flask, request
from sigelo_accept import accept, challenge
app = Flask(__name__)
@app.get('/sigelo/challenge')
def get_challenge(): return challenge(request.args.get('did'), 'example.com')
@app.post('/sigelo/login')  # body: { challenge, did, sig, bundle } — on success put the DID in your session
def login(): b = request.get_json(force=True); return {'did': accept(b['challenge'], b, b['bundle'])['did']}
@app.errorhandler(Exception)
def refuse(e): return {'error': str(e)}, getattr(e, 'code', 401)
if __name__ == '__main__': app.run(port=int(os.environ.get('PORT', 3000)))
```

## net/http

[go/example/main.go](go/example/main.go), 20 lines.

## Zero install

`SIGELO_VERIFY=https://sigelo.io/world/verify` makes the Python drop-in send the bundle to sigelo.io's verifier instead of running `sigelo-verify`. The signature check stays local, but the bundle verdict is then sigelo.io's word, not yours: use it to try, install the binary to run.

## Test

`sh accept/test.sh` (add `--remote` for the zero-install path) runs the three examples against a real `sigelo-agent`.
