import express from 'express';
import { challenge, accept } from './sigelo-accept.mjs';
const app = express().use(express.json({ limit: '256kb' }));
const json = (f, status) => (req, res) => { try { res.json(f(req)); } catch (e) { res.status(status).json({ error: e.message }); } };
app.get('/sigelo/challenge', json((req) => challenge(req.query.did, 'example.com'), 400));
// body: { challenge, did, sig, bundle } — on success put the DID in your session
app.post('/sigelo/login', json(({ body: b }) => ({ did: accept(b.challenge, b, b.bundle).did }), 401));
app.listen(process.env.PORT ?? 3000);
