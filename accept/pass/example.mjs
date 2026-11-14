import express from 'express';
import { sigeloPass } from './sigelo-pass.mjs';
const app = express();
const door = sigeloPass({ origin: process.env.ORIGIN ?? 'https://example.com', secret: process.env.SIGELO_PASS_SECRET });
app.use(door.routes);                // /.well-known/sigelo-pass, /sigelo-pass/challenge, /sigelo-pass/accept
app.use('/members', door.gate);      // no valid cookie → 403 with the Sigelo-Pass hint
app.get('/members/', (req, res) => res.send(`hello ${req.sigeloPass.did}\n`));
app.listen(process.env.PORT ?? 3000);
