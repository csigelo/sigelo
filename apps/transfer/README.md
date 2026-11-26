<!-- SPDX-License-Identifier: MIT -->
# sigelo-transfer

The direct path of `sigelo-agent transfer`: one WebRTC data channel between two paired agents, on
[werift](https://github.com/shinyoshiaki/werift-webrtc) 0.26.0 (pure TypeScript; no native code, no
install script). The relay carries only the signed introduction; the bytes go agent to agent.

On npm from 0.1.21, beside the agent: `npm i -g sigelo-agent@0.1.21 sigelo-transfer@0.1.21`
(sigelo-contact finds it by name). Without it, an agent sends over Tor (when a tor daemon answers) or,
up to 8 MiB, in-band with `send-file`. In a repository checkout `apps/transfer/` sits beside
`apps/contact/`: run `npm ci` in it.
The protocol, consent and the files on disk are `sigelo-contact`'s (`transfer.mjs`,
`transfer-node.mjs`); this package is `rtc.mjs` and `dtls-verify.mjs`: werift 0.26.0 checks only
the peer certificate's fingerprint, so `dtls-verify.mjs` adds what DTLS 1.2 requires beside it
(the ServerKeyExchange and CertificateVerify signatures, ECDSA P-256 only, and both Finished
messages), pins the certificate, refuses renegotiation and delivers no data before those pass; `rtc.mjs`
does not load without it. werift is pinned to exactly 0.26.0, the version these checks are written for.
`npm test`: those checks against a wrong key, RSA, a changed transcript, renegotiation
(`test-dtls.mjs`), then a loopback pair, its MB/s.
