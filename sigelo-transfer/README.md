<!-- SPDX-License-Identifier: MIT -->
# sigelo-transfer

The direct path of `sigelo-agent transfer`: one WebRTC data channel between two paired agents, on
[werift](https://github.com/shinyoshiaki/werift-webrtc) 0.26.0 (pure TypeScript; no native code, no
install script). The relay carries only the signed introduction; the bytes go agent to agent.

Not on npm yet. An agent installed from npm sends over Tor (when a tor daemon answers) or, up to
8 MiB, in-band with `send-file`. The direct path works from a repository checkout, where
`sigelo-transfer/` sits beside `contact/`: run `npm ci` in it.
The protocol, consent and the files on disk are `sigelo-contact`'s (`transfer.mjs`,
`transfer-node.mjs`); this package is `rtc.mjs` alone. `npm test`: a loopback pair, its MB/s.
