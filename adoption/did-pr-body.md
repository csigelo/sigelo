### DID Method Registration

As a DID method registrant, I have ensured that my DID method registration complies with the following statements:

- [x] The DID Method specification [defines the DID Method Syntax](https://w3c.github.io/did-core/#method-syntax). (§12.1, ABNF)
- [x] The DID Method specification [defines the Create, Read, Update, and Deactivate DID Method Operations](https://w3c.github.io/did-core/#method-operations). (§12.2–§12.5; `sigelo/0` has no deactivate operation, and §12.5 says what replaces it)
- [x] The DID Method specification [contains a Security Considerations section](https://w3c.github.io/did-core/#security-requirements). (§12.6)
- [x] The DID Method specification [contains a Privacy Considerations section](https://w3c.github.io/did-core/#privacy-requirements). (§12.7)
- [x] The JSON file I am submitting has [passed all automated validation tests below](#partial-pull-merging).
- [x] The JSON file contains a `contactEmail` address [OPTIONAL].
- [x] The JSON file contains a `verifiableDataRegistry` entry [OPTIONAL].

`did:sigelo` is self-certifying: the DID is the SHA-256 of a genesis document holding an Ed25519 key and a commitment to an offline recovery key. Resolution is offline verification of a bundle the subject presents; there is no registry, ledger or resolver service. MIT reference implementations in TypeScript and Go, with test vectors: https://github.com/csigelo/sigelo
