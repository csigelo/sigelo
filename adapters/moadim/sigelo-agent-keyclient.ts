// SPDX-License-Identifier: MIT
/**
 * Provider `agent` (design/key-providers.md §4): this process never holds the key and asks
 * `sigelo-key-agent` over its socket, synchronously (a worker thread, `Atomics.wait`). A STUB
 * until milestone K3: the signatures below are final, every call fails closed with
 * `key_provider_unbuilt`, and nothing falls back to a plain key.
 */
import { SigeloError } from 'sigelo';

/** One request of §4.2 (`{ op: "sign", did, body }`, …) and its reply; a refusal throws by its code. */
export function request(_req: Record<string, unknown>, _env: Record<string, string | undefined> = process.env): Record<string, unknown> {
  throw Object.assign(new SigeloError('key_provider_unbuilt: the key agent arrives with milestone K3; use a plain file (provider "file") until then'), { check: 'key_provider_unbuilt' });
}
