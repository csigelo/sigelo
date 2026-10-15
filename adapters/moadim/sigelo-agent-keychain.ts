// SPDX-License-Identifier: MIT
/**
 * Provider `keychain` (design/key-providers.md §3): the seed sealed in the identity file under a
 * random file key that the OS store holds (macOS keychain, Secret Service, DPAPI). A STUB until
 * milestone K2: the signatures below are final, every call fails closed with
 * `key_provider_unbuilt`, and nothing falls back to a plain key.
 */
import { SigeloError } from 'sigelo';
import type { Store } from './sigelo-agent.ts';

/** The `secret` field of a wrapped identity file (§2.2). */
export interface WrappedSecret { provider: 'keychain'; v: 'sigelo-wrap/1'; store: 'macos' | 'secret-service' | 'dpapi'; account: string; nonce: string; ct: string; dpapi?: string }
/** One OS store, injectable as the ceremony injects `Age`: the file key under service `sigelo`, account = the original DID. */
export interface Keychain { read(account: string): Uint8Array; write(account: string, key: Uint8Array): void; remove(account: string): void }

const unbuilt = (what: string): never => {
  throw Object.assign(new SigeloError(`key_provider_unbuilt: ${what}: the keychain provider arrives with milestone K2; use a plain file (provider "file") until then`), { check: 'key_provider_unbuilt' });
};
/** The store this system has, or `keychain_unavailable`. */
export function systemKeychain(_env: Record<string, string | undefined> = process.env): Keychain { return unbuilt('keychain'); }
/** Seal `seed` for the head key of `s`; the file key goes to `kc` once per identity. */
export function wrap(_seed: Uint8Array, _s: Store, _kc?: Keychain): WrappedSecret { return unbuilt('wrap'); }
/** The seed of a wrapped `s`, checked against its head key; the caller zeroes it after use. */
export function unwrap(_s: Store, _kc?: Keychain): Uint8Array { return unbuilt('unwrap'); }
