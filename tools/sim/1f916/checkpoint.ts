// SPDX-License-Identifier: MIT
// Stand-in for 1F916's src/checkpoint.ts `registrySigner`: REGISTRY_SEED is
// "<b64url 32-byte seed>.<b64url raw public key>", the shape adapters/1f916/sigelo.test.ts uses;
// `key` is the public half (b64url), `sign` returns a b64url Ed25519 signature over the string.
import { b64urlDecode, b64urlEncode } from "./keys.ts";
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex"); // RFC 8410 wrapper for a raw seed
export async function registrySigner(env: { REGISTRY_SEED?: string }) {
  const [seed, pub] = String(env.REGISTRY_SEED ?? "").split(".");
  if (!seed || !pub) throw new Error("REGISTRY_SEED unset");
  const der = Buffer.concat([PKCS8, Buffer.from(b64urlDecode(seed))]);
  const key = await crypto.subtle.importKey("pkcs8", der as unknown as BufferSource, { name: "Ed25519" }, false, ["sign"]);
  return {
    key: pub,
    sign: async (input: string) => b64urlEncode(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, new TextEncoder().encode(input) as unknown as BufferSource))),
  };
}
