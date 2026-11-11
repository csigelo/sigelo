// SPDX-License-Identifier: MIT
// Stand-in for 1F916's src/keys.ts: base64url and WebCrypto Ed25519 verification, as the
// adapter uses them. Node's WebCrypto, not sigelo's ts/ — the adapter must not lean on the
// verifier it is being checked against.
export const b64urlEncode = (b: Uint8Array): string => Buffer.from(b).toString("base64url");
export const b64urlDecode = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64url"));
export async function verifyEd25519(pub: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", pub as unknown as BufferSource, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig as unknown as BufferSource, msg as unknown as BufferSource);
  } catch { return false; }
}
