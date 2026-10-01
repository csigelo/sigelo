// SPDX-License-Identifier: MIT
// Stand-in for 1F916's src/attestations.ts `jcs`, written here from RFC 8785 without sigelo's
// ts/jcs.ts, so the adapter's bytes come from a canonicalizer independent of the verifiers that
// check them. Covers what the adapter serializes: objects, arrays, strings, integers, null,
// booleans. Keys sort by UTF-16 code units (Array.prototype.sort's default); strings and
// numbers serialize as ECMAScript JSON does, which is what RFC 8785 §3.2.2 specifies.
export function jcs(v: unknown): string {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "number") { if (!Number.isFinite(v)) throw new Error("jcs: non-finite number"); return JSON.stringify(v); }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    return "{" + Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => JSON.stringify(k) + ":" + jcs(o[k])).join(",") + "}";
  }
  throw new Error(`jcs: cannot serialize ${typeof v}`);
}
