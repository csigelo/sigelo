// SPDX-License-Identifier: MIT
/**
 * RFC 8785 (JCS) canonicalization and a strict JSON parser, restricted per SPEC §3:
 * integers only, no floats, no duplicate keys.
 *
 * Two facts about JavaScript make this shorter than it looks, and both are checked against
 * vector `attestation_unicode` rather than taken on faith (see src/test.ts):
 *
 *  - `Array.prototype.sort` with no comparator orders strings by UTF-16 code unit, which is
 *    exactly the order RFC 8785 specifies. Sorting by code point (what most languages do)
 *    diverges above U+FFFF, which is why the vector carries U+1D11E and U+FF5E.
 *  - `JSON.stringify` of a string emits exactly the ES6 escape set: `"` `\`, the five short
 *    forms, `\u00xx` with lowercase hex for the remaining C0 controls, and raw UTF-8 for
 *    everything else — U+007F, U+2028, U+2029 and all non-ASCII included. No `\/`.
 *
 * What JavaScript does *not* give us is number discipline: `JSON.stringify` will happily emit
 * `0.1` or `1e+30`. SPEC §3 forbids both, so every number passes through the check below.
 * Nor string discipline: a lone surrogate serializes happily and then `TextEncoder` turns it
 * into U+FFFD, so two different bodies would share one signing input. RFC 8785 requires
 * I-JSON input (RFC 7493 §2.1: no lone surrogates), and Python cannot encode one at all, so
 * both implementations reject it here (SPEC §3.1).
 */

/** Thrown by both functions. `verify` wraps these into a SigeloError naming the slot. */
export class JcsError extends Error {
  override readonly name = 'JcsError';
}

/**
 * A number literal `parse` read that is not an integer in ±2^53−1 (`0.5`, `1e2`, `2^53`),
 * kept as its text. `canonicalize` refuses it, so whichever item holds it is malformed — one
 * attestation's float discards that attestation, as it would arriving as a parsed object,
 * instead of failing the whole document (invariant 7; go/jcs.go's `Number` is the same thing).
 */
export class RawNumber {
  constructor(readonly text: string) { Object.freeze(this); }
}

/** With the `u` flag a well-formed pair is one code point, so this matches only a LONE surrogate. */
const LONE_SURROGATE = /[\ud800-\udfff]/u;

/**
 * Unicode noncharacters — U+FDD0..U+FDEF, and U+xFFFE / U+xFFFF in every plane — which I-JSON
 * (RFC 7493 §2.1, required by RFC 8785) forbids like a lone surrogate (SPEC §3.1).
 */
const NONCHAR = new RegExp('[\\uFDD0-\\uFDEF' +
  Array.from({ length: 17 }, (_, p) => `\\u{${(p * 0x10000 + 0xfffe).toString(16)}}\\u{${(p * 0x10000 + 0xffff).toString(16)}}`).join('') + ']', 'u');
const noncharIn = (s: string): string | undefined => {
  const m = NONCHAR.exec(s);
  return m === null ? undefined : 'U+' + m[0].codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0');
};

function str(s: string): string {
  if (LONE_SURROGATE.test(s)) throw new JcsError(`lone surrogate in string ${JSON.stringify(s)}`);
  const nc = noncharIn(s); // parse() refuses one, so only a value built in memory gets here
  if (nc !== undefined) throw new JcsError(`noncharacter ${nc} in string`);
  return JSON.stringify(s);
}

/**
 * The deepest nesting of arrays and objects, combined, that `parse` and `canonicalize` accept
 * (SPEC §3; the outermost container is level 1). go/jcs.go recurses once per level, and Go
 * running out of goroutine stack is a fatal runtime error that nothing can catch (it died near
 * 750 000 levels, where this file, iterative, still answered): without one bound in both, the
 * same bytes got a verdict here and a dead process there. 512 is `MaxDepth` in go/jcs.go.
 */
export const MAX_DEPTH = 512;

/** Output queued between a container's values: a literal, or the next object key. */
class Lit { constructor(readonly s: string) {} }
class Key { constructor(readonly k: string, readonly first: boolean) {} }

// A work list, not recursion: a recursive walk threw RangeError near depth 5000 — a crash
// naming no check, which sank a whole bundle over one deeply nested attestation (invariant 7;
// sim/REPORT.md finding S1). MAX_DEPTH now bounds the depth; the work list stays, because
// the call stack left for this depends on the caller's.
function ser(value: unknown, out: string[]): void {
  const todo: unknown[] = [value];
  let depth = 0;
  while (todo.length) {
    const v = todo.pop();
    if (v instanceof Lit) {
      if (v.s === ']' || v.s === '}') depth--;
      out.push(v.s);
    } else if (v instanceof Key) {
      if (!v.first) out.push(',');
      if (v.k === '__proto__') throw new JcsError('forbidden key "__proto__"'); // SPEC §3.1; see parse()
      out.push(str(v.k), ':');
    } else if (one(v, out, todo) && ++depth > MAX_DEPTH) {
      throw new JcsError(`nesting deeper than ${MAX_DEPTH}`); // a value no conforming parse returns
    }
  }
}

/** One value: a scalar is written, a container is opened and its parts queued in reverse (true). */
function one(value: unknown, out: string[], todo: unknown[]): boolean {
  if (value === null) return void out.push('null'), false;
  switch (typeof value) {
    case 'boolean': return void out.push(value ? 'true' : 'false'), false;
    case 'string': return void out.push(str(value)), false;
    case 'number':
      // SPEC §3: no floats, no exponents, nothing outside ±2^53−1. Forbidding them removes
      // the whole class of cross-language number-canonicalization disagreements.
      if (!Number.isInteger(value)) throw new JcsError(`non-integer number ${value}`);
      if (!Number.isSafeInteger(value)) throw new JcsError(`integer outside +-2^53-1: ${value}`);
      return void out.push(String(value)), false; // String(-0) === "0", as SPEC §3 requires
    case 'bigint': throw new JcsError('bigint is not a JSON number');
    case 'undefined': case 'function': case 'symbol':
      throw new JcsError(`unserializable type ${typeof value}`);
  }
  if (value instanceof RawNumber) {
    throw new JcsError(/[.eE]/.test(value.text) ? `non-integer number ${value.text}` : `integer outside +-2^53-1: ${value.text}`);
  }
  if (Array.isArray(value)) {
    out.push('[');
    todo.push(new Lit(']'));
    for (let n = value.length - 1; n >= 0; n--) {
      todo.push(value[n]);
      if (n) todo.push(new Lit(','));
    }
    return true;
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw new JcsError(`unserializable type ${value.constructor?.name ?? 'object'}`);
  const obj = value as Record<string, unknown>;
  out.push('{');
  todo.push(new Lit('}'));
  // Default string sort == UTF-16 code-unit order == RFC 8785 §3.2.3 key order.
  const keys = Object.keys(obj).sort();
  for (let n = keys.length - 1; n >= 0; n--) todo.push(obj[keys[n]!], new Key(keys[n]!, n === 0));
  return true;
}

/** JCS serialization of `value` as a JS string (UTF-8 once encoded). Throws JcsError. */
export function canonicalize(value: unknown): string {
  const out: string[] = [];
  ser(value, out);
  return out.join('');
}

const ESC: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };

/**
 * Parse JSON text, rejecting duplicate keys and "__proto__" at any depth. Those make the TEXT
 * ambiguous, so they are fatal to the whole document (invariant 7). A number that is not an
 * integer in ±2^53−1 is not ambiguous, only forbidden in signed objects: it parses to a
 * `RawNumber` that `canonicalize` refuses, so it sinks only the item that carries it.
 *
 * `JSON.parse` cannot do the first: it silently keeps the last duplicate, so two
 * implementations can read different bodies out of the same bytes and one of them verifies a
 * signature over bytes the other never saw (SPEC §3, THREAT-MODEL §2.8). Hence a hand-written
 * parser. It is not fast; it does not need to be.
 */
export function parse(text: string): unknown {
  let i = 0;
  const fail = (msg: string): never => {
    throw new JcsError(`${msg} at offset ${i}`);
  };
  const ws = (): void => {
    while (i < text.length && ' \t\n\r'.includes(text[i]!)) i++;
  };
  const lit = (word: string, value: unknown): unknown =>
    text.startsWith(word, i) ? (i += word.length, value) : fail(`unexpected token ${JSON.stringify(text[i] ?? '<end>')}`);

  function string(): string {
    if (text[i] !== '"') fail('expected string');
    const start = i++;
    let s = '';
    for (;;) {
      const c = text[i];
      if (c === undefined) fail('unterminated string');
      if (c === '"') {
        // SPEC §3.1 / I-JSON: a noncharacter, raw or escaped, in a string or key makes the text
        // unfit to sign; reported at the string's opening quote, as go/jcs.go does.
        const nc = noncharIn(s);
        if (nc !== undefined) { i = start; fail(`noncharacter ${nc} in string`); }
        return i++, s;
      }
      if (c !== '\\') {
        if (c!.charCodeAt(0) < 0x20) fail('unescaped control character in string');
        s += c;
        i++;
        continue;
      }
      const e = text[++i];
      if (e === 'u') {
        const hex = text.slice(i + 1, i + 5);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('bad \\u escape');
        s += String.fromCharCode(parseInt(hex, 16)); // surrogate pairs recombine naturally
        i += 5;
      } else if (e !== undefined && e in ESC) {
        s += ESC[e];
        i++;
      } else fail(`bad escape \\${e ?? '<end>'}`);
    }
  }

  function num(): number | RawNumber {
    const start = i;
    const digits = (): number => { const at = i; while (text[i]! >= '0' && text[i]! <= '9') i++; return i - at; };
    if (text[i] === '-') i++;
    if (text[i] === '0') i++;
    else if (!(text[i]! >= '1' && text[i]! <= '9' && digits())) fail('expected number');
    // A fraction or exponent is a non-integer literal even where its value is integral
    // ("1.0", "1e2"). SPEC §3 lets an implementation that sees the raw text reject those, and
    // failing closed (CLAUDE.md invariant 7) says to: the signer's bytes are not recoverable.
    let integer = true;
    if (text[i] === '.') { i++; integer = false; if (!digits()) fail('expected digit'); }
    if (text[i] === 'e' || text[i] === 'E') {
      i++; integer = false;
      if (text[i] === '+' || text[i] === '-') i++;
      if (!digits()) fail('expected digit');
    }
    const lex = text.slice(start, i);
    const n = Number(lex);
    return integer && Number.isSafeInteger(n) ? n : new RawNumber(lex);
  }

  /** After an object's "{" or ",": one key, its checks, and the ":". */
  function key(o: { obj: Record<string, unknown>; seen: Set<string>; k: string }): void {
    ws();
    const k = string();
    if (o.seen.has(k)) fail(`duplicate key ${JSON.stringify(k)}`);
    // `obj[k] = v` with k "__proto__" does not add a key: it calls the Object.prototype
    // setter and swaps the object's prototype, so the parsed body silently loses a field
    // and later fails as "unserializable" far from here. SPEC §3.1 forbids the key outright.
    if (k === '__proto__') fail('forbidden key "__proto__"');
    o.seen.add(k);
    ws();
    if (text[i] !== ':') fail('expected ":"'); // at the offending character (go/jcs.go `fail` states the convention)
    i++;
    o.k = k;
  }

  // Open containers live on this stack, not the call stack, for the reason ser() gives. Its
  // height is the nesting depth, bounded by MAX_DEPTH (SPEC §3).
  type Frame = { arr: unknown[] } | { obj: Record<string, unknown>; seen: Set<string>; k: string };
  const stack: Frame[] = [];
  for (;;) {
    // One value: a scalar, an empty container, or a container that is opened and pushed.
    ws();
    const c = text[i];
    let v: unknown;
    if (c === '{' || c === '[') {
      // Reported at the bracket that opens level MAX_DEPTH + 1, an empty container too, as in go/jcs.go.
      if (stack.length === MAX_DEPTH) fail(`nesting deeper than ${MAX_DEPTH}`);
      i++;
      ws();
      if (text[i] === (c === '{' ? '}' : ']')) { i++; v = c === '{' ? {} : []; }
      else if (c === '[') { stack.push({ arr: [] }); continue; }
      else { const o = { obj: {}, seen: new Set<string>(), k: '' }; key(o); stack.push(o); continue; }
    } else if (c === '"') v = string();
    else if (c !== undefined && (c === '-' || (c >= '0' && c <= '9'))) v = num();
    else if (c === 't') v = lit('true', true);
    else if (c === 'f') v = lit('false', false);
    else if (c === 'n') v = lit('null', null);
    else fail(c === undefined ? 'unexpected end of input' : `unexpected token ${JSON.stringify(c)}`);
    // Hand the value to its container; every container that ends here closes in turn.
    for (;;) {
      const top = stack[stack.length - 1];
      if (top === undefined) {
        ws();
        if (i !== text.length) fail('trailing content');
        return v;
      }
      if ('arr' in top) top.arr.push(v);
      // defineProperty, not assignment: always an own data property, never a setter call.
      else Object.defineProperty(top.obj, top.k, { value: v, enumerable: true, writable: true, configurable: true });
      ws();
      const d = text[i];
      if (d !== ',' && d !== ('arr' in top ? ']' : '}')) fail('arr' in top ? 'expected "," or "]"' : 'expected "," or "}"'); // at d, not past it
      i++;
      if (d === ',') {
        if (!('arr' in top)) key(top);
        break;
      }
      stack.pop();
      v = 'arr' in top ? top.arr : top.obj;
    }
  }
}

const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * `parse` for bytes: the one entry point for a signed document read off a file, a socket or
 * stdin. `parse` takes a JS string, so it never sees bytes, and every lossy decode
 * (`readFileSync(p, 'utf8')`, `setEncoding`, a default `TextDecoder`) turns invalid UTF-8 into
 * U+FFFD — which sank only the one item whose signature then failed, while go/jcs.go's Parse
 * rejects the whole document (RFC 8259 §8.1). Decoding fatally makes the two agree (SPEC §3).
 * `ignoreBOM: true` keeps a leading BOM as U+FEFF, which `parse` then refuses as an unexpected
 * token, as Go does: a BOM is not JSON whitespace.
 */
export function parseBytes(bytes: Uint8Array): unknown {
  let text: string;
  try { text = STRICT_UTF8.decode(bytes); } catch { throw new JcsError('invalid UTF-8 in document'); }
  return parse(text);
}
