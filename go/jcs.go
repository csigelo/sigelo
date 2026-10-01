// RFC 8785 (JCS) canonicalization and a strict JSON parser, restricted per SPEC §3:
// integers only, no floats, no duplicate keys, no "__proto__", no lone surrogates.
//
// Why not encoding/json/v2? It does reject duplicate keys, but it rejects a `\ud800` escape by
// failing the WHOLE document (or, with AllowInvalidUTF8, silently maps it to U+FFFD — the
// collision SPEC §3.1 forbids), and it reads numbers as float64. §9 step 2 needs a lone
// surrogate inside one attestation to discard that attestation only, and needs 2^53 to stay
// distinguishable from 2^53+1. So, like ts/src/jcs.ts, the parser is written out: a lone
// surrogate is kept (as its WTF-8 bytes) and Canonicalize refuses it, item by item.
package sigelo

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxInt is 2^53−1, the largest magnitude SPEC §3 allows.
const MaxInt = 1<<53 - 1

// MaxDepth is the deepest nesting of arrays and objects, combined, that Parse and Canonicalize
// accept (SPEC §3; the outermost container is level 1). Both recurse once per level, and in Go
// running out of goroutine stack is a fatal runtime error, not a panic: recover() cannot catch
// it, so an unbounded parser lets a 1.6 MB document kill every process that embeds this
// package. A bounded verifier has to bound depth, and ts/src/jcs.ts bounds it at the same place.
const MaxDepth = 512

// Object is a JSON object that remembers member order, so error messages and the order of
// checks match ts/ (which iterates in insertion order). JCS output is sorted regardless.
type Object []Member

// Member is one name/value pair of an Object.
type Member struct {
	Key   string
	Value any
}

// Number is a JSON number literal that is not an integer in ±2^53−1, kept as its text.
// Canonicalize always rejects it (SPEC §3), so it makes malformed only the item that holds it:
// a float in one attestation discards that attestation, never the whole document (invariant 7).
type Number string

// JcsError is returned by Parse and Canonicalize.
type JcsError string

func (e JcsError) Error() string { return string(e) }

// Get returns the member named k, if present.
func (o Object) Get(k string) (any, bool) {
	for _, m := range o {
		if m.Key == k {
			return m.Value, true
		}
	}
	return nil, false
}

// With returns a copy of o with k set to v (replaced in place, or appended).
func (o Object) With(k string, v any) Object {
	out := slices.Clone(o)
	for i := range out {
		if out[i].Key == k {
			out[i].Value = v
			return out
		}
	}
	return append(out, Member{k, v})
}

// units returns the UTF-16 code units of s. A lone surrogate the parser kept as WTF-8
// (ED A0..BF xx) yields its own unit, so sorting and quoting see what JavaScript sees.
func units(s string) []uint16 {
	var out []uint16
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n == 1 && i+2 < len(s) && s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2]&0xC0 == 0x80 {
			out = append(out, 0xD000|uint16(s[i+1]&0x3F)<<6|uint16(s[i+2]&0x3F))
			i += 3
			continue
		}
		out = utf16.AppendRune(out, r)
		i += n
	}
	return out
}

// nonchar returns the first Unicode noncharacter in s — U+FDD0..U+FDEF, and U+xFFFE / U+xFFFF
// in every plane — which I-JSON (RFC 7493 §2.1, required by RFC 8785) forbids, like a lone
// surrogate. A kept lone surrogate (WTF-8) ranges as U+FFFD, which is not one.
func nonchar(s string) (rune, bool) {
	for _, r := range s {
		if r >= 0xFDD0 && r <= 0xFDEF || r&0xFFFE == 0xFFFE {
			return r, true
		}
	}
	return 0, false
}

// str returns s as a JSON string with exactly the ES6 JSON.stringify escape set: `"`, `\`,
// the five short forms, lowercase \u00xx for other C0 controls, raw UTF-8 for everything else
// (U+007F, U+2028 and U+2029 included). A lone surrogate is written \udxxx, as JSON.stringify
// does; Canonicalize refuses one before it gets here.
func str(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	u := units(s)
	for i := 0; i < len(u); i++ {
		switch c := u[i]; {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(byte(c))
		case c < 0x20:
			if k := strings.IndexByte("\b\t\n\f\r", byte(c)); k >= 0 {
				b.WriteString(`\` + "btnfr"[k:k+1])
			} else {
				fmt.Fprintf(&b, `\u%04x`, c)
			}
		case utf16.IsSurrogate(rune(c)):
			if c < 0xDC00 && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] < 0xE000 {
				b.WriteRune(utf16.DecodeRune(rune(c), rune(u[i+1])))
				i++
			} else {
				fmt.Fprintf(&b, `\u%04x`, c)
			}
		default:
			b.WriteRune(rune(c))
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Canonicalize returns the JCS bytes of v. It fails on a Number (float or out of range), a lone
// surrogate or invalid UTF-8 in any string or key, a "__proto__" key, or a Go type that is not
// one of nil, bool, string, int64, int, []any, Object.
func Canonicalize(v any) ([]byte, error) {
	var b strings.Builder
	if err := ser(&b, v, true, 0); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// stringify is JSON.stringify for error messages: member order kept, never fails.
func stringify(v any) string {
	var b strings.Builder
	ser(&b, v, false, 0)
	return b.String()
}

// ser writes v, which sits inside `depth` containers.
func ser(b *strings.Builder, v any, canon bool, depth int) error {
	switch v.(type) {
	case []any, Object:
		if depth++; depth > MaxDepth { // a value no conforming Parse returns (SPEC §3)
			return JcsError(fmt.Sprintf("nesting deeper than %d", MaxDepth))
		}
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case int:
		return ser(b, int64(x), canon, depth)
	case int64:
		if canon && (x > MaxInt || x < -MaxInt) {
			return JcsError(fmt.Sprintf("integer outside +-2^53-1: %d", x))
		}
		b.WriteString(strconv.FormatInt(x, 10))
	case Number:
		if canon && strings.ContainsAny(string(x), ".eE") {
			return JcsError("non-integer number " + string(x))
		} else if canon {
			return JcsError("integer outside +-2^53-1: " + string(x))
		}
		b.WriteString(string(x))
	case string:
		if canon && !utf8.ValidString(x) {
			// RFC 8785 requires I-JSON (RFC 7493 §2.1). A lossy encoder would map a lone
			// surrogate to U+FFFD and give two different bodies one signing input.
			return JcsError("lone surrogate in string " + str(x))
		}
		if r, bad := nonchar(x); canon && bad { // SPEC §3.1; Parse refuses one, so only a built value gets here
			return JcsError(fmt.Sprintf("noncharacter U+%04X in string", r))
		}
		b.WriteString(str(x))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := ser(b, e, canon, depth); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case Object:
		ms := x
		if canon { // RFC 8785 §3.2.3: sort by UTF-16 code unit, NOT by code point or UTF-8 byte
			ms = slices.Clone(x)
			slices.SortStableFunc(ms, func(p, q Member) int { return slices.Compare(units(p.Key), units(q.Key)) })
		}
		b.WriteByte('{')
		for i, m := range ms {
			if i > 0 {
				b.WriteByte(',')
			}
			if canon && m.Key == "__proto__" { // SPEC §3.1; see Parse
				return JcsError(`forbidden key "__proto__"`)
			}
			if canon && !utf8.ValidString(m.Key) {
				return JcsError("lone surrogate in string " + str(m.Key))
			}
			if r, bad := nonchar(m.Key); canon && bad {
				return JcsError(fmt.Sprintf("noncharacter U+%04X in string", r))
			}
			b.WriteString(str(m.Key))
			b.WriteByte(':')
			if err := ser(b, m.Value, canon, depth); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return JcsError(fmt.Sprintf("unserializable type %T", v))
	}
	return nil
}

// Parse reads JSON text, rejecting duplicate keys at any depth, the key "__proto__" and invalid
// UTF-8 in the text: those make the text ambiguous, so they fail the whole document. A number
// literal that is not an integer in ±2^53−1 (including "1.0" and "1e2": the signer's bytes are
// not recoverable from them) and a `\ud800` escape are NOT parse errors: they are kept, as a
// Number and as WTF-8, and rejected by Canonicalize, so they discard only the item that
// carries them (SPEC §9 step 2).
func Parse(text []byte) (any, error) { return parse(text, true) }

// parse with strict=false is the loader for data ABOUT bodies (test-vectors.json), which must
// be able to carry "__proto__" keys: those survive as values for Canonicalize to refuse.
func parse(text []byte, strict bool) (any, error) {
	p := &parser{s: text, strict: strict}
	v, err := p.value()
	if err == nil {
		p.ws()
		if p.i != len(p.s) {
			err = p.fail("trailing content")
		}
	}
	return v, err
}

type parser struct {
	s      []byte
	i      int
	strict bool
	depth  int // containers open around the current value
}

// fail reports p.i as an offset in UTF-16 code units, as ts/src/jcs.ts does, so both say the
// same. The convention, which both parsers keep: p.i is AT the offending character, never past
// it — the character where a "," / ":" / closer was expected, the escape letter of a bad escape
// (the `u` of a bad \u escape), the opening quote of a string refused whole (a noncharacter),
// the bracket that opens a level too deep, and the end of the text for "unexpected end" and
// "unterminated". (They differed by one on four messages until the hostile-JSON differential,
// M1: ts post-incremented before failing where this peeked.)
func (p *parser) fail(msg string) error {
	return JcsError(fmt.Sprintf("%s at offset %d", msg, len(units(string(p.s[:min(p.i, len(p.s))])))))
}

func (p *parser) ws() {
	for p.i < len(p.s) && strings.IndexByte(" \t\n\r", p.s[p.i]) >= 0 {
		p.i++
	}
}

func (p *parser) peek() byte {
	if p.i < len(p.s) {
		return p.s[p.i]
	}
	return 0
}

func (p *parser) value() (any, error) {
	p.ws()
	if c := p.peek(); c == '{' || c == '[' {
		// SPEC §3: deeper than MaxDepth is a parse error, reported at the bracket that opens
		// level MaxDepth+1 — an empty container there too, as in ts/src/jcs.ts.
		if p.depth == MaxDepth {
			return nil, p.fail(fmt.Sprintf("nesting deeper than %d", MaxDepth))
		}
		p.depth++
		defer func() { p.depth-- }()
	}
	switch c := p.peek(); {
	case c == '{':
		p.i++
		obj, seen := Object{}, map[string]bool{}
		if p.ws(); p.peek() == '}' {
			p.i++
			return obj, nil
		}
		for {
			p.ws()
			k, err := p.string()
			if err != nil {
				return nil, err
			}
			if seen[k] {
				return nil, p.fail("duplicate key " + str(k))
			}
			// A JavaScript parser that assigns it swaps the object's prototype instead of
			// adding a key; SPEC §3.1 forbids it everywhere so every implementation agrees.
			if p.strict && k == "__proto__" {
				return nil, p.fail(`forbidden key "__proto__"`)
			}
			seen[k] = true
			if p.ws(); p.peek() != ':' {
				return nil, p.fail(`expected ":"`)
			}
			p.i++
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			obj = append(obj, Member{k, v})
			p.ws()
			switch p.peek() {
			case '}':
				p.i++
				return obj, nil
			case ',':
				p.i++
			default:
				return nil, p.fail(`expected "," or "}"`)
			}
		}
	case c == '[':
		p.i++
		arr := []any{}
		if p.ws(); p.peek() == ']' {
			p.i++
			return arr, nil
		}
		for {
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
			p.ws()
			switch p.peek() {
			case ']':
				p.i++
				return arr, nil
			case ',':
				p.i++
			default:
				return nil, p.fail(`expected "," or "]"`)
			}
		}
	case c == '"':
		return p.string()
	case c == '-' || c >= '0' && c <= '9':
		return p.number()
	}
	for _, w := range []struct {
		lit string
		v   any
	}{{"true", true}, {"false", false}, {"null", nil}} {
		if bytes.HasPrefix(p.s[p.i:], []byte(w.lit)) {
			p.i += len(w.lit)
			return w.v, nil
		}
	}
	if p.i >= len(p.s) {
		return nil, p.fail("unexpected end of input")
	}
	return nil, p.fail("unexpected token " + strconv.Quote(string(p.s[p.i:p.i+1])))
}

func (p *parser) number() (any, error) {
	start := p.i
	digits := func() int {
		n := 0
		for p.peek() >= '0' && p.peek() <= '9' {
			p.i++
			n++
		}
		return n
	}
	if p.peek() == '-' {
		p.i++
	}
	if p.peek() == '0' {
		p.i++
	} else if digits() == 0 {
		return nil, p.fail("expected number")
	}
	lex := string(p.s[start:p.i])
	if strings.IndexByte(".eE", p.peek()) >= 0 && p.peek() != 0 {
		if p.peek() == '.' {
			p.i++
			if digits() == 0 {
				return nil, p.fail("expected digit")
			}
		}
		if p.peek() == 'e' || p.peek() == 'E' {
			p.i++
			if p.peek() == '+' || p.peek() == '-' {
				p.i++
			}
			if digits() == 0 {
				return nil, p.fail("expected digit")
			}
		}
		return Number(p.s[start:p.i]), nil
	}
	n, err := strconv.ParseInt(lex, 10, 64)
	if err != nil || n > MaxInt || n < -MaxInt {
		return Number(lex), nil
	}
	return n, nil // "-0" is 0, as SPEC §3 requires
}

func (p *parser) hex4() (rune, bool) {
	if p.i+4 > len(p.s) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(p.s[p.i:p.i+4]), 16, 16)
	if err != nil {
		return 0, false
	}
	p.i += 4
	return rune(n), true
}

func (p *parser) string() (string, error) {
	if p.peek() != '"' {
		return "", p.fail("expected string")
	}
	start := p.i
	p.i++
	var b []byte
	for {
		if p.i >= len(p.s) {
			return "", p.fail("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			// SPEC §3.1 / I-JSON: a noncharacter, raw or escaped, in a string or key makes the
			// text unfit to sign; reported at the string's opening quote, as ts/src/jcs.ts does.
			if r, bad := nonchar(string(b)); bad {
				p.i = start
				return "", p.fail(fmt.Sprintf("noncharacter U+%04X in string", r))
			}
			return string(b), nil
		case c < 0x20:
			return "", p.fail("unescaped control character in string")
		case c >= 0x80:
			r, n := utf8.DecodeRune(p.s[p.i:])
			if r == utf8.RuneError && n <= 1 {
				return "", p.fail("invalid UTF-8 in string") // RFC 8259 §8.1: JSON text is UTF-8
			}
			b = append(b, p.s[p.i:p.i+n]...)
			p.i += n
		case c != '\\':
			b = append(b, c)
			p.i++
		default:
			p.i++
			e := p.peek()
			p.i++
			if short := strings.IndexByte(`"\/bfnrt`, e); short >= 0 && e != 0 {
				b = append(b, "\"\\/\b\f\n\r\t"[short])
				continue
			}
			if e != 'u' {
				p.i--
				return "", p.fail(fmt.Sprintf(`bad escape \%c`, e))
			}
			r, ok := p.hex4()
			if !ok {
				p.i-- // at the `u`, as for any bad escape
				return "", p.fail(`bad \u escape`)
			}
			if utf16.IsSurrogate(r) && r < 0xDC00 && bytes.HasPrefix(p.s[p.i:], []byte(`\u`)) {
				save := p.i
				p.i += 2
				if lo, ok := p.hex4(); ok && lo >= 0xDC00 && lo < 0xE000 {
					b = utf8.AppendRune(b, utf16.DecodeRune(r, lo))
					continue
				}
				p.i = save
			}
			if utf16.IsSurrogate(r) { // lone: keep its WTF-8 bytes for Canonicalize to refuse
				b = append(b, 0xED, byte(0x80|(r>>6)&0x3F), byte(0x80|r&0x3F))
				continue
			}
			b = utf8.AppendRune(b, r)
		}
	}
}
