// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csigelo/sigelo/go"
)

// The test binary doubles as the candidate: with SIGELO_FAKE_CANDIDATE set it is a verifier
// with the TASK-verifier.md interface, correct ("ok") or wrong in a known way.
func TestMain(m *testing.M) {
	if mode := os.Getenv("SIGELO_FAKE_CANDIDATE"); mode != "" {
		os.Exit(fakeCandidate(mode, os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeCandidate(mode string, args []string) int {
	switch mode {
	case "crash":
		return 3
	case "sleep":
		time.Sleep(time.Minute)
	}
	if len(args) != 3 || args[1] != "--now" {
		return 2
	}
	now, _ := strconv.ParseInt(args[2], 10, 64)
	var text []byte
	if args[0] == "-" {
		text, _ = io.ReadAll(os.Stdin)
	} else {
		text, _ = os.ReadFile(args[0])
	}
	b, err := sigelo.Parse(text)
	if err != nil && mode == "accept-all" {
		fmt.Println("{}")
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "REJECT: parse:", err)
		return 1
	}
	res, err := sigelo.Verify(b, now, nil)
	if err != nil {
		if mode == "accept-all" { // never rejects: answers an empty result instead
			fmt.Println("{}")
			return 0
		}
		fmt.Fprintln(os.Stderr, "REJECT:", err)
		return 1
	}
	out, _ := res.MarshalJSON()
	if mode == "flip" { // reports an unproven binding as proven
		out = bytes.ReplaceAll(out, []byte(`"proof":"unproven"`), []byte(`"proof":"proven"`))
	}
	fmt.Println(string(out))
	return 0
}

const vectorsPath = "../../../test-vectors.json"

func runFake(t *testing.T, mode string, stdin bool) (int, string) {
	t.Setenv("SIGELO_FAKE_CANDIDATE", mode)
	var out bytes.Buffer
	code := runImpl(&out, vectorsPath, implOpts{cmd: []string{os.Args[0]}, stdin: stdin, timeout: 20 * time.Second})
	return code, out.String()
}

func fails(out string) []string {
	var fs []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "FAIL ") {
			name, _, _ := strings.Cut(strings.TrimPrefix(l, "FAIL "), " — ")
			fs = append(fs, name)
		}
	}
	return fs
}

func TestImplRunner(t *testing.T) {
	text, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	cases, inexpressible, err := buildCases(text)
	if err != nil {
		t.Fatal(err)
	}
	seen, groups := map[string]bool{}, map[string]int{}
	for _, c := range cases {
		if seen[c.name] {
			t.Errorf("case name twice: %s", c.name)
		}
		seen[c.name] = true
		groups[c.group]++
	}
	if len(cases) < 100 || groups["positive"] == 0 || groups["monero"] == 0 || groups["negative"] == 0 || groups["parity"] == 0 {
		t.Fatalf("%d cases, groups %v", len(cases), groups)
	}
	for _, n := range inexpressible {
		if !strings.HasPrefix(n, "invoice_") {
			t.Errorf("inexpressible %s", n)
		}
	}

	t.Run("reference verifier, file", func(t *testing.T) {
		if code, out := runFake(t, "ok", false); code != 0 || len(fails(out)) != 0 || !strings.Contains(out, "\nALL PASS\n") {
			t.Fatalf("exit %d, fails %v", code, fails(out))
		}
	})
	t.Run("reference verifier, stdin", func(t *testing.T) {
		if code, out := runFake(t, "ok", true); code != 0 || len(fails(out)) != 0 {
			t.Fatalf("exit %d, fails %v", code, fails(out))
		}
	})
	t.Run("unproven reported as proven", func(t *testing.T) {
		code, out := runFake(t, "flip", false)
		want := []string{"bundle == expect", "binding_unproven → unproven", "parity binding_envelope_sig_id_only_unproven"}
		if code != 1 || strings.Join(fails(out), "|") != strings.Join(want, "|") || !strings.HasSuffix(out, "FAILURES\n") {
			t.Fatalf("exit %d, fails %v, want %v", code, fails(out), want)
		}
	})
	t.Run("never rejects", func(t *testing.T) {
		code, out := runFake(t, "accept-all", false)
		n := 0
		for _, c := range cases {
			if c.kind == "reject" {
				n++
			}
		}
		if code != 1 || len(fails(out)) != n {
			t.Fatalf("exit %d, %d fails, want one per reject case (%d)", code, len(fails(out)), n)
		}
	})
	t.Run("crashes are not rejections", func(t *testing.T) {
		if code, out := runFake(t, "crash", false); code != 1 || len(fails(out)) != len(cases) {
			t.Fatalf("exit %d, %d fails of %d", code, len(fails(out)), len(cases))
		}
	})
	t.Run("timeout", func(t *testing.T) {
		t.Setenv("SIGELO_FAKE_CANDIDATE", "sleep")
		start := time.Now()
		ok, why := runCase(implOpts{cmd: []string{os.Args[0]}, timeout: 300 * time.Millisecond}, t.TempDir(), 0, cases[0])
		if ok || !strings.HasPrefix(why, "timed out") || time.Since(start) > 10*time.Second {
			t.Fatalf("ok %v, why %q after %s", ok, why, time.Since(start))
		}
	})
}

func TestJudge(t *testing.T) {
	res := implCase{kind: "result", expect: surface(mustVal(`{"did":"d","chain":["d"],"recovery":null,"attestations":{},"bindings":[{"body":{"n":1000},"proof":"proven"}],"rejected":{"attestations":0,"bindings":0}}`))}
	chk := implCase{kind: "check", fn: func(r map[string]any) string {
		return want(len(proofs(r)) == 0 && field(r["rejected"], "bindings") == int64(1), "binding accepted")
	}}
	rjc := implCase{kind: "reject"}
	for _, x := range []struct {
		c      implCase
		exit   int
		stdout string
		ok     bool
	}{
		// extras ignored, key order and number spelling free (1e3 = 1000)
		{res, 0, `{"x":1,"rejected":{"bindings":0,"attestations":0,"why":[]},"bindings":[{"proof":"proven","body":{"n":1e3},"reason":"ok"}],"attestations":{},"recovery":null,"chain":["d"],"did":"d"}`, true},
		{res, 0, `{"did":"d","chain":["d"],"attestations":{},"bindings":[{"body":{"n":1000},"proof":"proven"}],"rejected":{"attestations":0,"bindings":0}}`, false}, // recovery absent ≠ null
		{res, 0, `{"did":"d","chain":["d"],"recovery":null,"attestations":{},"bindings":[{"body":{"n":1000},"proof":"unproven"}],"rejected":{"attestations":0,"bindings":0}}`, false},
		{res, 1, ``, false},
		{res, 0, `not json`, false},
		{chk, 0, `{"bindings":[],"rejected":{"attestations":0,"bindings":1}}`, true},
		{chk, 0, `{"bindings":{},"rejected":{"attestations":0,"bindings":1}}`, false}, // bindings not an array
		{chk, 0, `{"bindings":[],"rejected":{"attestations":0,"bindings":0}}`, false},
		{chk, 0, `[]`, false},
		{rjc, 1, ``, true},
		{rjc, 0, `{}`, false},
		{rjc, 2, ``, false},
	} {
		if ok, why := judge(x.c, x.exit, []byte(x.stdout), nil, ""); ok != x.ok {
			t.Errorf("%s exit %d %s: ok %v (%s), want %v", x.c.kind, x.exit, x.stdout, ok, why, x.ok)
		}
	}
	if ok, _ := judge(rjc, 1, nil, nil, "timed out after 1s"); ok {
		t.Error("a timed-out run passed as a rejection")
	}
}

func mustVal(s string) any { v, _ := decodeVal([]byte(s)); return v }

func TestSplitWords(t *testing.T) {
	for in, want := range map[string]string{
		`node x.mjs`:                     `node|x.mjs`,
		`  a   'b c'  "d \"e\" \\" f\ g`: `a|b c|d "e" \|f g`,
		`python3 -m my_verifier ''`:      `python3|-m|my_verifier|`,
	} {
		got, err := splitWords(in)
		if err != nil || strings.Join(got, "|") != want {
			t.Errorf("%q → %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{``, `  `, `a 'b`} {
		if _, err := splitWords(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}
