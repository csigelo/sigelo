// SPDX-License-Identifier: MIT

// Command sigelo-verify verifies a sigelo bundle offline (SPEC §9) and prints the §9.1 result.
//
//	sigelo-verify <bundle.json|-> [--now N]
//	sigelo-verify --conformance [test-vectors.json] [--monero monero-vectors.json]
//	sigelo-verify --conformance [test-vectors.json] --impl '<command>' [--impl-stdin] [--impl-timeout S]
//	sigelo-verify --version
//
// The bundle is read with the strict parser (duplicate keys and "__proto__" reject the
// document; a non-integer number is rejected where it sits, per item or fatally). The result is printed as JCS JSON on stdout, exit 0. A rejection is
// printed on stderr as "REJECT: <failing check>", exit 1. Usage errors exit 2. --now is Unix
// seconds; without it the wall clock is read here, in the command — never in the verifier.
//
// --conformance runs every vector in the file (default ./test-vectors.json) exactly as
// `go test` does — the same PASS/FAIL lines, from the same code (conformance.go) — and ends
// with ALL PASS (exit 0) or FAILURES (exit 1). The §6.2 Monero section needs
// ts/test/monero-vectors.json: --monero names it, otherwise it is looked for next to the
// vectors file, and the section is SKIPped (said so on a line of its own) if absent.
//
// --impl runs the vectors against a CANDIDATE verifier instead (impl.go): each case is a bundle
// file, handed over as `<command> <case.json> --now <N>` — the interface of this command and of
// docs-test/TASK-verifier.md, graded by docs-test/grade-verifier.mjs's rules, adopted verbatim.
// Exit 0 + §9.1 JSON on stdout is an accept, exit 1 a reject, anything else a failure. One
// PASS/FAIL line per case, ALL PASS (exit 0) or FAILURES (exit 1). --impl-stdin passes "-" and
// the case bytes on stdin instead of a file; --impl-timeout is per case, seconds (default 10).
//
// --version prints the wire version and the build info embedded by the Go toolchain.
package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/csigelo/sigelo/go"
)

func main() {
	var path, monero, impl string
	conformance, implStdin, implTimeout := false, false, 10*time.Second
	now := time.Now().Unix()
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--version" && len(args) == 1:
			version()
			return
		case args[i] == "--conformance":
			conformance = true
		case args[i] == "--impl" && i+1 < len(args):
			impl, i = args[i+1], i+1
		case args[i] == "--impl-stdin":
			implStdin = true
		case args[i] == "--impl-timeout" && i+1 < len(args):
			s, err := strconv.ParseFloat(args[i+1], 64)
			if err != nil || s <= 0 {
				usage("--impl-timeout must be positive seconds")
			}
			implTimeout, i = time.Duration(s*float64(time.Second)), i+1
		case args[i] == "--monero" && i+1 < len(args):
			monero, i = args[i+1], i+1
		case args[i] == "--now" && i+1 < len(args):
			n, err := strconv.ParseInt(args[i+1], 10, 64)
			if err != nil || n < 0 {
				usage("--now must be non-negative integer Unix seconds")
			}
			now, i = n, i+1
		case path == "" && (args[i] == "-" || args[i] != "" && args[i][0] != '-'):
			path = args[i]
		default:
			usage("unexpected argument " + strconv.Quote(args[i]))
		}
	}
	if impl != "" || implStdin {
		if !conformance || impl == "" || monero != "" {
			usage("--impl '<command>' goes with --conformance, without --monero")
		}
		cmd, err := splitWords(impl)
		if err != nil {
			usage("--impl: " + err.Error())
		}
		if path == "" {
			path = "test-vectors.json"
		}
		os.Exit(runImpl(os.Stdout, path, implOpts{cmd: cmd, stdin: implStdin, timeout: implTimeout}))
	}
	if conformance {
		os.Exit(runConformance(path, monero))
	}
	if monero != "" {
		usage("--monero is only for --conformance")
	}
	if path == "" {
		usage("missing bundle file")
	}
	var text []byte
	var err error
	if path == "-" {
		text, err = io.ReadAll(os.Stdin)
	} else {
		text, err = os.ReadFile(path)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sigelo-verify:", err)
		os.Exit(2)
	}
	bundle, err := sigelo.Parse(text)
	if err != nil {
		reject("parse: " + err.Error())
	}
	res, err := sigelo.Verify(bundle, now, nil)
	if err != nil {
		reject(err.Error())
	}
	out, err := res.MarshalJSON()
	if err != nil { // cannot happen: every accepted body passed Canonicalize
		reject("result: " + err.Error())
	}
	fmt.Println(string(out))
}

// runConformance is `--conformance`: exit 0 on ALL PASS, 1 on any FAIL, 2 if a file is unreadable.
func runConformance(path, monero string) int {
	if path == "" {
		path = "test-vectors.json"
	}
	if path == "-" {
		usage("--conformance needs a file, not stdin")
	}
	vectors, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sigelo-verify:", err)
		return 2
	}
	explicit := monero != ""
	if !explicit {
		monero = filepath.Join(filepath.Dir(path), "ts", "test", "monero-vectors.json")
	}
	mv, err := os.ReadFile(monero)
	if err != nil && (explicit || !errors.Is(err, fs.ErrNotExist)) {
		fmt.Fprintln(os.Stderr, "sigelo-verify:", err)
		return 2
	}
	rep := sigelo.Conformance(os.Stdout, vectors, mv) // mv nil: the Monero section is SKIPped
	fmt.Printf("\n%d passed, %d failed\n", rep.Passed, rep.Failed)
	if rep.OK() {
		fmt.Println("ALL PASS")
		return 0
	}
	fmt.Println("FAILURES")
	return 1
}

func version() {
	fmt.Println("sigelo-verify, wire " + sigelo.Version + " (SPEC v0.1)")
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		fmt.Println("build info: unavailable")
		return
	}
	fmt.Println(bi.GoVersion + " " + setting(bi, "GOOS") + "/" + setting(bi, "GOARCH"))
	if rev := setting(bi, "vcs.revision"); rev != "" {
		dirty := ""
		if setting(bi, "vcs.modified") == "true" {
			dirty = " +uncommitted changes"
		}
		fmt.Println("commit " + rev + " " + setting(bi, "vcs.time") + dirty)
	} else {
		fmt.Println("commit: unknown (built without VCS info)")
	}
	for _, d := range bi.Deps {
		fmt.Println("dep " + d.Path + " " + d.Version + " " + d.Sum)
	}
}

func setting(bi *debug.BuildInfo, key string) string {
	for _, s := range bi.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}

func reject(msg string) {
	fmt.Fprintln(os.Stderr, "REJECT: "+msg)
	os.Exit(1)
}

func usage(msg string) {
	fmt.Fprintf(os.Stderr, "sigelo-verify: %s\nusage: sigelo-verify <bundle.json|-> [--now N]\n"+
		"       sigelo-verify --conformance [test-vectors.json] [--monero monero-vectors.json]\n"+
		"       sigelo-verify --conformance [test-vectors.json] --impl '<command>' [--impl-stdin] [--impl-timeout S]\n"+
		"       sigelo-verify --version\n", msg)
	os.Exit(2)
}
