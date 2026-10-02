#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Runs the REAL Hermes Agent (`hermes -z`, unmodified) with adapters/hermes/config.yaml against
# sigelo's MCP server. No model key exists here, so the LLM is a scripted OpenAI-compatible
# endpoint below: it emits exactly the tool calls the prompt spells out (`CALL <tool> <json>`),
# so everything between "model chose a tool" and "result back in the model's context" is
# Hermes' own code (config load, ${VAR} interpolation, MCP client, tool registry, agent loop).
# The world is examples/world.mjs, the keeper a loopback mock, and the bundle is re-verified by
# the Go reference verifier. Usage: HERMES="hermes" python3 adapters/hermes/test.py
import json, os, re, shlex, shutil, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HERMES = shlex.split(os.environ.get("HERMES", "hermes"))
if not shutil.which(HERMES[0]):
    print(f"SKIP hermes test: {HERMES[0]} not found (set HERMES to the hermes command)"); sys.exit(0)
fails = 0
def ok(cond, what, extra=""):
    global fails; fails += not cond
    print(("ok   " if cond else "FAIL ") + what + ("" if cond else f"  {extra}"[:400]))

def serve(handler):
    s = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s.server_address[1]

def unwrap(content):  # Hermes fences MCP results as <untrusted_tool_result>; the JSON is inside
    m = re.search(r"\n\n(\{.*\})\n</untrusted_tool_result>", content, re.S)
    d = json.loads(m.group(1) if m else content)
    if "result" not in d: return d
    try: return json.loads(d["result"])
    except ValueError: return d["result"]

OFFERED, FENCED = set(), []
class LLM(BaseHTTPRequestHandler):  # the scripted model
    def log_message(self, *a): pass
    def reply(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self): self.reply({"object": "list", "data": [{"id": "scripted", "object": "model"}]})
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        tools = [t["function"]["name"] for t in req.get("tools") or []]
        OFFERED.update(tools); msgs = req.get("messages") or [{"role": "user", "content": ""}]  # aux calls too
        u = max((i for i, m in enumerate(msgs) if m["role"] == "user"), default=0)
        calls = re.findall(r"CALL (\S+) (\{.*?\})(?=\nCALL |\Z)", msgs[u]["content"], re.S) if tools else []
        done = [unwrap(m["content"]) for m in msgs[u:] if m["role"] == "tool"]
        ids = {c["id"]: c["function"]["name"] for m in msgs if m.get("tool_calls") for c in m["tool_calls"]}
        FENCED.extend("<untrusted_tool_result" in m["content"] for m in msgs[u:] if m["role"] == "tool" and "sigelo" in ids.get(m.get("tool_call_id"), ""))
        msg = {"role": "assistant", "content": "RESULTS " + json.dumps(done)}
        if len(done) < len(calls):
            name, args = calls[len(done)]
            name = next((t for t in tools if t.endswith("__" + name)), name)
            msg = {"role": "assistant", "content": None, "tool_calls": [{"id": f"c{u}_{len(done)}",
                   "type": "function", "function": {"name": name, "arguments": args}}]}
        fin = "tool_calls" if msg.get("tool_calls") else "stop"
        if req.get("stream"):
            self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
            if fin == "tool_calls": msg["tool_calls"][0]["index"] = 0
            for c in ({"delta": msg, "finish_reason": None}, {"delta": {}, "finish_reason": fin}):
                self.wfile.write(b"data: " + json.dumps({"object": "chat.completion.chunk", "model": "scripted", "choices": [dict(c, index=0)]}).encode() + b"\n\n")
            self.wfile.write(b"data: [DONE]\n\n"); return
        self.reply({"id": "x", "object": "chat.completion", "created": 0, "model": "scripted",
                    "choices": [{"index": 0, "message": msg, "finish_reason": fin}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

TOKEN, PAID = "test-token", []
class Keeper(BaseHTTPRequestHandler):  # MONERO.md §4.2 surface, canned answers
    def log_message(self, *a): pass
    def do_GET(self): self.do_POST()
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        r = {"/balance": {"balance": "1500000000000", "unlocked_balance": "1500000000000", "remaining": "1000000000000", "per_tx_max": "500000000000", "period_seconds": 86400},
             "/receive": {"address": "8" + "A" * 94}, "/pay": {"txid": "ab" * 32, "fee": "30000000"},
             "/history": {"entries": [{"dir": "out", "ts": 1758700000, "amount": "50000000000", "label": "alice", "purpose": "test", "status": "relayed"}]}}.get(self.path.split("?")[0])
        if self.path == "/pay": PAID.append(json.loads(body))
        code = 401 if self.headers.get("Authorization") != f"Bearer {TOKEN}" else 200 if r else 404
        b = json.dumps(r if code == 200 else {"error": "no", "code": "token"}).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b)

tmp = tempfile.mkdtemp(prefix="sigelo-hermes-")
home = os.environ.get("HERMES_TEST_HOME") or os.path.join(tmp, "hermes-home")  # reuse one to skip Hermes' first-run setup
os.makedirs(home, exist_ok=True); os.makedirs(os.path.join(tmp, ".hermes"))
cfg = open(os.path.join(os.path.dirname(__file__), "config.yaml")).read()
cfg = re.sub(r"# (SIGELO_WALLET_\w+:) .*", lambda m: m.group(1) + ' "${' + m.group(1)[:-1] + '}"', cfg)  # uncomment the wallet lines
cfg += f"model:\n  provider: custom\n  base_url: http://127.0.0.1:{serve(LLM)}/v1\n  default: scripted\n"
open(os.path.join(home, "config.yaml"), "w").write(cfg)
env = dict(os.environ, HERMES_HOME=home, HOME=tmp, SIGELO_HOME=REPO, OPENAI_API_KEY="unused",
           SIGELO_WALLET_URL=f"http://127.0.0.1:{serve(Keeper)}", SIGELO_WALLET_TOKEN=TOKEN)

def turn(*calls):  # one `hermes -z` process per turn: identity must persist across processes
    prompt = "\n".join(f"CALL {n} {json.dumps(a)}" for n, a in calls)
    p = subprocess.run(HERMES + ["-z", prompt], env=env, cwd=tmp, capture_output=True, text=True, timeout=600)
    m = re.search(r"RESULTS (\[.*\])", p.stdout, re.S)
    if not m: print(p.stdout[-2000:], p.stderr[-2000:]); sys.exit("FAIL hermes produced no tool results")
    return json.loads(m.group(1))

def world(*args):
    p = subprocess.run(["node", os.path.join(REPO, "examples", "world.mjs"), *args], cwd=tmp, capture_output=True, text=True)
    return json.loads(p.stdout)

init, skills = turn(("sigelo_init", {"recovery": "none"}), ("skills_list", {}))
ok(isinstance(init, dict) and init.get("did", "").startswith("did:sigelo:"), "sigelo_init through Hermes", init)
ok(init.get("identity_file") == os.path.join(tmp, ".hermes", "sigelo.local.json"), "identity at ${userHome}/.hermes (interpolated)", init.get("identity_file"))
ok(any(k.get("name") == "sigelo" for k in skills.get("skills", [])) if isinstance(skills, dict) else False, "the sigelo skill loads from skills.external_dirs", str(skills)[:300])
ok({f"mcp__sigelo__sigelo_{t}" for t in "whoami init sign_challenge add_issuer add_attestation bundle verify rotate wallet_balance wallet_receive wallet_pay wallet_history".split()} <= OFFERED,
   "all 12 sigelo tools offered to the model", sorted(t for t in OFFERED if "sigelo" in t))
gen = os.path.join(tmp, "genesis.json"); json.dump(init["genesis"], open(gen, "w"))
ch = world("challenge", gen)
(signed,) = turn(("sigelo_sign_challenge", {"challenge": ch}))
ok(signed.get("did") == init["did"], "sign_challenge in a new Hermes process: same identity", signed)
att = world("attest", gen, signed["sig"])
added, bundled = turn(("sigelo_add_attestation", {"attestation": att["attestation"], "issuer": att["issuer"]}), ("sigelo_bundle", {}))
ok(added.get("attestations") == 1, "add_attestation", added)
bundle = os.path.join(tmp, "bundle.json"); json.dump(bundled["bundle"], open(bundle, "w"))
gobin = os.path.join(REPO, "go", "sigelo-verify")
cmd = [gobin, bundle] if os.path.exists(gobin) else ["go", "run", "./cmd/sigelo-verify", bundle]
g = subprocess.run(cmd, cwd=os.path.join(REPO, "go"), capture_output=True, text=True)
v = json.loads(g.stdout) if g.returncode == 0 else {}
ok(v.get("did") == init["did"] and len(next(iter(v.get("attestations", {}).values()), [])) == 1, "Go sigelo-verify ACCEPTs the bundle Hermes emitted, 1 attestation", g.stderr)
bal, rcv, pay, hist = turn(("sigelo_wallet_balance", {}), ("sigelo_wallet_receive", {"note": "from bob"}),
                          ("sigelo_wallet_pay", {"to": "alice", "amount": "0.05", "purpose": "test payment"}), ("sigelo_wallet_history", {"n": 5}))
ok(str(bal).startswith("BALANCE 1.5 XMR"), "wallet_balance", bal)
ok(str(rcv).startswith("RECEIVE 8A"), "wallet_receive", rcv)
ok(str(pay).startswith("PAID 0.05 XMR") and len(PAID) == 1, "wallet_pay reached the keeper once", pay)
ok("paid 0.05 XMR to alice" in str(hist), "wallet_history", hist)
ok(FENCED and all(FENCED), "Hermes fenced every sigelo result as untrusted data before the model saw it")
shutil.rmtree(tmp, ignore_errors=True)
print("ALL PASS" if not fails else f"{fails} FAILURE(S)"); sys.exit(1 if fails else 0)
