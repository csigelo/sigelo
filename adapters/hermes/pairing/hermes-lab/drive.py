# SPDX-License-Identifier: MIT
"""Initiator side, run in an instance's env: pair with a configured a2a_agents peer through Hermes'
own outbound client (plugins/platforms/a2a/tools.py a2a_call), no model.
  drive.py pair <peer>      ask <peer> for a challenge, check its ctx, sign, answer
  drive.py revoke <did>     owner revokes a contact in this instance's store
  drive.py lookup <did>"""
import json, os, shlex, subprocess, sys
sys.path.insert(0, os.environ["HERMES_SRC"]); sys.path.insert(0, os.path.join(os.environ["SIGELO_HOME"], "accept", "python"))
from sigelo_pair import EXT, Contacts
op, arg = sys.argv[1], sys.argv[2]
store_path = os.path.join(os.environ["HERMES_HOME"], "contacts.json")
pick = lambda c: c and {k: c[k] for k in ("name", "did", "current_did", "revoked")}
if op == "lookup": print(json.dumps(pick(Contacts(store_path).lookup(arg)))); sys.exit()
if op == "revoke": print(json.dumps(pick(Contacts(store_path).revoke(arg)))); sys.exit()
import importlib; tools = importlib.import_module("plugins.platforms.a2a.tools")
agent = lambda *a, stdin=None: subprocess.run(shlex.split(os.environ["SIGELO_AGENT"]) + list(a), input=stdin, capture_output=True, text=True, check=True).stdout
def call(msg):
    out = tools.a2a_call({"agent": arg, "message": json.dumps(msg)})
    i = out.find('{"sigelo_pair"')
    if i < 0: sys.exit("no sigelo_pair reply: " + out[:600])
    return json.JSONDecoder().raw_decode(out[i:])[0]
me = json.loads(agent("whoami"))["did"]
peer = tools._resolve_peer(arg); card = tools._fetch_card(peer["url"], {}, 10)
peer_did = next(x["params"]["did"] for x in card["capabilities"]["extensions"] if x["uri"] == EXT)
r = call({"sigelo_pair": "challenge", "did": os.environ.get("CLAIM_DID", me)})
c = r["challenge"]
if c["ctx"] != "hermes-contacts:" + peer_did: sys.exit(f"refusing to sign: {c}")
sig = json.loads(agent("sign-challenge", "-", stdin=json.dumps(c)))
sig = sig.get("sig", sig) if isinstance(sig, dict) else sig
ans = {"sigelo_pair": "answer", "body": c, "sig": sig}
print(json.dumps(call(ans)))
if os.environ.get("REPLAY"): print("replay:", json.dumps(call(ans)))
