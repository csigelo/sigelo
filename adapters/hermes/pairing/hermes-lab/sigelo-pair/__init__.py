# SPDX-License-Identifier: MIT
"""Lab plugin: sigelo-a2a-pairing/0 inside Hermes, standalone (no core edit).
Env: SIGELO_HOME (repo subtree), SIGELO_AGENT (cmd to sigelo-agent), SIGELO_IDENTITY, SIGELO_VERIFY.
Files in HERMES_HOME: contacts.json (store), sigelo-expect.json {did: name} (owner-confirmed DIDs)."""
import json, logging, os, shlex, subprocess, sys, time, urllib.request
log = logging.getLogger("sigelo-pair")
sys.path.insert(0, os.path.join(os.environ["SIGELO_HOME"], "accept", "python"))
from sigelo_pair import EXT, Contacts, PairingError, pair  # noqa: E402

def home(): return os.environ["HERMES_HOME"]
def agent(*args, stdin=None):
    p = subprocess.run(shlex.split(os.environ["SIGELO_AGENT"]) + list(args), input=stdin, capture_output=True, text=True, timeout=20)
    if p.returncode: raise RuntimeError(p.stderr.strip() or p.stdout.strip())
    return p.stdout
_cache = {}
def my_bundle():
    st = os.stat(os.environ["SIGELO_IDENTITY"]).st_mtime_ns
    if _cache.get("st") != st: _cache.update(st=st, b=json.loads(agent("bundle")), w=json.loads(agent("whoami")))
    return _cache["w"]["did"], _cache["b"]

def card_extension():
    did, bundle = my_bundle()
    return {"uri": EXT, "description": "sigelo identity: the pairing binds to params.did, verified offline from params.bundle",
            "required": False, "params": {"did": did, "bundle": bundle}}

def patch_card():
    """SEAM: Hermes has no card hook; wrap protocol.build_agent_card wherever the a2a plugin lives."""
    n = 0
    for name, mod in list(sys.modules.items()):
        f = getattr(mod, "build_agent_card", None)
        if name.endswith(".protocol") and callable(f) and not getattr(f, "_sigelo", False):
            def wrapped(*a, _f=f, **k):
                card = _f(*a, **k)
                try: card["capabilities"].setdefault("extensions", []).append(card_extension())
                except Exception: log.exception("sigelo-pair: no extension on card")
                return card
            wrapped._sigelo = True; mod.build_agent_card = wrapped; n += 1
            log.warning("sigelo-pair: card patched in %s", name)
    return n

def peer_url(peer):  # the token-authenticated peer name -> its configured URL (a2a_agents)
    from hermes_cli.config import load_config_readonly
    e = ((load_config_readonly() or {}).get("a2a_agents") or {}).get(peer) or {}
    return e.get("url")

def fetch_card(url):
    with urllib.request.urlopen(url.rstrip("/") + "/.well-known/agent-card.json", timeout=10) as r: return json.load(r)

_store = []
def get_store():  # SIGELO_PAIR_LONGLIVED=1: one store for the process, as the README's plugin snippet does
    if os.environ.get("SIGELO_PAIR_LONGLIVED"):
        if not _store: _store.append(Contacts(os.path.join(home(), "contacts.json")))
        return _store[0]
    return Contacts(os.path.join(home(), "contacts.json"))

def handle(msg, peer):
    store, now = get_store(), int(time.time())
    if msg.get("sigelo_pair") == "challenge":
        expect = json.load(open(os.path.join(home(), "sigelo-expect.json"))) if os.path.exists(os.path.join(home(), "sigelo-expect.json")) else {}
        my_did, _ = my_bundle()
        c = store.issue(msg["did"], "hermes-contacts:" + my_did, now, expect.get(msg["did"]))
        return {"sigelo_pair": "challenge", "challenge": c}
    if msg.get("sigelo_pair") == "answer":
        url = peer_url(peer)
        if not url: return {"sigelo_pair": "refused", "check": "card", "why": f"no a2a_agents url for peer {peer!r}"}
        try: return {"sigelo_pair": "paired", "contact": pair(fetch_card(url), {"body": msg.get("body"), "sig": msg.get("sig")}, store, now)}
        except PairingError as e: return {"sigelo_pair": "refused", "check": e.check, "why": str(e)}
    return {"sigelo_pair": "refused", "check": "op", "why": "unknown op"}

def parse(text):  # the adapter framed it: PRIVACY_PREFIX + filtered text
    i = text.find('{"sigelo_pair"')
    if i < 0: return None
    try: return json.JSONDecoder().raw_decode(text[i:])[0]
    except ValueError: return None

async def pre_gateway_dispatch(event=None, gateway=None, **_):
    src = getattr(event, "source", None)
    if not src or getattr(src.platform, "value", "") != "a2a": return None
    msg = parse(event.text or "")
    if msg is None: return None
    patch_card()
    try: reply = handle(msg, src.user_id)
    except Exception as e: log.exception("sigelo-pair"); reply = {"sigelo_pair": "refused", "check": "internal", "why": str(e)}
    adapter = gateway._intake_adapter_for(src) or gateway.adapters.get(src.platform)
    await adapter.send(src.chat_id, json.dumps(reply), metadata={"notify": True})  # resolves the A2A task; no model ran
    return {"action": "skip", "reason": "sigelo-pair handled"}

def register(ctx):
    patch_card()
    ctx.register_hook("pre_gateway_dispatch", pre_gateway_dispatch)
    import threading  # the a2a plugin may load after us: retry the card patch briefly
    threading.Thread(target=lambda: [time.sleep(1) or patch_card() for _ in range(30)], daemon=True).start()
