#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Runs fixtures/pairing-v0.json through the Python acceptor (accept/python/sigelo_pair.py), re-opening
# each JSON contacts store from disk at every step. Needs `cryptography` and a sigelo-verify binary:
# $SIGELO_VERIFY, else one on PATH, else it is built from go/ into a temporary directory.
#   python3 adapters/hermes/pairing/test.py
import json, os, shutil, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__)); REPO = os.path.normpath(os.path.join(HERE, '..', '..', '..'))
sys.path.insert(0, os.path.join(REPO, 'accept', 'python'))
tmp = tempfile.mkdtemp(prefix='sigelo-pairing-')
if not os.environ.get('SIGELO_VERIFY') and not shutil.which('sigelo-verify'):
    subprocess.run(['go', 'build', '-o', os.path.join(tmp, 'sigelo-verify'), './cmd/sigelo-verify'], cwd=os.path.join(REPO, 'go'), check=True)
    os.environ['SIGELO_VERIFY'] = os.path.join(tmp, 'sigelo-verify')
if os.environ.get('SIGELO_VERIFY', '').startswith('https://'): sys.exit('FAIL the fixture run is offline: point SIGELO_VERIFY at a binary')
from sigelo_pair import Contacts, PairingError, pair

fx = json.load(open(os.path.join(HERE, 'fixtures', 'pairing-v0.json'), encoding='utf-8'))
fails = 0
def ok(cond, what, extra=''):
    global fails; fails += not cond
    print(('ok   ' if cond else 'FAIL ') + what + ('' if cond else '  ' + str(extra)[:300]))
pick = lambda c: c and {k: c[k] for k in ('name', 'did', 'current_did', 'current_key', 'revoked')}

ok(fx['v'] == 'sigelo-a2a-pairing/0', f"fixture version {fx['v']}")
for s in fx['steps']:
    store, what = Contacts(os.path.join(tmp, s['store'] + '.json')), f"{s['case']} [{s['store']} {s['op']}]"
    if s['op'] == 'issue': ok(store.issue(s['did'], s['ctx'], s['now'], s['contact_name'], s['expect']['nonce']) == s['expect'], what)
    elif s['op'] == 'lookup': ok(pick(store.lookup(s['did'])) == s['expect'], what, pick(store.lookup(s['did'])))
    elif s['op'] == 'revoke': ok(pick(store.revoke(s['did'])) == s['expect'], what)
    else:
        try: got, err = pair(fx['cards'][s['card']], s['answer'], store, s['now']), None
        except PairingError as e: got, err = None, e
        if 'error' in s: ok(err is not None and err.check == s['error'], f"{what} -> rejected: {s['error']}", err or 'accepted')
        else: ok(err is None and got == s['expect'], f"{what} -> {s['expect']['current_did'][:20]}... accepted", err or json.dumps(got))
shutil.rmtree(tmp, ignore_errors=True)
print('ALL PASS' if not fails else f'FAILURES: {fails}'); sys.exit(1 if fails else 0)
