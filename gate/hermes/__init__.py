# SPDX-License-Identifier: MIT
# sigelo provenance gate for Hermes Agent (prototype). A standalone plugin, three hooks:
#   pre_gateway_dispatch   an inbound message on a gated platform (A2A by default) is rewritten: a verified
#                          sigelo/instruction from a pinned operator DID is labelled and opens a grant for
#                          that chat; anything else is fenced as DATA and closes it.
#   pre_tool_call          a privileged tool in a gated chat without an open grant is blocked.
#   transform_tool_result  A2A client tool results (a peer's reply) are fenced as DATA unless verified;
#                          a tool result never opens a grant.
# Hermes catches plugin exceptions and falls through (fail open), so every hook catches its own and
# fails closed. Config: $SIGELO_GATE_CONFIG, the same gate.json as the Claude Code hook.
import logging, time
from .core import fence, gate, load_config

log = logging.getLogger(__name__)
_STATE = {'cfg': None, 'store': None, 'grants': {}, 'nonces': {}}  # one gateway process


def _cfg():
    if _STATE['cfg'] is None: _STATE['cfg'] = load_config()
    return _STATE['cfg']


def _key(src):
    return (str(getattr(src.platform, 'value', src.platform)), str(src.chat_id))


def on_dispatch(event, gateway=None, session_store=None, **_):
    k = None
    try:
        if session_store is not None: _STATE['store'] = session_store
        k = _key(event.source)
        if k[0] not in _cfg()['platforms'] or getattr(event, 'internal', False): return None
        kind, text, body = gate(event.text, k[0] + ':' + str(event.source.user_id), _cfg(), nonces=_STATE['nonces'])
        if kind == 'instruction': _STATE['grants'][k] = (body['exp'], body['claims'].get('tools'))
        else: _STATE['grants'].pop(k, None)
        return {'action': 'rewrite', 'text': text}
    except Exception as e:
        log.warning('sigelo-gate: dispatch failed closed: %s', e)
        if k: _STATE['grants'].pop(k, None)
        return {'action': 'rewrite', 'text': fence(getattr(event, 'text', ''), 'unknown', 'gate error')}


def on_pre_tool_call(tool_name='', session_id='', **_):
    try:
        if tool_name not in _cfg()['privileged']: return None
        store = _STATE['store']
        entry = store.lookup_by_session_id(session_id) if store is not None and session_id else None
        src = getattr(entry, 'origin', None)
        if src is None: return None  # not a gateway session (CLI, cron): Hermes' own approvals govern it
        k = _key(src)
        if k[0] not in _cfg()['platforms']: return None
        exp, tools = _STATE['grants'].get(k, (0, None))
        if exp > time.time() and (tools is None or tool_name in tools): return None
        why = 'no verified instruction from an allowed DID in this conversation'
    except Exception as e:
        why = f'gate error, failing closed: {e}'
    return {'action': 'block', 'message': f'sigelo-gate: {tool_name} blocked ({why}). Only the operator can authorise it, by signing the request.'}


def on_transform_tool_result(tool_name='', result=None, **_):
    try:
        if tool_name not in _cfg()['data_tools'] or not isinstance(result, str): return None
        return gate(result, 'tool:' + tool_name, _cfg(), nonces=_STATE['nonces'])[1]  # a label only, never a grant
    except Exception:
        return fence(str(result), 'tool:' + tool_name, 'gate error')


def register(ctx):
    ctx.register_hook('pre_gateway_dispatch', on_dispatch)
    ctx.register_hook('pre_tool_call', on_pre_tool_call)
    ctx.register_hook('transform_tool_result', on_transform_tool_result)
