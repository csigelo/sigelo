# SPDX-License-Identifier: MIT
# sigelo provenance gate for Hermes Agent (prototype). A standalone plugin, three hooks:
#   pre_gateway_dispatch   an inbound message on a gated platform (A2A by default) is rewritten: a verified
#                          sigelo/instruction from a pinned operator DID is labelled and opens a grant for
#                          that chat; anything else is fenced as DATA and closes it.
#   pre_tool_call          a privileged tool in a gated chat without an open, untainted grant is blocked.
#                          Any other tool except hermes_taint_exempt taints the grant BEFORE it runs:
#                          after it, privileged tools need taint_ok in the signed claims (DESIGN §6).
#   transform_tool_result  A2A client tool results (a peer's reply) are fenced as DATA unless verified;
#                          a tool result never opens a grant. It records the taint again, as a backstop:
#                          Hermes runs this hook fail-open, pre_tool_call fail-closed, so the latter decides.
# Hermes catches plugin exceptions and falls through (fail open), so every hook catches its own and
# fails closed. Config: $SIGELO_GATE_CONFIG, the same gate.json as the Claude Code hook.
import logging, time
from .core import fence, gate, load_config, privileged

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
        if kind == 'instruction':
            c = body['claims']
            _STATE['grants'][k] = {'exp': body['exp'], 'tools': c.get('tools'), 'taint_ok': c.get('taint_ok'), 'tainted': None}
        else: _STATE['grants'].pop(k, None)
        return {'action': 'rewrite', 'text': text}
    except Exception as e:
        log.warning('sigelo-gate: dispatch failed closed: %s', e)
        if k: _STATE['grants'].pop(k, None)
        return {'action': 'rewrite', 'text': fence(getattr(event, 'text', ''), 'unknown', 'gate error')}


def _gated_key(session_id):
    """The (platform, chat) of a gated gateway session, or None (CLI, cron, ungated platform)."""
    store = _STATE['store']
    entry = store.lookup_by_session_id(session_id) if store is not None and session_id else None
    src = getattr(entry, 'origin', None)
    if src is None: return None  # not a gateway session: Hermes' own approvals govern it
    k = _key(src)
    return k if k[0] in _cfg()['platforms'] else None


def _taint(k, tool_name):
    g = _STATE['grants'].get(k)
    if g and g['exp'] > time.time() and not g['tainted']: g['tainted'] = tool_name


def on_pre_tool_call(tool_name='', session_id='', **_):
    try:
        cfg = _cfg()
        priv = privileged(cfg, tool_name)
        if not priv and tool_name in cfg['taint_exempt']: return None
        k = _gated_key(session_id)
        if k is None: return None
        g = _STATE['grants'].get(k)
        if priv:
            ok = g and (g['taint_ok'] is True or (isinstance(g['taint_ok'], list) and tool_name in g['taint_ok']))
            why = ('no verified instruction from an allowed DID in this conversation' if not g or g['exp'] <= time.time()
                   else f"the signed instruction does not cover {tool_name}" if g['tools'] is not None and tool_name not in g['tools']
                   else f"untrusted content ({g['tainted']}) was read after the signed instruction, which did not allow it (taint_ok)" if g['tainted'] and not ok
                   else None)
            if why: raise PermissionError(why)
        if tool_name not in cfg['taint_exempt']: _taint(k, tool_name)  # before its result exists
        return None
    except PermissionError as e:
        why = str(e)
    except Exception as e:
        why = f'gate error, failing closed: {e}'
    return {'action': 'block', 'message': f'sigelo-gate: {tool_name} blocked ({why}). Only the operator can authorise it, by signing the request.'}


def on_transform_tool_result(tool_name='', result=None, session_id='', **_):
    try:
        if tool_name not in _cfg()['taint_exempt']:
            k = _gated_key(session_id)
            if k is not None: _taint(k, tool_name)
        if tool_name not in _cfg()['data_tools'] or not isinstance(result, str): return None
        return gate(result, 'tool:' + tool_name, _cfg(), nonces=_STATE['nonces'])[1]  # a label only, never a grant
    except Exception:
        return fence(str(result), 'tool:' + tool_name, 'gate error')


def register(ctx):
    ctx.register_hook('pre_gateway_dispatch', on_dispatch)
    ctx.register_hook('pre_tool_call', on_pre_tool_call)
    ctx.register_hook('transform_tool_result', on_transform_tool_result)
