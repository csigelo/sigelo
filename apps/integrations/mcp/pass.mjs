// SPDX-License-Identifier: MIT
// sigelo_pass: `sigelo-agent pass` as an MCP tool (apps/agent/sigelo-agent-pass.ts, accept/pass).
// Apart from server.mjs because it is the one identity tool that goes on the network: the plugin
// build (apps/plugins/build.mjs) answers null here, as it does for contact.mjs.
export async function load({ installed, loadStore }) {
  const p = await import(installed ? 'sigelo-agent/dist/sigelo-agent-pass.js' : '../../agent/sigelo-agent-pass.ts');
  return {
    tools: [['sigelo_pass', 'Through a website\'s agent door (sigelo-pass): when a page answers 403 or a captcha with a Sigelo-Pass hint, this proves your DID to that site and returns its clearance cookie {name, value, exp, path} and header "name=value"; load the page with it. Only where the site installed the door; never solves a captcha. Refusals name what the site wants (wants_age, wants_operator) or why (no_hint, pass_ctx, rate_limited).',
      { type: 'object', properties: { url: { type: 'string', description: 'the page you were refused, https://…' }, fresh: { type: 'boolean', description: 'a new pass even if a kept cookie still works' },
        identity: { type: 'string', description: 'optional profile name [a-z0-9_-], e.g. your subagent name; omit for the default identity' } }, required: ['url'], additionalProperties: false }]],
    handlers: { sigelo_pass: ({ url, fresh }, path) => p.pass(path, loadStore(path), String(url ?? ''), { fresh: fresh === true }) },
  };
}
