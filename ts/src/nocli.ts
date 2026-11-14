#!/usr/bin/env node
// SPDX-License-Identifier: MIT
/**
 * `sigelo` — the bare package's name as a command, so that `npm i -g sigelo` or `npx sigelo`
 * (the package-name trap: agents took the library for the CLI) says where the CLI is and
 * fails, rather than leaving `sigelo-offline` to be taken for it. No dependency, no argument.
 */
const NO_CLI = 'the CLI is the npm package sigelo-agent; the MCP server is sigelo-mcp; the package sigelo is the library and has no CLI.';

console.error(NO_CLI);
process.exit(2);
