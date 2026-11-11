// SPDX-License-Identifier: MIT
// The Node.js this CLI needs (package.json engines), checked before anything else loads: npm only
// warns about engines, and on an older Node the CLI ran until some later call failed obscurely.
// cli.ts imports this first, so it runs before the other modules do.
export const NEED = [22, 18] as const;
/** True when `v` ("24.18.1", process.versions.node) is older than NEED. */
export function tooOld(v: string): boolean {
  const [major = 0, minor = 0] = v.split('.').map(Number);
  return major < NEED[0] || (major === NEED[0] && minor < NEED[1]);
}
if (tooOld(process.versions.node)) {
  console.error(`sigelo-agent: Node.js ${process.versions.node} is too old: it needs ${NEED.join('.')} or newer (tested on 24)`);
  process.exit(1);
}
