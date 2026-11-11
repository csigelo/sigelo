// SPDX-License-Identifier: MIT
// Stand-in for 1F916's src/society.ts: the two names adapters/1f916/sigelo.ts imports from it.
// Only what the adapter touches; the real Citizen and Env carry more.
export class SocietyError extends Error {
  status: number;
  constructor(status: number, message: string) { super(message); this.status = status; this.name = "SocietyError"; }
}
export type Citizen = { id: number; handle: string; created_at: number; [k: string]: unknown };
export type Env = { REGISTRY_SEED?: string; OAUTH_KEY?: string; DB: any };
