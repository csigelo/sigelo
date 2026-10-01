#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// kit/drill/grade.mjs — the operator's own self-assessment of a completed drill, offline.
//
//   sigelo-kit-grade <drills dir>/<date>/TIMELINE.md [--json]
//
// Scores the timeline the template (drill/TIMELINE.template.md) lays out, 100 points:
//   steps     40  every step row (`0.1`, `2.2a`, …) has a UTC time; a step marked `N/A — why` counts
//   evidence  20  the Evidence table has rows, every row a valid sha256
//   sweeps    20  the Sweeps table has rows, every row a 64-hex txid (a tabletop drill moves no
//                 coins: not graded, its 20 points spread over the other parts)
//   findings  10  at least one post-mortem finding (a drill with none says why, as a bullet)
//   order     10  detect ≤ frozen ≤ last sweep, and steps 1.x–3.x never go backwards in time
// The step rows are whatever the timeline holds (the template lays out DRILL.md's numbered steps,
// 0.1–7.2, incl. 4.4 licence and 5.3 keeper DID since the T14 corrections); only 1.1, 2.4 and 3.4
// are read by number. Pass: 80 or more with no step missing its time. Also prints detect → frozen
// and detect → last sweep, the two numbers to beat next time (T14, the stagenet rehearsal: 15 min
// 26 s to the last sweep). Exit 0 on a pass, 1 on a fail, 2 on a file it cannot read as a timeline.
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const HEX64 = /^[0-9a-f]{64}$/i;
const cells = (l) => l.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim().replace(/^`|`$/g, ''));
const strip = (s) => s.replace(/<!--[\s\S]*?-->/g, '');

/** The rows of the first table under `## <name>` (header and separator dropped). */
function table(md, name) {
  const m = md.match(new RegExp(`^## ${name}\\s*$([\\s\\S]*?)(?=^## |(?![\\s\\S]))`, 'm'));
  if (!m) return undefined;
  const rows = m[1].split('\n').filter((l) => l.trim().startsWith('|')).map(cells);
  return rows.slice(2);
}
const secs = (t) => { const m = t.match(/\b(\d{2}):(\d{2})(?::(\d{2}))?\b/); return m ? +m[1] * 3600 + +m[2] * 60 + +(m[3] ?? 0) : undefined; };
const dur = (a, b) => { if (a === undefined || b === undefined) return undefined; let d = b - a; if (d < 0) d += 86400; return d; };
const fmt = (s) => (s === undefined ? 'n/a' : `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, '0')} s`);

export function grade(text) {
  const md = strip(text);
  const meta = Object.fromEntries((md.match(/^\| field \| value \|[\s\S]*?(?=\n\n)/m)?.[0] ?? '').split('\n').slice(2).map(cells).map(([k, v]) => [k, v ?? '']));
  const kind = (meta.kind ?? '').toLowerCase();
  const steps = table(md, 'Steps');
  if (!steps || steps.length === 0) throw new Error('no "## Steps" table — is this a kit TIMELINE.md?');
  const stepRows = steps.filter((r) => /^\d+\.\d+[a-z]?$/.test(r[0]));
  const timed = stepRows.map((r) => ({ id: r[0], what: r[1], t: secs(r[2] ?? ''), na: /^n\/a\b/i.test(r[4] ?? ''), evidence: r[3] ?? '', result: r[4] ?? '' }));
  const missing = timed.filter((s) => s.t === undefined).map((s) => s.id);
  const evidence = table(md, 'Evidence') ?? [];
  const evRows = evidence.filter((r) => r.some((c) => c !== ''));
  const badEv = evRows.filter((r) => !HEX64.test(r[1] ?? '')).map((r) => r[0] || '(unnamed)');
  const sweeps = (table(md, 'Sweeps') ?? []).filter((r) => r.some((c) => c !== ''));
  const badTx = sweeps.filter((r) => !HEX64.test(r[1] ?? '')).map((r) => `account ${r[0] || '?'}`);
  const findingsSec = md.match(/^## Findings\s*$([\s\S]*?)(?=^## |(?![\s\S]))/m)?.[1] ?? '';
  const findings = findingsSec.split('\n').filter((l) => /^\s*[-*]\s+\S/.test(l));
  const at = (id) => timed.find((s) => s.id === id)?.t;
  const detect = at('1.1'), frozen = at('2.4'), last = at('3.4');
  let backwards = 0;
  // Only the time-critical run, detect → freeze → sweep, must be in order; later steps overlap in
  // practice (T14 wrote steps 5–6 on paper while waiting for the sweeps to unlock).
  const seq = timed.filter((s) => s.t !== undefined && /^[123]\./.test(s.id));
  for (let i = 1; i < seq.length; i++) if (dur(seq[i - 1].t, seq[i].t) > 12 * 3600) backwards++; // wrapped by more than half a day = went backwards

  const tabletop = kind === 'tabletop';
  const w = tabletop ? { steps: 50, evidence: 25, sweeps: 0, findings: 12.5, order: 12.5 } : { steps: 40, evidence: 20, sweeps: 20, findings: 10, order: 10 };
  const parts = {
    steps: { score: w.steps * (timed.length - missing.length) / Math.max(timed.length, 1), of: w.steps,
      note: missing.length ? `no time: ${missing.join(', ')}` : `${timed.length} steps timed (${timed.filter((s) => s.na).length} N/A)` },
    evidence: { score: evRows.length && !badEv.length ? w.evidence : evRows.length ? w.evidence * (evRows.length - badEv.length) / evRows.length : 0, of: w.evidence,
      note: !evRows.length ? 'no evidence rows' : badEv.length ? `not a sha256: ${badEv.join(', ')}` : `${evRows.length} file(s) hashed` },
    sweeps: tabletop ? { score: 0, of: 0, note: 'tabletop: no coins move, not graded' }
      : { score: sweeps.length && !badTx.length ? w.sweeps : sweeps.length ? w.sweeps * (sweeps.length - badTx.length) / sweeps.length : 0, of: w.sweeps,
        note: !sweeps.length ? 'no sweep txids' : badTx.length ? `not a txid: ${badTx.join(', ')}` : `${sweeps.length} sweep txid(s)` },
    findings: { score: findings.length ? w.findings : 0, of: w.findings, note: findings.length ? `${findings.length} finding(s)` : 'no findings: zero findings is itself a finding — say why' },
    order: { score: detect !== undefined && frozen !== undefined && (tabletop || last !== undefined) && !backwards && dur(detect, frozen) <= dur(detect, last ?? frozen) ? w.order : 0, of: w.order,
      note: backwards ? `${backwards} step time(s) go backwards` : detect === undefined || frozen === undefined ? 'detect (1.1) or frozen (2.4) has no time' : 'detect ≤ frozen ≤ last sweep' },
  };
  const score = Math.round(Object.values(parts).reduce((a, p) => a + p.score, 0));
  return { kind: kind || 'unknown', score, pass: score >= 80 && missing.length === 0, parts,
    detect_to_frozen: fmt(dur(detect, frozen)), detect_to_last_sweep: tabletop ? 'n/a (tabletop)' : fmt(dur(detect, last)), findings: findings.length };
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const f = process.argv.slice(2).find((x) => !x.startsWith('--'));
  if (!f) { console.error('usage: sigelo-kit-grade <TIMELINE.md> [--json]'); process.exit(2); }
  let g;
  try { g = grade(readFileSync(f, 'utf8')); } catch (e) { console.error(`grade: ${e.message}`); process.exit(2); }
  if (process.argv.includes('--json')) console.log(JSON.stringify(g, null, 2));
  else {
    console.log(`drill (${g.kind}): ${g.score}/100 — ${g.pass ? 'PASS' : 'FAIL'}`);
    for (const [k, p] of Object.entries(g.parts)) console.log(`  ${k.padEnd(9)} ${String(Math.round(p.score)).padStart(3)}/${p.of}  ${p.note}`);
    console.log(`  detect → frozen      ${g.detect_to_frozen}\n  detect → last sweep  ${g.detect_to_last_sweep}`);
  }
  process.exit(g.pass ? 0 : 1);
}
