#!/usr/bin/env node
'use strict';
/**
 * aggregate.js — roll up many execution-log.json files into dataset-level
 * metrics and a "what was stolen" breakdown.
 *
 * Usage:
 *   node aggregate.js <results-dir> [--label 0|1]
 *     <results-dir>  directory containing *.json sandbox reports (searched recursively)
 *     --label        ground-truth label for ALL samples in this dir (1=malicious, 0=benign)
 *
 * Verdict rule (tunable): a sample is flagged MALICIOUS if critical_events > 0.
 */
const fs   = require('fs');
const path = require('path');

const args   = process.argv.slice(2);
const dir    = args[0];
const li     = args.indexOf('--label');
const label  = li >= 0 ? Number(args[li + 1]) : null;
if (!dir) { console.error('usage: node aggregate.js <results-dir> [--label 0|1]'); process.exit(1); }

function findJson(d, out = []) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const full = path.join(d, e.name);
    if (e.isDirectory()) findJson(full, out);
    else if (e.name.endsWith('.json')) out.push(full);
  }
  return out;
}

const files = findJson(dir);
let flagged = 0, silent = 0, noEntry = 0;
const stolenTally = {};        // category -> count of samples
const destTally   = {};        // destination -> count
const perSample   = [];

for (const f of files) {
  let r; try { r = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { continue; }
  const s        = r.summary || {};
  const critical = s.critical_events || 0;
  // Prefer the sandbox's explainable verdict (v2.1+); fall back to critical>0.
  const verdict  = r.verdict && r.verdict.verdict
                     ? (r.verdict.is_malicious ? 'MALICIOUS' : (r.verdict.verdict === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'clean'))
                     : (critical > 0 ? 'MALICIOUS' : 'clean');
  if (verdict === 'MALICIOUS') flagged++; else silent++;
  if (!r.target || !r.target.main) { /* entry may have been auto-detected; informational */ }

  const cats = (r.stolen_data && r.stolen_data.categories) || s.stolen_categories || [];
  for (const c of cats) stolenTally[c] = (stolenTally[c] || 0) + 1;
  const dests = (r.stolen_data && r.stolen_data.destinations) || s.exfil_destinations || [];
  for (const d of dests) destTally[d] = (destTally[d] || 0) + 1;

  perSample.push({
    sample:  r.target ? `${r.target.publisher}.${r.target.name}` : path.basename(f),
    critical, verdict,
    stole:   cats.join('|') || '-',
    dest:    dests.join('|') || '-',
  });
}

const total = flagged + silent;
console.log('═'.repeat(70));
console.log(`  DATASET AGGREGATE — ${dir}`);
console.log('═'.repeat(70));
console.log(`  Samples analyzed     : ${total}`);
console.log(`  Flagged MALICIOUS    : ${flagged}`);
console.log(`  No critical events   : ${silent}  (re-trigger / anti-analysis / benign)`);
if (label === 1) {
  const recall = total ? (flagged / total) : 0;
  console.log(`  Recall (TP/(TP+FN))  : ${(recall * 100).toFixed(1)}%   [TP=${flagged} FN=${silent}]`);
}
if (label === 0) {
  const fpr = total ? (flagged / total) : 0;
  console.log(`  False-positive rate  : ${(fpr * 100).toFixed(1)}%   [FP=${flagged} TN=${silent}]`);
}
console.log('\n  ── Data categories stolen across dataset ──');
Object.entries(stolenTally).sort((a, b) => b[1] - a[1])
  .forEach(([c, n]) => console.log(`    ${String(n).padStart(4)}  ${c}`));
if (!Object.keys(stolenTally).length) console.log('    (none captured)');

console.log('\n  ── Top exfiltration destinations ──');
Object.entries(destTally).sort((a, b) => b[1] - a[1]).slice(0, 15)
  .forEach(([d, n]) => console.log(`    ${String(n).padStart(4)}  ${d}`));
if (!Object.keys(destTally).length) console.log('    (none captured)');

// Write a CSV for the report / ML pipeline
const csv = ['sample,critical_events,verdict,stolen_categories,exfil_destinations']
  .concat(perSample.map(p => `"${p.sample}",${p.critical},${p.verdict},"${p.stole}","${p.dest}"`))
  .join('\n');
const outCsv = path.join(dir, 'aggregate.csv');
fs.writeFileSync(outCsv, csv);
console.log(`\n  CSV written → ${outCsv}`);
console.log('═'.repeat(70));
