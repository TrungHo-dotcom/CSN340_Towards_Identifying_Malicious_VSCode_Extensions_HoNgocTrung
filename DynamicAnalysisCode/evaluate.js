#!/usr/bin/env node
'use strict';
/**
 * evaluate.js — confusion matrix + precision/recall/F1 from a results CSV
 * ======================================================================
 * Reads a CSV produced by run_dataset.js (must contain `label`, `is_malicious`
 * and `is_flagged` columns) and prints classification metrics, computed two
 * ways so you can choose the threshold for the report:
 *   • strict  — positive = verdict MALICIOUS only
 *   • flagged — positive = verdict MALICIOUS or SUSPICIOUS
 *
 * Usage:  node evaluate.js results.csv
 *
 * Rows with an empty label are ignored (cannot be scored).
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */
const fs = require('fs');

const file = process.argv[2];
if (!file) { console.error('usage: node evaluate.js <results.csv>'); process.exit(1); }
if (!fs.existsSync(file)) { console.error(`not found: ${file}`); process.exit(1); }

// ── minimal CSV parser (handles quoted fields with commas) ───────────────────
function parseCsv(text) {
  const rows = [];
  let row = [], field = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i+1] === '"') { field += '"'; i++; }
      else if (c === '"') q = false;
      else field += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else if (c === '\r') { /* ignore */ }
    else field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows;
}

const raw  = parseCsv(fs.readFileSync(file, 'utf8')).filter(r => r.length > 1);
const head = raw.shift();
const idx  = (name) => head.indexOf(name);
const iLabel = idx('label'), iMal = idx('is_malicious'), iFlag = idx('is_flagged');
const iFinalMal = idx('final_is_malicious'), iFinalFlag = idx('final_is_flagged');
if (iLabel < 0 || iMal < 0) { console.error('CSV missing required columns: label, is_malicious'); process.exit(1); }

function metrics(rows, predIdx) {
  let TP = 0, FP = 0, FN = 0, TN = 0;
  for (const r of rows) {
    const truth = r[iLabel];
    if (truth !== '0' && truth !== '1') continue;       // unlabeled → skip
    const y = Number(truth), p = Number(r[predIdx]) ? 1 : 0;
    if (y === 1 && p === 1) TP++;
    else if (y === 0 && p === 1) FP++;
    else if (y === 1 && p === 0) FN++;
    else TN++;
  }
  const prec = TP + FP ? TP / (TP + FP) : 0;
  const rec  = TP + FN ? TP / (TP + FN) : 0;
  const f1   = prec + rec ? 2 * prec * rec / (prec + rec) : 0;
  const acc  = (TP + TN + FP + FN) ? (TP + TN) / (TP + TN + FP + FN) : 0;
  return { TP, FP, FN, TN, prec, rec, f1, acc };
}

function show(title, m) {
  console.log('\n  ' + title);
  console.log('  ' + '-'.repeat(54));
  console.log('                    Predicted MAL   Predicted BENIGN');
  console.log(`    Actual MAL          TP = ${String(m.TP).padStart(4)}        FN = ${String(m.FN).padStart(4)}`);
  console.log(`    Actual BENIGN       FP = ${String(m.FP).padStart(4)}        TN = ${String(m.TN).padStart(4)}`);
  console.log('  ' + '-'.repeat(54));
  console.log(`    Precision ${(m.prec*100).toFixed(1)}%   Recall ${(m.rec*100).toFixed(1)}%   F1 ${(m.f1*100).toFixed(1)}%   Accuracy ${(m.acc*100).toFixed(1)}%`);
}

console.log('═'.repeat(60));
console.log(`  EVALUATION — ${file}`);
console.log('═'.repeat(60));
const labeled = raw.filter(r => r[iLabel] === '0' || r[iLabel] === '1').length;
console.log(`  Rows: ${raw.length}   Labeled: ${labeled}`);

if (iFinalMal >= 0) show('FINAL  (static+dynamic, positive = MALICIOUS)  ★ headline', metrics(raw, iFinalMal));
if (iFinalFlag >= 0) show('FINAL FLAGGED (static+dynamic, MALICIOUS or SUSPICIOUS)', metrics(raw, iFinalFlag));
show('DYNAMIC-only STRICT  (positive = verdict MALICIOUS)', metrics(raw, iMal));
if (iFlag >= 0) show('DYNAMIC-only FLAGGED (MALICIOUS or SUSPICIOUS)', metrics(raw, iFlag));
console.log('\n═'.repeat(1) + '═'.repeat(59) + '\n');
