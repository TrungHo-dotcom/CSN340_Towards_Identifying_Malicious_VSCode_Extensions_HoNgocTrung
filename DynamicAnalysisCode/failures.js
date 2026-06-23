#!/usr/bin/env node
'use strict';
/**
 * failures.js — Misclassification collector + automated ROOT-CAUSE analysis
 * =========================================================================
 * Splits a labelled results CSV into TP / TN / FP / FN, writes a dedicated
 * FAILURES.md (+ failures.csv), and for every False Positive / False Negative
 * reads that sample's execution-log.json + static-analysis.json to explain WHY
 * the algorithm missed it or flagged it wrongly — the raw material for the
 * Limitations & Future-Work chapter.
 *
 * Usage:
 *   node failures.js <combined.csv> [resultsDir1 resultsDir2 ...]
 *      <combined.csv>  : produced by run_dataset.js (needs columns
 *                        label, final_is_malicious, final_verdict, sample, version)
 *      resultsDir*     : dirs to search for per-sample execution-log.json /
 *                        static-analysis.json (e.g. ./results2 ./results_benign)
 *
 * "Positive" = MALICIOUS (strict). Treats SUSPICIOUS as NOT malicious for the
 * strict confusion matrix; this is reported separately too.
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */
const fs   = require('fs');
const path = require('path');

// ── CSV ──────────────────────────────────────────────────────────────────────
function parseCsv(text){
  const rows=[]; let row=[],f='',q=false;
  for(let i=0;i<text.length;i++){const c=text[i];
    if(q){ if(c==='"'&&text[i+1]==='"'){f+='"';i++;} else if(c==='"'){q=false;} else f+=c; }
    else if(c==='"')q=true; else if(c===','){row.push(f);f='';}
    else if(c==='\n'){row.push(f);rows.push(row);row=[];f='';}
    else if(c==='\r'){} else f+=c; }
  if(f.length||row.length){row.push(f);rows.push(row);}
  return rows;
}
const readJson = p => { try { return JSON.parse(fs.readFileSync(p,'utf8')); } catch(e){ return null; } };
const key = (s,v) => `${String(s).toLowerCase()}@@${String(v)}`;

// ── index every per-sample log found under the given results dirs ─────────────
function indexLogs(dirs){
  const map = {};
  const walk = (d) => {
    let ents; try { ents = fs.readdirSync(d,{withFileTypes:true}); } catch(e){ return; }
    for (const e of ents){
      const full = path.join(d,e.name);
      if (e.isDirectory()) { if (e.name!=='node_modules') walk(full); }
      else if (e.name==='execution-log.json'){
        const log = readJson(full); if(!log||!log.target) continue;
        const stat = readJson(path.join(path.dirname(full),'static-analysis.json'));
        const t = log.target;
        map[key(`${t.publisher}.${t.name}`, t.version)] = { log, stat };
      }
    }
  };
  for (const d of dirs) walk(d);
  return map;
}

// ── root-cause reasoning ──────────────────────────────────────────────────────
function rootCauseFN(row, rec){          // truth=malicious, predicted not-malicious
  const log = rec && rec.log, stat = rec && rec.stat, s = log && log.summary || {};
  const events = (log && log.events) || [];
  const iocs   = (stat && stat.iocs) || [];
  const timedOut = row.timed_out === '1' || (log && log.timedOut);
  if (timedOut && events.length === 0)
    return 'Dynamic analysis was killed/timed-out before any behaviour surfaced, and static found no IOC. Mitigation: raise per-sample timeout or memory guard.';
  if (events.length === 0 && iocs.length === 0)
    return 'No runtime behaviour executed AND no static IOC present — the sample ships functional/clean code with no observable payload (clean re-publish or dormant first-stage). Behavioural+content analysis cannot reach it; requires publisher-reputation / threat-intel.';
  if (events.length === 0 && iocs.length)
    return 'Code never executed its payload in the sandbox (gated/dormant) but static did see indicators that scored below threshold — consider lowering the static threshold or strengthening de-obfuscation.';
  if (log && log.intel && log.intel.purpose && /No malicious/.test(log.intel.purpose))
    return 'Runtime activity occurred but matched no malicious signature (behaviour indistinguishable from benign at observation time).';
  return 'Observed activity scored below the MALICIOUS threshold (likely SUSPICIOUS) — borderline behaviour; tune weights or treat SUSPICIOUS as positive.';
}
function rootCauseFP(row, rec){          // truth=benign, predicted malicious
  const stat = rec && rec.stat, log = rec && rec.log;
  const reasons = [
    ...((stat && stat.verdict && stat.verdict.reasons) || []).map(r => `(static) ${r.reason}`),
    ...((log && log.verdict && log.verdict.reasons) || []).map(r => `(dynamic) ${r.reason}`),
  ];
  const blob = reasons.join(' | ').toLowerCase();
  let cause;
  if (/invisible-unicode|glassworm/.test(blob))
    cause = 'Invisible-Unicode rule over-triggered (emoji variation selectors / ZWJ counted as GlassWorm). Fix: restrict counting to U+E0000–E007F & U+E0100–E01EF only.';
  else if (/reverse shell pattern|child_process|os process/.test(blob))
    cause = 'Generic process/socket marker fired on a legitimate language-server / dev-tool that uses child_process. Fix: scan generic markers in the extension\'s own code only, not node_modules.';
  else if (/cradle/.test(blob))
    cause = 'Download-cradle proximity matched benign library text (LOLBIN keyword near an unrelated URL). Fix: tighten proximity / restrict to app code.';
  else if (/non-code category|theme|snippet/.test(blob))
    cause = 'Category-mismatch heuristic flagged a legitimate multi-category extension. Fix: drop or restrict this heuristic.';
  else if (/install.*script|lifecycle/.test(blob))
    cause = 'Legitimate build/lifecycle script (e.g. esbuild in vscode:prepublish) matched the install-script rule. Fix: restrict to postinstall/preinstall only.';
  else if (/ephemeral|cloud backend|raw public ip/.test(blob))
    cause = 'Legitimate backend host (the extension\'s own API on a cloud platform) matched a C2-staging rule. Fix: require a transmitted body / combine with another signal.';
  else
    cause = `Flagged by: ${reasons.join(' | ') || '(reason not captured in logs)'} — review weighting.`;
  return cause;
}

// ── main ──────────────────────────────────────────────────────────────────────
const [csvFile, ...dirs] = process.argv.slice(2);
if (!csvFile){ console.error('usage: node failures.js <combined.csv> [resultsDir ...]'); process.exit(1); }
const raw = parseCsv(fs.readFileSync(csvFile,'utf8')).filter(r=>r.length>1);
const head = raw.shift(); const idx = n => head.indexOf(n);
const iLabel=idx('label'), iMal=idx('final_is_malicious')>=0?idx('final_is_malicious'):idx('is_malicious'),
      iVer=idx('final_verdict')>=0?idx('final_verdict'):idx('verdict'), iS=idx('sample'), iV=idx('version'),
      iTO=idx('timed_out');
const logs = dirs.length ? indexLogs(dirs.map(d=>path.resolve(d))) : {};

const buckets = { TP:[], TN:[], FP:[], FN:[] };
for (const r of raw){
  const label = r[iLabel];
  if (label!=='0' && label!=='1') continue;
  const pred = Number(r[iMal])?1:0, truth=Number(label);
  const row = { sample:r[iS], version:r[iV], verdict:r[iVer], timed_out: iTO>=0?r[iTO]:'0' };
  if (truth===1 && pred===1) buckets.TP.push(row);
  else if (truth===0 && pred===0) buckets.TN.push(row);
  else if (truth===0 && pred===1) buckets.FP.push(row);
  else buckets.FN.push(row);
}
const TP=buckets.TP.length, TN=buckets.TN.length, FP=buckets.FP.length, FN=buckets.FN.length;
const prec = TP+FP? TP/(TP+FP):0, rec = TP+FN? TP/(TP+FN):0, f1 = prec+rec? 2*prec*rec/(prec+rec):0;
const acc = (TP+TN+FP+FN)? (TP+TN)/(TP+TN+FP+FN):0;

// ── write FAILURES.md ─────────────────────────────────────────────────────────
const L = [];
L.push('# Misclassification & Root-Cause Report', '');
L.push(`Generated: ${new Date().toISOString()}`);
L.push(`Source CSV: ${csvFile}`, '');
L.push('## Confusion matrix (strict: positive = MALICIOUS)', '');
L.push('|              | Predicted MAL | Predicted BENIGN |');
L.push('|--------------|---------------|------------------|');
L.push(`| **Actual MAL**    | TP = ${TP} | FN = ${FN} |`);
L.push(`| **Actual BENIGN** | FP = ${FP} | TN = ${TN} |`);
L.push('');
L.push(`Precision **${(prec*100).toFixed(1)}%**  ·  Recall **${(rec*100).toFixed(1)}%**  ·  F1 **${(f1*100).toFixed(1)}%**  ·  Accuracy **${(acc*100).toFixed(1)}%**`, '');

L.push('---', '', `## FALSE NEGATIVES (missed malware) — ${FN}`, '',
       '_Malicious samples our pipeline did NOT flag as MALICIOUS._', '');
if (!FN) L.push('_None._','');
for (const r of buckets.FN){
  const rec = logs[key(r.sample, r.version)];
  L.push(`### ❌ ${r.sample} (v${r.version})  — predicted ${r.verdict}`);
  L.push(`**Root cause:** ${rootCauseFN(r, rec)}`);
  if (rec && rec.log){ const s=rec.log.summary||{}; L.push(`*(events=${(rec.log.events||[]).length}, net=${s.http_requests||0}, exec=${s.child_process_calls||0}, static IOCs=${((rec.stat&&rec.stat.iocs)||[]).length})*`); }
  L.push('');
}

L.push('---', '', `## FALSE POSITIVES (benign flagged as malware) — ${FP}`, '',
       '_Benign samples our pipeline wrongly flagged as MALICIOUS._', '');
if (!FP) L.push('_None._','');
for (const r of buckets.FP){
  const rec = logs[key(r.sample, r.version)];
  L.push(`### ⚠️ ${r.sample} (v${r.version})  — predicted ${r.verdict}`);
  L.push(`**Root cause:** ${rootCauseFP(r, rec)}`);
  L.push('');
}

fs.writeFileSync('FAILURES.md', L.join('\n'));

// failures.csv
const fc = [['type','sample','version','predicted_verdict','root_cause']];
for (const r of buckets.FN) fc.push(['FN', r.sample, r.version, r.verdict, rootCauseFN(r, logs[key(r.sample,r.version)])]);
for (const r of buckets.FP) fc.push(['FP', r.sample, r.version, r.verdict, rootCauseFP(r, logs[key(r.sample,r.version)])]);
const esc = v => { const s=String(v==null?'':v); return /[",\n]/.test(s)?`"${s.replace(/"/g,'""')}"`:s; };
fs.writeFileSync('failures.csv', fc.map(r=>r.map(esc).join(',')).join('\n'));

console.log(`Confusion: TP=${TP} TN=${TN} FP=${FP} FN=${FN}`);
console.log(`Precision ${(prec*100).toFixed(1)}%  Recall ${(rec*100).toFixed(1)}%  F1 ${(f1*100).toFixed(1)}%`);
console.log(`Wrote FAILURES.md (${FN} FN + ${FP} FP with root causes) and failures.csv`);
