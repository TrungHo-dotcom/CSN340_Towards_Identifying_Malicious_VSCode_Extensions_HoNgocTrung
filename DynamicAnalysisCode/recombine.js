#!/usr/bin/env node
'use strict';
/**
 * recombine.js — merge a FRESH static pass with the ALREADY-SAVED dynamic verdicts
 * so we can re-evaluate after tuning preprocess.js WITHOUT re-running the 1.5h
 * dynamic analysis.
 *
 * Inputs:
 *   1) the combined CSV from the previous full run (has per-sample DYNAMIC verdict
 *      columns: verdict, is_malicious, is_flagged, label) — e.g. results2/all.csv
 *   2+) one or more NEW static CSVs from `preprocess.js --csv` (have static_verdict,
 *      static_is_malicious, static_is_flagged) — e.g. static_mal.csv static_ben.csv
 *
 * Output: all_final.csv  with FINAL = max(saved dynamic, fresh static).
 * Then:   node evaluate.js all_final.csv
 *
 * Usage:
 *   node recombine.js results2/all.csv static_mal.csv static_ben.csv
 */
const fs = require('fs');

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
function load(file){
  const raw=parseCsv(fs.readFileSync(file,'utf8')).filter(r=>r.length>1);
  const head=raw.shift(); return { head, rows:raw, idx:(n)=>head.indexOf(n) };
}
const key=(s,v)=>`${String(s).toLowerCase()}@@${String(v)}`;
const RANK={BENIGN:0,SUSPICIOUS:1,MALICIOUS:2}, NAME=['BENIGN','SUSPICIOUS','MALICIOUS'];

const [dynFile, ...statFiles] = process.argv.slice(2);
if(!dynFile||!statFiles.length){ console.error('usage: node recombine.js <dynamic_all.csv> <static1.csv> [static2.csv ...]'); process.exit(1); }

// fresh static map
const stat={};
for(const sf of statFiles){
  const {rows,idx}=load(sf);
  const iS=idx('sample'),iV=idx('version'),iSV=idx('static_verdict'),iSM=idx('static_is_malicious'),iSF=idx('static_is_flagged'),iU=idx('invisible_unicode');
  for(const r of rows){ stat[key(r[iS],r[iV])]={ verdict:r[iSV]||'BENIGN', mal:+r[iSM]||0, flag:+r[iSF]||0, inv:r[iU]||'0' }; }
}

const {head,rows,idx}=load(dynFile);
const iS=idx('sample'),iV=idx('version'),iL=idx('label'),iDV=idx('verdict'),iDM=idx('is_malicious'),iDF=idx('is_flagged');
const out=[['sample','version','label','final_verdict','final_is_malicious','final_is_flagged',
           'dyn_verdict','dyn_is_malicious','static_verdict','static_is_malicious','invisible_unicode','decided_by']];
let matched=0,missing=0;
for(const r of rows){
  const s=stat[key(r[iS],r[iV])];
  if(s) matched++; else missing++;
  const sv = s? s.verdict : (r[idx('static_verdict')]||'BENIGN');
  const sMal = s? s.mal : (+r[idx('static_is_malicious')]||0);
  const inv = s? s.inv : (r[idx('invisible_unicode')]||'0');
  const dynV=r[iDV]||'BENIGN', dynMal=+r[iDM]||0;
  const rank=Math.max(RANK[dynV]||0, RANK[sv]||0);
  const fv=NAME[rank];
  const by=(RANK[sv]||0)>(RANK[dynV]||0)?'static':(RANK[dynV]||0)>(RANK[sv]||0)?'dynamic':'both';
  out.push([r[iS],r[iV],r[iL],fv, rank===2?1:0, rank>=1?1:0, dynV,dynMal, sv,sMal, inv, by]);
}
const esc=v=>{const s=String(v==null?'':v);return /[",\n]/.test(s)?`"${s.replace(/"/g,'""')}"`:s;};
fs.writeFileSync('all_final.csv', out.map(r=>r.map(esc).join(',')).join('\n'));
console.log(`Merged ${rows.length} rows (static matched ${matched}, fallback ${missing}) → all_final.csv`);
console.log('Now run:  node evaluate.js all_final.csv');
