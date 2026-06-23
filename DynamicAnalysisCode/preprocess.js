#!/usr/bin/env node
'use strict';
/**
 * preprocess.js — Static Pre-processing / Pre-filter (pre-execution triage)
 * =========================================================================
 * Static stage that runs FIRST: it unpacks the package, DE-OBFUSCATES every
 * text file (\xNN / \uNNNN escapes + base64 blobs), and scans for malware
 * indicators. The dynamic sandbox observes runtime behaviour; this stage
 * catches payloads the sandbox never reaches (trojanised node_modules,
 * dormant/gated code, obfuscation).
 *
 * PRECISION-FIRST DESIGN (v2 — calibrated against a 49-extension benign set):
 *   • HOST IOCs (ngrok/catbox/solana-RPC/discord-webhook/raw-IP/cloud-C2) are
 *     specific enough to scan EVERYWHERE, incl. node_modules (this is how the
 *     ETHCode trojan in keythereum-utils is caught).
 *   • GENERIC behavioural markers (child_process, raw socket, cradle, secret
 *     reads, installExtension) are scanned ONLY in the extension's OWN code,
 *     NEVER in node_modules — otherwise every real language extension trips.
 *   • Invisible-Unicode detection counts ONLY the GlassWorm encoding ranges
 *     U+E0000–E007F (tags) and U+E0100–E01EF (variation-selectors supplement).
 *     It deliberately EXCLUDES emoji selectors (U+FE0F), ZWJ (U+200D), bidi
 *     marks and zero-width spaces, which appear in legitimate code constantly.
 *
 * Usage:
 *   node preprocess.js <.vsix | extension dir | dataset-root> [--csv out.csv]
 *
 * Writes static-analysis.json next to the analysed package and prints a verdict.
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');

const MAX_FILE_BYTES  = 1.5 * 1024 * 1024;
const MAX_TOTAL_BYTES = 60  * 1024 * 1024;
const MAX_FILES       = 6000;
const TEXT_EXT        = /\.(js|cjs|mjs|jsx|ts|tsx|json|sh|ps1|bat|cmd|py)$/i;

// ── HIGH-CONFIDENCE host/string IOCs — safe to scan everywhere (incl node_modules)
//    These strings essentially never occur in legitimate extension code.
const HOST_IOCS = [
  [/ngrok|trycloudflare|\.tcp\.\w|loca\.lt|serveo\.net|localtunnel/i,           50, 'tunnelled C2 endpoint (ngrok / cloudflare / tcp tunnel)'],
  [/catbox\.moe|pastebin\.com|paste\.ee|0x0\.st|transfer\.sh|anonfiles|tmpfiles\.org/i, 45, 'anonymous file-drop host (payload staging)'],
  [/mainnet-beta\.solana|api\.devnet\.solana|api\.mainnet-/i,                   40, 'Solana RPC used as decentralized C2'],
  [/discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot/i,              45, 'chat-app webhook used for exfiltration'],
  [/https?:\/\/[a-z0-9.-]*(?:herokuapp\.com|elasticbeanstalk|pythonanywhere\.com|onrender\.com|workers\.dev|\.repl\.co|glitch\.me|railway\.app)/i, 35, 'ephemeral/free cloud backend endpoint (C2 staging)'],
  [/function\.undefined|\.undefined\d|undefined\d+\.com/i,                       35, 'auto-generated throwaway C2 domain'],
];

// ── GENERIC IOCs — scanned ONLY in the extension's own (non-node_modules) code
const APP_IOCS = [
  [/(?:powershell|cmd\.exe|certutil|bitsadmin|mshta|curl\.exe|\bcurl\s+-|\bwget\s+https?|invoke-webrequest|downloadstring|downloadfile)[^\n]{0,150}(?:https?:\/\/|\.bat\b|\.ps1\b|\.hta\b|catbox|pastebin|\s-o\s|-outfile)/i,
                                                                                55, 'download-and-execute cradle (LOLBIN fetches & runs a remote payload)'],
  [/https?:\/\/(?!127\.|10\.|192\.168\.|0\.|169\.254\.|255\.|localhost|1\.1\.1\.1|8\.8\.8\.8|8\.8\.4\.4)\d{1,3}(?:\.\d{1,3}){3}/, 40, 'hard-coded raw public IP endpoint'],
  [/workbench\.extensions\.installExtension/i,                                  25, 'programmatically installs a VSIX (marketplace bypass)'],
  [/(?:readFileSync|readFile|createReadStream)\s*\([^)]{0,40}(?:\.ssh[\/\\]|id_rsa|\.aws[\/\\]credentials|wallet\.json|keystore)/i, 25, 'reads credential / wallet / secret files'],
];

// ── helpers ──────────────────────────────────────────────────────────────────
function safeReaddir(d){ try { return fs.readdirSync(d,{withFileTypes:true}); } catch(e){ return []; } }

function unzip(vsixPath) {
  const tmp = path.join(os.tmpdir(), `vsix-pre-${path.basename(vsixPath).replace(/[^\w.-]/g,'_')}-${Date.now()}`);
  fs.mkdirSync(tmp, { recursive: true });
  let r = spawnSync('unzip', ['-q','-o',vsixPath,'-d',tmp], { encoding:'utf8' });
  if (r.status !== 0) {
    const py='import zipfile,sys\nwith zipfile.ZipFile(sys.argv[1]) as z: z.extractall(sys.argv[2])';
    r = spawnSync('python3', ['-c',py,vsixPath,tmp], { encoding:'utf8' });
    if (r.status !== 0) throw new Error(`unzip failed: ${r.stderr||''}`);
  }
  return tmp;
}

function findExtRoot(root) {
  if (fs.existsSync(path.join(root,'extension','package.json'))) return path.join(root,'extension');
  if (fs.existsSync(path.join(root,'package.json'))) return root;
  for (const e of safeReaddir(root)) {
    if (e.isDirectory()) {
      const d = path.join(root, e.name);
      if (fs.existsSync(path.join(d,'extension','package.json'))) return path.join(d,'extension');
      if (fs.existsSync(path.join(d,'package.json'))) return d;
    }
  }
  return root;
}

/** Reveal hidden text: decode \xNN / \uNNNN escapes and embedded base64 blobs. */
function deobfuscate(src) {
  let out = src;
  out += '\n' + src.replace(/\\x([0-9a-fA-F]{2})/g, (_,h)=>String.fromCharCode(parseInt(h,16)))
                   .replace(/\\u([0-9a-fA-F]{4})/g, (_,h)=>String.fromCharCode(parseInt(h,16)));
  const blobs = src.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || [];
  for (const b of blobs.slice(0, 40)) {
    try {
      const d = Buffer.from(b,'base64').toString('utf8');
      if (/[ -~]/.test(d) && /[a-zA-Z]{4}/.test(d) && d.replace(/[^\x20-\x7e]/g,'').length > d.length*0.7) out += '\n' + d;
    } catch(e){}
  }
  return out;
}

/**
 * Count ONLY GlassWorm-style invisible encoding codepoints:
 *   U+E0000–U+E007F  (Tags)        and  U+E0100–U+E01EF (Variation Selectors Supp.)
 * Emoji selectors (U+FE0F), ZWJ (U+200D), bidi marks and zero-width spaces are
 * EXCLUDED — they occur in legitimate code/emoji/i18n and caused false positives.
 */
function glasswormUnicodeCount(src) {
  let n = 0;
  for (let i = 0; i < src.length; i++) {
    let cp = src.charCodeAt(i);
    if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < src.length) {
      const lo = src.charCodeAt(i + 1);
      if (lo >= 0xDC00 && lo <= 0xDFFF) { cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00); i++; }
    }
    if ((cp >= 0xE0000 && cp <= 0xE007F) || (cp >= 0xE0100 && cp <= 0xE01EF)) n++;
  }
  return n;
}

// ── walk + scan ──────────────────────────────────────────────────────────────
function scanTree(extRoot) {
  const findings = [];
  const add = (pts, reason, file) => findings.push({ points: pts, reason, file: path.relative(extRoot, file) || '.' });
  let scannedFiles = 0, scannedBytes = 0, invisibleTotal = 0;
  let appCodeBytes = 0, appHasRealLogic = false;
  const seenHost = new Set();      // de-dupe host IOCs across files
  let revShellFlagged = false;
  const REAL_LOGIC = /require\(['"](?:fs|net|https?|child_process|crypto|axios|dns|os|node-fetch)['"]\)|\bfetch\s*\(|\beval\s*\(|new\s+Function|createWriteStream/;
  const SOCK = /new\s+net\.Socket|net\.createConnection/i;
  const EXEC = /child_process|\.execSync\(|\.spawnSync\(|child_process\.(?:exec|spawn|execFile|fork)/i;

  (function walk(dir) {
    if (scannedFiles >= MAX_FILES || scannedBytes >= MAX_TOTAL_BYTES) return;
    for (const e of safeReaddir(dir)) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (e.name !== '.git') walk(full); }
      else if (e.name === 'execution-log.json' || e.name === 'static-analysis.json') { continue; }
      else if (TEXT_EXT.test(e.name)) {
        let st; try { st = fs.statSync(full); } catch(e){ continue; }
        if (st.size > MAX_FILE_BYTES) continue;
        if (scannedFiles >= MAX_FILES || scannedBytes >= MAX_TOTAL_BYTES) return;
        let raw; try { raw = fs.readFileSync(full,'utf8'); } catch(e){ continue; }
        scannedFiles++; scannedBytes += st.size;
        const isApp = !/[\/\\]node_modules[\/\\]/.test(full);
        if (isApp && /\.(js|cjs|mjs|ts)$/i.test(e.name)) { appCodeBytes += st.size; if (REAL_LOGIC.test(raw)) appHasRealLogic = true; }
        invisibleTotal += glasswormUnicodeCount(raw);
        const text = deobfuscate(raw);

        // HOST IOCs everywhere (de-duped by reason)
        for (const [re, pts, reason] of HOST_IOCS) {
          if (re.test(text) && !seenHost.has(reason)) { seenHost.add(reason); add(pts, reason, full); }
        }
        // GENERIC IOCs only in app code
        if (isApp) {
          for (const [re, pts, reason] of APP_IOCS) {
            if (re.test(text) && !seenHost.has(reason)) { seenHost.add(reason); add(pts, reason, full); }
          }
          // reverse shell = outbound socket + process exec in the SAME app file
          if (!revShellFlagged && SOCK.test(text) && EXEC.test(text)) {
            revShellFlagged = true;
            add(55, 'reverse shell pattern (outbound TCP socket + child_process in the same file)', full);
          }
        }
      }
    }
  })(extRoot);

  if (invisibleTotal > 6) add(40, `GlassWorm invisible-Unicode encoding present (${invisibleTotal} tag/variation-selector codepoints)`, extRoot);

  return { findings, scannedFiles, scannedBytes, invisibleTotal, appCodeBytes, appHasRealLogic };
}

// ── manifest metadata heuristics (low-FP only) ───────────────────────────────
function scanManifest(extRoot, stats) {
  const out = [];
  let pkg = {};
  try { pkg = JSON.parse(fs.readFileSync(path.join(extRoot,'package.json'),'utf8')); } catch(e){ return { out, pkg }; }

  // Malicious lifecycle hook: a postinstall/preinstall/install script that pulls
  // and runs remote content (legit build scripts live in vscode:prepublish).
  const scripts = pkg.scripts || {};
  for (const k of ['postinstall','preinstall','install']) {
    if (scripts[k] && /curl|wget|powershell|node\s+-e|base64|https?:\/\//i.test(scripts[k])) {
      out.push({ points: 40, reason: `malicious ${k} lifecycle script in package.json` }); break;
    }
  }

  // Functionality mismatch: advertises substantial tooling yet ships only a
  // trivial stub with no real logic (the "clean first stage" placeholder).
  const blurb = `${pkg.displayName||''} ${pkg.name||''} ${pkg.description||''}`.toLowerCase();
  const advertises = /toolkit|suite|manager|\bpro\b|\bai\b|security|wallet|companion|assistant|copilot|formatter/.test(blurb);
  if (pkg.main && stats && advertises && !stats.appHasRealLogic && stats.appCodeBytes > 0 && stats.appCodeBytes < 4000)
    out.push({ points: 25, reason: 'advertises substantial functionality but ships only a trivial stub (possible first-stage placeholder)' });

  return { out, pkg };
}

function classify(findings) {
  const byReason = new Map();
  for (const f of findings) { const c = byReason.get(f.reason); if (!c || f.points > c.points) byReason.set(f.reason, f); }
  const reasons = [...byReason.values()].sort((a,b)=>b.points-a.points);
  const score = reasons.reduce((s,r)=>s+r.points, 0);
  let verdict = 'BENIGN';
  if (score >= 50)      verdict = 'MALICIOUS';
  else if (score >= 25) verdict = 'SUSPICIOUS';
  return { verdict, score, reasons, is_malicious: verdict==='MALICIOUS'?1:0, is_flagged: verdict==='BENIGN'?0:1 };
}

function analyse(inputPath) {
  const abs = path.resolve(inputPath);
  let extRoot, cleanup = null;
  if (fs.statSync(abs).isFile()) {
    if (!/\.(vsix|zip)$/i.test(abs)) throw new Error('not a .vsix/.zip or directory');
    const tmp = unzip(abs); extRoot = findExtRoot(tmp); cleanup = tmp;
  } else extRoot = findExtRoot(abs);

  const stats = scanTree(extRoot);
  const { findings, scannedFiles, invisibleTotal } = stats;
  const { out: metaFindings, pkg } = scanManifest(extRoot, stats);
  const all = findings.concat(metaFindings.map(m=>({ ...m, file: 'package.json' })));
  const verdict = classify(all);

  const report = {
    static_version: '2.0.0',
    analysed_at: new Date().toISOString(),
    target: { name: pkg.name||'', publisher: pkg.publisher||'', version: pkg.version||'', categories: pkg.categories||[], main: pkg.main||'' },
    verdict, files_scanned: scannedFiles, invisible_unicode: invisibleTotal, iocs: all,
  };
  const outPath = cleanup ? path.join(path.dirname(abs),'static-analysis.json') : path.join(extRoot,'static-analysis.json');
  try { fs.writeFileSync(outPath, JSON.stringify(report,null,2)); } catch(e){}
  return { report, outPath, sample: `${pkg.publisher||''}.${pkg.name||''}` };
}

// ── CLI ──────────────────────────────────────────────────────────────────────
function findVsix(root, out=[]) {
  for (const e of safeReaddir(root)) {
    const full = path.join(root,e.name);
    if (e.isDirectory()) { if (e.name!=='node_modules') findVsix(full,out); }
    else if (/\.vsix$/i.test(e.name)) out.push(full);
  }
  return out;
}

function printOne(sample, r) {
  const icon = r.verdict.verdict==='MALICIOUS'?'🔴':r.verdict.verdict==='SUSPICIOUS'?'🟡':'🟢';
  console.log(`  ${icon} [STATIC] ${sample}  → ${r.verdict.verdict} (score ${r.verdict.score}, files ${r.files_scanned})`);
  for (const ioc of r.verdict.reasons.slice(0,6)) console.log(`        • (+${ioc.points}) ${ioc.reason}  [${ioc.file}]`);
}

function main() {
  const args = process.argv.slice(2);
  const input = args[0];
  const ci = args.indexOf('--csv'); const csv = ci>=0 ? args[ci+1] : null;
  if (!input) { console.error('usage: node preprocess.js <.vsix | dir | dataset-root> [--csv out.csv]'); process.exit(1); }
  const abs = path.resolve(input);
  if (!fs.existsSync(abs)) { console.error('not found: '+abs); process.exit(1); }

  const isDir = fs.statSync(abs).isDirectory();
  const targets = (isDir && !fs.existsSync(path.join(abs,'package.json')) && findExtRoot(abs)===abs && findVsix(abs).length)
    ? findVsix(abs) : [abs];

  console.log('═'.repeat(70));
  console.log('  STATIC PRE-PROCESSING  (pre-filter v2)');
  console.log(`  Targets: ${targets.length}`);
  console.log('═'.repeat(70));

  const rows = [];
  for (const t of targets) {
    try {
      const { report, sample } = analyse(t);
      printOne(sample || path.basename(t), report);
      rows.push({ sample: sample || path.basename(t), version: report.target.version,
                  static_verdict: report.verdict.verdict, static_score: report.verdict.score,
                  static_is_malicious: report.verdict.is_malicious, static_is_flagged: report.verdict.is_flagged,
                  invisible_unicode: report.invisible_unicode,
                  static_reasons: report.verdict.reasons.map(r=>r.reason).join(' ; ').slice(0,300) });
    } catch(e) { console.error(`  [ERROR] ${path.basename(t)}: ${e.message}`); }
  }

  if (csv && rows.length) {
    const headers = Object.keys(rows[0]);
    const esc = v => { const s=String(v==null?'':v); return /[",\n]/.test(s)?`"${s.replace(/"/g,'""')}"`:s; };
    fs.writeFileSync(csv, [headers.join(','), ...rows.map(r=>headers.map(h=>esc(r[h])).join(','))].join('\n'));
    console.log(`\n  Static CSV → ${csv}`);
  }
  console.log('═'.repeat(70));
}

main();
