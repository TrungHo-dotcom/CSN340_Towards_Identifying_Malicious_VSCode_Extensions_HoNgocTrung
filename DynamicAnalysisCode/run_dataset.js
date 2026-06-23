#!/usr/bin/env node
'use strict';
/**
 * run_dataset.js — Batch Dynamic Analysis over a dataset tree
 * ===========================================================
 * Built for the project dataset layout where every sample is stored as
 *     <datasetRoot>/<publisher.name>/<version>.vsix
 * (i.e. a folder per extension containing a single .vsix). It also accepts a
 * flat folder of .vsix files, or already-unpacked extension directories.
 *
 * For each sample it:
 *   1. unpacks the .vsix into the output directory (kept separate from the
 *      dataset so the dataset is never modified),
 *   2. runs sandbox.js on the unpacked extension (auto-descends into extension/),
 *   3. reads execution-log.json and records the behavioural verdict, the key
 *      features, and the captured outbound messages,
 *   4. writes a combined CSV + JSON, and — when --label is given — prints a
 *      confusion-matrix summary (precision / recall / F1) for the write-up.
 *
 * Usage:
 *   node run_dataset.js --input <datasetRoot> --output <resultsDir> --label 1
 *   node run_dataset.js --input <benignRoot>  --output <resultsDir> --label 0 --csv results.csv --append
 *
 * Flags:
 *   --input    <dir>    dataset root (searched recursively for *.vsix)   [required]
 *   --output   <dir>    where to write unpacked samples + reports        [default ./results]
 *   --label    <0|1>    ground truth for this batch (1=malicious 0=benign)
 *   --timeout  <ms>     hard per-sample timeout                          [default 90000]
 *   --wait     <ms>     SANDBOX_WAIT_MS passed to the sandbox            [default 12000]
 *   --platform <os>     SANDBOX_OS spoof (win32|darwin|linux)            [default win32]
 *   --csv      <file>   combined CSV path                               [default <output>/results.csv]
 *   --append            append rows to --csv instead of overwriting (combine 2 runs)
 *   --keep              keep unpacked sample folders (default: keep; set --no-keep to delete)
 *   --no-keep           delete each unpacked sample after analysis (saves disk)
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');

// ── CLI parsing ──────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const a = { input: null, output: './results', label: null, timeout: 90000,
              wait: 12000, platform: 'win32', csv: null, append: false, keep: true };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    if      (k === '--input'    && argv[i+1]) a.input    = argv[++i];
    else if (k === '--output'   && argv[i+1]) a.output   = argv[++i];
    else if (k === '--label'    && argv[i+1]) a.label    = Number(argv[++i]);
    else if (k === '--timeout'  && argv[i+1]) a.timeout  = Number(argv[++i]);
    else if (k === '--wait'     && argv[i+1]) a.wait     = Number(argv[++i]);
    else if (k === '--platform' && argv[i+1]) a.platform = argv[++i];
    else if (k === '--csv'      && argv[i+1]) a.csv      = argv[++i];
    else if (k === '--append')                a.append  = true;
    else if (k === '--keep')                  a.keep    = true;
    else if (k === '--no-keep')               a.keep    = false;
  }
  return a;
}

// ── Recursively collect *.vsix under a root ──────────────────────────────────
function findVsix(root, out = []) {
  let entries; try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch (e) { return out; }
  for (const e of entries) {
    const full = path.join(root, e.name);
    if (e.isDirectory()) {
      if (e.name === 'node_modules') continue;
      findVsix(full, out);
    } else if (/\.vsix$/i.test(e.name)) {
      out.push(full);
    }
  }
  return out;
}

// ── Unpack a .vsix (zip) — prefers unzip, falls back to python3 ───────────────
function unpackVsix(vsixPath, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  let r = spawnSync('unzip', ['-q', '-o', vsixPath, '-d', destDir], { encoding: 'utf8' });
  if (r.status !== 0) {
    const py = 'import zipfile,sys\nwith zipfile.ZipFile(sys.argv[1]) as z: z.extractall(sys.argv[2])';
    r = spawnSync('python3', ['-c', py, vsixPath, destDir], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`unzip failed (need 'unzip' or 'python3'): ${r.stderr || ''}`);
  }
  // VS Code packs code under extension/ ; fall back to the root otherwise.
  const ext = path.join(destDir, 'extension');
  if (fs.existsSync(path.join(ext, 'package.json'))) return ext;
  return destDir;
}

// ── Run sandbox.js on one unpacked extension dir ─────────────────────────────
function runSandbox(extensionDir, opts) {
  const sandboxPath = path.resolve(__dirname, 'sandbox.js');
  const r = spawnSync(process.execPath, [sandboxPath, extensionDir], {
    timeout:  opts.timeout,
    encoding: 'utf8',
    maxBuffer: 20 * 1024 * 1024,
    env: Object.assign({}, process.env, {
      SANDBOX_WAIT_MS: String(opts.wait),
      SANDBOX_OS:      opts.platform,
    }),
  });
  return { timedOut: r.status === null, stdout: r.stdout || '', stderr: r.stderr || '' };
}

// ── Run preprocess.js (static pre-filter) on one unpacked extension dir ──────
function runStatic(extensionDir) {
  const pre = path.resolve(__dirname, 'preprocess.js');
  spawnSync(process.execPath, [pre, extensionDir], { timeout: 60000, encoding: 'utf8', maxBuffer: 20*1024*1024 });
  const p = path.join(extensionDir, 'static-analysis.json');
  if (fs.existsSync(p)) { try { return JSON.parse(fs.readFileSync(p,'utf8')); } catch(e){} }
  return null;
}

// ── Combine static + dynamic verdicts (final = the stronger of the two) ──────
const RANK = { BENIGN: 0, SUSPICIOUS: 1, MALICIOUS: 2 };
const NAME = ['BENIGN', 'SUSPICIOUS', 'MALICIOUS'];
function combine(staticV, dynV) {
  const s = staticV || { verdict:'BENIGN', score:0 };
  const d = dynV    || { verdict:'BENIGN', score:0 };
  const rank = Math.max(RANK[s.verdict]||0, RANK[d.verdict]||0);
  return {
    verdict: NAME[rank],
    is_malicious: rank === 2 ? 1 : 0,
    is_flagged:   rank >= 1 ? 1 : 0,
    by: (RANK[s.verdict]||0) > (RANK[d.verdict]||0) ? 'static'
        : (RANK[d.verdict]||0) > (RANK[s.verdict]||0) ? 'dynamic' : 'both',
  };
}

// ── Turn a report into a flat CSV row ────────────────────────────────────────
function toRow(report, meta) {
  const s = report.summary  || {};
  const v = report.verdict  || {};
  const t = report.target   || {};
  const beacons = report.outbound_messages || [];
  const reasons = (v.reasons || []).map(r => r.reason).join(' ; ');
  const dests   = [...new Set(beacons.map(b => b.host || b.destination).filter(Boolean))];
  const sample  = `${t.publisher || ''}.${t.name || ''}`.replace(/^\.|\.$/g, '') || meta.baseName;

  const sv  = (meta.staticReport && meta.staticReport.verdict) || null;   // static verdict
  const cmb = combine(sv, v);                                             // combined (final)

  return {
    sample,
    version:               t.version || '',
    label:                 meta.label != null ? meta.label : '',
    // FINAL verdict = stronger of static + dynamic
    final_verdict:         cmb.verdict,
    final_is_malicious:    cmb.is_malicious,
    final_is_flagged:      cmb.is_flagged,
    decided_by:            cmb.by,
    // dynamic-only
    verdict:               v.verdict || (s.critical_events > 0 ? 'MALICIOUS' : 'BENIGN'),
    score:                 v.score != null ? v.score : '',
    is_malicious:          v.is_malicious != null ? v.is_malicious : (s.critical_events > 0 ? 1 : 0),
    is_flagged:            v.is_flagged   != null ? v.is_flagged   : (s.critical_events > 0 ? 1 : 0),
    // static-only
    static_verdict:        sv ? sv.verdict : 'BENIGN',
    static_score:          sv ? sv.score   : 0,
    static_is_malicious:   sv ? sv.is_malicious : 0,
    invisible_unicode:     meta.staticReport ? (meta.staticReport.invisible_unicode || 0) : 0,
    total_events:          s.total_events        || 0,
    critical_events:       s.critical_events     || 0,
    child_process_calls:   s.child_process_calls || 0,
    http_requests:         s.http_requests       || 0,
    net_socket_calls:      s.net_socket_calls     || 0,
    eval_calls:            s.eval_calls           || 0,
    crypto_decrypt_calls:  s.crypto_decrypt_calls || 0,
    fs_writes:             s.fs_writes_blocked    || 0,
    outbound_messages:     beacons.length,
    data_stolen:           s.data_stolen ? 1 : 0,
    stolen_categories:     (s.stolen_categories || []).join('|'),
    destinations:          dests.slice(0, 5).join(' | '),
    sample_message:        (beacons[0] && (beacons[0].decoded || beacons[0].body) || '').replace(/\s+/g, ' ').slice(0, 200),
    reasons:               reasons.slice(0, 300),
    timed_out:             meta.timedOut ? 1 : 0,
    error:                 (report.errors || []).join(' | ').slice(0, 160),
  };
}

function rowsToCsv(rows) {
  if (!rows.length) return '';
  const headers = Object.keys(rows[0]);
  const esc = (val) => {
    const s = String(val == null ? '' : val);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [headers.join(','), ...rows.map(r => headers.map(h => esc(r[h])).join(','))].join('\n');
}

// ── Main ─────────────────────────────────────────────────────────────────────
function main() {
  const args = parseArgs(process.argv);
  if (!args.input) { console.error('[ERROR] --input <datasetRoot> is required'); process.exit(1); }
  if (!fs.existsSync(args.input)) { console.error(`[ERROR] input not found: ${args.input}`); process.exit(1); }
  fs.mkdirSync(args.output, { recursive: true });
  const csvPath = args.csv || path.join(args.output, 'results.csv');

  const vsixFiles = findVsix(path.resolve(args.input));
  if (!vsixFiles.length) { console.error(`[ERROR] no .vsix files found under ${args.input}`); process.exit(1); }

  console.log('\n' + '═'.repeat(72));
  console.log('  DATASET DYNAMIC ANALYSIS');
  console.log(`  Input    : ${args.input}  (${vsixFiles.length} samples)`);
  console.log(`  Output   : ${args.output}`);
  console.log(`  Label    : ${args.label != null ? args.label : 'unset'}   Platform spoof: ${args.platform}   Wait: ${args.wait}ms`);
  console.log('═'.repeat(72));

  const rows = [];
  let processed = 0, errored = 0, malicious = 0, flagged = 0;

  for (const vsix of vsixFiles) {
    processed++;
    const rel      = path.relative(path.resolve(args.input), vsix);
    const baseName = rel.replace(/\.vsix$/i, '');
    const safe     = baseName.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 100);
    const destDir  = path.join(args.output, safe);

    process.stdout.write(`\n[${processed}/${vsixFiles.length}] ${baseName}\n`);

    let extDir;
    try { extDir = unpackVsix(vsix, destDir); }
    catch (e) { console.error(`  [ERROR] ${e.message}`); errored++; rows.push({ sample: baseName, label: args.label, verdict: 'ERROR', error: 'UNPACK_FAILED' }); continue; }

    // Static pre-processing (pre-filter) first — scans all files incl node_modules.
    const staticReport = runStatic(extDir);

    const run = runSandbox(extDir, args);
    if (run.timedOut) console.warn(`  [TIMEOUT] exceeded ${args.timeout} ms`);

    const logPath = path.join(extDir, 'execution-log.json');
    if (!fs.existsSync(logPath)) {
      // Dynamic run was killed (e.g. OOM on heavy crypto) or timed out. Fall back
      // to the STATIC verdict alone so the sample is still classified — this is the
      // whole point of the two-stage design.
      const note = run.timedOut ? 'dynamic timed out/killed' : 'dynamic produced no log';
      const row = toRow({ summary:{}, verdict:null, target:(staticReport&&staticReport.target)||{}, outbound_messages:[] },
                        { baseName, label: args.label, timedOut: run.timedOut, staticReport });
      row.error = note;
      rows.push(row);
      if (row.final_is_malicious) malicious++;
      if (row.final_is_flagged)   flagged++;
      const icon = row.final_verdict === 'MALICIOUS' ? '🔴' : row.final_verdict === 'SUSPICIOUS' ? '🟡' : '🟢';
      console.log(`  ${icon} FINAL ${row.final_verdict} [static-only, ${note}]  (static ${row.static_verdict}/${row.static_score})`);
    } else {
      let report; try { report = JSON.parse(fs.readFileSync(logPath, 'utf8')); }
      catch (e) { errored++; rows.push({ sample: baseName, label: args.label, final_verdict: 'ERROR', verdict: 'ERROR', error: 'BAD_LOG' }); continue; }
      const row = toRow(report, { baseName, label: args.label, timedOut: run.timedOut, staticReport });
      rows.push(row);
      if (row.final_is_malicious) malicious++;
      if (row.final_is_flagged)   flagged++;
      const icon = row.final_verdict === 'MALICIOUS' ? '🔴' : row.final_verdict === 'SUSPICIOUS' ? '🟡' : '🟢';
      console.log(`  ${icon} FINAL ${row.final_verdict} [${row.decided_by}]  (dyn ${row.verdict}/${row.score}, static ${row.static_verdict}/${row.static_score})  events=${row.total_events} msgs=${row.outbound_messages}`);
      if (row.destinations) console.log(`     dest: ${row.destinations}`);
    }

    if (!args.keep) { try { fs.rmSync(destDir, { recursive: true, force: true }); } catch (_) {} }
  }

  // ── Write CSV (with optional append to combine malicious + benign runs) ─────
  const haveExisting = args.append && fs.existsSync(csvPath);
  const csvBody = rowsToCsv(rows);
  if (haveExisting) {
    const withoutHeader = csvBody.split('\n').slice(1).join('\n');
    fs.appendFileSync(csvPath, '\n' + withoutHeader, 'utf8');
  } else {
    fs.writeFileSync(csvPath, csvBody, 'utf8');
  }
  fs.writeFileSync(path.join(args.output, 'batch-summary.json'),
    JSON.stringify({ generated_at: new Date().toISOString(), input: args.input, label: args.label,
                     total: vsixFiles.length, processed, errored, predicted_malicious: malicious,
                     predicted_flagged: flagged, rows }, null, 2), 'utf8');

  // ── Per-run confusion-matrix contribution ──────────────────────────────────
  console.log('\n' + '═'.repeat(72));
  console.log('  BATCH COMPLETE');
  console.log('═'.repeat(72));
  console.log(`  Samples processed     : ${processed}   (errors/no-log: ${errored})`);
  console.log(`  FINAL MALICIOUS       : ${malicious}   (static+dynamic combined)`);
  console.log(`  FINAL FLAGGED         : ${flagged}   (MALICIOUS + SUSPICIOUS)`);
  const analysed = processed - errored;
  if (args.label === 1) {
    console.log(`  --- treating this batch as ground-truth MALICIOUS (label=1) ---`);
    console.log(`  Recall (strict)       : ${pct(malicious, analysed)}   [TP=${malicious} FN=${analysed - malicious}]`);
    console.log(`  Recall (flagged)      : ${pct(flagged, analysed)}   [TP=${flagged} FN=${analysed - flagged}]`);
  } else if (args.label === 0) {
    console.log(`  --- treating this batch as ground-truth BENIGN (label=0) ---`);
    console.log(`  False-positive (strict): ${pct(malicious, analysed)}   [FP=${malicious} TN=${analysed - malicious}]`);
    console.log(`  False-positive (flagged): ${pct(flagged, analysed)}   [FP=${flagged} TN=${analysed - flagged}]`);
  }
  console.log(`\n  CSV     → ${csvPath}`);
  console.log(`  Summary → ${path.join(args.output, 'batch-summary.json')}`);
  console.log('═'.repeat(72) + '\n');
  console.log('  Tip: run once on the malicious set (--label 1) and once on the benign set');
  console.log('       (--label 0 --append) into the SAME --csv, then: node evaluate.js <csv>\n');
}

function pct(n, d) { return d ? `${(100 * n / d).toFixed(1)}%` : 'n/a'; }

main();
