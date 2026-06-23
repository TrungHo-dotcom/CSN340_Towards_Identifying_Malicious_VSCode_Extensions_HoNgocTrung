#!/usr/bin/env node
/**
 * run_batch.js — Batch Dynamic Analysis Runner
 * =============================================
 * Iterates over a folder of .vsix files, unpacks each one into a temp
 * directory, runs sandbox.js on it with a hard timeout, collects the
 * execution-log.json output, and writes a combined JSON + CSV dataset.
 *
 * Usage:
 *   node run_batch.js --input ./samples/  --output ./results/
 *   node run_batch.js --input ./malicious/ --output ./results/ --label 1
 *   node run_batch.js --input ./benign/   --output ./results/ --label 0
 *
 * Flags:
 *   --input   <dir>   Directory containing .vsix files  (required)
 *   --output  <dir>   Directory to write results to     (default: ./results)
 *   --label   <0|1>   Ground-truth label for this batch (0=benign, 1=malicious)
 *   --timeout <ms>    Per-extension timeout in ms       (default: 30000 = 30s)
 *   --keep            Keep unpacked extension directories after analysis
 *   --csv     <file>  Path to the combined CSV output   (default: results.csv)
 *
 * Output per extension:
 *   results/<publisher.name-version>/execution-log.json
 *
 * Combined output:
 *   results/batch-summary.json   — full structured data
 *   results.csv                  — one row per extension, ML-ready
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

'use strict';

const fs         = require('fs');
const path       = require('path');
const os         = require('os');
const { execSync, spawnSync } = require('child_process');

// ─────────────────────────────────────────────────────────────────────────────
//  CLI argument parsing
// ─────────────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { input: null, output: './results', label: null, timeout: 30000, keep: false, csv: 'results.csv' };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--input'   && argv[i+1]) { args.input   = argv[++i]; }
    else if (a === '--output'  && argv[i+1]) { args.output  = argv[++i]; }
    else if (a === '--label'   && argv[i+1]) { args.label   = Number(argv[++i]); }
    else if (a === '--timeout' && argv[i+1]) { args.timeout = Number(argv[++i]); }
    else if (a === '--keep')                 { args.keep    = true; }
    else if (a === '--csv' && argv[i+1])     { args.csv     = argv[++i]; }
  }
  return args;
}

// ─────────────────────────────────────────────────────────────────────────────
//  VSIX unpacker — a .vsix is a ZIP archive
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Unpack a .vsix file into destDir.
 * Uses the system `unzip` command (available on Ubuntu by default).
 * Returns the path to the `extension/` subdirectory inside the extracted content.
 */
function unpackVsix(vsixPath, destDir) {
  fs.mkdirSync(destDir, { recursive: true });

  // Try unzip first (Ubuntu), fall back to Python zipfile
  const result = spawnSync('unzip', ['-q', '-o', vsixPath, '-d', destDir], { encoding: 'utf8' });

  if (result.status !== 0) {
    // Fallback: Python zipfile module
    const pyScript = `
import zipfile, sys
with zipfile.ZipFile(sys.argv[1]) as z:
    z.extractall(sys.argv[2])
`.trim();
    const pyResult = spawnSync('python3', ['-c', pyScript, vsixPath, destDir], { encoding: 'utf8' });
    if (pyResult.status !== 0) {
      throw new Error(`Failed to unpack ${path.basename(vsixPath)}: ${result.stderr || pyResult.stderr}`);
    }
  }

  // The extension code lives in extension/ (some .vsix files have this prefix)
  const extSubdir = path.join(destDir, 'extension');
  if (fs.existsSync(extSubdir) && fs.existsSync(path.join(extSubdir, 'package.json'))) {
    return extSubdir;
  }
  // Otherwise the package.json is at the root
  return destDir;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Dynamic analysis runner
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Run sandbox.js on an unpacked extension directory with a hard timeout.
 * Returns the contents of execution-log.json, or null on timeout/error.
 */
function runSandbox(extensionDir, timeoutMs) {
  const sandboxPath = path.resolve(__dirname, 'sandbox.js');

  const result = spawnSync(
    process.execPath,   // node binary
    [sandboxPath, extensionDir],
    {
      timeout: timeoutMs,
      encoding: 'utf8',
      maxBuffer: 10 * 1024 * 1024, // 10 MB
    }
  );

  if (result.status === null) {
    return { timedOut: true, stdout: result.stdout || '', stderr: 'TIMEOUT' };
  }

  return {
    timedOut: false,
    exitCode: result.status,
    stdout:   result.stdout  || '',
    stderr:   result.stderr  || '',
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Feature extraction from execution-log.json
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Convert an execution-log.json report into a flat feature row suitable for
 * a pandas DataFrame / ML training dataset.
 */
function extractDynamicFeatures(report) {
  const s = report.summary || {};
  const t = report.target  || {};
  const events = report.events || [];

  // Helper: count events matching a predicate
  const cnt = (pred) => events.filter(pred).length;
  // Helper: get unique values
  const uniq = (arr) => [...new Set(arr)];

  // Extract all commanded URLs / hosts
  const urls = events
    .filter(e => e.arguments && e.arguments.url)
    .map(e => String(e.arguments.url));

  const commands = events
    .filter(e => e.arguments && e.arguments.command)
    .map(e => String(e.arguments.command));

  const writtenPaths = events
    .filter(e => e.module === 'fs' && e.arguments && e.arguments.path &&
                 ['writeFile','writeFileSync','appendFile','appendFileSync','createWriteStream'].includes(e.function_hooked))
    .map(e => String(e.arguments.path));

  const decryptAlgorithms = events
    .filter(e => e.module === 'crypto' && e.function_hooked === 'createDecipheriv')
    .map(e => String(e.arguments.algorithm || ''));

  return {
    // ── Identity ─────────────────────────────────────────────────────────────
    name:             t.name          || '',
    display_name:     t.display_name  || '',
    publisher:        t.publisher     || '',
    version:          t.version       || '',
    categories:       (t.categories || []).join('|'),
    activation_events:(t.activation_events || []).join('|'),

    // ── Event counts (numeric) ────────────────────────────────────────────────
    total_events:           s.total_events          || 0,
    critical_events:        s.critical_events        || 0,
    child_process_calls:    s.child_process_calls    || 0,
    http_requests:          s.http_requests          || 0,
    fs_writes_blocked:      s.fs_writes_blocked      || 0,
    fs_reads:               s.fs_reads               || 0,
    eval_calls:             s.eval_calls             || 0,
    crypto_decrypt_calls:   s.crypto_decrypt_calls   || 0,
    net_socket_calls:       s.net_socket_calls        || 0,
    dns_lookups:            s.dns_lookups            || 0,
    os_recon_calls:         s.os_recon_calls         || 0,
    unique_hosts:           (s.unique_hosts_contacted || []).length,
    unique_shell_commands:  (s.shell_commands_attempted || []).length,

    // ── Binary features (0/1) ─────────────────────────────────────────────────
    has_network:            (s.http_requests || 0) > 0 ? 1 : 0,
    has_exec:               (s.child_process_calls || 0) > 0 ? 1 : 0,
    has_eval:               (s.eval_calls || 0) > 0 ? 1 : 0,
    has_crypto_decrypt:     (s.crypto_decrypt_calls || 0) > 0 ? 1 : 0,
    has_fs_write:           (s.fs_writes_blocked || 0) > 0 ? 1 : 0,
    has_os_recon:           (s.os_recon_calls || 0) > 0 ? 1 : 0,
    has_net_socket:         (s.net_socket_calls || 0) > 0 ? 1 : 0,
    has_solana_rpc:         urls.some(u => u.includes('solana')) ? 1 : 0,
    has_ngrok:              urls.some(u => u.includes('ngrok')) ? 1 : 0,
    has_blockchain_rpc:     urls.some(u => u.includes('solana') || u.includes('etherscan') || u.includes('blockchain')) ? 1 : 0,
    has_activation_star:    (t.activation_events || []).includes('*') ? 1 : 0,
    timed_out:              (report.timedOut || false) ? 1 : 0,

    // ── String evidence (for analyst review) ─────────────────────────────────
    contacted_urls:         uniq(urls).slice(0, 5).join(' | '),
    shell_commands:         uniq(commands).slice(0, 3).join(' | '),
    written_paths:          uniq(writtenPaths).slice(0, 3).join(' | '),
    decrypt_algorithms:     uniq(decryptAlgorithms).join(' | '),

    // ── Analysis metadata ─────────────────────────────────────────────────────
    analysis_timestamp:     report.analysis_timestamp || '',
    elapsed_ms:             report.elapsed_ms         || 0,
    sandbox_error:          (report.errors || []).join(' | ').slice(0, 200),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  CSV writer (no dependency on pandas)
// ─────────────────────────────────────────────────────────────────────────────

function rowsToCsv(rows) {
  if (rows.length === 0) return '';
  const headers = Object.keys(rows[0]);
  const escape  = (v) => {
    const s = String(v == null ? '' : v);
    return s.includes(',') || s.includes('"') || s.includes('\n')
      ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [
    headers.join(','),
    ...rows.map(r => headers.map(h => escape(r[h])).join(',')),
  ];
  return lines.join('\n');
}

// ─────────────────────────────────────────────────────────────────────────────
//  Main batch runner
// ─────────────────────────────────────────────────────────────────────────────

async function runBatch(args) {
  if (!args.input) { console.error('[ERROR] --input is required'); process.exit(1); }
  if (!fs.existsSync(args.input)) { console.error(`[ERROR] Input directory not found: ${args.input}`); process.exit(1); }

  fs.mkdirSync(args.output, { recursive: true });

  // Collect all .vsix files in the input directory
  const vsixFiles = fs.readdirSync(args.input)
    .filter(f => f.endsWith('.vsix'))
    .map(f => path.join(args.input, f));

  if (vsixFiles.length === 0) {
    console.error('[ERROR] No .vsix files found in:', args.input);
    process.exit(1);
  }

  console.log(`\n${'═'.repeat(68)}`);
  console.log('  VSIX BATCH DYNAMIC ANALYSIS');
  console.log(`  Input  : ${args.input}  (${vsixFiles.length} files)`);
  console.log(`  Output : ${args.output}`);
  console.log(`  Label  : ${args.label !== null ? args.label : 'unset'}`);
  console.log(`  Timeout: ${args.timeout} ms per extension`);
  console.log('═'.repeat(68) + '\n');

  const allRows    = [];
  const allReports = [];
  let processed    = 0;
  let errored      = 0;

  for (const vsixPath of vsixFiles) {
    const baseName  = path.basename(vsixPath, '.vsix');
    const safeBase  = baseName.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80);
    const tmpDir    = path.join(os.tmpdir(), `vsix-sandbox-${safeBase}-${Date.now()}`);
    const resultDir = path.join(args.output, safeBase);

    processed++;
    process.stdout.write(`\n[${processed}/${vsixFiles.length}] ${baseName}\n`);
    process.stdout.write(`  Unpacking → ${tmpDir}\n`);

    let extensionDir;
    try {
      extensionDir = unpackVsix(vsixPath, tmpDir);
    } catch (e) {
      console.error(`  [ERROR] Unpack failed: ${e.message}`);
      errored++;
      allRows.push({ name: baseName, sandbox_error: 'UNPACK_FAILED', label: args.label });
      continue;
    }

    process.stdout.write(`  Running sandbox (timeout ${args.timeout / 1000}s)...\n`);
    const runResult = runSandbox(extensionDir, args.timeout);

    if (runResult.timedOut) {
      console.warn(`  [TIMEOUT] Extension exceeded ${args.timeout} ms`);
    }

    // Read the execution-log.json produced by sandbox.js
    const logPath = path.join(extensionDir, 'execution-log.json');
    let report    = null;

    if (fs.existsSync(logPath)) {
      try {
        report = JSON.parse(fs.readFileSync(logPath, 'utf8'));
        if (runResult.timedOut) report.timedOut = true;

        // Copy report to results directory
        fs.mkdirSync(resultDir, { recursive: true });
        fs.copyFileSync(logPath, path.join(resultDir, 'execution-log.json'));
      } catch (e) {
        console.error(`  [ERROR] Failed to read execution-log.json: ${e.message}`);
      }
    }

    if (report) {
      const features = extractDynamicFeatures(report);
      if (args.label !== null) features.label = args.label;
      features.vsix_file = path.basename(vsixPath);
      allRows.push(features);
      allReports.push({ vsix: baseName, report });

      // Quick summary
      const s = report.summary || {};
      console.log(`  ✓ Events: ${s.total_events || 0}  critical: ${s.critical_events || 0}  network: ${s.http_requests || 0}  eval: ${s.eval_calls || 0}  exec: ${s.child_process_calls || 0}  decrypt: ${s.crypto_decrypt_calls || 0}`);
    } else {
      const row = { name: baseName, vsix_file: path.basename(vsixPath), sandbox_error: 'NO_LOG', label: args.label };
      allRows.push(row);
      errored++;
      console.log('  ✗ No execution log produced');
    }

    // Clean up temp directory unless --keep
    if (!args.keep) {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
    }
  }

  // ── Write batch summary JSON ──────────────────────────────────────────────
  const summaryPath = path.join(args.output, 'batch-summary.json');
  fs.writeFileSync(summaryPath, JSON.stringify({
    generated_at: new Date().toISOString(),
    input_dir:    args.input,
    total_files:  vsixFiles.length,
    processed:    processed,
    errored,
    label:        args.label,
    extensions:   allReports,
  }, null, 2), 'utf8');

  // ── Write combined CSV ─────────────────────────────────────────────────────
  const csvPath = path.resolve(args.output, args.csv);
  const csvContent = rowsToCsv(allRows);
  fs.writeFileSync(csvPath, csvContent, 'utf8');

  console.log('\n' + '═'.repeat(68));
  console.log('  BATCH COMPLETE');
  console.log('═'.repeat(68));
  console.log(`  Processed        : ${processed}/${vsixFiles.length}`);
  console.log(`  Errored/Skipped  : ${errored}`);
  console.log(`  Summary JSON     : ${summaryPath}`);
  console.log(`  Features CSV     : ${csvPath}`);
  console.log('═'.repeat(68) + '\n');
}

// ─────────────────────────────────────────────────────────────────────────────
//  Entry point
// ─────────────────────────────────────────────────────────────────────────────

const args = parseArgs(process.argv);
runBatch(args).catch(e => { console.error('[FATAL]', e); process.exit(1); });
