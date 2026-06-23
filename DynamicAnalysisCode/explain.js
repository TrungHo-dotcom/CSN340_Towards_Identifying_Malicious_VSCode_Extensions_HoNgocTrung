#!/usr/bin/env node
'use strict';
/**
 * explain.js — Forensic Behaviour Report Generator
 * ================================================
 * Turns the raw execution-log.json (+ static-analysis.json) of each analysed
 * sample into a HUMAN-READABLE forensic report that answers the three questions
 * a reviewer actually cares about:
 *     1. WHAT did the extension do at runtime?
 *     2. WHAT did it send out, and what was in those messages?
 *     3. WHY is that behaviour classified as malicious?
 *
 * It also maps each observed behaviour to the relevant MITRE ATT&CK technique,
 * so the output is suitable for an academic write-up / research paper.
 *
 * Usage:
 *   node explain.js ./results                 # whole results tree → per-sample + combined
 *   node explain.js ./results/<sample>/extension/execution-log.json   # one sample
 *
 * Writes  analysis.md  next to each execution-log.json, and  ANALYSIS.md  at the
 * root summarising every sample (sorted by verdict).
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

const fs   = require('fs');
const path = require('path');

// ── tiny helpers ─────────────────────────────────────────────────────────────
const readJson = (p) => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return null; } };
const clip = (s, n) => { s = String(s == null ? '' : s).replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n) + '…' : s; };
const uniq = (a) => [...new Set(a)];

// ── behaviour detectors → narrative + MITRE technique ────────────────────────
function analyseBehaviour(log, stat) {
  const events  = log.events || [];
  const beacons = log.outbound_messages || [];
  const s       = log.summary || {};
  const ev      = (mod, re) => events.filter(e => e.module === mod && (!re || re.test(e.function_hooked)));

  const behaviours = [];   // { title, technique, detail, evidence[] }
  const add = (title, technique, detail, evidence) => behaviours.push({ title, technique, detail, evidence: evidence || [] });

  // ── command / shell execution ──────────────────────────────────────────────
  const cp = ev('child_process');
  if (cp.length) {
    const cmds = uniq(cp.map(e => [e.arguments.command, e.arguments.args, e.arguments.file, e.arguments.modulePath].filter(Boolean).join(' ')));
    const cradle = cmds.find(c => /(powershell|cmd\.exe|certutil|bitsadmin|curl|wget|invoke-webrequest)/i.test(c) && /(https?:\/\/|\.bat|\.ps1|\.exe|catbox|pastebin)/i.test(c));
    if (cradle) add(
      'Download-and-execute cradle',
      'T1059 (Command Execution) + T1105 (Ingress Tool Transfer)',
      'The extension launched a living-off-the-land binary (LOLBIN) that downloads a remote payload and runs it — a classic two-stage stager that fetches the real malware after install.',
      cmds);
    else add(
      'OS process / shell execution',
      'T1059 (Command and Scripting Interpreter)',
      'The extension spawned external operating-system processes via child_process, something a normal UI extension has no reason to do.',
      cmds);
  }

  // ── reverse shell ───────────────────────────────────────────────────────────
  const sock = ev('net', /connect|createConnection|Socket/i);
  if (sock.length && cp.length) {
    const dests = uniq(sock.map(e => `${e.arguments.host || '?'}:${e.arguments.port || '?'}`));
    add('Reverse shell',
        'T1059 + T1571 (Non-Standard Port C2)',
        'A raw TCP socket was opened to a remote host and bound to a system shell, giving the attacker interactive remote command execution on the victim machine.',
        dests);
  } else if (sock.length) {
    add('Raw TCP connection',
        'T1095 (Non-Application Layer Protocol)',
        'The extension opened a raw TCP socket to an external host (not normal HTTP), often used for covert C2 channels.',
        uniq(sock.map(e => `${e.arguments.host || '?'}:${e.arguments.port || '?'}`)));
  }

  // ── dropper (download a binary to disk + launch) ───────────────────────────
  const dlBeacon = beacons.filter(b => /\.(exe|dll|bin|ps1|scr|msi)\b/i.test(b.destination || ''));
  const fsWrite  = ev('fs', /writeFile|createWriteStream/);
  if (dlBeacon.length) add(
    'Payload download (dropper)',
    'T1105 (Ingress Tool Transfer)',
    'The extension downloaded an executable/DLL from a remote server' + (cp.length ? ' and attempted to launch it' : '') + '.',
    uniq(dlBeacon.map(b => b.destination)));

  // ── data exfiltration / C2 beacon ──────────────────────────────────────────
  const SKIP = new Set(['', 'localhost', '127.0.0.1', '0.0.0.0']);
  const sentBeacons = beacons.filter(b => (b.body_bytes || (b.body || '').length) > 0 && !SKIP.has(b.host));
  if (sentBeacons.length) {
    const recon = ev('os', /userInfo|homedir|hostname|networkInterfaces/).length > 0;
    add(recon ? 'Host reconnaissance + exfiltration' : 'Outbound C2 / data transmission',
        recon ? 'T1082 (System Information Discovery) + T1567 (Exfiltration Over Web)' : 'T1071 (Application-Layer C2)',
        recon
          ? 'The extension harvested information about the host (username, home directory, platform, etc.) and transmitted it to an external server.'
          : 'The extension transmitted data to an external endpoint.',
        sentBeacons.map(b => `${b.method} ${b.host || b.destination} :: ${clip(b.decoded || b.body, 160)}`));
  }

  // ── runtime-decrypted payload ───────────────────────────────────────────────
  const dec = ev('crypto', /createDecipheriv/);
  if (dec.length) add(
    'Runtime-decrypted payload',
    'T1027 (Obfuscated/Encrypted Files) + T1140 (Deobfuscate/Decode)',
    'The extension decrypted an embedded payload in memory at runtime (AES), a technique used to hide the malicious code from static scanners.',
    uniq(dec.map(e => `${e.arguments.algorithm} key=${clip(e.arguments.key_preview, 24)}`)));

  // ── dynamic code evaluation ─────────────────────────────────────────────────
  const evl = events.filter(e => e.module === 'eval');
  if (evl.length) add(
    'Dynamic code evaluation',
    'T1059 + T1140',
    'The extension built and executed code at runtime via eval()/new Function(), a hallmark of multi-stage / obfuscated malware.',
    uniq(evl.map(e => clip(e.arguments.code_preview, 120))));

  // ── silent remote install ───────────────────────────────────────────────────
  if (s.outbound_message_count > 0 && /installExtension/i.test(JSON.stringify(stat && stat.iocs || []))) add(
    'Silent remote extension install',
    'T1195 (Supply-Chain Compromise)',
    'The extension fetched content from a non-marketplace server and used the VS Code API to silently install a downloaded VSIX, bypassing marketplace review.',
    []);

  // ── obfuscation markers (no executable behaviour) ───────────────────────────
  const inv = (stat && stat.invisible_unicode) || 0;
  if (inv > 8) add(
    'Invisible-Unicode obfuscation',
    'T1027.010 (Command Obfuscation)',
    `The source contains ${inv} invisible Unicode codepoints (zero-width / variation selectors) — the GlassWorm technique for hiding malicious code from human reviewers and scanners.`,
    []);

  // ── static-only / dormant ───────────────────────────────────────────────────
  if (!behaviours.length) {
    const statReasons = (stat && stat.verdict && stat.verdict.reasons) || [];
    if (statReasons.length) add(
      'Static indicators only (no runtime detonation)',
      'T1195 (Supply-Chain) / dormant first stage',
      'No malicious behaviour executed during analysis. The sample was flagged by static indicators only — consistent with a dormant first-stage package that receives its payload via a later update.',
      statReasons.map(r => r.reason));
    else add(
      'No observable malicious behaviour',
      'n/a',
      'Neither dynamic execution nor static scanning revealed a payload. This is either a clean (re-published) package or a dormant first stage whose malware is delivered later — undetectable by content/behaviour analysis alone.',
      []);
  }

  return behaviours;
}

// ── collect IOCs ─────────────────────────────────────────────────────────────
function collectIocs(log) {
  const s = log.summary || {};
  const beacons = log.outbound_messages || [];
  return {
    hosts:    uniq([...(s.unique_hosts_contacted || []), ...beacons.map(b => b.host).filter(Boolean)]).filter(h => !['', 'localhost', '127.0.0.1'].includes(h)),
    commands: uniq(s.shell_commands_attempted || []),
    fileWrites: uniq((log.events || []).filter(e => e.module === 'fs' && /writeFile|createWriteStream/.test(e.function_hooked) && e.arguments && e.arguments.path).map(e => e.arguments.path)),
  };
}

// ── render one sample → markdown ─────────────────────────────────────────────
function renderSample(log, stat) {
  const t = log.target || {};
  const v = log.verdict || {};
  const sv = (stat && stat.verdict) || {};
  const finalVerdict = rankName(Math.max(rank(v.verdict), rank(sv.verdict)));
  const behaviours = analyseBehaviour(log, stat);
  const iocs = collectIocs(log);
  const beacons = log.outbound_messages || [];

  const L = [];
  const icon = finalVerdict === 'MALICIOUS' ? '🔴' : finalVerdict === 'SUSPICIOUS' ? '🟡' : '🟢';
  L.push(`## ${icon} ${t.publisher || '?'}.${t.name || '?'}  (v${t.version || '?'})`);
  L.push('');
  L.push(`**Final verdict: ${finalVerdict}**  —  dynamic ${v.verdict || 'n/a'} (score ${v.score != null ? v.score : '-'}), static ${sv.verdict || 'n/a'} (score ${sv.score != null ? sv.score : '-'})`);
  L.push('');

  // threat-intel breakdown (the report's required log fields)
  const intel = log.intel;
  if (intel && finalVerdict !== 'BENIGN') {
    L.push('### Threat intelligence (log breakdown)');
    L.push(`- **Purpose / family:** ${intel.purpose}${(intel.families||[]).length ? ' [' + intel.families.join(', ') + ']' : ''}`);
    if ((intel.actions||[]).length)       L.push(`- **Actions executed:** ${intel.actions.join('; ')}`);
    if ((intel.data_targeted||[]).length) L.push(`- **Data targeted/stolen:** ${intel.data_targeted.join(', ')}`);
    if ((intel.c2_indicators||[]).length) L.push(`- **C2 indicators:** ${intel.c2_indicators.join(', ')}`);
    if ((intel.network||[]).length) {
      L.push('- **Network traffic:**');
      for (const n of intel.network.slice(0, 12))
        L.push(`    - ${n.transport}/${n.method || '-'} → domain=\`${n.domain || '-'}\` ip=\`${n.ip || '-'}\` port=\`${n.port || '-'}\`${n.body_preview ? '  body=`' + clip(n.body_preview, 100) + '`' : ''}`);
    }
    L.push('');
  }

  // executive summary
  L.push('### Executive summary');
  L.push(behaviours.map(b => `- **${b.title}** — ${b.detail}`).join('\n'));
  L.push('');

  // behaviours with MITRE + evidence
  L.push('### Observed behaviour & MITRE ATT&CK mapping');
  L.push('| Behaviour | MITRE technique | Evidence |');
  L.push('|---|---|---|');
  for (const b of behaviours) {
    const evi = b.evidence.length ? b.evidence.map(e => '`' + clip(e, 90) + '`').join('<br>') : '—';
    L.push(`| ${b.title} | ${b.technique} | ${evi} |`);
  }
  L.push('');

  // outbound messages (the key requirement: what it sent)
  if (beacons.length) {
    L.push('### Outbound messages (what the extension sent)');
    L.push('| # | Transport | Method | Destination | Body / decoded content |');
    L.push('|---|---|---|---|---|');
    beacons.slice(0, 25).forEach((b, i) => {
      const content = clip(b.decoded || b.body || '(empty)', 180).replace(/\|/g, '\\|');
      L.push(`| ${i + 1} | ${b.transport} | ${b.method || ''} | ${b.host || b.destination} | ${content} |`);
    });
    if (beacons.length > 25) L.push(`\n_(+${beacons.length - 25} more — see execution-log.json)_`);
    L.push('');
  }

  // IOCs
  L.push('### Indicators of Compromise (IOCs)');
  if (iocs.hosts.length)      L.push(`- **Hosts/IPs contacted:** ${iocs.hosts.map(h => '`' + h + '`').join(', ')}`);
  if (iocs.commands.length)   L.push(`- **Shell commands:** ${iocs.commands.map(c => '`' + clip(c, 120) + '`').join(', ')}`);
  if (iocs.fileWrites.length) L.push(`- **Files written:** ${iocs.fileWrites.map(f => '`' + clip(f, 100) + '`').join(', ')}`);
  if (!iocs.hosts.length && !iocs.commands.length && !iocs.fileWrites.length) L.push('- _(none captured at runtime)_');
  L.push('');

  // why malicious
  L.push('### Why this is classified as malicious');
  const reasons = [...(v.reasons || []).map(r => `(dynamic) ${r.reason}`), ...((sv.reasons || []).map(r => `(static) ${r.reason}`))];
  L.push(reasons.length ? reasons.map(r => `- ${r}`).join('\n') : '- No malicious indicators were observed (see Limitations).');
  L.push('');
  return { md: L.join('\n'), finalVerdict, sample: `${t.publisher || '?'}.${t.name || '?'}` };
}

const RANKN = ['BENIGN', 'SUSPICIOUS', 'MALICIOUS'];
function rank(v) { return Math.max(0, RANKN.indexOf(v)); }
function rankName(r) { return RANKN[r] || 'BENIGN'; }

// ── walk results tree ────────────────────────────────────────────────────────
function findLogs(root, out = []) {
  for (const e of (() => { try { return fs.readdirSync(root, { withFileTypes: true }); } catch { return []; } })()) {
    const full = path.join(root, e.name);
    if (e.isDirectory()) { if (e.name !== 'node_modules') findLogs(full, out); }
    else if (e.name === 'execution-log.json') out.push(full);
  }
  return out;
}

function main() {
  const input = process.argv[2];
  if (!input) { console.error('usage: node explain.js <results-dir | execution-log.json>'); process.exit(1); }
  const abs = path.resolve(input);
  const logs = fs.statSync(abs).isFile() ? [abs] : findLogs(abs);
  if (!logs.length) { console.error('no execution-log.json found under ' + abs); process.exit(1); }

  const summaries = [];
  for (const logPath of logs) {
    const log = readJson(logPath); if (!log) continue;
    const stat = readJson(path.join(path.dirname(logPath), 'static-analysis.json'));
    const { md, finalVerdict, sample } = renderSample(log, stat);
    fs.writeFileSync(path.join(path.dirname(logPath), 'analysis.md'), `# Forensic analysis — ${sample}\n\n${md}`, 'utf8');
    summaries.push({ sample, finalVerdict, md, logPath });
  }

  // combined report, malicious first
  summaries.sort((a, b) => rank(b.finalVerdict) - rank(a.finalVerdict) || a.sample.localeCompare(b.sample));
  const counts = summaries.reduce((m, s) => (m[s.finalVerdict] = (m[s.finalVerdict] || 0) + 1, m), {});
  const head = [
    '# Dataset forensic analysis report', '',
    `Generated: ${new Date().toISOString()}`,
    `Samples: ${summaries.length}  —  MALICIOUS ${counts.MALICIOUS || 0}, SUSPICIOUS ${counts.SUSPICIOUS || 0}, BENIGN ${counts.BENIGN || 0}`, '',
    '| Sample | Verdict |', '|---|---|',
    ...summaries.map(s => `| ${s.sample} | ${s.finalVerdict} |`), '',
    '---', '',
  ];
  const out = path.join(fs.statSync(abs).isFile() ? path.dirname(abs) : abs, 'ANALYSIS.md');
  fs.writeFileSync(out, head.join('\n') + '\n' + summaries.map(s => s.md).join('\n---\n\n'), 'utf8');

  console.log(`\n  Wrote ${summaries.length} per-sample analysis.md files`);
  console.log(`  Combined report → ${out}`);
  console.log(`  MALICIOUS ${counts.MALICIOUS || 0}  SUSPICIOUS ${counts.SUSPICIOUS || 0}  BENIGN ${counts.BENIGN || 0}\n`);
}

main();
