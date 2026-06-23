'use strict';
/**
 * data-intel.js — Sensitive-Data Intelligence & Exfiltration Taint Layer
 * ======================================================================
 * Answers the question the detector previously could NOT: when a malicious
 * extension steals data, *what exactly* is it taking, and *where* does it
 * send it?
 *
 * Two stages:
 *   1. noteRead(path, content)  — every file the extension reads is
 *      classified (SSH key? AWS creds? .env? wallet? source code?).
 *      Distinctive fingerprints of secret content are stored in a TAINT
 *      registry.
 *   2. scanExfil(destination, payload) — every outbound payload
 *      (http/https/net/fetch body or URL) is decoded (base64 / url-encode)
 *      and checked against (a) secret regexes directly and (b) the TAINT
 *      registry. A hit means "data read earlier is now leaving the machine"
 *      = confirmed exfiltration, attributed to a category + source + sink.
 *
 * Design choice: reading a secret alone is only suspicious; reading a secret
 * and then SENDING it is the malicious act. Separating READ from EXFIL keeps
 * false positives low (benign tools read source files all the time).
 *
 * Evidence is REDACTED (first/last few chars) so the report proves the theft
 * without dumping raw private keys into log files.
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

const crypto = require('crypto');

// ─────────────────────────────────────────────────────────────────────────────
//  Secret classification rules
//   pathRe    — matches the file path being read (location-based signal)
//   contentRe — matches inside the file content / payload (value-based signal)
//   sev       — severity to attach when this category is merely READ
// ─────────────────────────────────────────────────────────────────────────────

const SECRET_RULES = [
  { category: 'ssh_private_key',     sev: 'CRITICAL',
    pathRe: /(^|[\/\\])\.ssh[\/\\]/i,
    contentRe: /-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY-----/ },

  { category: 'aws_credentials',     sev: 'CRITICAL',
    pathRe: /(^|[\/\\])\.aws[\/\\](?:credentials|config)/i,
    contentRe: /aws_secret_access_key|AKIA[0-9A-Z]{16}/ },

  { category: 'gcp_credentials',     sev: 'CRITICAL',
    pathRe: /application_default_credentials\.json|[\/\\]gcloud[\/\\]/i,
    contentRe: /"private_key":\s*"-----BEGIN/ },

  { category: 'dotenv_secrets',      sev: 'CRITICAL',
    pathRe: /(^|[\/\\])\.env(\.\w+)?$/i,
    contentRe: /\b(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY)\b\s*[:=]\s*\S+/i },

  { category: 'github_token',        sev: 'CRITICAL',
    pathRe: /\.config[\/\\]gh[\/\\]|hosts\.yml/i,
    contentRe: /gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/ },

  { category: 'npm_token',           sev: 'CRITICAL',
    pathRe: /(^|[\/\\])\.npmrc$/i,
    contentRe: /npm_[A-Za-z0-9]{20,}|_authToken\s*=/ },

  { category: 'slack_token',         sev: 'CRITICAL',
    contentRe: /xox[baprs]-[A-Za-z0-9-]{10,}/ },

  { category: 'google_api_key',      sev: 'CRITICAL',
    contentRe: /AIza[0-9A-Za-z\-_]{35}/ },

  { category: 'openai_key',          sev: 'CRITICAL',
    contentRe: /sk-(?:proj-)?[A-Za-z0-9]{20,}/ },

  { category: 'generic_bearer',      sev: 'WARN',
    contentRe: /bearer\s+[A-Za-z0-9._\-]{15,}/i },

  { category: 'crypto_wallet',       sev: 'CRITICAL',
    pathRe: /(id\.json|wallet\.json|keystore|MetaMask|[\/\\]solana[\/\\]|\.config[\/\\]solana)/i,
    // 64-hex secret key, BIP39 mnemonic field, or Solana keypair byte array
    contentRe: /"mnemonic"\s*:|\b[0-9a-fA-F]{64}\b|\[\s*\d{1,3}(?:\s*,\s*\d{1,3}){31,}\s*\]/ },

  { category: 'seed_phrase',         sev: 'CRITICAL',
    // heuristic: 12–24 lowercase words in a row (BIP39 style)
    contentRe: /\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b/ },

  { category: 'browser_credentials', sev: 'CRITICAL',
    pathRe: /(Login Data|Cookies|cookies\.sqlite|Local State|logins\.json|key4\.db)/i },

  { category: 'vscode_secrets',      sev: 'CRITICAL',
    pathRe: /(Code[\/\\]User[\/\\]|globalStorage|\.vscode[\/\\])/i,
    contentRe: /"?(?:sessionToken|access_token|refresh_token|serviceMachineId)"?\s*[:=]/i },

  { category: 'shell_history',       sev: 'WARN',
    pathRe: /\.(?:bash|zsh|sh)_history$/i },

  { category: 'system_passwd',       sev: 'CRITICAL',
    pathRe: /^\/etc\/(?:passwd|shadow)$/ },

  { category: 'source_code',         sev: 'WARN', quietRead: true,
    pathRe: /\.(?:js|ts|jsx|tsx|py|java|go|rs|c|cpp|cs|rb|php|sol)$/i },
];

// ─────────────────────────────────────────────────────────────────────────────
//  Registries (per-process; one sandbox.js run = one extension)
// ─────────────────────────────────────────────────────────────────────────────

const TAINT  = [];   // { category, token, source }  — fingerprints of read secrets
const STOLEN = [];   // { destination, categories, via, evidence, source }

const MAX_TAINT_TOKENS = 80;
const MIN_TOKEN_LEN     = 12;

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

function toStr(x) {
  if (x == null) return '';
  if (Buffer.isBuffer(x)) return x.toString('utf8');
  return String(x);
}

function isPrintable(s) {
  if (!s) return false;
  let printable = 0;
  const n = Math.min(s.length, 2000);
  for (let i = 0; i < n; i++) {
    const c = s.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c > 160) printable++;
  }
  return printable / n > 0.85;
}

/** Mask the middle of a secret so the report proves it without leaking it. */
function redact(s) {
  s = toStr(s).replace(/\s+/g, ' ').trim();
  if (s.length <= 12) return s.slice(0, 2) + '***' + s.slice(-2);
  return s.slice(0, 4) + '…[' + s.length + 'B]…' + s.slice(-4);
}

/** Produce decoded variants of an outbound payload so encoded exfil is caught. */
function decodeLayers(s) {
  s = toStr(s);
  const out = [s];
  const seen = new Set([s]);
  const push = (v) => { if (v && !seen.has(v)) { seen.add(v); out.push(v); } };

  // whole-string base64
  const t = s.trim();
  if (/^[A-Za-z0-9+/=\s]{16,}$/.test(t)) {
    try { const d = Buffer.from(t, 'base64').toString('utf8'); if (isPrintable(d)) push(d); } catch (e) {}
  }
  // embedded base64 blobs
  const blobs = s.match(/[A-Za-z0-9+/]{24,}={0,2}/g) || [];
  for (const b of blobs.slice(0, 12)) {
    try { const d = Buffer.from(b, 'base64').toString('utf8'); if (isPrintable(d) && d.length > 8) push(d); } catch (e) {}
  }
  // url-encoded
  try { const u = decodeURIComponent(s.replace(/\+/g, ' ')); push(u); } catch (e) {}
  // hex blob
  const hex = s.match(/\b[0-9a-fA-F]{32,}\b/);
  if (hex) { try { const d = Buffer.from(hex[0], 'hex').toString('utf8'); if (isPrintable(d)) push(d); } catch (e) {} }
  return out;
}

/** Classify a path against location-based rules. */
function classifyPath(p) {
  p = toStr(p);
  const hits = [];
  for (const r of SECRET_RULES) {
    if (r.pathRe && r.pathRe.test(p)) hits.push({ category: r.category, sev: r.sev });
  }
  return hits;
}

/** Classify content against value-based rules; returns {category,sev,token}. */
function classifyContent(s) {
  s = toStr(s);
  if (!s) return [];
  const hits = [];
  for (const r of SECRET_RULES) {
    if (!r.contentRe) continue;
    const m = s.match(r.contentRe);
    if (m) hits.push({ category: r.category, sev: r.sev, token: redact(m[0]) });
  }
  return hits;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 1 — record a file read, classify it, register taint
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @param {string}   filePath
 * @param {Buffer|string} content   (may be undefined if read failed)
 * @param {Function} logEvent       sandbox.js logger (module, fn, args, sev)
 */
function noteRead(filePath, content, logEvent) {
  const p   = toStr(filePath);
  const str = content != null ? toStr(content) : '';

  const cats = new Map(); // category -> sev
  for (const h of classifyPath(p))            cats.set(h.category, h.sev);
  const contentHits = classifyContent(str);
  for (const h of contentHits)                cats.set(h.category, h.sev);

  if (cats.size === 0) return null;

  const categories = [...cats.keys()];
  const worstSev   = [...cats.values()].includes('CRITICAL') ? 'CRITICAL' : 'WARN';

  // Register taint fingerprints so we can detect this data leaving later.
  registerTaint(categories[0], str, contentHits, p);

  // "Quiet" categories (e.g. source_code) are tracked for taint but NOT logged
  // as a sensitive read — benign tools read source files constantly.
  const quietCats = new Set(SECRET_RULES.filter(r => r.quietRead).map(r => r.category));
  const reportable = categories.filter(c => !quietCats.has(c));
  if (reportable.length === 0) return { categories, sev: worstSev, quiet: true };

  if (typeof logEvent === 'function') {
    logEvent('data', 'sensitive_read', {
      path:        p,
      categories:  reportable.join(', '),
      evidence:    contentHits.map(h => `${h.category}:${h.token}`).join(' | ') || '(path-based)',
      bytes:       str.length,
    }, worstSev);
  }
  return { categories, sev: worstSev };
}

function registerTaint(defaultCat, str, contentHits, source) {
  // 1) exact secret tokens found by regex (strongest fingerprints)
  for (const h of contentHits) {
    // re-extract the RAW (un-redacted) token for matching
    const rule = SECRET_RULES.find(r => r.category === h.category && r.contentRe);
    const m = rule && str.match(rule.contentRe);
    if (m && m[0].length >= MIN_TOKEN_LEN) addTaint(h.category, m[0], source);
  }
  // 2) a few distinctive raw lines (covers proprietary source code / configs
  //    that have no famous regex but must still be tracked if exfiltrated)
  if (str && TAINT.length < MAX_TAINT_TOKENS) {
    const lines = str.split(/\r?\n/).map(l => l.trim()).filter(l => l.length >= 16);
    for (const l of lines.slice(0, 3)) addTaint(defaultCat, l, source);
  }
}

function addTaint(category, token, source) {
  if (!token || token.length < MIN_TOKEN_LEN) return;
  if (TAINT.length >= MAX_TAINT_TOKENS) return;
  if (TAINT.some(t => t.token === token)) return;
  TAINT.push({ category, token, source });
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 2 — scan an outbound payload for secrets / tainted data
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @param {string} destination  e.g. 'https://evil.tld/c2' or 'host:port'
 * @param {string} payload      request body and/or URL
 * @param {Function} logEvent
 * @returns {Object|null} exfil record if a leak was detected
 */
function scanExfil(destination, payload, logEvent) {
  const dest    = toStr(destination) || 'unknown';
  const layers  = decodeLayers(payload);

  const found   = new Map();  // category -> { via, evidence }

  for (const layer of layers) {
    // (a) direct secret patterns in the (decoded) payload
    for (const h of classifyContent(layer)) {
      if (!found.has(h.category)) found.set(h.category, { via: 'pattern', evidence: h.token });
    }
    // (b) tainted data (something read earlier now leaving)
    for (const t of TAINT) {
      if (layer.includes(t.token)) {
        const prev = found.get(t.category);
        // taint is the stronger signal — prefer it, and record the source file
        found.set(t.category, { via: 'taint', evidence: redact(t.token), source: t.source });
      }
    }
  }

  if (found.size === 0) return null;

  const categories = [...found.keys()];
  const evidence   = [...found.entries()].map(([cat, info]) =>
    `${cat} (${info.via}${info.source ? ' from ' + info.source : ''}: ${info.evidence})`);

  const rec = { destination: dest, categories, evidence,
                via: [...found.values()].some(i => i.via === 'taint') ? 'taint' : 'pattern' };
  STOLEN.push(rec);

  if (typeof logEvent === 'function') {
    logEvent('data', 'exfiltration', {
      destination: dest,
      stole:       categories.join(', '),
      evidence:    evidence.join(' | ').slice(0, 400),
      method:      rec.via,
    }, 'CRITICAL');
  }
  return rec;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Aggregation for the final report
// ─────────────────────────────────────────────────────────────────────────────

function getStolenSummary() {
  const categories  = [...new Set(STOLEN.flatMap(s => s.categories))];
  const destinations= [...new Set(STOLEN.map(s => s.destination))];
  return {
    data_stolen:       categories.length > 0,
    categories,
    destinations,
    exfiltration_count: STOLEN.length,
    events:            STOLEN,
    secrets_read:      [...new Set(TAINT.map(t => t.category))],
  };
}

function reset() { TAINT.length = 0; STOLEN.length = 0; }

module.exports = {
  noteRead, scanExfil, getStolenSummary, reset,
  classifyPath, classifyContent, decodeLayers, redact, SECRET_RULES,
};
