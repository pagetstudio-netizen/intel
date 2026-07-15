import { URL } from 'url';

// ── SSRF guard — shared across scan/fuzz/load-test/phishing/fintech-fraud/auth-audit ──
const BLOCKED_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,       // link-local
  /^::1$/,             // IPv6 loopback
  /^fc[0-9a-f]{2}:/i,  // IPv6 ULA
  /^fe80:/i,           // IPv6 link-local
  /^0\./,              // 0.x.x.x
  /^metadata\.google\.internal$/i,
  /^169\.254\.169\.254$/, // AWS/GCP metadata
];

export function validateTargetUrl(raw: string): { ok: true; url: string; domain: string } | { ok: false; error: string } {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, error: 'URL invalide' };
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, error: 'http/https uniquement' };
  }
  const hostname = parsed.hostname.toLowerCase();
  if (BLOCKED_PATTERNS.some((p) => p.test(hostname))) {
    return { ok: false, error: 'Adresse réseau privée ou restreinte interdite' };
  }
  // Strip credentials before storing/passing downstream
  const safe = `${parsed.protocol}//${parsed.host}${parsed.pathname}${parsed.search}`;
  return { ok: true, url: safe, domain: hostname };
}
