import { Router, Request, Response } from 'express';
import { pool } from '../db';
import { URL } from 'url';
import * as dns from 'dns/promises';
import * as https from 'https';

const router = Router();

// ── SSRF guard (same as load-test) ───────────────────────────────────────────
const BLOCKED = [
  /^localhost$/i, /^127\./, /^10\./, /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./, /^169\.254\./, /^::1$/, /^0\./,
  /^metadata\.google\.internal$/i, /^169\.254\.169\.254$/,
];
function validateUrl(raw: string): { ok: true; url: string; domain: string } | { ok: false; error: string } {
  let p: URL;
  try { p = new URL(raw); } catch { return { ok: false, error: 'URL invalide' }; }
  if (!['http:', 'https:'].includes(p.protocol)) return { ok: false, error: 'http/https uniquement' };
  const h = p.hostname.toLowerCase();
  if (BLOCKED.some(r => r.test(h))) return { ok: false, error: 'Adresse réseau privée interdite' };
  return { ok: true, url: `${p.protocol}//${p.host}${p.pathname}`, domain: p.hostname };
}

// ── GET /api/phishing ─────────────────────────────────────────────────────────
router.get('/', async (_req, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM phishing_assessments ORDER BY created_at DESC LIMIT 50');
    res.json(rows);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

// ── GET /api/phishing/:id ─────────────────────────────────────────────────────
router.get('/:id', async (req, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM phishing_assessments WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

// ── POST /api/phishing ────────────────────────────────────────────────────────
router.post('/', async (req: Request, res: Response) => {
  const validated = validateUrl(String(req.body?.target_url ?? ''));
  if (!validated.ok) return res.status(400).json({ error: validated.error });

  let job: Record<string, unknown>;
  try {
    const { rows } = await pool.query(
      `INSERT INTO phishing_assessments (target_url, domain, status) VALUES ($1, $2, 'running') RETURNING *`,
      [validated.url, validated.domain]
    );
    job = rows[0];
  } catch { return res.status(500).json({ error: 'Failed to create assessment' }); }

  res.status(202).json(job);

  // Run async
  runAssessment(validated.url, validated.domain)
    .then(async result => {
      await pool.query(
        `UPDATE phishing_assessments SET
          status='completed', risk_score=$1, risk_level=$2,
          checks=$3, summary=$4, completed_at=NOW()
         WHERE id=$5`,
        [result.score, result.level, JSON.stringify(result.checks), result.summary, job.id]
      );
    })
    .catch(async err => {
      await pool.query(
        `UPDATE phishing_assessments SET status='failed', summary=$1, completed_at=NOW() WHERE id=$2`,
        [`Erreur d'analyse: ${err.message}`, job.id]
      );
    });
});

// ── Core assessment logic ─────────────────────────────────────────────────────
interface Check {
  id: string;
  name: string;
  category: 'email' | 'http' | 'dns' | 'ssl';
  passed: boolean;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  detail: string;
  fix: string;
}

async function fetchHeaders(url: string): Promise<Record<string, string>> {
  return new Promise((resolve) => {
    const isHttps = url.startsWith('https');
    const mod = isHttps ? https : require('http');
    const timeout = setTimeout(() => resolve({}), 8000);
    try {
      const req = mod.get(url, { timeout: 7000, headers: { 'User-Agent': 'Mozilla/5.0 SecurityAudit/1.0' } }, (res: any) => {
        clearTimeout(timeout);
        const headers: Record<string, string> = {};
        Object.entries(res.headers).forEach(([k, v]) => { headers[k.toLowerCase()] = String(v); });
        resolve(headers);
        res.destroy();
      });
      req.on('error', () => { clearTimeout(timeout); resolve({}); });
    } catch { clearTimeout(timeout); resolve({}); }
  });
}

async function lookupTxt(domain: string): Promise<string[]> {
  try {
    const records = await dns.resolveTxt(domain);
    return records.flat();
  } catch { return []; }
}

async function runAssessment(url: string, domain: string) {
  const checks: Check[] = [];

  // ── Fetch HTTP headers ────────────────────────────────────────────────────
  const headers = await fetchHeaders(url);

  // 1. X-Frame-Options (clickjacking → phishing overlay)
  const xfo = headers['x-frame-options'];
  checks.push({
    id: 'xframe',
    name: 'Protection anti-iframe (Clickjacking)',
    category: 'http',
    passed: !!(xfo && /deny|sameorigin/i.test(xfo)),
    risk: 'HIGH',
    detail: xfo
      ? `X-Frame-Options: ${xfo}`
      : 'Absent — le site peut être intégré dans un faux site de phishing (iframe overlay)',
    fix: 'Ajouter l\'en-tête: X-Frame-Options: DENY',
  });

  // 2. Content-Security-Policy frame-ancestors
  const csp = headers['content-security-policy'] ?? '';
  const hasFrameAncestors = /frame-ancestors/i.test(csp);
  checks.push({
    id: 'csp_frame',
    name: 'CSP frame-ancestors',
    category: 'http',
    passed: hasFrameAncestors,
    risk: 'HIGH',
    detail: hasFrameAncestors
      ? `CSP contient frame-ancestors`
      : 'Absent — complément manquant à X-Frame-Options pour les navigateurs modernes',
    fix: "Ajouter dans Content-Security-Policy: frame-ancestors 'none'",
  });

  // 3. HSTS (force HTTPS, bloque les attaques SSL-strip)
  const hsts = headers['strict-transport-security'];
  checks.push({
    id: 'hsts',
    name: 'HTTPS forcé (HSTS)',
    category: 'http',
    passed: !!(hsts && /max-age=\d+/i.test(hsts)),
    risk: 'MEDIUM',
    detail: hsts ? `HSTS: ${hsts}` : 'Absent — attaques SSL-strip possibles pour rediriger vers HTTP',
    fix: 'Ajouter: Strict-Transport-Security: max-age=31536000; includeSubDomains',
  });

  // 4. X-Content-Type-Options (MIME sniffing)
  const xcto = headers['x-content-type-options'];
  checks.push({
    id: 'xcto',
    name: 'MIME Sniffing Protection',
    category: 'http',
    passed: xcto === 'nosniff',
    risk: 'LOW',
    detail: xcto ? `X-Content-Type-Options: ${xcto}` : 'Absent — peut permettre l\'injection de scripts via MIME confusion',
    fix: 'Ajouter: X-Content-Type-Options: nosniff',
  });

  // 5. Referrer-Policy (fuite d'URL via phishing redirect)
  const rp = headers['referrer-policy'];
  checks.push({
    id: 'refpol',
    name: 'Referrer-Policy',
    category: 'http',
    passed: !!(rp && /no-referrer|strict-origin/i.test(rp)),
    risk: 'LOW',
    detail: rp ? `Referrer-Policy: ${rp}` : 'Absent — les URL internes peuvent fuir via des liens dans des emails de phishing',
    fix: 'Ajouter: Referrer-Policy: strict-origin-when-cross-origin',
  });

  // ── DNS / Email checks ────────────────────────────────────────────────────
  const rootDomain = domain.split('.').slice(-2).join('.');
  const txtRecords = await lookupTxt(rootDomain);
  const allTxt = txtRecords.join('\n');

  // 6. SPF (empêche l'usurpation d'email "from: @clientsite.com")
  const spf = txtRecords.find(r => r.startsWith('v=spf1'));
  checks.push({
    id: 'spf',
    name: 'Enregistrement SPF (anti-usurpation email)',
    category: 'email',
    passed: !!spf,
    risk: 'CRITICAL',
    detail: spf
      ? `SPF trouvé: ${spf.substring(0, 80)}...`
      : `Absent — n'importe qui peut envoyer des emails en se faisant passer pour @${rootDomain}`,
    fix: `Ajouter dans le DNS: TXT "v=spf1 include:_spf.${rootDomain} ~all"`,
  });

  // 7. DMARC (politique globale anti-phishing email)
  const dmarcRecords = await lookupTxt(`_dmarc.${rootDomain}`);
  const dmarc = dmarcRecords.find(r => r.startsWith('v=DMARC1'));
  const dmarcReject = dmarc && /p=(reject|quarantine)/i.test(dmarc);
  checks.push({
    id: 'dmarc',
    name: 'Politique DMARC (p=reject/quarantine)',
    category: 'email',
    passed: !!dmarcReject,
    risk: 'CRITICAL',
    detail: dmarc
      ? (dmarcReject ? `DMARC avec ${dmarc.match(/p=\w+/)?.[0]}` : `DMARC présent mais politique faible: ${dmarc}`)
      : `Absent — aucune politique DMARC pour bloquer les faux emails @${rootDomain}`,
    fix: `Ajouter dans le DNS: TXT pour _dmarc.${rootDomain} → "v=DMARC1; p=reject; rua=mailto:dmarc@${rootDomain}"`,
  });

  // 8. DKIM
  let dkimFound = false;
  for (const sel of ['default', 'google', 'mail', 'smtp', 'k1', 'dkim']) {
    try {
      await dns.resolveTxt(`${sel}._domainkey.${rootDomain}`);
      dkimFound = true; break;
    } catch { /* not found */ }
  }
  checks.push({
    id: 'dkim',
    name: 'Signature DKIM (authenticité email)',
    category: 'email',
    passed: dkimFound,
    risk: 'HIGH',
    detail: dkimFound
      ? 'Signature DKIM détectée — les emails sont signés cryptographiquement'
      : 'Absent — impossible de vérifier l\'authenticité des emails envoyés',
    fix: 'Configurer DKIM via votre fournisseur d\'email (Google Workspace, Microsoft 365, Mailgun...)',
  });

  // 9. MX Records (serveur email légitime configuré)
  let hasMx = false;
  try { const mx = await dns.resolveMx(rootDomain); hasMx = mx.length > 0; } catch {}
  checks.push({
    id: 'mx',
    name: 'Serveurs MX configurés',
    category: 'dns',
    passed: hasMx,
    risk: 'MEDIUM',
    detail: hasMx
      ? 'Serveurs MX détectés — email opérationnel'
      : `Aucun serveur MX pour ${rootDomain} — domaine sans email (moins exposé aux attaques email)`,
    fix: 'Configurer des serveurs MX si vous utilisez ce domaine pour envoyer des emails',
  });

  // ── Score calculation ─────────────────────────────────────────────────────
  const weights = { CRITICAL: 30, HIGH: 20, MEDIUM: 10, LOW: 5 };
  let maxScore = 0;
  let score = 0;
  for (const c of checks) {
    const w = weights[c.risk];
    maxScore += w;
    if (!c.passed) score += w;
  }
  const pct = Math.round((score / maxScore) * 100);

  const level = pct >= 70 ? 'CRITIQUE' : pct >= 40 ? 'ÉLEVÉ' : pct >= 20 ? 'MOYEN' : 'FAIBLE';

  const failed = checks.filter(c => !c.passed);
  const critical = failed.filter(c => c.risk === 'CRITICAL').map(c => c.name);

  const summary = pct >= 70
    ? `🚨 Site hautement vulnérable au phishing — ${failed.length} failles dont ${critical.length} critiques`
    : pct >= 40
    ? `⚠️ Risque de phishing élevé — corriger en priorité : ${critical.slice(0, 2).join(', ')}`
    : pct >= 20
    ? `⚡ Risque modéré — quelques protections manquantes à renforcer`
    : `✅ Bonne protection anti-phishing — les points critiques sont couverts`;

  return { score: pct, level, checks, summary };
}

export default router;
