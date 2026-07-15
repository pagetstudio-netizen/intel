import { scanLimiter } from '../rate-limit';
import { Router, Request, Response } from 'express';
import { pool } from '../db';
import * as https from 'https';
import * as http from 'http';
import { validateTargetUrl } from '../ssrf-guard';
import { runScan } from '../intel';

const router = Router();

// ── GET /api/security-audit ───────────────────────────────────────────────────
router.get('/', async (_req: Request, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM security_audits ORDER BY created_at DESC LIMIT 50');
    res.json(rows);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

// ── GET /api/security-audit/:id ───────────────────────────────────────────────
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM security_audits WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

// ── POST /api/security-audit ──────────────────────────────────────────────────
router.post('/', scanLimiter, async (req: Request, res: Response) => {
  const validated = validateTargetUrl(String(req.body?.target_url ?? ''));
  if (!validated.ok) return res.status(400).json({ error: validated.error });

  let job: Record<string, unknown>;
  try {
    const { rows } = await pool.query(
      `INSERT INTO security_audits (target_url, domain, status) VALUES ($1, $2, 'running') RETURNING *`,
      [validated.url, validated.domain]
    );
    job = rows[0];
  } catch { return res.status(500).json({ error: "Échec de la création de l'audit" }); }

  res.status(202).json(job);

  runFullAudit(validated.url)
    .then(async (result) => {
      await pool.query(
        `UPDATE security_audits SET
          status = 'completed', score = $1, risk_level = $2,
          findings = $3, summary = $4, completed_at = NOW()
         WHERE id = $5`,
        [result.score, result.level, JSON.stringify(result.findings), result.summary, job.id]
      );
    })
    .catch(async (err) => {
      await pool.query(
        `UPDATE security_audits SET status = 'failed', summary = $1, completed_at = NOW() WHERE id = $2`,
        [`Erreur d'audit : ${err.message}`, job.id]
      );
    });
});

// ── Types ──────────────────────────────────────────────────────────────────────
interface Finding {
  id: string;
  name: string;
  category: 'headers' | 'tls' | 'vuln';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  passed: boolean;
  description: string;
  recommendation: string;
}

// ── HTTP header fetch ───────────────────────────────────────────────────────────
interface HeadResult {
  headers: Record<string, string>;
  tlsProtocol?: string;
  tlsAuthorized?: boolean;
}

function fetchHeadInfo(url: string): Promise<HeadResult> {
  return new Promise((resolve) => {
    let parsed: URL;
    try { parsed = new URL(url); } catch { return resolve({ headers: {} }); }
    const mod = parsed.protocol === 'https:' ? https : http;
    const timer = setTimeout(() => resolve({ headers: {} }), 8000);
    try {
      const req = (mod as any).request(
        {
          hostname: parsed.hostname,
          port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
          path: parsed.pathname || '/',
          method: 'GET',
          headers: { 'User-Agent': 'Mozilla/5.0 INTEL-SecurityAudit/1.0' },
          timeout: 7000,
          rejectUnauthorized: false, // on veut observer le certificat même s'il est invalide, pour le signaler
        },
        (r: any) => {
          clearTimeout(timer);
          const headers: Record<string, string> = {};
          Object.entries(r.headers ?? {}).forEach(([k, v]) => { headers[k.toLowerCase()] = String(v); });
          const socket = r.socket;
          resolve({
            headers,
            tlsProtocol: socket?.getProtocol ? socket.getProtocol() : undefined,
            tlsAuthorized: socket?.authorized,
          });
          r.destroy();
        }
      );
      req.on('error', () => { clearTimeout(timer); resolve({ headers: {} }); });
      req.end();
    } catch { clearTimeout(timer); resolve({ headers: {} }); }
  });
}

function parseVulnFindings(output: string): { title: string; description: string; severity: string }[] {
  const findings: { title: string; description: string; severity: string }[] = [];
  let current: { title: string; description: string; severity: string } | null = null;
  for (const line of output.split('\n')) {
    const m = line.match(/^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\] (.+?) — (.+)$/);
    if (m) {
      if (current) findings.push(current);
      current = { severity: m[1], title: m[2], description: m[3] };
    }
  }
  if (current) findings.push(current);
  return findings;
}

// ── Core audit logic — combine security headers + TLS + Rust vuln scan ─────────
async function runFullAudit(targetUrl: string) {
  const findings: Finding[] = [];

  const head = await fetchHeadInfo(targetUrl);
  const h = head.headers;

  const headerChecks: Array<Omit<Finding, 'passed' | 'description'> & { check: () => boolean; ok: string; bad: string }> = [
    {
      id: 'hsts', name: 'HTTP Strict Transport Security (HSTS)', category: 'headers', severity: 'MEDIUM',
      check: () => /max-age=\d+/i.test(h['strict-transport-security'] ?? ''),
      ok: `HSTS actif : ${h['strict-transport-security']}`,
      bad: 'Absent — les connexions HTTP ne sont pas automatiquement redirigées/forcées vers HTTPS',
      recommendation: 'Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains',
    },
    {
      id: 'csp', name: 'Content-Security-Policy', category: 'headers', severity: 'HIGH',
      check: () => !!h['content-security-policy'],
      ok: 'CSP présent',
      bad: 'Absent — aucune restriction sur les sources de scripts/styles, expose à des XSS plus dangereux',
      recommendation: "Définir une politique CSP stricte, ex : default-src 'self'; script-src 'self'",
    },
    {
      id: 'xfo', name: 'X-Frame-Options', category: 'headers', severity: 'MEDIUM',
      check: () => /deny|sameorigin/i.test(h['x-frame-options'] ?? ''),
      ok: `X-Frame-Options: ${h['x-frame-options']}`,
      bad: 'Absent — le site peut être intégré dans un iframe pour du clickjacking',
      recommendation: 'Ajouter : X-Frame-Options: DENY (ou CSP frame-ancestors)',
    },
    {
      id: 'xcto', name: 'X-Content-Type-Options', category: 'headers', severity: 'LOW',
      check: () => h['x-content-type-options'] === 'nosniff',
      ok: 'X-Content-Type-Options: nosniff',
      bad: 'Absent — le navigateur peut interpréter un fichier avec un type MIME différent de celui déclaré',
      recommendation: 'Ajouter : X-Content-Type-Options: nosniff',
    },
    {
      id: 'refpol', name: 'Referrer-Policy', category: 'headers', severity: 'LOW',
      check: () => /no-referrer|strict-origin/i.test(h['referrer-policy'] ?? ''),
      ok: `Referrer-Policy: ${h['referrer-policy']}`,
      bad: 'Absent — les URL internes (avec tokens éventuels) peuvent fuir via l\'en-tête Referer',
      recommendation: 'Ajouter : Referrer-Policy: strict-origin-when-cross-origin',
    },
    {
      id: 'permspolicy', name: 'Permissions-Policy', category: 'headers', severity: 'INFO',
      check: () => !!h['permissions-policy'],
      ok: 'Permissions-Policy présent',
      bad: 'Absent — les API navigateur sensibles (caméra, géoloc...) ne sont pas explicitement restreintes',
      recommendation: "Ajouter : Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
    {
      id: 'serververs', name: "En-tête Server / X-Powered-By (fuite d'information)", category: 'headers', severity: 'LOW',
      check: () => !h['x-powered-by'] && !/\/[\d.]+/.test(h['server'] ?? ''),
      ok: 'Aucune version de serveur/framework exposée',
      bad: `Version exposée : ${[h['server'], h['x-powered-by']].filter(Boolean).join(', ')} — facilite le ciblage de CVE connues`,
      recommendation: "Supprimer ou masquer les en-têtes Server et X-Powered-By.",
    },
  ];

  for (const c of headerChecks) {
    const passed = c.check();
    findings.push({
      id: c.id, name: c.name, category: c.category, severity: c.severity, passed,
      description: passed ? c.ok : c.bad,
      recommendation: c.recommendation,
    });
  }

  // TLS
  if (targetUrl.startsWith('https')) {
    const tlsOk = head.tlsAuthorized !== false;
    findings.push({
      id: 'tls_cert', name: 'Certificat TLS valide', category: 'tls', severity: 'HIGH', passed: tlsOk,
      description: tlsOk ? `Certificat valide (${head.tlsProtocol ?? 'TLS'})` : 'Certificat invalide, auto-signé ou expiré — le navigateur affichera un avertissement de sécurité',
      recommendation: 'Utiliser un certificat émis par une autorité reconnue (ex : Let\'s Encrypt) et le renouveler avant expiration.',
    });
    const oldProtocol = head.tlsProtocol && /TLSv1(\.0|\.1)?$|SSLv/i.test(head.tlsProtocol);
    findings.push({
      id: 'tls_version', name: 'Version TLS moderne', category: 'tls', severity: 'MEDIUM', passed: !oldProtocol,
      description: head.tlsProtocol ? `Protocole négocié : ${head.tlsProtocol}` : 'Impossible de déterminer la version TLS',
      recommendation: 'Désactiver TLS 1.0/1.1 et SSLv3 ; n\'accepter que TLS 1.2+.',
    });
  } else {
    findings.push({
      id: 'no_https', name: 'HTTPS non utilisé', category: 'tls', severity: 'CRITICAL', passed: false,
      description: "La cible répond en HTTP simple — tout le trafic (identifiants, cookies) circule en clair",
      recommendation: 'Migrer vers HTTPS et rediriger tout le trafic HTTP vers HTTPS.',
    });
  }

  // Vulnerability scan (moteur Rust) — best effort, ne bloque pas le rapport s'il échoue
  try {
    const output = await runScan({ target: targetUrl, deep: true, timeout: 60 });
    const vulns = parseVulnFindings(output);
    for (const v of vulns) {
      findings.push({
        id: `vuln_${v.title.toLowerCase().replace(/[^a-z0-9]+/g, '_').slice(0, 40)}`,
        name: v.title,
        category: 'vuln',
        severity: (v.severity as Finding['severity']) ?? 'INFO',
        passed: false,
        description: v.description,
        recommendation: 'Voir le détail dans l\'onglet Scanner pour le correctif suggéré par le moteur.',
      });
    }
  } catch {
    // Le binaire Rust peut être indisponible — l'audit se rabat sur headers/TLS uniquement.
  }

  // ── Score ────────────────────────────────────────────────────────────────────
  const weights: Record<Finding['severity'], number> = { CRITICAL: 30, HIGH: 20, MEDIUM: 10, LOW: 5, INFO: 2 };
  let maxScore = 0;
  let deducted = 0;
  for (const f of findings) {
    const w = weights[f.severity] ?? 5;
    maxScore += w;
    if (!f.passed) deducted += w;
  }
  const riskPct = maxScore > 0 ? Math.round((deducted / maxScore) * 100) : 0;
  const score = Math.max(0, 100 - riskPct);
  const level = riskPct >= 70 ? 'CRITIQUE' : riskPct >= 40 ? 'ÉLEVÉ' : riskPct >= 20 ? 'MOYEN' : 'FAIBLE';

  const failed = findings.filter((f) => !f.passed);
  const criticals = failed.filter((f) => f.severity === 'CRITICAL');

  const summary = riskPct >= 70
    ? `🚨 Posture de sécurité critique — ${failed.length} problème(s) dont ${criticals.length} critique(s) à corriger immédiatement`
    : riskPct >= 40
    ? `⚠️ Risque élevé — ${failed.length} problème(s) détecté(s), priorité sur : ${criticals.slice(0, 2).map((f) => f.name).join(', ') || failed[0]?.name}`
    : riskPct >= 20
    ? `⚡ Risque modéré — ${failed.length} amélioration(s) recommandée(s)`
    : `✅ Bonne posture de sécurité — ${failed.length} point(s) mineur(s) à surveiller`;

  return { score, level, findings, summary };
}

export default router;
