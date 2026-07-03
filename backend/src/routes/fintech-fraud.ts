import { Router, Request, Response } from 'express';
import { pool } from '../db';
import { URL } from 'url';
import * as https from 'https';
import * as http from 'http';
import * as dns from 'dns/promises';

const router = Router();

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

router.get('/', async (_req, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM fintech_fraud_audits ORDER BY created_at DESC LIMIT 50');
    res.json(rows);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

router.get('/:id', async (req, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM fintech_fraud_audits WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

router.post('/', async (req: Request, res: Response) => {
  const validated = validateUrl(String(req.body?.target_url ?? ''));
  if (!validated.ok) return res.status(400).json({ error: validated.error });

  let job: Record<string, unknown>;
  try {
    const { rows } = await pool.query(
      `INSERT INTO fintech_fraud_audits (target_url, domain, status) VALUES ($1, $2, 'running') RETURNING *`,
      [validated.url, validated.domain]
    );
    job = rows[0];
  } catch { return res.status(500).json({ error: 'Failed to create audit' }); }

  res.status(202).json(job);

  runFraudAudit(validated.url, validated.domain)
    .then(async result => {
      await pool.query(
        `UPDATE fintech_fraud_audits SET
          status='completed', risk_score=$1, risk_level=$2,
          checks=$3, summary=$4, completed_at=NOW()
         WHERE id=$5`,
        [result.score, result.level, JSON.stringify(result.checks), result.summary, job.id]
      );
    })
    .catch(async err => {
      await pool.query(
        `UPDATE fintech_fraud_audits SET status='failed', summary=$1, completed_at=NOW() WHERE id=$2`,
        [`Erreur: ${err.message}`, job.id]
      );
    });
});

interface FraudCheck {
  id: string;
  name: string;
  category: 'auth' | 'csrf' | 'cors' | 'ratelimit' | 'headers' | 'exposure';
  passed: boolean;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  detail: string;
  fix: string;
}

async function fetchResponse(url: string, options: { method?: string; headers?: Record<string, string>; timeout?: number } = {}): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  return new Promise((resolve) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const timeout = options.timeout ?? 8000;
    const timer = setTimeout(() => resolve({ status: 0, headers: {}, body: '' }), timeout);

    try {
      const reqOptions = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: options.method ?? 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 SecurityAudit/1.0',
          ...(options.headers ?? {}),
        },
        timeout: timeout - 500,
        rejectUnauthorized: false,
      };

      const req = (mod as any).request(reqOptions, (res: any) => {
        clearTimeout(timer);
        const hdrs: Record<string, string> = {};
        Object.entries(res.headers).forEach(([k, v]) => { hdrs[k.toLowerCase()] = String(v); });
        let body = '';
        res.on('data', (d: Buffer) => { if (body.length < 2000) body += d.toString(); });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: hdrs, body }));
        res.on('error', () => { clearTimeout(timer); resolve({ status: 0, headers: hdrs, body }); });
      });
      req.on('error', () => { clearTimeout(timer); resolve({ status: 0, headers: {}, body: '' }); });
      req.end();
    } catch { clearTimeout(timer); resolve({ status: 0, headers: {}, body: '' }); }
  });
}

async function runFraudAudit(url: string, domain: string) {
  const checks: FraudCheck[] = [];

  const base = await fetchResponse(url);
  const headers = base.headers;

  // Common fintech API paths to probe
  const apiPaths = ['/api/withdraw', '/api/transfer', '/api/payment', '/api/transaction',
    '/api/v1/withdraw', '/api/v1/transfer', '/api/v1/payment', '/api/transactions',
    '/withdraw', '/transfer', '/payment', '/payout', '/api/payout', '/api/v1/payout'];

  // ── 1. CORS — Cross-Origin Request forgery via API ────────────────────────
  const corsResp = await fetchResponse(url, {
    headers: {
      'Origin': 'https://evil-attacker.com',
      'Access-Control-Request-Method': 'POST',
    }
  });
  const acao = corsResp.headers['access-control-allow-origin'] ?? '';
  const acac = corsResp.headers['access-control-allow-credentials'] ?? '';
  const corsWild = acao === '*';
  const corsMirror = acao === 'https://evil-attacker.com';
  const corsDangerous = (corsWild || corsMirror) && acac === 'true';
  checks.push({
    id: 'cors',
    name: 'CORS — Requêtes cross-origin vers l\'API',
    category: 'cors',
    passed: !corsDangerous && !corsWild,
    risk: 'CRITICAL',
    detail: corsWild
      ? `⚠️ CORS wildcard (*) — n'importe quel site peut appeler votre API`
      : corsMirror
        ? `⚠️ CORS miroir l'origine de l'attaquant avec credentials=true — vol de session possible`
        : `Access-Control-Allow-Origin: ${acao || 'non défini'} — origine externe rejetée`,
    fix: 'Définir explicitement Access-Control-Allow-Origin avec une liste blanche de domaines autorisés. Ne jamais combiner * avec credentials=true.',
  });

  // ── 2. Auth sur les endpoints de paiement ────────────────────────────────
  let authBypassFound = false;
  let authBypassPath = '';
  for (const path of apiPaths) {
    const testUrl = `${new URL(url).origin}${path}`;
    const r = await fetchResponse(testUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
    if (r.status !== 0 && r.status !== 401 && r.status !== 403 && r.status !== 404 && r.status !== 405) {
      authBypassFound = true;
      authBypassPath = path;
      break;
    }
  }
  checks.push({
    id: 'auth_bypass',
    name: 'Authentification — Endpoints transaction sans token',
    category: 'auth',
    passed: !authBypassFound,
    risk: 'CRITICAL',
    detail: authBypassFound
      ? `🚨 L'endpoint ${authBypassPath} répond sans authentification — retrait possible sans compte`
      : 'Tous les endpoints de transaction testés retournent 401/403/404 sans token',
    fix: 'Toutes les routes de transaction/retrait doivent exiger un Bearer token JWT valide. Utiliser un middleware d\'authentification global.',
  });

  // ── 3. CSRF — Protection formulaire de virement ──────────────────────────
  const setCookie = headers['set-cookie'] ?? '';
  const hasSameSite = /samesite=(strict|lax)/i.test(setCookie);
  const hasSecure = /secure/i.test(setCookie);
  const hasCsrfHeader = !!(headers['x-csrf-token'] || headers['x-xsrf-token']);
  const csrfOk = hasSameSite || hasCsrfHeader;
  checks.push({
    id: 'csrf',
    name: 'CSRF — Falsification de requête cross-site',
    category: 'csrf',
    passed: csrfOk,
    risk: 'CRITICAL',
    detail: csrfOk
      ? `Protection CSRF détectée: ${hasSameSite ? 'SameSite cookie' : ''} ${hasCsrfHeader ? 'CSRF header' : ''}`
      : `Pas de SameSite cookie ni de header CSRF — un attaquant peut déclencher des virements depuis un site tiers`,
    fix: 'Ajouter SameSite=Strict sur les cookies de session ET un token CSRF (double submit cookie ou header X-CSRF-Token).',
  });

  // ── 4. Rate Limiting — Spam de retraits ──────────────────────────────────
  const rl1 = await fetchResponse(url);
  const rl2 = await fetchResponse(url);
  const hasRateLimit = !!(
    rl1.headers['x-ratelimit-limit'] ||
    rl1.headers['ratelimit-limit'] ||
    rl1.headers['retry-after'] ||
    rl2.headers['x-ratelimit-limit'] ||
    rl2.headers['ratelimit-limit']
  );
  checks.push({
    id: 'rate_limit',
    name: 'Rate Limiting — Spam de requêtes de retrait',
    category: 'ratelimit',
    passed: hasRateLimit,
    risk: 'HIGH',
    detail: hasRateLimit
      ? `Headers de rate limiting détectés: ${rl1.headers['x-ratelimit-limit'] || rl1.headers['ratelimit-limit']}`
      : 'Aucun header de rate limiting détecté — un attaquant peut spammer des milliers de retraits par seconde',
    fix: 'Implémenter un rate limiter (ex: 5 retraits/min/user). Utiliser Redis + sliding window. Bloquer après N échecs consécutifs.',
  });

  // ── 5. Exposition d'admin / endpoints internes ────────────────────────────
  const adminPaths = ['/admin', '/api/admin', '/internal', '/api/internal', '/dashboard/admin', '/.env', '/api/debug', '/api/config'];
  let exposedAdmin = '';
  for (const path of adminPaths) {
    const testUrl = `${new URL(url).origin}${path}`;
    const r = await fetchResponse(testUrl);
    if (r.status !== 0 && r.status !== 404 && r.status !== 410) {
      exposedAdmin = `${path} (HTTP ${r.status})`;
      break;
    }
  }
  checks.push({
    id: 'admin_exposure',
    name: 'Exposition — Interfaces admin accessibles',
    category: 'exposure',
    passed: !exposedAdmin,
    risk: 'HIGH',
    detail: exposedAdmin
      ? `🚨 Endpoint sensible accessible: ${exposedAdmin}`
      : 'Aucun endpoint admin/interne exposé sur les chemins communs',
    fix: 'Restreindre les interfaces admin par IP (liste blanche). Ne jamais exposer /admin sur le même domaine public.',
  });

  // ── 6. Security headers financiers ───────────────────────────────────────
  const cacheControl = headers['cache-control'] ?? '';
  const noCacheOk = /no-store/i.test(cacheControl);
  checks.push({
    id: 'cache_control',
    name: 'Cache — Données financières mises en cache',
    category: 'headers',
    passed: noCacheOk,
    risk: 'HIGH',
    detail: noCacheOk
      ? `Cache-Control: ${cacheControl} — données non mises en cache`
      : `Cache-Control: ${cacheControl || 'absent'} — les données de transaction peuvent être mises en cache (navigateur, CDN, proxy)`,
    fix: 'Ajouter Cache-Control: no-store sur toutes les réponses contenant des données financières ou personnelles.',
  });

  // ── 7. HTTPS strict ───────────────────────────────────────────────────────
  const hsts = headers['strict-transport-security'] ?? '';
  const hstsOk = /max-age=\d+/i.test(hsts);
  checks.push({
    id: 'hsts_fintech',
    name: 'HTTPS forcé — Interception en clair (Man-in-the-Middle)',
    category: 'headers',
    passed: hstsOk,
    risk: 'CRITICAL',
    detail: hstsOk
      ? `HSTS configuré: ${hsts}`
      : 'Absence de HSTS — un attaquant réseau peut intercepter et modifier les transactions en clair (SSL-strip)',
    fix: 'Ajouter: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
  });

  // ── 8. DNS — Détournement de domaine de paiement ──────────────────────────
  const rootDomain = domain.split('.').slice(-2).join('.');
  let caaFound = false;
  try {
    const caa = await dns.resolveCaa(rootDomain);
    caaFound = caa.length > 0;
  } catch { /* no CAA */ }
  checks.push({
    id: 'caa_dns',
    name: 'DNS CAA — Émission frauduleuse de certificat SSL',
    category: 'exposure',
    passed: caaFound,
    risk: 'MEDIUM',
    detail: caaFound
      ? `Enregistrement CAA présent — seules les CAs autorisées peuvent émettre un certificat pour ${rootDomain}`
      : `Absent — n'importe quelle autorité de certification peut émettre un certificat pour ${rootDomain} (clonage HTTPS possible)`,
    fix: `Ajouter un enregistrement DNS CAA: ${rootDomain} CAA 0 issue "letsencrypt.org"`,
  });

  // ── 9. Idempotency — Requêtes en double ───────────────────────────────────
  const hasIdempotency = !!(headers['idempotency-key'] || headers['x-idempotency-key']);
  checks.push({
    id: 'idempotency',
    name: 'Idempotence — Double soumission de retrait',
    category: 'ratelimit',
    passed: hasIdempotency,
    risk: 'HIGH',
    detail: hasIdempotency
      ? 'Header d\'idempotence détecté — les doublons sont protégés'
      : 'Aucun mécanisme d\'idempotence détecté — un retrait peut être exécuté plusieurs fois si la requête est rejouée',
    fix: 'Implémenter des clés d\'idempotence (UUID par transaction). Stocker les clés 24h et rejeter les doublons.',
  });

  // ── Score ─────────────────────────────────────────────────────────────────
  const weights = { CRITICAL: 30, HIGH: 20, MEDIUM: 10, LOW: 5 };
  let maxScore = 0, score = 0;
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
    ? `🚨 Site exposé à la fraude financière — ${failed.length} vulnérabilités dont ${critical.length} critiques`
    : pct >= 40
    ? `⚠️ Risque élevé de fraude API — corriger en priorité: ${critical.slice(0, 2).join(', ')}`
    : pct >= 20
    ? `⚡ Risque modéré — ${failed.length} point(s) à renforcer`
    : `✅ Bonne sécurité API — résistant aux attaques de fraude courantes`;

  return { score: pct, level, checks, summary };
}

export default router;
