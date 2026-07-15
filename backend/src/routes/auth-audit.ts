import { scanLimiter } from '../rate-limit';
import { Router, Request, Response } from 'express';
import { pool } from '../db';
import { URL } from 'url';
import * as https from 'https';
import * as http from 'http';

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
  return { ok: true, url: `${p.protocol}//${p.host}`, domain: p.hostname };
}

interface ProbeResult {
  status: number;
  headers: Record<string, string>;
  bodySize: number;
  hasJson: boolean;
  isRedirect: boolean;
}

async function probe(
  targetUrl: string,
  path: string,
  method = 'GET',
  extraHeaders: Record<string, string> = {},
  timeoutMs = 7000
): Promise<ProbeResult> {
  return new Promise((resolve) => {
    const empty: ProbeResult = { status: 0, headers: {}, bodySize: 0, hasJson: false, isRedirect: false };
    let p: URL;
    try { p = new URL(targetUrl + path); } catch { return resolve(empty); }
    const mod = p.protocol === 'https:' ? https : http;
    const timer = setTimeout(() => resolve(empty), timeoutMs);

    try {
      const options = {
        hostname: p.hostname,
        port: p.port || (p.protocol === 'https:' ? 443 : 80),
        path: p.pathname + p.search,
        method,
        headers: {
          'User-Agent': 'Mozilla/5.0 INTEL-PentestAudit/1.0',
          'Accept': 'application/json, text/html, */*',
          ...extraHeaders,
        },
        timeout: timeoutMs - 500,
        rejectUnauthorized: false,
      };

      const req = (mod as any).request(options, (res: any) => {
        clearTimeout(timer);
        const hdrs: Record<string, string> = {};
        Object.entries(res.headers ?? {}).forEach(([k, v]) => { hdrs[k.toLowerCase()] = String(v); });
        let body = '';
        res.on('data', (d: Buffer) => { if (body.length < 4000) body += d.toString(); });
        res.on('end', () => {
          const ct = hdrs['content-type'] ?? '';
          const hasJson = ct.includes('application/json') || (body.trimStart().startsWith('{') || body.trimStart().startsWith('['));
          const isRedirect = res.statusCode >= 300 && res.statusCode < 400;
          resolve({ status: res.statusCode ?? 0, headers: hdrs, bodySize: body.length, hasJson, isRedirect });
        });
        res.on('error', () => { clearTimeout(timer); resolve(empty); });
      });
      req.on('error', () => { clearTimeout(timer); resolve(empty); });
      req.setTimeout(timeoutMs - 200, () => { req.destroy(); resolve(empty); });
      if (method === 'POST') req.write(JSON.stringify({}));
      req.end();
    } catch { clearTimeout(timer); resolve(empty); }
  });
}

function isExposed(r: ProbeResult): boolean {
  return r.status >= 200 && r.status < 300 && r.bodySize > 20;
}

function isBlocked(r: ProbeResult): boolean {
  return r.status === 401 || r.status === 403;
}

router.get('/', async (_req, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM auth_audits ORDER BY created_at DESC LIMIT 50');
    res.json(rows);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

router.get('/:id', async (req, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM auth_audits WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

router.post('/', scanLimiter, async (req: Request, res: Response) => {
  const validated = validateUrl(String(req.body?.target_url ?? ''));
  if (!validated.ok) return res.status(400).json({ error: validated.error });

  let job: Record<string, unknown>;
  try {
    const { rows } = await pool.query(
      `INSERT INTO auth_audits (target_url, domain, status) VALUES ($1, $2, 'running') RETURNING *`,
      [validated.url, validated.domain]
    );
    job = rows[0];
  } catch { return res.status(500).json({ error: 'Failed to create audit' }); }

  res.status(202).json(job);

  runAuthAudit(validated.url, validated.domain)
    .then(async result => {
      await pool.query(
        `UPDATE auth_audits SET
          status='completed', risk_score=$1, risk_level=$2,
          checks=$3, exposed_endpoints=$4, summary=$5, completed_at=NOW()
         WHERE id=$6`,
        [result.score, result.level, JSON.stringify(result.checks), JSON.stringify(result.exposedEndpoints), result.summary, job.id]
      );
    })
    .catch(async err => {
      await pool.query(
        `UPDATE auth_audits SET status='failed', summary=$1, completed_at=NOW() WHERE id=$2`,
        [`Erreur: ${err.message}`, job.id]
      );
    });
});

interface AuthCheck {
  id: string;
  name: string;
  category: 'unauth_access' | 'cookie' | 'bypass' | 'admin' | 'token' | 'header';
  passed: boolean;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  detail: string;
  fix: string;
}

interface ExposedEndpoint {
  path: string;
  method: string;
  status: number;
  response_size: number;
  has_json: boolean;
  auth_required: boolean;
}

async function runAuthAudit(baseUrl: string, domain: string) {
  const checks: AuthCheck[] = [];
  const exposedEndpoints: ExposedEndpoint[] = [];

  // ── Probe de base ─────────────────────────────────────────────────────────
  const base = await probe(baseUrl, '/');
  const baseCookies = base.headers['set-cookie'] ?? '';

  // ── 1. Endpoints de données sans authentification ─────────────────────────
  const dataPaths = [
    '/api/users', '/api/user', '/api/accounts', '/api/account',
    '/api/me', '/api/profile', '/api/v1/users', '/api/v1/user',
    '/api/v1/me', '/api/v1/profile', '/api/v1/accounts',
    '/api/v2/users', '/api/v2/me', '/api/v2/profile',
    '/api/members', '/api/customers', '/api/clients',
    '/api/orders', '/api/transactions', '/api/payments',
    '/api/data', '/api/export', '/api/list',
    '/users', '/accounts', '/members',
  ];

  let unauthExposed: string[] = [];
  for (const path of dataPaths) {
    const r = await probe(baseUrl, path);
    const authRequired = isBlocked(r);
    if (isExposed(r)) {
      unauthExposed.push(path);
      exposedEndpoints.push({
        path, method: 'GET',
        status: r.status,
        response_size: r.bodySize,
        has_json: r.hasJson,
        auth_required: false,
      });
    } else if (authRequired) {
      exposedEndpoints.push({
        path, method: 'GET',
        status: r.status,
        response_size: 0,
        has_json: false,
        auth_required: true,
      });
    }
  }

  checks.push({
    id: 'unauth_data',
    name: 'Endpoints de données sans authentification',
    category: 'unauth_access',
    passed: unauthExposed.length === 0,
    risk: 'CRITICAL',
    detail: unauthExposed.length > 0
      ? `🚨 ${unauthExposed.length} endpoint(s) exposent des données sans token : ${unauthExposed.slice(0, 3).join(', ')}${unauthExposed.length > 3 ? ` +${unauthExposed.length - 3}` : ''}`
      : 'Aucun endpoint de données accessible sans authentification',
    fix: 'Appliquer un middleware d\'authentification global (JWT, session) sur toutes les routes /api/*. Retourner 401 si le token est absent ou invalide.',
  });

  // ── 2. Interfaces admin sans authentification ─────────────────────────────
  const adminPaths = [
    '/admin', '/admin/', '/admin/login',
    '/api/admin', '/api/admin/users', '/api/admin/config',
    '/api/v1/admin', '/dashboard/admin', '/api/management',
    '/api/internal', '/internal', '/api/debug',
    '/api/config', '/config', '/api/settings',
    '/_admin', '/wp-admin', '/administrator',
  ];

  let adminExposed: string[] = [];
  for (const path of adminPaths) {
    const r = await probe(baseUrl, path);
    if (isExposed(r) && !r.isRedirect) {
      adminExposed.push(`${path} (HTTP ${r.status}, ${r.bodySize}B)`);
      exposedEndpoints.push({
        path, method: 'GET',
        status: r.status,
        response_size: r.bodySize,
        has_json: r.hasJson,
        auth_required: false,
      });
    }
  }

  checks.push({
    id: 'admin_no_auth',
    name: 'Interface admin accessible sans mot de passe',
    category: 'admin',
    passed: adminExposed.length === 0,
    risk: 'CRITICAL',
    detail: adminExposed.length > 0
      ? `🚨 Panneau admin accessible sans authentification : ${adminExposed.slice(0, 2).join(', ')}`
      : 'Aucun panneau d\'administration exposé sans authentification',
    fix: 'Protéger /admin et toutes les routes d\'administration avec authentification forte + restriction par IP. Ne jamais exposer /admin sur le domaine public.',
  });

  // ── 3. Bypass du header Authorization ────────────────────────────────────
  const bypassTests = [
    { label: 'Bearer vide', headers: { 'Authorization': 'Bearer ' } },
    { label: 'Bearer null', headers: { 'Authorization': 'Bearer null' } },
    { label: 'Bearer undefined', headers: { 'Authorization': 'Bearer undefined' } },
    { label: 'Token malformé', headers: { 'Authorization': 'Bearer eyJhbGciOiJub25lIn0.e30.' } },
    { label: 'Alg:none JWT', headers: { 'Authorization': 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiIxIn0.' } },
  ];

  let bypassFound: string[] = [];
  for (const test of bypassTests) {
    for (const path of dataPaths.slice(0, 8)) {
      const r = await probe(baseUrl, path, 'GET', test.headers);
      if (isExposed(r)) {
        bypassFound.push(`${test.label} → ${path}`);
        break;
      }
    }
    if (bypassFound.length >= 2) break;
  }

  checks.push({
    id: 'auth_bypass',
    name: 'Bypass d\'authentification (JWT malformé / alg:none)',
    category: 'bypass',
    passed: bypassFound.length === 0,
    risk: 'CRITICAL',
    detail: bypassFound.length > 0
      ? `🚨 Token invalide accepté : ${bypassFound.join(' | ')}`
      : 'Les tokens invalides, vides ou avec alg:none sont correctement rejetés',
    fix: 'Valider strictement la signature JWT côté serveur. Interdire l\'algorithme "none". Utiliser une bibliothèque JWT maintenue (jsonwebtoken, jose). Ne jamais faire confiance au champ "alg" du header.',
  });

  // ── 4. Sécurité des cookies de session ────────────────────────────────────
  const cookieRaw = Array.isArray(base.headers['set-cookie'])
    ? (base.headers['set-cookie'] as unknown as string[]).join('; ')
    : baseCookies;

  const hasHttpOnly = /httponly/i.test(cookieRaw);
  const hasSecure = /;\s*secure/i.test(cookieRaw);
  const hasSameSite = /samesite=(strict|lax)/i.test(cookieRaw);
  const hasCookie = cookieRaw.length > 0;
  const cookieOk = !hasCookie || (hasHttpOnly && hasSecure && hasSameSite);

  checks.push({
    id: 'cookie_flags',
    name: 'Sécurité des cookies de session (HttpOnly / Secure / SameSite)',
    category: 'cookie',
    passed: cookieOk,
    risk: 'HIGH',
    detail: !hasCookie
      ? 'Aucun cookie de session détecté sur la page principale'
      : cookieOk
        ? `Cookie sécurisé : HttpOnly=${hasHttpOnly}, Secure=${hasSecure}, SameSite=${hasSameSite}`
        : `⚠️ Flags manquants — HttpOnly:${hasHttpOnly}, Secure:${hasSecure}, SameSite:${hasSameSite} — vol de session possible via XSS ou réseau`,
    fix: 'Tous les cookies de session doivent avoir : HttpOnly (protection XSS), Secure (HTTPS uniquement), SameSite=Strict ou Lax (protection CSRF).',
  });

  // ── 5. Token JWT ou session exposé dans les headers de réponse ────────────
  const jwtPattern = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/;
  const tokenInHeader = Object.values(base.headers).some(v => jwtPattern.test(String(v)));
  const tokenInCookie = jwtPattern.test(cookieRaw);
  const tokenExposedInHeader = tokenInHeader && !tokenInCookie;

  checks.push({
    id: 'token_exposure',
    name: 'JWT exposé dans les en-têtes de réponse HTTP',
    category: 'token',
    passed: !tokenExposedInHeader,
    risk: 'HIGH',
    detail: tokenExposedInHeader
      ? `⚠️ Un token JWT a été détecté dans les headers de réponse HTTP — risque d'interception`
      : 'Aucun token JWT détecté en clair dans les headers de réponse',
    fix: 'Ne jamais retourner de token dans les headers de réponse. Utiliser un cookie HttpOnly pour les sessions, ou demander au client de stocker le token lui-même après login.',
  });

  // ── 6. En-têtes de sécurité auth ─────────────────────────────────────────
  const wwwAuth = base.headers['www-authenticate'] ?? '';
  const xContentType = base.headers['x-content-type-options'] ?? '';
  const cacheControl = base.headers['cache-control'] ?? '';
  const noCacheSensitive = /no-store/i.test(cacheControl) || /no-cache/i.test(cacheControl);

  checks.push({
    id: 'security_headers_auth',
    name: 'Cache des réponses authentifiées (données privées en cache)',
    category: 'header',
    passed: noCacheSensitive,
    risk: 'MEDIUM',
    detail: noCacheSensitive
      ? `Cache-Control: ${cacheControl} — données non mises en cache`
      : `Cache-Control: ${cacheControl || 'absent'} — les données authentifiées peuvent être mises en cache (proxy, navigateur partagé)`,
    fix: 'Ajouter sur toutes les réponses avec données privées : Cache-Control: no-store. Cela empêche les données d\'être mises en cache sur un proxy ou navigateur partagé.',
  });

  // ── 7. Méthode OPTIONS — CORS sur endpoints protégés ─────────────────────
  const optionsResp = await probe(baseUrl, '/api/users', 'OPTIONS', {
    'Origin': 'https://attacker.evil.com',
    'Access-Control-Request-Method': 'GET',
    'Access-Control-Request-Headers': 'Authorization',
  });
  const acao = optionsResp.headers['access-control-allow-origin'] ?? '';
  const acac = optionsResp.headers['access-control-allow-credentials'] ?? '';
  const allowsAttacker = acao === '*' || acao.includes('attacker.evil.com');
  const dangerousCors = allowsAttacker && acac === 'true';

  checks.push({
    id: 'cors_auth',
    name: 'CORS — Endpoint protégé accessible depuis domaine attaquant',
    category: 'bypass',
    passed: !dangerousCors,
    risk: 'CRITICAL',
    detail: dangerousCors
      ? `🚨 CORS + credentials=true pour domaine externe — un site attaquant peut lire vos données avec la session de la victime`
      : `CORS: ${acao || 'non défini'} — origine externe non autorisée à accéder avec credentials`,
    fix: 'Ne jamais combiner Access-Control-Allow-Origin: * avec Access-Control-Allow-Credentials: true. Maintenir une liste blanche explicite de domaines autorisés.',
  });

  // ── 8. Énumération d'IDs (IDOR) ───────────────────────────────────────────
  const idorPaths = [
    '/api/users/1', '/api/users/2', '/api/user/1',
    '/api/accounts/1', '/api/orders/1', '/api/profile/1',
    '/api/v1/users/1', '/api/v1/user/1',
  ];
  let idorExposed: string[] = [];
  for (const path of idorPaths) {
    const r = await probe(baseUrl, path);
    if (isExposed(r)) {
      idorExposed.push(`${path} (${r.status}, ${r.bodySize}B${r.hasJson ? ', JSON' : ''})`);
      exposedEndpoints.push({
        path, method: 'GET',
        status: r.status,
        response_size: r.bodySize,
        has_json: r.hasJson,
        auth_required: false,
      });
    }
  }

  checks.push({
    id: 'idor',
    name: 'IDOR — Accès direct aux objets sans vérification d\'identité',
    category: 'unauth_access',
    passed: idorExposed.length === 0,
    risk: 'HIGH',
    detail: idorExposed.length > 0
      ? `⚠️ Accès non autorisé à des ressources par ID direct : ${idorExposed.slice(0, 2).join(', ')}`
      : 'Aucun accès non autorisé par ID direct détecté',
    fix: 'Vérifier systématiquement que l\'utilisateur authentifié est propriétaire de la ressource demandée (contrôle d\'accès au niveau objet - OWASP BOLA/IDOR). Ne jamais se fier uniquement à l\'ID dans l\'URL.',
  });

  // ── Score ─────────────────────────────────────────────────────────────────
  const weights: Record<string, number> = { CRITICAL: 30, HIGH: 20, MEDIUM: 10, LOW: 5 };
  let maxScore = 0, rawScore = 0;
  for (const c of checks) {
    const w = weights[c.risk] ?? 10;
    maxScore += w;
    if (!c.passed) rawScore += w;
  }
  const score = Math.round((rawScore / maxScore) * 100);
  const level = score >= 70 ? 'CRITIQUE' : score >= 40 ? 'ÉLEVÉ' : score >= 20 ? 'MOYEN' : 'FAIBLE';

  const failed = checks.filter(c => !c.passed);
  const criticals = failed.filter(c => c.risk === 'CRITICAL').map(c => c.name);

  const summary = score >= 70
    ? `🚨 Contrôle d'accès gravement défaillant — ${exposedEndpoints.filter(e => !e.auth_required).length} endpoint(s) exposés, ${criticals.length} faille(s) critique(s)`
    : score >= 40
    ? `⚠️ Mauvaises configurations d'auth détectées — corriger en priorité : ${criticals.slice(0, 1).join(', ')}`
    : score >= 20
    ? `⚡ Risque modéré — ${failed.length} point(s) à améliorer`
    : `✅ Authentification correctement configurée — aucune exposition non autorisée détectée`;

  return { score, level, checks, exposedEndpoints, summary };
}

export default router;
