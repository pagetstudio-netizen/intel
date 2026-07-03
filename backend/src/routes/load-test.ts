import { Router, Request, Response } from 'express';
import { pool } from '../db';
import { spawn } from 'child_process';
import path from 'path';
import { URL } from 'url';

const router = Router();
const BINARY = path.join(__dirname, '../../../security-core/target/release/intel');

// ── Limits ───────────────────────────────────────────────────────────────────
const LIMITS = {
  concurrent_users: { min: 1, max: 2000 },
  rps:              { min: 1, max: 500 },
  duration_seconds: { min: 5, max: 300 },
};

// ── SSRF guard ────────────────────────────────────────────────────────────────
// Private/loopback/link-local CIDRs to block
const BLOCKED_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,        // link-local
  /^::1$/,              // IPv6 loopback
  /^fc[0-9a-f]{2}:/i,   // IPv6 ULA
  /^fe80:/i,            // IPv6 link-local
  /^0\./,               // 0.x.x.x
  /^metadata\.google\.internal$/i,
  /^169\.254\.169\.254$/,  // AWS/GCP metadata
];

function validateTargetUrl(raw: string): { ok: true; url: string } | { ok: false; error: string } {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, error: 'Invalid URL format' };
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, error: 'Only http and https protocols are allowed' };
  }
  const hostname = parsed.hostname.toLowerCase();
  for (const pattern of BLOCKED_PATTERNS) {
    if (pattern.test(hostname)) {
      return { ok: false, error: 'Target URL resolves to a private or restricted network address' };
    }
  }
  // Strip credentials from URL before storing/passing
  const safe = `${parsed.protocol}//${parsed.host}${parsed.pathname}${parsed.search}`;
  return { ok: true, url: safe };
}

function clamp(val: unknown, min: number, max: number, def: number): number {
  const n = parseInt(String(val), 10);
  if (isNaN(n)) return def;
  return Math.min(max, Math.max(min, n));
}

// ── Routes ────────────────────────────────────────────────────────────────────

// GET /api/load-test
router.get('/', async (_req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM load_tests ORDER BY created_at DESC LIMIT 50'
    );
    res.json(rows);
  } catch {
    res.status(500).json({ error: 'Database error' });
  }
});

// GET /api/load-test/:id
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM load_tests WHERE id = $1', [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch {
    res.status(500).json({ error: 'Database error' });
  }
});

// POST /api/load-test
router.post('/', async (req: Request, res: Response) => {
  const { target_url, concurrent_users, rps, duration_seconds } = req.body;

  // Validate URL (SSRF guard)
  const validated = validateTargetUrl(String(target_url ?? ''));
  if (!validated.ok) {
    return res.status(400).json({ error: validated.error });
  }

  // Clamp parameters to safe server-side limits
  const safeUsers    = clamp(concurrent_users,  LIMITS.concurrent_users.min,  LIMITS.concurrent_users.max,  50);
  const safeRps      = clamp(rps,               LIMITS.rps.min,               LIMITS.rps.max,               10);
  const safeDuration = clamp(duration_seconds,  LIMITS.duration_seconds.min,  LIMITS.duration_seconds.max,  30);

  let job: Record<string, unknown>;
  try {
    const { rows } = await pool.query(
      `INSERT INTO load_tests (target_url, status, concurrent_users, rps, duration_seconds)
       VALUES ($1, 'running', $2, $3, $4) RETURNING *`,
      [validated.url, safeUsers, safeRps, safeDuration]
    );
    job = rows[0];
  } catch {
    return res.status(500).json({ error: 'Failed to create load test record' });
  }

  res.status(202).json(job);

  // Run load test as child process (fire-and-forget)
  const args = [
    'load-test',
    '--target', validated.url,
    '--users',    String(safeUsers),
    '--rps',      String(safeRps),
    '--duration', String(safeDuration),
  ];

  const proc = spawn(BINARY, args, { timeout: (safeDuration + 30) * 1000 });
  let stdout = '';
  proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });

  const finalize = async (crashed: boolean, rawOutput: string) => {
    const data = parseLoadOutput(rawOutput);
    const effectiveCrash = crashed || data.crash;
    const successRate = data.total > 0 ? data.successful / data.total : 0;
    const verdict = effectiveCrash
      ? '💥 SERVEUR TOMBÉ — Système vulnérable à la charge'
      : successRate >= 0.95
      ? '✅ SYSTÈME SOLIDE — Félicitations, infrastructure résistante'
      : successRate >= 0.70
      ? '⚠️ SYSTÈME FRAGILE — Des optimisations sont nécessaires'
      : '❌ SYSTÈME INSTABLE — Trop d\'erreurs sous charge';

    try {
      // Store geo_breakdown in results column (JSONB)
      const results = {
        geo_breakdown: data.geoBreakdown,
        countries_used: data.countries,
      };
      await pool.query(
        `UPDATE load_tests SET
          status = 'completed',
          total_requests = $1, successful_requests = $2, failed_requests = $3,
          requests_per_second = $4, avg_response_ms = $5,
          server_crash = $6, verdict = $7, results = $8, completed_at = NOW()
         WHERE id = $9`,
        [data.total, data.successful, data.failed, data.rps, data.avgMs,
         effectiveCrash, verdict, JSON.stringify(results), job.id]
      );
    } catch (dbErr) {
      console.error('Load test DB update failed:', dbErr);
    }
  };

  proc.on('close', (code: number | null) => {
    finalize(code !== 0, stdout).catch(console.error);
  });

  proc.on('error', async () => {
    try {
      await pool.query(
        `UPDATE load_tests SET status = 'failed',
          verdict = '❌ Erreur — binaire non compilé (lancer le workflow Build)',
          completed_at = NOW() WHERE id = $1`,
        [job.id]
      );
    } catch (dbErr) {
      console.error('Load test error DB update failed:', dbErr);
    }
  });
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function parseLoadOutput(output: string) {
  const get = (key: string): string => {
    const m = output.match(new RegExp(`^${key}=(.+)$`, 'm'));
    return m ? m[1].trim() : '0';
  };
  let geoBreakdown: any[] = [];
  try {
    const geoRaw = get('GEO_BREAKDOWN');
    if (geoRaw && geoRaw !== '0') geoBreakdown = JSON.parse(geoRaw);
  } catch {}
  return {
    total:        parseInt(get('TOTAL_REQUESTS'), 10) || 0,
    successful:   parseInt(get('SUCCESSFUL'),     10) || 0,
    failed:       parseInt(get('FAILED'),         10) || 0,
    rps:          parseInt(get('RPS'),            10) || 0,
    avgMs:        parseInt(get('AVG_MS'),         10) || 0,
    crash:        get('CRASH') === 'true',
    countries:    parseInt(get('COUNTRIES'),      10) || 0,
    geoBreakdown,
  };
}

export default router;
