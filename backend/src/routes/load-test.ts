import { Router, Request, Response } from 'express';
import { pool } from '../db';
import { spawn } from 'child_process';
import path from 'path';

const router = Router();
const BINARY = path.join(__dirname, '../../../security-core/target/release/intel');

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
  const {
    target_url,
    concurrent_users = 50,
    rps = 10,
    duration_seconds = 30,
  } = req.body;

  if (!target_url) return res.status(400).json({ error: 'target_url required' });

  const { rows } = await pool.query(
    `INSERT INTO load_tests (target_url, status, concurrent_users, rps, duration_seconds)
     VALUES ($1, 'running', $2, $3, $4) RETURNING *`,
    [target_url, concurrent_users, rps, duration_seconds]
  );
  const job = rows[0];
  res.status(202).json(job);

  // Run load test as child process
  const args = [
    'load-test',
    '--target', target_url,
    '--users', String(concurrent_users),
    '--rps', String(rps),
    '--duration', String(duration_seconds),
  ];

  const proc = spawn(BINARY, args, { timeout: (duration_seconds + 30) * 1000 });
  let stdout = '';
  proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
  proc.on('close', async (code: number | null) => {
    const data = parseLoadOutput(stdout);
    const crashed = data.crash || code !== 0;
    const successRate = data.total > 0 ? data.successful / data.total : 0;
    const verdict = crashed
      ? '💥 SERVEUR TOMBÉ — Système vulnérable à la charge'
      : successRate >= 0.95
      ? '✅ SYSTÈME SOLIDE — Félicitations, infrastructure résistante'
      : successRate >= 0.7
      ? '⚠️ SYSTÈME FRAGILE — Des optimisations sont nécessaires'
      : '❌ SYSTÈME INSTABLE — Trop d\'erreurs sous charge';

    await pool.query(
      `UPDATE load_tests SET
        status = 'completed',
        total_requests = $1,
        successful_requests = $2,
        failed_requests = $3,
        requests_per_second = $4,
        avg_response_ms = $5,
        server_crash = $6,
        verdict = $7,
        completed_at = NOW()
       WHERE id = $8`,
      [data.total, data.successful, data.failed, data.rps, data.avgMs, crashed, verdict, job.id]
    );
  });
  proc.on('error', async () => {
    await pool.query(
      `UPDATE load_tests SET status = 'failed', verdict = $1, completed_at = NOW() WHERE id = $2`,
      ['❌ Erreur lors du test — binary non compilé', job.id]
    );
  });
});

function parseLoadOutput(output: string) {
  const get = (key: string) => {
    const m = output.match(new RegExp(`^${key}=(.+)$`, 'm'));
    return m ? m[1].trim() : '0';
  };
  return {
    total: parseInt(get('TOTAL_REQUESTS')) || 0,
    successful: parseInt(get('SUCCESSFUL')) || 0,
    failed: parseInt(get('FAILED')) || 0,
    rps: parseInt(get('RPS')) || 0,
    avgMs: parseInt(get('AVG_MS')) || 0,
    crash: get('CRASH') === 'true',
  };
}

export default router;
