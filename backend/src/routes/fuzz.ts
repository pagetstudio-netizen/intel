import { Router, Request, Response } from 'express';
import { pool } from '../db';
import { runFuzz } from '../intel';
import { validateTargetUrl } from '../ssrf-guard';

const router = Router();

// GET /api/fuzz
router.get('/', async (_req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM fuzz_jobs ORDER BY created_at DESC LIMIT 50'
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// GET /api/fuzz/:id
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM fuzz_jobs WHERE id = $1',
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// POST /api/fuzz
router.post('/', async (req: Request, res: Response) => {
  const { concurrency = 10, timeout_ms = 5000 } = req.body;
  const validated = validateTargetUrl(String(req.body?.target_url ?? ''));
  if (!validated.ok) return res.status(400).json({ error: validated.error });
  const target_url = validated.url;

  const { rows } = await pool.query(
    `INSERT INTO fuzz_jobs (target_url, status, concurrency, timeout_ms)
     VALUES ($1, 'running', $2, $3) RETURNING *`,
    [target_url, concurrency, timeout_ms]
  );
  const job = rows[0];
  res.status(202).json(job);

  runFuzz({ target: target_url, concurrency, timeoutMs: timeout_ms })
    .then(async (output) => {
      const results = parseFuzzResults(output);
      await pool.query(
        `UPDATE fuzz_jobs SET status = 'completed', results = $1, completed_at = NOW() WHERE id = $2`,
        [JSON.stringify(results), job.id]
      );
    })
    .catch(async (err) => {
      await pool.query(
        `UPDATE fuzz_jobs SET status = 'failed', completed_at = NOW() WHERE id = $1`,
        [job.id]
      );
      console.error('Fuzz error:', err.message);
    });
});

function parseFuzzResults(output: string) {
  const results: Array<{ status: number; path: string; size: number; ms: number }> = [];
  for (const line of output.split('\n')) {
    const m = line.match(/^\[(\d{3})\] (.+?) — (\d+)b in (\d+)ms/);
    if (m) {
      results.push({ status: parseInt(m[1]), path: m[2], size: parseInt(m[3]), ms: parseInt(m[4]) });
    }
  }
  return results;
}

export default router;
