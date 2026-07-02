import { Router, Request, Response } from 'express';
import { pool } from '../db';
import { runScan } from '../intel';

const router = Router();

// GET /api/scans
router.get('/', async (_req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM scans ORDER BY created_at DESC LIMIT 50'
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// GET /api/scans/:id
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM scans WHERE id = $1',
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// POST /api/scans
router.post('/', async (req: Request, res: Response) => {
  const { target_url, deep = false, timeout = 60 } = req.body;
  if (!target_url) return res.status(400).json({ error: 'target_url required' });

  // Create scan record
  const { rows } = await pool.query(
    `INSERT INTO scans (target_url, scan_type, status, config)
     VALUES ($1, 'vulnerability', 'running', $2)
     RETURNING *`,
    [target_url, JSON.stringify({ deep, timeout })]
  );
  const scan = rows[0];
  res.status(202).json(scan);

  // Run scan asynchronously
  runScan({ target: target_url, deep, timeout })
    .then(async (output) => {
      const findings = parseFindings(output);
      await pool.query(
        `UPDATE scans SET status = 'completed', findings = $1, completed_at = NOW() WHERE id = $2`,
        [JSON.stringify(findings), scan.id]
      );
    })
    .catch(async (err) => {
      await pool.query(
        `UPDATE scans SET status = 'failed', findings = $1, completed_at = NOW() WHERE id = $2`,
        [JSON.stringify([{ title: 'Scan error', description: err.message, severity: 'Info' }]), scan.id]
      );
    });
});

function parseFindings(output: string) {
  const findings: Array<{ title: string; description: string; severity: string; ref?: string; fix?: string }> = [];
  const lines = output.split('\n');
  let current: typeof findings[0] | null = null;

  for (const line of lines) {
    const match = line.match(/^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\] (.+?) — (.+)$/);
    if (match) {
      if (current) findings.push(current);
      current = { severity: match[1], title: match[2], description: match[3] };
    } else if (current && line.trim().startsWith('↳ Fix:')) {
      current.fix = line.trim().replace('↳ Fix:', '').trim();
    } else if (current && line.trim().startsWith('↳ Ref:')) {
      current.ref = line.trim().replace('↳ Ref:', '').trim();
    }
  }
  if (current) findings.push(current);
  return findings;
}

export default router;
