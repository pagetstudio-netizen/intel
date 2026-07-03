import { Router, Request, Response } from 'express';
import { pool } from '../db';

const router = Router();

// GET /api/mandates
router.get('/', async (_req, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM mandates ORDER BY created_at DESC LIMIT 100');
    res.json(rows);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

// GET /api/mandates/:id
router.get('/:id', async (req, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM mandates WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

// GET /api/mandates/confirm/:token  — client reads the mandate
router.get('/confirm/:token', async (req, res: Response) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM mandates WHERE token = $1',
      [req.params.token]
    );
    if (!rows.length) return res.status(404).json({ error: 'Mandat introuvable ou lien invalide' });
    const m = rows[0];
    if (m.status === 'expired') return res.status(410).json({ error: 'Ce mandat a expiré' });
    // Return all except nothing sensitive — token is needed for POST
    res.json(m);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

// POST /api/mandates  — create new mandate
router.post('/', async (req: Request, res: Response) => {
  const {
    tester_company, client_name, client_email, client_company,
    target_urls, scope, valid_from, valid_until, notes,
  } = req.body;

  if (!client_name || !client_email || !client_company || !target_urls?.length || !scope?.length || !valid_from || !valid_until) {
    return res.status(400).json({ error: 'Champs obligatoires manquants' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(client_email)) {
    return res.status(400).json({ error: 'Email client invalide' });
  }

  try {
    const { rows } = await pool.query(
      `INSERT INTO mandates
        (tester_company, client_name, client_email, client_company, target_urls, scope, valid_from, valid_until, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING *`,
      [
        tester_company || 'INTEL Security',
        client_name, client_email, client_company,
        target_urls, scope,
        valid_from, valid_until,
        notes || null,
      ]
    );
    res.status(201).json(rows[0]);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/mandates/confirm/:token  — client signs the mandate
router.post('/confirm/:token', async (req: Request, res: Response) => {
  const ip = req.headers['x-forwarded-for']?.toString().split(',')[0].trim()
    || req.socket.remoteAddress
    || 'unknown';

  try {
    const { rows } = await pool.query(
      'SELECT * FROM mandates WHERE token = $1',
      [req.params.token]
    );
    if (!rows.length) return res.status(404).json({ error: 'Mandat introuvable' });
    const m = rows[0];
    if (m.status === 'authorized') return res.status(409).json({ error: 'Mandat déjà signé' });
    if (m.status === 'expired') return res.status(410).json({ error: 'Mandat expiré' });

    const { rows: updated } = await pool.query(
      `UPDATE mandates
       SET status = 'authorized', signed_ip = $1, signed_at = NOW()
       WHERE token = $2
       RETURNING *`,
      [ip, req.params.token]
    );
    res.json(updated[0]);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

// DELETE /api/mandates/:id  — revoke mandate
router.delete('/:id', async (req, res: Response) => {
  try {
    await pool.query("UPDATE mandates SET status = 'expired' WHERE id = $1", [req.params.id]);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'Database error' }); }
});

export default router;
