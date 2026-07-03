import { Router, Request, Response } from 'express';
import { pool } from '../db';
import nodemailer from 'nodemailer';

const router = Router();

function createTransport() {
  const host = process.env.SMTP_HOST;
  const port = parseInt(process.env.SMTP_PORT || '587');
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) return null;

  return nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass },
    tls: { rejectUnauthorized: false },
  });
}

// POST /api/demo-email
router.post('/', async (req: Request, res: Response) => {
  const { assessment_id, to_email, spoof_name, custom_message, button_text, button_url } = req.body;

  if (!to_email || !assessment_id) {
    return res.status(400).json({ error: 'assessment_id et to_email requis' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to_email)) {
    return res.status(400).json({ error: 'Adresse email invalide' });
  }

  // Fetch assessment to get the client's domain
  let assessment: Record<string, any>;
  try {
    const { rows } = await pool.query(
      'SELECT * FROM phishing_assessments WHERE id = $1', [assessment_id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Analyse non trouvée' });
    assessment = rows[0];
  } catch {
    return res.status(500).json({ error: 'Erreur base de données' });
  }

  const transport = createTransport();
  if (!transport) {
    return res.status(503).json({
      error: 'SMTP non configuré',
      setup: true,
      required: ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS'],
    });
  }

  const domain = assessment.domain as string;
  const displayName = spoof_name || `Support ${domain}`;

  // From uses the CLIENT's domain — this is the spoof
  const spoofFrom = `"${displayName}" <noreply@${domain}>`;

  const html = buildPhishingTemplate(domain, displayName, custom_message, button_text, button_url);

  try {
    await transport.sendMail({
      from: spoofFrom,           // ← adresse du domaine client
      to: to_email,
      replyTo: spoofFrom,
      subject: `[ACTION REQUISE] Vérification de sécurité — ${domain}`,
      html,
    });

    await pool.query(
      `UPDATE phishing_assessments
       SET summary = COALESCE(summary,'') || ' | Email envoyé à ' || $1
       WHERE id = $2`,
      [to_email, assessment_id]
    );

    res.json({
      ok: true,
      message: `Email envoyé à ${to_email} en se faisant passer pour noreply@${domain}`,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message ?? "Échec de l'envoi" });
  }
});

function buildPhishingTemplate(
  domain: string,
  displayName: string,
  customMessage?: string,
  buttonText?: string,
  buttonUrl?: string,
): string {
  const year = new Date().getFullYear();

  // Convert newlines to <br> for HTML display
  const bodyHtml = (customMessage || '')
    .split('\n')
    .map(l => l.trim() ? `<p>${l}</p>` : '')
    .join('');

  const btnLabel = buttonText || '🔐 Vérifier mon identité';
  const btnLink  = buttonUrl  || '#';
  const hasButton = btnLink !== '#' && btnLink !== '' && btnLink !== 'https://';

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 20px; }
    .container { max-width: 580px; margin: 0 auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    .header { background: #1a1a2e; padding: 28px 32px; text-align: center; }
    .header h1 { color: #ffffff; margin: 0; font-size: 22px; letter-spacing: 1px; }
    .header p { color: #94a3b8; margin: 6px 0 0; font-size: 13px; }
    .banner { background: #dc2626; color: #fff; text-align: center; padding: 10px; font-size: 12px; font-weight: bold; letter-spacing: 1px; }
    .body { padding: 32px; color: #1e293b; }
    .body p { line-height: 1.7; margin: 0 0 14px; font-size: 15px; }
    .cta { text-align: center; margin: 28px 0; }
    .cta a { background: #dc2626; color: #ffffff !important; text-decoration: none; padding: 14px 36px; border-radius: 6px; font-size: 15px; font-weight: bold; display: inline-block; }
    .footer { background: #f8fafc; padding: 20px 32px; text-align: center; color: #94a3b8; font-size: 12px; border-top: 1px solid #e2e8f0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="banner">⚠️ ALERTE SÉCURITÉ — ACTION IMMÉDIATE REQUISE</div>
    <div class="header">
      <h1>${displayName}</h1>
      <p>${domain} · Service Sécurité</p>
    </div>
    <div class="body">
      <p>Bonjour,</p>
      ${bodyHtml}
      ${hasButton ? `<div class="cta"><a href="${btnLink}">${btnLabel}</a></div>` : ''}
    </div>
    <div class="footer">
      © ${year} ${domain} · Tous droits réservés<br>
      Ce message a été envoyé depuis ${domain} · <a href="#" style="color:#94a3b8">Se désabonner</a>
    </div>
  </div>
</body>
</html>`;
}

export default router;
