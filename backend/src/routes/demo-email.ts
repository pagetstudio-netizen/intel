import { Router, Request, Response } from 'express';
import { pool } from '../db';
import { Resend } from 'resend';

const router = Router();

// POST /api/demo-email
router.post('/', async (req: Request, res: Response) => {
  const { assessment_id, to_email, spoof_name } = req.body;

  if (!to_email || !assessment_id) {
    return res.status(400).json({ error: 'assessment_id et to_email requis' });
  }

  // Validate destination email (simple check)
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to_email)) {
    return res.status(400).json({ error: 'Adresse email invalide' });
  }

  // Fetch assessment
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

  const apiKey = process.env.RESEND_API_KEY;
  const fromEmail = process.env.RESEND_FROM_EMAIL;

  if (!apiKey || !fromEmail) {
    return res.status(503).json({
      error: 'RESEND_API_KEY et RESEND_FROM_EMAIL non configurés',
      setup: true,
    });
  }

  const resend = new Resend(apiKey);
  const domain = assessment.domain as string;
  const displayName = spoof_name || `Support ${domain}`;
  const spoofFrom = `${displayName} <${fromEmail}>`;

  // Build realistic phishing email template
  const html = buildPhishingTemplate(domain, displayName);

  try {
    const result = await resend.emails.send({
      from: spoofFrom,
      to: [to_email],
      replyTo: `noreply@${domain}`,
      subject: `[ACTION REQUISE] Vérification de sécurité — ${domain}`,
      html,
    });

    if (result.error) {
      return res.status(500).json({ error: result.error.message });
    }

    // Log the demo in the assessment
    await pool.query(
      `UPDATE phishing_assessments SET
        summary = summary || ' | Demo email envoyé à ' || $1
       WHERE id = $2`,
      [to_email, assessment_id]
    );

    res.json({
      ok: true,
      message: `Email de démonstration envoyé à ${to_email}`,
      email_id: result.data?.id,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message ?? 'Échec de l\'envoi' });
  }
});

function buildPhishingTemplate(domain: string, displayName: string): string {
  const year = new Date().getFullYear();
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
    .body p { line-height: 1.7; margin: 0 0 16px; font-size: 15px; }
    .alert-box { background: #fef2f2; border: 1px solid #fca5a5; border-radius: 6px; padding: 16px 20px; margin: 20px 0; }
    .alert-box p { margin: 0; color: #991b1b; font-size: 14px; }
    .cta { text-align: center; margin: 28px 0; }
    .cta a { background: #dc2626; color: #ffffff; text-decoration: none; padding: 14px 36px; border-radius: 6px; font-size: 15px; font-weight: bold; display: inline-block; }
    .info-grid { background: #f8fafc; border-radius: 6px; padding: 16px 20px; margin: 20px 0; }
    .info-row { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #e2e8f0; font-size: 13px; }
    .info-row:last-child { border-bottom: none; }
    .info-label { color: #64748b; }
    .info-value { color: #1e293b; font-weight: 600; }
    .footer { background: #f8fafc; padding: 20px 32px; text-align: center; color: #94a3b8; font-size: 12px; border-top: 1px solid #e2e8f0; }
    .demo-badge { background: #fbbf24; color: #1e293b; text-align: center; padding: 12px; font-size: 13px; font-weight: bold; border-radius: 0 0 8px 8px; }
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
      <p>Nous avons détecté une <strong>connexion suspecte</strong> sur votre compte depuis un appareil non reconnu. Par mesure de sécurité, votre accès a été temporairement restreint.</p>

      <div class="alert-box">
        <p>🔴 <strong>Connexion bloquée détectée :</strong><br>
        Vous devez vérifier votre identité dans les <strong>24 heures</strong> pour éviter la suspension de votre compte.</p>
      </div>

      <div class="info-grid">
        <div class="info-row">
          <span class="info-label">Appareil détecté</span>
          <span class="info-value">Inconnu · Linux</span>
        </div>
        <div class="info-row">
          <span class="info-label">Localisation</span>
          <span class="info-value">Lagos, Nigeria</span>
        </div>
        <div class="info-row">
          <span class="info-label">Date / Heure</span>
          <span class="info-value">${new Date().toLocaleString('fr-FR')}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Statut</span>
          <span class="info-value" style="color:#dc2626">⛔ Accès bloqué</span>
        </div>
      </div>

      <p>Si vous êtes à l'origine de cette tentative de connexion, ignorez cet email. Dans le cas contraire, sécurisez immédiatement votre compte :</p>

      <div class="cta">
        <a href="#">🔐 Vérifier mon identité</a>
      </div>

      <p style="font-size:13px; color:#64748b;">Ce lien expire dans <strong>24 heures</strong>. Passé ce délai, vous devrez contacter notre support.</p>
    </div>
    <div class="footer">
      © ${year} ${domain} · Tous droits réservés<br>
      Ce message a été envoyé depuis ${domain} · <a href="#" style="color:#94a3b8">Se désabonner</a>
    </div>
    <div class="demo-badge">
      🔬 CECI EST UN EMAIL DE DÉMONSTRATION PENTEST — Envoyé par INTEL Security Platform
    </div>
  </div>
</body>
</html>`;
}

export default router;
