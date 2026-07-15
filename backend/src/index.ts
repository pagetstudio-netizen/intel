import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { pool } from './db';
import scansRouter from './routes/scans';
import fuzzRouter from './routes/fuzz';
import loadTestRouter from './routes/load-test';
import phishingRouter from './routes/phishing';
import demoEmailRouter from './routes/demo-email';
import fintechFraudRouter from './routes/fintech-fraud';
import mandatesRouter from './routes/mandates';
import osintRouter from './routes/osint';
import authAuditRouter from './routes/auth-audit';
import { scanLimiter, mutationLimiter } from './rate-limit';

const app = express();
const PORT = parseInt(process.env.PORT || '3000');

// CORS — en production, restreindre aux origines listées dans ALLOWED_ORIGINS
// (séparées par des virgules). Sans variable définie, autorise tout en dev pour
// ne pas casser le poste de développement local.
const allowedOrigins = (process.env.ALLOWED_ORIGINS ?? '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: allowedOrigins.length > 0
    ? allowedOrigins
    : (process.env.NODE_ENV === 'production' ? false : true),
}));
app.use(express.json());

// Health check — vérifie les vrais points de défaillance possibles (DB, binaire Rust, build frontend)
app.get('/api/health', async (_req, res) => {
  const checks: { name: string; ok: boolean; detail: string }[] = [];

  // 1) Base de données
  try {
    await pool.query('SELECT 1');
    checks.push({ name: 'database', ok: true, detail: 'Connexion PostgreSQL OK' });
  } catch (e: any) {
    checks.push({ name: 'database', ok: false, detail: `Connexion PostgreSQL échouée : ${e?.message || e}` });
  }

  // 2) Variable DATABASE_URL présente
  const hasDbUrl = !!(process.env.DATABASE_URL || process.env.SUPABASE_DATABASE_URL);
  checks.push({
    name: 'database_url',
    ok: hasDbUrl,
    detail: hasDbUrl ? 'DATABASE_URL définie' : 'DATABASE_URL manquante — définis-la dans Plesk > Node.js > Variables d\'environnement',
  });

  // 3) Binaire Rust compilé (nécessaire pour Scan / Fuzz / Load-test)
  // __dirname = backend/src, donc ../../ = racine du projet, quel que soit le cwd du process
  const projectRoot = path.resolve(__dirname, '..', '..');
  const binaryPath = path.resolve(projectRoot, 'security-core', 'target', 'release', 'intel');
  const binaryExists = fs.existsSync(binaryPath);
  let binaryExecutable = false;
  if (binaryExists) {
    try {
      fs.accessSync(binaryPath, fs.constants.X_OK);
      binaryExecutable = true;
    } catch {
      binaryExecutable = false;
    }
  }
  checks.push({
    name: 'rust_binary',
    ok: binaryExists && binaryExecutable,
    detail: !binaryExists
      ? `Binaire introuvable (${binaryPath}) — lance "bash deploy.sh" ou "cd security-core && cargo build --release" sur ce serveur`
      : !binaryExecutable
      ? `Binaire présent mais non exécutable — lance "chmod +x ${binaryPath}"`
      : 'security-core compilé et exécutable',
  });

  // 4) Build frontend (web-ui/dist)
  const distIndexPath = path.resolve(projectRoot, 'web-ui', 'dist', 'index.html');
  const distExists = fs.existsSync(distIndexPath);
  checks.push({
    name: 'frontend_build',
    ok: distExists,
    detail: distExists
      ? 'web-ui/dist/index.html trouvé'
      : `Build frontend manquant (${distIndexPath}) — lance "cd web-ui && npm run build" ou "bash deploy.sh"`,
  });

  const allOk = checks.every(c => c.ok);
  res.status(allOk ? 200 : 503).json({
    status: allOk ? 'ok' : 'error',
    time: new Date().toISOString(),
    node_env: process.env.NODE_ENV || 'development',
    cwd: process.cwd(),
    checks,
  });
});

// Les endpoints qui déclenchent des requêtes sortantes (scan/fuzz/load-test/etc.)
// sont limités en débit pour éviter les abus (DoS, usage comme proxy d'attaque).
app.use('/api/scans', scanLimiter, scansRouter);
app.use('/api/fuzz', scanLimiter, fuzzRouter);
app.use('/api/load-test', scanLimiter, loadTestRouter);
app.use('/api/phishing', scanLimiter, phishingRouter);
app.use('/api/demo-email', mutationLimiter, demoEmailRouter);
app.use('/api/fintech-fraud', scanLimiter, fintechFraudRouter);
app.use('/api/mandates', mutationLimiter, mandatesRouter);
app.use('/api/osint', scanLimiter, osintRouter);
app.use('/api/auth-audit', scanLimiter, authAuditRouter);

// Servir le frontend React en production (Plesk / déploiement)
const distPath = path.resolve(__dirname, '..', '..', 'web-ui', 'dist');
if (process.env.NODE_ENV === 'production' && fs.existsSync(distPath)) {
  app.use(express.static(distPath));
  app.get('*', (_req, res) => {
    res.sendFile(path.join(distPath, 'index.html'));
  });
  console.log(`Frontend servi depuis : ${distPath}`);
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`INTEL API running on port ${PORT}`);
});
