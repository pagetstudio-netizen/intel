import express from 'express';
import cors from 'cors';
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

const app = express();
const PORT = parseInt(process.env.PORT || '3000');

app.use(cors());
app.use(express.json());

// Health check
app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected', time: new Date().toISOString() });
  } catch {
    res.status(503).json({ status: 'error', db: 'disconnected' });
  }
});

app.use('/api/scans', scansRouter);
app.use('/api/fuzz', fuzzRouter);
app.use('/api/load-test', loadTestRouter);
app.use('/api/phishing', phishingRouter);
app.use('/api/demo-email', demoEmailRouter);
app.use('/api/fintech-fraud', fintechFraudRouter);
app.use('/api/mandates', mandatesRouter);
app.use('/api/osint', osintRouter);
app.use('/api/auth-audit', authAuditRouter);

app.listen(PORT, '0.0.0.0', () => {
  console.log(`INTEL API running on port ${PORT}`);
});
