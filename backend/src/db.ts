import { Pool } from 'pg';

const connectionString = process.env.SUPABASE_DATABASE_URL || process.env.DATABASE_URL;

// En production, la plupart des fournisseurs (Neon, Supabase, RDS...) exposent un certificat
// valide — on vérifie donc la chaîne TLS. Autorise un contournement explicite via
// DB_SSL_REJECT_UNAUTHORIZED=false uniquement si un environnement impose un certificat auto-signé.
const allowInsecureTls = process.env.DB_SSL_REJECT_UNAUTHORIZED === 'false';

export const pool = new Pool({
  connectionString,
  ssl: { rejectUnauthorized: !allowInsecureTls },
});

pool.on('error', (err) => {
  console.error('Database pool error:', err);
});
