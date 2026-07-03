import { Pool } from 'pg';

const connectionString = process.env.SUPABASE_DATABASE_URL || process.env.DATABASE_URL;

export const pool = new Pool({
  connectionString,
  ssl: { rejectUnauthorized: false },
});

pool.on('error', (err) => {
  console.error('Database pool error:', err);
});
