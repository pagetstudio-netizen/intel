-- INTEL Security Platform — Schéma PostgreSQL
-- À exécuter une seule fois sur le serveur Plesk

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_url TEXT NOT NULL,
    scan_type TEXT NOT NULL DEFAULT 'vulnerability',
    status TEXT NOT NULL DEFAULT 'pending',
    findings JSONB DEFAULT '[]',
    config JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS fuzz_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    results JSONB DEFAULT '[]',
    concurrency INT DEFAULT 10,
    timeout_ms INT DEFAULT 5000,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS load_tests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    concurrent_users INT NOT NULL DEFAULT 50,
    rps INT NOT NULL DEFAULT 10,
    duration_seconds INT NOT NULL DEFAULT 30,
    total_requests BIGINT DEFAULT 0,
    successful_requests BIGINT DEFAULT 0,
    failed_requests BIGINT DEFAULT 0,
    requests_per_second BIGINT DEFAULT 0,
    avg_response_ms BIGINT DEFAULT 0,
    server_crash BOOLEAN DEFAULT FALSE,
    verdict TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS phishing_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_url TEXT NOT NULL,
    domain TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    risk_score INT DEFAULT 0,
    risk_level TEXT DEFAULT 'UNKNOWN',
    checks JSONB DEFAULT '[]',
    summary TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
