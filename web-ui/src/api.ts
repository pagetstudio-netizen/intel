const BASE = '/api';

export interface PhishingCheck {
  id: string;
  name: string;
  category: 'email' | 'http' | 'dns' | 'ssl';
  passed: boolean;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  detail: string;
  fix: string;
}

export interface PhishingAssessment {
  id: string;
  target_url: string;
  domain: string;
  status: 'running' | 'completed' | 'failed';
  risk_score: number;
  risk_level: 'CRITIQUE' | 'ÉLEVÉ' | 'MOYEN' | 'FAIBLE' | 'UNKNOWN';
  checks: PhishingCheck[];
  summary?: string;
  created_at: string;
  completed_at?: string;
}

export interface LoadTest {
  id: string;
  target_url: string;
  status: 'running' | 'completed' | 'failed';
  concurrent_users: number;
  rps: number;
  duration_seconds: number;
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  requests_per_second: number;
  avg_response_ms: number;
  server_crash: boolean;
  verdict?: string;
  created_at: string;
  completed_at?: string;
}

export interface Scan {
  id: string;
  target_url: string;
  scan_type: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  findings: Finding[];
  config: Record<string, unknown>;
  created_at: string;
  completed_at?: string;
}

export interface Finding {
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  fix?: string;
  ref?: string;
}

export interface FuzzJob {
  id: string;
  target_url: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  results: FuzzResult[];
  concurrency: number;
  timeout_ms: number;
  created_at: string;
  completed_at?: string;
}

export interface FuzzResult {
  status: number;
  path: string;
  size: number;
  ms: number;
}

export const api = {
  async getScans(): Promise<Scan[]> {
    const r = await fetch(`${BASE}/scans`);
    return r.json();
  },
  async getScan(id: string): Promise<Scan> {
    const r = await fetch(`${BASE}/scans/${id}`);
    return r.json();
  },
  async startScan(target_url: string, deep = false, timeout = 60): Promise<Scan> {
    const r = await fetch(`${BASE}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url, deep, timeout }),
    });
    return r.json();
  },
  async getFuzzJobs(): Promise<FuzzJob[]> {
    const r = await fetch(`${BASE}/fuzz`);
    return r.json();
  },
  async getFuzzJob(id: string): Promise<FuzzJob> {
    const r = await fetch(`${BASE}/fuzz/${id}`);
    return r.json();
  },
  async startFuzz(target_url: string, concurrency = 10, timeout_ms = 5000): Promise<FuzzJob> {
    const r = await fetch(`${BASE}/fuzz`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url, concurrency, timeout_ms }),
    });
    return r.json();
  },
  async getLoadTests(): Promise<LoadTest[]> {
    const r = await fetch(`${BASE}/load-test`);
    return r.json();
  },
  async startLoadTest(target_url: string, concurrent_users = 50, rps = 10, duration_seconds = 30): Promise<LoadTest> {
    const r = await fetch(`${BASE}/load-test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url, concurrent_users, rps, duration_seconds }),
    });
    return r.json();
  },
  async getPhishingAssessments(): Promise<PhishingAssessment[]> {
    const r = await fetch(`${BASE}/phishing`);
    return r.json();
  },
  async startPhishing(target_url: string): Promise<PhishingAssessment> {
    const r = await fetch(`${BASE}/phishing`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url }),
    });
    return r.json();
  },
};
