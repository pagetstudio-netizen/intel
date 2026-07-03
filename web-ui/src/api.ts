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

export interface FraudCheck {
  id: string;
  name: string;
  category: 'auth' | 'csrf' | 'cors' | 'ratelimit' | 'headers' | 'exposure';
  passed: boolean;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  detail: string;
  fix: string;
}

export interface FintechFraudAudit {
  id: string;
  target_url: string;
  domain: string;
  status: 'running' | 'completed' | 'failed';
  risk_score: number;
  risk_level: 'CRITIQUE' | 'ÉLEVÉ' | 'MOYEN' | 'FAIBLE' | 'UNKNOWN';
  checks: FraudCheck[];
  summary?: string;
  created_at: string;
  completed_at?: string;
}

export interface OsintSource {
  type: string;
  value: string;
  detail: string;
}

export interface OsintScan {
  id: string;
  domain: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  emails_found: string[];
  sources: OsintSource[];
  subdomains: string[];
  dns_records: Record<string, any>;
  created_at: string;
  completed_at?: string;
}

export interface Mandate {
  id: string;
  tester_company: string;
  client_name: string;
  client_email: string;
  client_company: string;
  target_urls: string[];
  scope: string[];
  status: 'pending' | 'authorized' | 'expired';
  token: string;
  valid_from: string;
  valid_until: string;
  notes?: string;
  signed_ip?: string;
  signed_at?: string;
  created_at: string;
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
  async getFintechFraudAudits(): Promise<FintechFraudAudit[]> {
    const r = await fetch(`${BASE}/fintech-fraud`);
    return r.json();
  },
  async startFintechFraud(target_url: string): Promise<FintechFraudAudit> {
    const r = await fetch(`${BASE}/fintech-fraud`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url }),
    });
    return r.json();
  },

  async getOsintScans(): Promise<OsintScan[]> {
    const r = await fetch(`${BASE}/osint`);
    return r.json();
  },
  async startOsint(domain: string): Promise<OsintScan> {
    const r = await fetch(`${BASE}/osint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    return r.json();
  },

  async getMandates(): Promise<Mandate[]> {
    const r = await fetch(`${BASE}/mandates`);
    return r.json();
  },
  async createMandate(data: {
    tester_company: string; client_name: string; client_email: string;
    client_company: string; target_urls: string[]; scope: string[];
    valid_from: string; valid_until: string; notes?: string;
  }): Promise<Mandate> {
    const r = await fetch(`${BASE}/mandates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return r.json();
  },
  async getMandateByToken(token: string): Promise<Mandate> {
    const r = await fetch(`${BASE}/mandates/confirm/${token}`);
    return r.json();
  },
  async confirmMandate(token: string): Promise<Mandate> {
    const r = await fetch(`${BASE}/mandates/confirm/${token}`, { method: 'POST' });
    return r.json();
  },
  async revokeMandate(id: string): Promise<void> {
    await fetch(`${BASE}/mandates/${id}`, { method: 'DELETE' });
  },
};
