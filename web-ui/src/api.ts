const BASE = '/api';

async function safeFetch<T>(input: RequestInfo, init?: RequestInit): Promise<T> {
  const r = await fetch(input, init);
  if (!r.ok) {
    let msg = `Erreur ${r.status}`;
    try {
      const body = await r.json();
      if (body?.error) msg = body.error;
    } catch {}
    throw new Error(msg);
  }
  return r.json();
}

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

export interface GeoStat {
  country: string;
  country_code: string;
  requests: number;
  successful: number;
  failed: number;
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
  results?: { geo_breakdown?: GeoStat[]; countries_used?: number };
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

export interface AuthCheck {
  id: string;
  name: string;
  category: 'unauth_access' | 'cookie' | 'bypass' | 'admin' | 'token' | 'header';
  passed: boolean;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  detail: string;
  fix: string;
}

export interface ExposedEndpoint {
  path: string;
  method: string;
  status: number;
  response_size: number;
  has_json: boolean;
  auth_required: boolean;
}

export interface AuthAudit {
  id: string;
  target_url: string;
  domain: string;
  status: 'running' | 'completed' | 'failed';
  checks: AuthCheck[];
  exposed_endpoints: ExposedEndpoint[];
  risk_score: number;
  risk_level: 'CRITIQUE' | 'ÉLEVÉ' | 'MOYEN' | 'FAIBLE' | 'UNKNOWN';
  summary?: string;
  created_at: string;
  completed_at?: string;
}

export interface SecurityFinding {
  id: string;
  name: string;
  category: 'headers' | 'tls' | 'vuln';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  passed: boolean;
  description: string;
  recommendation: string;
}

export interface SecurityAudit {
  id: string;
  target_url: string;
  domain: string;
  status: 'running' | 'completed' | 'failed';
  findings: SecurityFinding[];
  score: number;
  risk_level: 'CRITIQUE' | 'ÉLEVÉ' | 'MOYEN' | 'FAIBLE' | 'UNKNOWN';
  summary?: string;
  created_at: string;
  completed_at?: string;
}

export const api = {
  getScans: (): Promise<Scan[]> =>
    safeFetch(`${BASE}/scans`),
  getScan: (id: string): Promise<Scan> =>
    safeFetch(`${BASE}/scans/${id}`),
  startScan: (target_url: string, deep = false, timeout = 60): Promise<Scan> =>
    safeFetch(`${BASE}/scans`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target_url, deep, timeout }) }),

  getFuzzJobs: (): Promise<FuzzJob[]> =>
    safeFetch(`${BASE}/fuzz`),
  getFuzzJob: (id: string): Promise<FuzzJob> =>
    safeFetch(`${BASE}/fuzz/${id}`),
  startFuzz: (target_url: string, concurrency = 10, timeout_ms = 5000): Promise<FuzzJob> =>
    safeFetch(`${BASE}/fuzz`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target_url, concurrency, timeout_ms }) }),

  getLoadTests: (): Promise<LoadTest[]> =>
    safeFetch(`${BASE}/load-test`),
  startLoadTest: (target_url: string, concurrent_users = 50, rps = 10, duration_seconds = 30): Promise<LoadTest> =>
    safeFetch(`${BASE}/load-test`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target_url, concurrent_users, rps, duration_seconds }) }),

  getPhishingAssessments: (): Promise<PhishingAssessment[]> =>
    safeFetch(`${BASE}/phishing`),
  startPhishing: (target_url: string): Promise<PhishingAssessment> =>
    safeFetch(`${BASE}/phishing`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target_url }) }),

  getFintechFraudAudits: (): Promise<FintechFraudAudit[]> =>
    safeFetch(`${BASE}/fintech-fraud`),
  startFintechFraud: (target_url: string): Promise<FintechFraudAudit> =>
    safeFetch(`${BASE}/fintech-fraud`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target_url }) }),

  getOsintScans: (): Promise<OsintScan[]> =>
    safeFetch(`${BASE}/osint`),
  startOsint: (domain: string): Promise<OsintScan> =>
    safeFetch(`${BASE}/osint`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain }) }),

  getMandates: (): Promise<Mandate[]> =>
    safeFetch(`${BASE}/mandates`),
  createMandate: (data: {
    tester_company: string; client_name: string; client_email: string;
    client_company: string; target_urls: string[]; scope: string[];
    valid_from: string; valid_until: string; notes?: string;
  }): Promise<Mandate> =>
    safeFetch(`${BASE}/mandates`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }),
  getMandateByToken: (token: string): Promise<Mandate> =>
    safeFetch(`${BASE}/mandates/confirm/${token}`),

  getAuthAudits: (): Promise<AuthAudit[]> =>
    safeFetch(`${BASE}/auth-audit`),
  startAuthAudit: (target_url: string): Promise<AuthAudit> =>
    safeFetch(`${BASE}/auth-audit`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target_url }) }),

  confirmMandate: (token: string): Promise<Mandate> =>
    safeFetch(`${BASE}/mandates/confirm/${token}`, { method: 'POST' }),
  revokeMandate: (id: string): Promise<void> =>
    safeFetch(`${BASE}/mandates/${id}`, { method: 'DELETE' }),

  getSecurityAudits: (): Promise<SecurityAudit[]> =>
    safeFetch(`${BASE}/security-audit`),
  startSecurityAudit: (target_url: string): Promise<SecurityAudit> =>
    safeFetch(`${BASE}/security-audit`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target_url }) }),
};
