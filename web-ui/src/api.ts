const BASE = '/api';

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
};
