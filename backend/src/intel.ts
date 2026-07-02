import { spawn } from 'child_process';
import path from 'path';

const BINARY = path.join(__dirname, '../../security-core/target/release/intel');

export interface ScanOptions {
  target: string;
  deep?: boolean;
  timeout?: number;
}

export interface FuzzOptions {
  target: string;
  concurrency?: number;
  timeoutMs?: number;
}

function runIntel(args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const proc = spawn(BINARY, args, { timeout: 120_000 });
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d) => { stdout += d.toString(); });
    proc.stderr.on('data', (d) => { stderr += d.toString(); });
    proc.on('close', (code) => {
      if (code === 0) resolve(stdout);
      else reject(new Error(stderr || `Exit code ${code}`));
    });
    proc.on('error', reject);
  });
}

export async function runScan(opts: ScanOptions): Promise<string> {
  const args = ['scan', '--target', opts.target];
  if (opts.deep) args.push('--deep');
  if (opts.timeout) args.push('--timeout', String(opts.timeout));
  return runIntel(args);
}

export async function runFuzz(opts: FuzzOptions): Promise<string> {
  const args = ['fuzz', '--target', opts.target];
  if (opts.concurrency) args.push('--concurrency', String(opts.concurrency));
  if (opts.timeoutMs) args.push('--timeout-ms', String(opts.timeoutMs));
  return runIntel(args);
}
