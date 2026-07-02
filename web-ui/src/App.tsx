import { useState, useEffect, useCallback } from 'react';
import { api, Scan, FuzzJob } from './api';
import './app.css';

type Tab = 'scanner' | 'fuzzer' | 'history';

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: '#ff3b5c',
  HIGH: '#ff6b35',
  MEDIUM: '#fbbf24',
  LOW: '#60d394',
  INFO: '#60a5fa',
};

function Badge({ s }: { s: string }) {
  const colors: Record<string, string> = {
    completed: '#60d394', running: '#60a5fa', failed: '#ff3b5c', pending: '#94a3b8',
  };
  return (
    <span style={{ color: colors[s] ?? '#94a3b8', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1 }}>
      {s === 'running' ? '⟳ ' : s === 'completed' ? '✓ ' : s === 'failed' ? '✗ ' : '· '}{s}
    </span>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>('scanner');
  const [scans, setScans] = useState<Scan[]>([]);
  const [fuzzes, setFuzzes] = useState<FuzzJob[]>([]);
  const [selected, setSelected] = useState<Scan | FuzzJob | null>(null);

  // Scanner form
  const [scanTarget, setScanTarget] = useState('https://');
  const [scanDeep, setScanDeep] = useState(false);
  const [scanLoading, setScanLoading] = useState(false);

  // Fuzzer form
  const [fuzzTarget, setFuzzTarget] = useState('https://');
  const [fuzzConcurrency, setFuzzConcurrency] = useState(10);
  const [fuzzLoading, setFuzzLoading] = useState(false);

  const refresh = useCallback(async () => {
    const [s, f] = await Promise.all([api.getScans(), api.getFuzzJobs()]);
    setScans(s);
    setFuzzes(f);
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 4000);
    return () => clearInterval(t);
  }, [refresh]);

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    setScanLoading(true);
    try {
      await api.startScan(scanTarget, scanDeep);
      await refresh();
      setTab('history');
    } finally {
      setScanLoading(false);
    }
  }

  async function handleFuzz(e: React.FormEvent) {
    e.preventDefault();
    setFuzzLoading(true);
    try {
      await api.startFuzz(fuzzTarget, fuzzConcurrency);
      await refresh();
      setTab('history');
    } finally {
      setFuzzLoading(false);
    }
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0a0e1a' }}>
      {/* Header */}
      <header style={{ background: '#0d1424', borderBottom: '1px solid #1e293b', padding: '16px 32px', display: 'flex', alignItems: 'center', gap: 16 }}>
        <span style={{ fontSize: 20, fontWeight: 700, color: '#60a5fa', letterSpacing: 2 }}>⬡ INTEL</span>
        <span style={{ color: '#475569', fontSize: 13 }}>Pentest & Security Platform</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          {(['scanner', 'fuzzer', 'history'] as Tab[]).map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              background: tab === t ? '#1e3a5f' : 'transparent',
              color: tab === t ? '#60a5fa' : '#94a3b8',
              border: tab === t ? '1px solid #2563eb' : '1px solid transparent',
              borderRadius: 6, padding: '6px 16px', cursor: 'pointer', fontSize: 13, fontFamily: 'inherit', textTransform: 'uppercase', letterSpacing: 1,
            }}>{t}</button>
          ))}
        </div>
      </header>

      <main style={{ maxWidth: 960, margin: '0 auto', padding: '32px 24px' }}>

        {/* Scanner Tab */}
        {tab === 'scanner' && (
          <div>
            <h2 style={{ color: '#e2e8f0', marginBottom: 24, fontSize: 18 }}>🔍 Vulnerability Scanner</h2>
            <form onSubmit={handleScan} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 28 }}>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Target URL</label>
              <input value={scanTarget} onChange={e => setScanTarget(e.target.value)} required
                style={{ width: '100%', background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 14, fontFamily: 'inherit', marginBottom: 16 }} />
              <label style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#94a3b8', fontSize: 13, marginBottom: 20, cursor: 'pointer' }}>
                <input type="checkbox" checked={scanDeep} onChange={e => setScanDeep(e.target.checked)} />
                Deep scan (plus long mais plus complet)
              </label>
              <button type="submit" disabled={scanLoading} style={{
                background: scanLoading ? '#1e3a5f' : '#2563eb', color: '#fff', border: 'none', borderRadius: 6,
                padding: '10px 24px', cursor: 'pointer', fontSize: 14, fontFamily: 'inherit', fontWeight: 600,
              }}>{scanLoading ? '⟳ Lancement...' : '▶ Lancer le scan'}</button>
            </form>
          </div>
        )}

        {/* Fuzzer Tab */}
        {tab === 'fuzzer' && (
          <div>
            <h2 style={{ color: '#e2e8f0', marginBottom: 24, fontSize: 18 }}>🕸 Endpoint Fuzzer</h2>
            <form onSubmit={handleFuzz} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 28 }}>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Target URL</label>
              <input value={fuzzTarget} onChange={e => setFuzzTarget(e.target.value)} required
                style={{ width: '100%', background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 14, fontFamily: 'inherit', marginBottom: 16 }} />
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Concurrence ({fuzzConcurrency} threads)</label>
              <input type="range" min={1} max={50} value={fuzzConcurrency} onChange={e => setFuzzConcurrency(parseInt(e.target.value))}
                style={{ width: '100%', marginBottom: 20 }} />
              <button type="submit" disabled={fuzzLoading} style={{
                background: fuzzLoading ? '#1e3a5f' : '#7c3aed', color: '#fff', border: 'none', borderRadius: 6,
                padding: '10px 24px', cursor: 'pointer', fontSize: 14, fontFamily: 'inherit', fontWeight: 600,
              }}>{fuzzLoading ? '⟳ Lancement...' : '▶ Lancer le fuzzing'}</button>
            </form>
          </div>
        )}

        {/* History Tab */}
        {tab === 'history' && (
          <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 1fr' : '1fr', gap: 24 }}>
            <div>
              <h2 style={{ color: '#e2e8f0', marginBottom: 16, fontSize: 18 }}>Scans</h2>
              {scans.length === 0 && <p style={{ color: '#475569', fontSize: 14 }}>Aucun scan lancé.</p>}
              {scans.map(s => (
                <div key={s.id} onClick={() => setSelected(s)} style={{
                  background: '#0d1424', border: `1px solid ${selected?.id === s.id ? '#2563eb' : '#1e293b'}`,
                  borderRadius: 8, padding: '14px 18px', marginBottom: 10, cursor: 'pointer',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span style={{ color: '#e2e8f0', fontSize: 14, fontWeight: 600, wordBreak: 'break-all' }}>{s.target_url}</span>
                    <Badge s={s.status} />
                  </div>
                  <div style={{ color: '#475569', fontSize: 12 }}>
                    {new Date(s.created_at).toLocaleString()} · {s.findings?.length ?? 0} finding(s)
                  </div>
                </div>
              ))}

              <h2 style={{ color: '#e2e8f0', margin: '24px 0 16px', fontSize: 18 }}>Fuzz Jobs</h2>
              {fuzzes.length === 0 && <p style={{ color: '#475569', fontSize: 14 }}>Aucun fuzzing lancé.</p>}
              {fuzzes.map(f => (
                <div key={f.id} onClick={() => setSelected(f)} style={{
                  background: '#0d1424', border: `1px solid ${selected?.id === f.id ? '#7c3aed' : '#1e293b'}`,
                  borderRadius: 8, padding: '14px 18px', marginBottom: 10, cursor: 'pointer',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span style={{ color: '#e2e8f0', fontSize: 14, fontWeight: 600, wordBreak: 'break-all' }}>{f.target_url}</span>
                    <Badge s={f.status} />
                  </div>
                  <div style={{ color: '#475569', fontSize: 12 }}>
                    {new Date(f.created_at).toLocaleString()} · {f.results?.length ?? 0} endpoint(s) découvert(s)
                  </div>
                </div>
              ))}
            </div>

            {/* Detail panel */}
            {selected && (
              <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 24 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 20 }}>
                  <h3 style={{ color: '#60a5fa', fontSize: 15 }}>Détails</h3>
                  <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: '#475569', cursor: 'pointer', fontSize: 18 }}>✕</button>
                </div>
                <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 16, wordBreak: 'break-all' }}>{selected.target_url}</div>

                {'findings' in selected && selected.findings?.length > 0 && (
                  <div>
                    {selected.findings.map((f, i) => (
                      <div key={i} style={{ borderLeft: `3px solid ${SEVERITY_COLOR[f.severity] ?? '#60a5fa'}`, padding: '10px 14px', marginBottom: 10, background: '#0a0e1a', borderRadius: '0 6px 6px 0' }}>
                        <div style={{ display: 'flex', gap: 10, marginBottom: 4 }}>
                          <span style={{ color: SEVERITY_COLOR[f.severity], fontSize: 11, fontWeight: 700 }}>{f.severity}</span>
                          <span style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>{f.title}</span>
                        </div>
                        <div style={{ color: '#94a3b8', fontSize: 12 }}>{f.description}</div>
                        {f.fix && <div style={{ color: '#60d394', fontSize: 11, marginTop: 4 }}>↳ Fix: {f.fix}</div>}
                        {f.ref && <div style={{ color: '#60a5fa', fontSize: 11 }}>↳ Ref: {f.ref}</div>}
                      </div>
                    ))}
                  </div>
                )}

                {'results' in selected && selected.results?.length > 0 && (
                  <div>
                    {selected.results.map((r, i) => (
                      <div key={i} style={{ display: 'flex', gap: 12, padding: '8px 12px', marginBottom: 6, background: '#0a0e1a', borderRadius: 6, fontSize: 12, alignItems: 'center' }}>
                        <span style={{ color: r.status < 300 ? '#60d394' : r.status < 400 ? '#fbbf24' : '#ff6b35', fontWeight: 700, width: 36 }}>{r.status}</span>
                        <span style={{ color: '#e2e8f0', flex: 1 }}>{r.path}</span>
                        <span style={{ color: '#475569' }}>{r.ms}ms</span>
                      </div>
                    ))}
                  </div>
                )}

                {'findings' in selected && selected.status === 'completed' && selected.findings?.length === 0 && (
                  <p style={{ color: '#60d394', fontSize: 14 }}>✓ Aucune vulnérabilité détectée</p>
                )}
                {'results' in selected && selected.status === 'completed' && selected.results?.length === 0 && (
                  <p style={{ color: '#94a3b8', fontSize: 14 }}>Aucun endpoint découvert</p>
                )}
                {selected.status === 'running' && (
                  <p style={{ color: '#60a5fa', fontSize: 14 }}>⟳ En cours... (actualisation auto)</p>
                )}
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
