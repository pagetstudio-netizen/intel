import { useState, useEffect, useCallback } from 'react';
import { api, Scan, FuzzJob, LoadTest } from './api';
import './app.css';

type Tab = 'scanner' | 'fuzzer' | 'loadtest' | 'history';

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff3b5c', HIGH: '#ff6b35', MEDIUM: '#fbbf24', LOW: '#60d394', INFO: '#60a5fa',
};

function Badge({ s }: { s: string }) {
  const c: Record<string, string> = { completed: '#60d394', running: '#60a5fa', failed: '#ff3b5c', pending: '#94a3b8' };
  return <span style={{ color: c[s] ?? '#94a3b8', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1 }}>
    {s === 'running' ? '⟳ ' : s === 'completed' ? '✓ ' : s === 'failed' ? '✗ ' : '· '}{s}
  </span>;
}

function VerdictBanner({ verdict }: { verdict: string }) {
  const color = verdict.startsWith('✅') ? '#60d394' : verdict.startsWith('⚠️') ? '#fbbf24' : '#ff3b5c';
  return (
    <div style={{ background: `${color}18`, border: `1px solid ${color}40`, borderRadius: 8, padding: '14px 18px', marginTop: 16, fontSize: 15, fontWeight: 700, color }}>
      {verdict}
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>('loadtest');
  const [scans, setScans] = useState<Scan[]>([]);
  const [fuzzes, setFuzzes] = useState<FuzzJob[]>([]);
  const [loadTests, setLoadTests] = useState<LoadTest[]>([]);
  const [selected, setSelected] = useState<Scan | FuzzJob | LoadTest | null>(null);

  // Scanner
  const [scanTarget, setScanTarget] = useState('https://');
  const [scanDeep, setScanDeep] = useState(false);
  const [scanLoading, setScanLoading] = useState(false);

  // Fuzzer
  const [fuzzTarget, setFuzzTarget] = useState('https://');
  const [fuzzConcurrency, setFuzzConcurrency] = useState(10);
  const [fuzzLoading, setFuzzLoading] = useState(false);

  // Load test
  const [ltTarget, setLtTarget] = useState('https://');
  const [ltUsers, setLtUsers] = useState(50);
  const [ltRps, setLtRps] = useState(10);
  const [ltDuration, setLtDuration] = useState(30);
  const [ltLoading, setLtLoading] = useState(false);

  const refresh = useCallback(async () => {
    const [s, f, l] = await Promise.all([api.getScans(), api.getFuzzJobs(), api.getLoadTests()]);
    setScans(s); setFuzzes(f); setLoadTests(l);
    // Refresh selected if it's running
    if (selected && ('verdict' in selected || 'findings' in selected || 'results' in selected)) {
      const running = [...s, ...f, ...l].find(x => x.id === selected.id);
      if (running) setSelected(running);
    }
  }, [selected]);

  useEffect(() => { refresh(); const t = setInterval(refresh, 3000); return () => clearInterval(t); }, [refresh]);

  async function handleScan(e: React.FormEvent) {
    e.preventDefault(); setScanLoading(true);
    try { await api.startScan(scanTarget, scanDeep); await refresh(); setTab('history'); } finally { setScanLoading(false); }
  }
  async function handleFuzz(e: React.FormEvent) {
    e.preventDefault(); setFuzzLoading(true);
    try { await api.startFuzz(fuzzTarget, fuzzConcurrency); await refresh(); setTab('history'); } finally { setFuzzLoading(false); }
  }
  async function handleLoadTest(e: React.FormEvent) {
    e.preventDefault(); setLtLoading(true);
    try { const job = await api.startLoadTest(ltTarget, ltUsers, ltRps, ltDuration); setSelected(job); await refresh(); setTab('history'); } finally { setLtLoading(false); }
  }

  const input = (val: string, set: (v: string) => void) => (
    <input value={val} onChange={e => set(e.target.value)} required style={{ width: '100%', background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 14, fontFamily: 'inherit', marginBottom: 16, outline: 'none' }} />
  );
  const slider = (label: string, val: number, set: (v: number) => void, min: number, max: number, unit = '') => (
    <div style={{ marginBottom: 20 }}>
      <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 }}>{label} — <span style={{ color: '#60a5fa' }}>{val}{unit}</span></label>
      <input type="range" min={min} max={max} value={val} onChange={e => set(parseInt(e.target.value))} style={{ width: '100%' }} />
    </div>
  );

  return (
    <div style={{ minHeight: '100vh', background: '#0a0e1a' }}>
      <header style={{ background: '#0d1424', borderBottom: '1px solid #1e293b', padding: '14px 28px', display: 'flex', alignItems: 'center', gap: 14 }}>
        <span style={{ fontSize: 18, fontWeight: 700, color: '#60a5fa', letterSpacing: 2 }}>⬡ INTEL</span>
        <span style={{ color: '#475569', fontSize: 12 }}>Security Platform</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
          {([['loadtest', '⚡ Load Test'], ['scanner', '🔍 Scanner'], ['fuzzer', '🕸 Fuzzer'], ['history', '📋 History']] as [Tab, string][]).map(([t, label]) => (
            <button key={t} onClick={() => setTab(t)} style={{ background: tab === t ? '#1e3a5f' : 'transparent', color: tab === t ? '#60a5fa' : '#94a3b8', border: tab === t ? '1px solid #2563eb' : '1px solid transparent', borderRadius: 6, padding: '5px 14px', cursor: 'pointer', fontSize: 12, fontFamily: 'inherit', fontWeight: 600 }}>{label}</button>
          ))}
        </div>
      </header>

      <main style={{ maxWidth: 1000, margin: '0 auto', padding: '28px 20px' }}>

        {/* ⚡ LOAD TEST */}
        {tab === 'loadtest' && (
          <div>
            <h2 style={{ color: '#e2e8f0', marginBottom: 6, fontSize: 20 }}>⚡ Test de Résistance</h2>
            <p style={{ color: '#64748b', fontSize: 13, marginBottom: 24 }}>
              Simule de vraies vagues de trafic sur le site client. Si le serveur tient → victoire. S'il tombe → le client a un problème.
            </p>
            <form onSubmit={handleLoadTest} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 28 }}>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>URL du site client</label>
              {input(ltTarget, setLtTarget)}
              {slider('Utilisateurs simultanés', ltUsers, setLtUsers, 1, 500)}
              {slider('Requêtes / seconde par user', ltRps, setLtRps, 1, 100)}
              {slider('Durée du test', ltDuration, setLtDuration, 5, 120, 's')}

              <div style={{ background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '12px 16px', marginBottom: 20, fontSize: 12, color: '#64748b' }}>
                Estimation : <span style={{ color: '#60a5fa' }}>{ltUsers * ltRps} req/s</span> pendant <span style={{ color: '#60a5fa' }}>{ltDuration}s</span> = <span style={{ color: '#fbbf24' }}>~{ltUsers * ltRps * ltDuration} requêtes</span> au total
              </div>

              <button type="submit" disabled={ltLoading} style={{ background: ltLoading ? '#3b1c5c' : '#7c3aed', color: '#fff', border: 'none', borderRadius: 6, padding: '11px 28px', cursor: 'pointer', fontSize: 14, fontFamily: 'inherit', fontWeight: 700, letterSpacing: 1 }}>
                {ltLoading ? '⟳ Test en cours...' : '⚡ LANCER LE STRESS TEST'}
              </button>
            </form>

            {/* Recent load tests inline */}
            {loadTests.length > 0 && (
              <div style={{ marginTop: 28 }}>
                <h3 style={{ color: '#94a3b8', fontSize: 13, marginBottom: 12, textTransform: 'uppercase', letterSpacing: 1 }}>Derniers tests</h3>
                {loadTests.slice(0, 5).map(lt => (
                  <div key={lt.id} onClick={() => { setSelected(lt); setTab('history'); }} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 8, padding: '14px 18px', marginBottom: 8, cursor: 'pointer' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>{lt.target_url}</span>
                      <Badge s={lt.status} />
                    </div>
                    {lt.verdict && <div style={{ fontSize: 13, color: lt.verdict.startsWith('✅') ? '#60d394' : lt.verdict.startsWith('⚠️') ? '#fbbf24' : '#ff3b5c', marginTop: 4 }}>{lt.verdict}</div>}
                    {!lt.verdict && lt.status === 'running' && <div style={{ color: '#60a5fa', fontSize: 12 }}>⟳ Test en cours — {lt.concurrent_users} users × {lt.rps} req/s × {lt.duration_seconds}s...</div>}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* SCANNER */}
        {tab === 'scanner' && (
          <div>
            <h2 style={{ color: '#e2e8f0', marginBottom: 24, fontSize: 18 }}>🔍 Vulnerability Scanner</h2>
            <form onSubmit={handleScan} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 28 }}>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Target URL</label>
              {input(scanTarget, setScanTarget)}
              <label style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#94a3b8', fontSize: 13, marginBottom: 20, cursor: 'pointer' }}>
                <input type="checkbox" checked={scanDeep} onChange={e => setScanDeep(e.target.checked)} />
                Deep scan (plus long mais plus complet)
              </label>
              <button type="submit" disabled={scanLoading} style={{ background: scanLoading ? '#1e3a5f' : '#2563eb', color: '#fff', border: 'none', borderRadius: 6, padding: '10px 24px', cursor: 'pointer', fontSize: 14, fontFamily: 'inherit', fontWeight: 600 }}>
                {scanLoading ? '⟳ Lancement...' : '▶ Lancer le scan'}
              </button>
            </form>
          </div>
        )}

        {/* FUZZER */}
        {tab === 'fuzzer' && (
          <div>
            <h2 style={{ color: '#e2e8f0', marginBottom: 24, fontSize: 18 }}>🕸 Endpoint Fuzzer</h2>
            <form onSubmit={handleFuzz} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 28 }}>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Target URL</label>
              {input(fuzzTarget, setFuzzTarget)}
              {slider('Concurrence', fuzzConcurrency, setFuzzConcurrency, 1, 50, ' threads')}
              <button type="submit" disabled={fuzzLoading} style={{ background: fuzzLoading ? '#1e3a5f' : '#0891b2', color: '#fff', border: 'none', borderRadius: 6, padding: '10px 24px', cursor: 'pointer', fontSize: 14, fontFamily: 'inherit', fontWeight: 600 }}>
                {fuzzLoading ? '⟳ Lancement...' : '▶ Lancer le fuzzing'}
              </button>
            </form>
          </div>
        )}

        {/* HISTORY */}
        {tab === 'history' && (
          <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 1fr' : '1fr', gap: 24 }}>
            <div>
              {/* Load Tests */}
              <h3 style={{ color: '#94a3b8', fontSize: 12, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>Stress Tests</h3>
              {loadTests.length === 0 && <p style={{ color: '#334155', fontSize: 13, marginBottom: 20 }}>Aucun test lancé.</p>}
              {loadTests.map(lt => (
                <div key={lt.id} onClick={() => setSelected(lt)} style={{ background: '#0d1424', border: `1px solid ${selected?.id === lt.id ? '#7c3aed' : '#1e293b'}`, borderRadius: 8, padding: '12px 16px', marginBottom: 8, cursor: 'pointer' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600, wordBreak: 'break-all' }}>{lt.target_url}</span>
                    <Badge s={lt.status} />
                  </div>
                  <div style={{ color: '#475569', fontSize: 11 }}>{new Date(lt.created_at).toLocaleString()} · {lt.concurrent_users}u × {lt.rps}r/s × {lt.duration_seconds}s</div>
                  {lt.verdict && <div style={{ fontSize: 12, marginTop: 4, color: lt.verdict.startsWith('✅') ? '#60d394' : lt.verdict.startsWith('⚠️') ? '#fbbf24' : '#ff3b5c' }}>{lt.verdict}</div>}
                </div>
              ))}

              {/* Scans */}
              <h3 style={{ color: '#94a3b8', fontSize: 12, textTransform: 'uppercase', letterSpacing: 1, margin: '20px 0 10px' }}>Scans</h3>
              {scans.map(s => (
                <div key={s.id} onClick={() => setSelected(s)} style={{ background: '#0d1424', border: `1px solid ${selected?.id === s.id ? '#2563eb' : '#1e293b'}`, borderRadius: 8, padding: '12px 16px', marginBottom: 8, cursor: 'pointer' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>{s.target_url}</span>
                    <Badge s={s.status} />
                  </div>
                  <div style={{ color: '#475569', fontSize: 11 }}>{new Date(s.created_at).toLocaleString()} · {s.findings?.length ?? 0} finding(s)</div>
                </div>
              ))}

              {/* Fuzz Jobs */}
              <h3 style={{ color: '#94a3b8', fontSize: 12, textTransform: 'uppercase', letterSpacing: 1, margin: '20px 0 10px' }}>Fuzz Jobs</h3>
              {fuzzes.map(f => (
                <div key={f.id} onClick={() => setSelected(f)} style={{ background: '#0d1424', border: `1px solid ${selected?.id === f.id ? '#0891b2' : '#1e293b'}`, borderRadius: 8, padding: '12px 16px', marginBottom: 8, cursor: 'pointer' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>{f.target_url}</span>
                    <Badge s={f.status} />
                  </div>
                  <div style={{ color: '#475569', fontSize: 11 }}>{new Date(f.created_at).toLocaleString()} · {f.results?.length ?? 0} endpoint(s)</div>
                </div>
              ))}
            </div>

            {/* Detail panel */}
            {selected && (
              <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 22, position: 'sticky', top: 20, alignSelf: 'start' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                  <h3 style={{ color: '#60a5fa', fontSize: 14 }}>
                    {'verdict' in selected ? '⚡ Stress Test' : 'findings' in selected ? '🔍 Scan' : '🕸 Fuzz'}
                  </h3>
                  <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: '#475569', cursor: 'pointer', fontSize: 16 }}>✕</button>
                </div>
                <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 14, wordBreak: 'break-all' }}>{selected.target_url}</div>

                {/* Load test detail */}
                {'verdict' in selected && (
                  <div>
                    {selected.status === 'running' && <p style={{ color: '#60a5fa', fontSize: 13 }}>⟳ Test en cours — actualisation auto...</p>}
                    {selected.verdict && <VerdictBanner verdict={selected.verdict} />}
                    {selected.status === 'completed' && (
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginTop: 16 }}>
                        {[
                          ['Total requêtes', selected.total_requests],
                          ['Succès', selected.successful_requests],
                          ['Échecs', selected.failed_requests],
                          ['Req/s réel', selected.requests_per_second],
                          ['Temps moy.', `${selected.avg_response_ms}ms`],
                          ['Crash', selected.server_crash ? '💥 OUI' : '✅ NON'],
                        ].map(([k, v]) => (
                          <div key={String(k)} style={{ background: '#0a0e1a', borderRadius: 6, padding: '10px 12px' }}>
                            <div style={{ color: '#475569', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>{k}</div>
                            <div style={{ color: '#e2e8f0', fontSize: 16, fontWeight: 700 }}>{v}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Scan findings */}
                {'findings' in selected && selected.findings?.map((f, i) => (
                  <div key={i} style={{ borderLeft: `3px solid ${SEV_COLOR[f.severity] ?? '#60a5fa'}`, padding: '8px 12px', marginBottom: 8, background: '#0a0e1a', borderRadius: '0 6px 6px 0' }}>
                    <div style={{ display: 'flex', gap: 8, marginBottom: 3 }}>
                      <span style={{ color: SEV_COLOR[f.severity], fontSize: 10, fontWeight: 700 }}>{f.severity}</span>
                      <span style={{ color: '#e2e8f0', fontSize: 12, fontWeight: 600 }}>{f.title}</span>
                    </div>
                    <div style={{ color: '#94a3b8', fontSize: 11 }}>{f.description}</div>
                    {f.fix && <div style={{ color: '#60d394', fontSize: 11 }}>↳ {f.fix}</div>}
                  </div>
                ))}
                {'findings' in selected && selected.status === 'completed' && !selected.findings?.length && (
                  <p style={{ color: '#60d394', fontSize: 13 }}>✓ Aucune vulnérabilité détectée</p>
                )}

                {/* Fuzz results */}
                {'results' in selected && selected.results?.map((r, i) => (
                  <div key={i} style={{ display: 'flex', gap: 10, padding: '6px 10px', marginBottom: 4, background: '#0a0e1a', borderRadius: 5, fontSize: 11 }}>
                    <span style={{ color: r.status < 300 ? '#60d394' : r.status < 400 ? '#fbbf24' : '#ff6b35', fontWeight: 700, width: 34 }}>{r.status}</span>
                    <span style={{ color: '#e2e8f0', flex: 1 }}>{r.path}</span>
                    <span style={{ color: '#475569' }}>{r.ms}ms</span>
                  </div>
                ))}
                {selected.status === 'running' && !('verdict' in selected) && <p style={{ color: '#60a5fa', fontSize: 13 }}>⟳ En cours...</p>}
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
