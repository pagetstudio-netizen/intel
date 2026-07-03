import { useState, useEffect, useCallback } from 'react';
import { api, Scan, FuzzJob, LoadTest, PhishingAssessment, PhishingCheck } from './api';
import './app.css';

type Tab = 'phishing' | 'loadtest' | 'scanner' | 'fuzzer' | 'history';

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff3b5c', HIGH: '#ff6b35', MEDIUM: '#fbbf24', LOW: '#60d394', INFO: '#60a5fa',
};
const RISK_COLOR: Record<string, string> = {
  CRITIQUE: '#ff3b5c', ÉLEVÉ: '#ff6b35', MOYEN: '#fbbf24', FAIBLE: '#60d394', UNKNOWN: '#475569',
};
const CAT_ICON: Record<string, string> = { email: '📧', http: '🌐', dns: '🔗', ssl: '🔒' };

function Badge({ s }: { s: string }) {
  const c: Record<string, string> = { completed: '#60d394', running: '#60a5fa', failed: '#ff3b5c', pending: '#94a3b8' };
  return <span style={{ color: c[s] ?? '#94a3b8', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1 }}>
    {s === 'running' ? '⟳ ' : s === 'completed' ? '✓ ' : s === 'failed' ? '✗ ' : '· '}{s}
  </span>;
}

function ScoreRing({ score, level }: { score: number; level: string }) {
  const color = RISK_COLOR[level] ?? '#475569';
  const r = 44; const circ = 2 * Math.PI * r;
  const dash = circ * (score / 100);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 20 }}>
      <svg width={110} height={110} viewBox="0 0 110 110">
        <circle cx={55} cy={55} r={r} fill="none" stroke="#1e293b" strokeWidth={10} />
        <circle cx={55} cy={55} r={r} fill="none" stroke={color} strokeWidth={10}
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          transform="rotate(-90 55 55)" />
        <text x={55} y={52} textAnchor="middle" fill={color} fontSize={22} fontWeight={700} fontFamily="Courier New">{score}</text>
        <text x={55} y={68} textAnchor="middle" fill="#475569" fontSize={10} fontFamily="Courier New">/ 100</text>
      </svg>
      <div>
        <div style={{ color, fontSize: 22, fontWeight: 700, marginBottom: 4 }}>Risque {level}</div>
        <div style={{ color: '#475569', fontSize: 12 }}>Score de vulnérabilité phishing</div>
      </div>
    </div>
  );
}

function DemoEmailPanel({ assessmentId, domain }: { assessmentId: string; domain: string }) {
  const [to, setTo] = useState('');
  const [name, setName] = useState(`Support ${domain}`);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ ok?: boolean; error?: string; message?: string } | null>(null);

  async function send(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true); setResult(null);
    try {
      const r = await fetch('/api/demo-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assessment_id: assessmentId, to_email: to, spoof_name: name }),
      });
      setResult(await r.json());
    } catch { setResult({ error: 'Erreur réseau' }); }
    finally { setLoading(false); }
  }

  return (
    <div style={{ background: '#0a0e1a', border: '1px solid #dc262640', borderRadius: 8, padding: '16px 18px', marginTop: 20 }}>
      <div style={{ color: '#fbbf24', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>
        🎭 Envoyer l'email de preuve au client
      </div>
      <form onSubmit={send}>
        <div style={{ marginBottom: 10 }}>
          <label style={{ display: 'block', color: '#64748b', fontSize: 11, marginBottom: 4, textTransform: 'uppercase' }}>Email du client (destinataire)</label>
          <input value={to} onChange={e => setTo(e.target.value)} required type="email" placeholder="client@sondomaine.com"
            style={{ width: '100%', background: '#0d1424', border: '1px solid #1e293b', borderRadius: 5, padding: '8px 12px', color: '#e2e8f0', fontSize: 13, fontFamily: 'inherit', outline: 'none' }} />
        </div>
        <div style={{ marginBottom: 14 }}>
          <label style={{ display: 'block', color: '#64748b', fontSize: 11, marginBottom: 4, textTransform: 'uppercase' }}>Nom affiché (expéditeur usurpé)</label>
          <input value={name} onChange={e => setName(e.target.value)} required
            style={{ width: '100%', background: '#0d1424', border: '1px solid #1e293b', borderRadius: 5, padding: '8px 12px', color: '#e2e8f0', fontSize: 13, fontFamily: 'inherit', outline: 'none' }} />
        </div>
        <button type="submit" disabled={loading} style={{ background: loading ? '#4a1c1c' : '#dc2626', color: '#fff', border: 'none', borderRadius: 5, padding: '8px 20px', cursor: 'pointer', fontSize: 13, fontFamily: 'inherit', fontWeight: 700 }}>
          {loading ? '⟳ Envoi...' : '📧 Envoyer l\'email de preuve'}
        </button>
      </form>
      {result?.ok && <div style={{ color: '#60d394', fontSize: 12, marginTop: 10 }}>✓ {result.message}</div>}
      {result?.error && (
        <div style={{ color: '#ff6b35', fontSize: 12, marginTop: 10 }}>
          {result.error}
          {(result as any).setup && (
            <div style={{ color: '#64748b', marginTop: 6 }}>
              → Configure <code style={{ color: '#60a5fa' }}>RESEND_API_KEY</code> et <code style={{ color: '#60a5fa' }}>RESEND_FROM_EMAIL</code> dans les secrets Replit
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function CheckRow({ c }: { c: PhishingCheck }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ borderLeft: `3px solid ${c.passed ? '#60d394' : SEV_COLOR[c.risk] ?? '#ff6b35'}`, background: '#0a0e1a', borderRadius: '0 6px 6px 0', marginBottom: 6, cursor: 'pointer' }} onClick={() => setOpen(o => !o)}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px' }}>
        <span style={{ fontSize: 14 }}>{CAT_ICON[c.category]}</span>
        <span style={{ flex: 1, color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>{c.name}</span>
        {!c.passed && <span style={{ color: SEV_COLOR[c.risk], fontSize: 10, fontWeight: 700, background: `${SEV_COLOR[c.risk]}22`, padding: '2px 8px', borderRadius: 4 }}>{c.risk}</span>}
        <span style={{ color: c.passed ? '#60d394' : '#ff3b5c', fontSize: 16 }}>{c.passed ? '✓' : '✗'}</span>
      </div>
      {open && (
        <div style={{ padding: '0 14px 12px 38px' }}>
          <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 6 }}>{c.detail}</div>
          {!c.passed && <div style={{ color: '#60a5fa', fontSize: 11 }}>💡 {c.fix}</div>}
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>('phishing');
  const [scans, setScans] = useState<Scan[]>([]);
  const [fuzzes, setFuzzes] = useState<FuzzJob[]>([]);
  const [loadTests, setLoadTests] = useState<LoadTest[]>([]);
  const [phishings, setPhishings] = useState<PhishingAssessment[]>([]);
  const [selected, setSelected] = useState<Scan | FuzzJob | LoadTest | PhishingAssessment | null>(null);

  // Phishing form
  const [phTarget, setPhTarget] = useState('https://');
  const [phLoading, setPhLoading] = useState(false);

  // Scanner form
  const [scanTarget, setScanTarget] = useState('https://');
  const [scanDeep, setScanDeep] = useState(false);
  const [scanLoading, setScanLoading] = useState(false);

  // Fuzzer form
  const [fuzzTarget, setFuzzTarget] = useState('https://');
  const [fuzzConcurrency, setFuzzConcurrency] = useState(10);
  const [fuzzLoading, setFuzzLoading] = useState(false);

  // Load test form
  const [ltTarget, setLtTarget] = useState('https://');
  const [ltUsers, setLtUsers] = useState(50);
  const [ltRps, setLtRps] = useState(10);
  const [ltDuration, setLtDuration] = useState(30);
  const [ltLoading, setLtLoading] = useState(false);

  const refresh = useCallback(async () => {
    const [s, f, l, p] = await Promise.all([
      api.getScans(), api.getFuzzJobs(), api.getLoadTests(), api.getPhishingAssessments()
    ]);
    setScans(s); setFuzzes(f); setLoadTests(l); setPhishings(p);
    if (selected) {
      const fresh = [...s, ...f, ...l, ...p].find(x => x.id === selected.id);
      if (fresh) setSelected(fresh);
    }
  }, [selected]);

  useEffect(() => { refresh(); const t = setInterval(refresh, 3000); return () => clearInterval(t); }, [refresh]);

  async function handlePhishing(e: React.FormEvent) {
    e.preventDefault(); setPhLoading(true);
    try { const r = await api.startPhishing(phTarget); setSelected(r); await refresh(); setTab('history'); } finally { setPhLoading(false); }
  }
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
    try { const r = await api.startLoadTest(ltTarget, ltUsers, ltRps, ltDuration); setSelected(r); await refresh(); setTab('history'); } finally { setLtLoading(false); }
  }

  const urlInput = (val: string, set: (v: string) => void) => (
    <input value={val} onChange={e => set(e.target.value)} required
      style={{ width: '100%', background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 14, fontFamily: 'inherit', marginBottom: 16, outline: 'none' }} />
  );
  const slider = (label: string, val: number, set: (v: number) => void, min: number, max: number, unit = '') => (
    <div style={{ marginBottom: 20 }}>
      <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 }}>
        {label} — <span style={{ color: '#60a5fa' }}>{val}{unit}</span>
      </label>
      <input type="range" min={min} max={max} value={val} onChange={e => set(parseInt(e.target.value))} style={{ width: '100%' }} />
    </div>
  );

  const TABS: [Tab, string][] = [
    ['phishing', '🎣 Phishing'],
    ['loadtest', '⚡ Load Test'],
    ['scanner', '🔍 Scanner'],
    ['fuzzer', '🕸 Fuzzer'],
    ['history', '📋 History'],
  ];

  return (
    <div style={{ minHeight: '100vh', background: '#0a0e1a' }}>
      <header style={{ background: '#0d1424', borderBottom: '1px solid #1e293b', padding: '14px 28px', display: 'flex', alignItems: 'center', gap: 14 }}>
        <span style={{ fontSize: 18, fontWeight: 700, color: '#60a5fa', letterSpacing: 2 }}>⬡ INTEL</span>
        <span style={{ color: '#475569', fontSize: 12 }}>Security Platform</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {TABS.map(([t, label]) => (
            <button key={t} onClick={() => setTab(t)} style={{
              background: tab === t ? '#1e3a5f' : 'transparent',
              color: tab === t ? '#60a5fa' : '#94a3b8',
              border: tab === t ? '1px solid #2563eb' : '1px solid transparent',
              borderRadius: 6, padding: '5px 12px', cursor: 'pointer', fontSize: 12, fontFamily: 'inherit', fontWeight: 600,
            }}>{label}</button>
          ))}
        </div>
      </header>

      <main style={{ maxWidth: 1060, margin: '0 auto', padding: '28px 20px' }}>

        {/* 🎣 PHISHING */}
        {tab === 'phishing' && (
          <div>
            <h2 style={{ color: '#e2e8f0', marginBottom: 6, fontSize: 20 }}>🎣 Analyse Anti-Phishing</h2>
            <p style={{ color: '#64748b', fontSize: 13, marginBottom: 24, lineHeight: 1.6 }}>
              Vérifie si le site client peut être usurpé pour du phishing — clonage dans un iframe, faux emails en son nom, absence de DMARC/SPF/DKIM. Génère un rapport complet avec score de risque.
            </p>

            <form onSubmit={handlePhishing} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 28, marginBottom: 24 }}>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>URL du site client</label>
              {urlInput(phTarget, setPhTarget)}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 20 }}>
                {[['🌐 En-têtes HTTP', 'X-Frame, CSP, HSTS'], ['📧 SPF / DMARC', 'Usurpation email'], ['🔗 DKIM', 'Signature email'], ['🔒 SSL/DNS', 'Infrastructure']].map(([icon, desc]) => (
                  <div key={icon} style={{ background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 12px', textAlign: 'center' }}>
                    <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 2 }}>{icon}</div>
                    <div style={{ fontSize: 11, color: '#475569' }}>{desc}</div>
                  </div>
                ))}
              </div>
              <button type="submit" disabled={phLoading} style={{
                background: phLoading ? '#3b1c5c' : 'linear-gradient(135deg, #dc2626, #7c3aed)',
                color: '#fff', border: 'none', borderRadius: 6, padding: '11px 28px',
                cursor: 'pointer', fontSize: 14, fontFamily: 'inherit', fontWeight: 700, letterSpacing: 1,
              }}>{phLoading ? '⟳ Analyse en cours...' : '🎣 LANCER L\'ANALYSE PHISHING'}</button>
            </form>

            {phishings.length > 0 && (
              <div>
                <h3 style={{ color: '#94a3b8', fontSize: 12, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>Dernières analyses</h3>
                {phishings.slice(0, 5).map(p => (
                  <div key={p.id} onClick={() => { setSelected(p); setTab('history'); }}
                    style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 8, padding: '14px 18px', marginBottom: 8, cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600, marginBottom: 4 }}>{p.domain}</div>
                      {p.summary && <div style={{ color: '#64748b', fontSize: 12 }}>{p.summary}</div>}
                      {!p.summary && <div style={{ color: '#60a5fa', fontSize: 12 }}>⟳ Analyse DNS + HTTP en cours...</div>}
                    </div>
                    <div style={{ textAlign: 'right', minWidth: 80 }}>
                      {p.risk_level !== 'UNKNOWN' && (
                        <div style={{ color: RISK_COLOR[p.risk_level], fontWeight: 700, fontSize: 13 }}>{p.risk_score}% risque</div>
                      )}
                      <Badge s={p.status} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ⚡ LOAD TEST */}
        {tab === 'loadtest' && (
          <div>
            <h2 style={{ color: '#e2e8f0', marginBottom: 6, fontSize: 20 }}>⚡ Test de Résistance</h2>
            <p style={{ color: '#64748b', fontSize: 13, marginBottom: 24 }}>Simule de vraies vagues de trafic. Si le serveur tient → victoire. S'il tombe → le client a un problème.</p>
            <form onSubmit={handleLoadTest} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 28 }}>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>URL du site client</label>
              {urlInput(ltTarget, setLtTarget)}

              {/* Quick presets */}
              <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
                {([
                  { label: '10k req', u: 100, r: 10, d: 10 },
                  { label: '25k req', u: 250, r: 10, d: 10 },
                  { label: '50k req', u: 500, r: 10, d: 10 },
                  { label: '50k rapide', u: 1000, r: 50, d: 1 },
                  { label: 'MAX', u: 2000, r: 500, d: 300 },
                ] as { label: string; u: number; r: number; d: number }[]).map(p => (
                  <button key={p.label} type="button"
                    onClick={() => { setLtUsers(p.u); setLtRps(p.r); setLtDuration(p.d); }}
                    style={{ background: '#0a0e1a', border: '1px solid #334155', borderRadius: 6, color: '#94a3b8', fontSize: 11, padding: '5px 10px', cursor: 'pointer', fontFamily: 'inherit', fontWeight: 600 }}>
                    {p.label}
                  </button>
                ))}
              </div>

              {slider('Utilisateurs simultanés', ltUsers, setLtUsers, 1, 2000)}
              {slider('Requêtes / seconde par user', ltRps, setLtRps, 1, 500)}
              {slider('Durée du test', ltDuration, setLtDuration, 5, 300, 's')}
              <div style={{ background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '12px 16px', marginBottom: 20, fontSize: 12, color: '#64748b' }}>
                Estimation : <span style={{ color: '#60a5fa' }}>{ltUsers * ltRps} req/s</span> × <span style={{ color: '#60a5fa' }}>{ltDuration}s</span> = <span style={{ color: '#fbbf24' }}>~{ltUsers * ltRps * ltDuration} requêtes</span>
              </div>
              <button type="submit" disabled={ltLoading} style={{ background: ltLoading ? '#3b1c5c' : '#7c3aed', color: '#fff', border: 'none', borderRadius: 6, padding: '11px 28px', cursor: 'pointer', fontSize: 14, fontFamily: 'inherit', fontWeight: 700 }}>
                {ltLoading ? '⟳ Test en cours...' : '⚡ LANCER LE STRESS TEST'}
              </button>
            </form>
          </div>
        )}

        {/* 🔍 SCANNER */}
        {tab === 'scanner' && (
          <div>
            <h2 style={{ color: '#e2e8f0', marginBottom: 24, fontSize: 18 }}>🔍 Vulnerability Scanner</h2>
            <form onSubmit={handleScan} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 28 }}>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Target URL</label>
              {urlInput(scanTarget, setScanTarget)}
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

        {/* 🕸 FUZZER */}
        {tab === 'fuzzer' && (
          <div>
            <h2 style={{ color: '#e2e8f0', marginBottom: 24, fontSize: 18 }}>🕸 Endpoint Fuzzer</h2>
            <form onSubmit={handleFuzz} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 28 }}>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Target URL</label>
              {urlInput(fuzzTarget, setFuzzTarget)}
              {slider('Concurrence', fuzzConcurrency, setFuzzConcurrency, 1, 50, ' threads')}
              <button type="submit" disabled={fuzzLoading} style={{ background: fuzzLoading ? '#1e3a5f' : '#0891b2', color: '#fff', border: 'none', borderRadius: 6, padding: '10px 24px', cursor: 'pointer', fontSize: 14, fontFamily: 'inherit', fontWeight: 600 }}>
                {fuzzLoading ? '⟳ Lancement...' : '▶ Lancer le fuzzing'}
              </button>
            </form>
          </div>
        )}

        {/* 📋 HISTORY */}
        {tab === 'history' && (
          <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 1fr' : '1fr', gap: 24 }}>
            <div>
              {/* Phishing */}
              <h3 style={{ color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>🎣 Analyses Phishing</h3>
              {phishings.length === 0 && <p style={{ color: '#334155', fontSize: 12, marginBottom: 16 }}>Aucune analyse lancée.</p>}
              {phishings.map(p => (
                <div key={p.id} onClick={() => setSelected(p)}
                  style={{ background: '#0d1424', border: `1px solid ${selected?.id === p.id ? '#dc2626' : '#1e293b'}`, borderRadius: 8, padding: '12px 16px', marginBottom: 7, cursor: 'pointer' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                    <span style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>{p.domain}</span>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      {p.risk_level !== 'UNKNOWN' && <span style={{ color: RISK_COLOR[p.risk_level], fontSize: 11, fontWeight: 700 }}>{p.risk_score}%</span>}
                      <Badge s={p.status} />
                    </div>
                  </div>
                  {p.summary && <div style={{ color: '#475569', fontSize: 11 }}>{p.summary}</div>}
                </div>
              ))}

              {/* Load tests */}
              <h3 style={{ color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, margin: '16px 0 8px' }}>⚡ Stress Tests</h3>
              {loadTests.map(lt => (
                <div key={lt.id} onClick={() => setSelected(lt)}
                  style={{ background: '#0d1424', border: `1px solid ${selected?.id === lt.id ? '#7c3aed' : '#1e293b'}`, borderRadius: 8, padding: '12px 16px', marginBottom: 7, cursor: 'pointer' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                    <span style={{ color: '#e2e8f0', fontSize: 12, fontWeight: 600 }}>{lt.target_url}</span>
                    <Badge s={lt.status} />
                  </div>
                  {lt.verdict && <div style={{ fontSize: 11, color: lt.verdict.startsWith('✅') ? '#60d394' : lt.verdict.startsWith('⚠️') ? '#fbbf24' : '#ff3b5c' }}>{lt.verdict}</div>}
                </div>
              ))}

              {/* Scans */}
              <h3 style={{ color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, margin: '16px 0 8px' }}>🔍 Scans</h3>
              {scans.map(s => (
                <div key={s.id} onClick={() => setSelected(s)}
                  style={{ background: '#0d1424', border: `1px solid ${selected?.id === s.id ? '#2563eb' : '#1e293b'}`, borderRadius: 8, padding: '12px 16px', marginBottom: 7, cursor: 'pointer' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                    <span style={{ color: '#e2e8f0', fontSize: 12, fontWeight: 600 }}>{s.target_url}</span>
                    <Badge s={s.status} />
                  </div>
                  <div style={{ color: '#475569', fontSize: 11 }}>{s.findings?.length ?? 0} finding(s)</div>
                </div>
              ))}

              {/* Fuzz */}
              <h3 style={{ color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, margin: '16px 0 8px' }}>🕸 Fuzz Jobs</h3>
              {fuzzes.map(f => (
                <div key={f.id} onClick={() => setSelected(f)}
                  style={{ background: '#0d1424', border: `1px solid ${selected?.id === f.id ? '#0891b2' : '#1e293b'}`, borderRadius: 8, padding: '12px 16px', marginBottom: 7, cursor: 'pointer' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                    <span style={{ color: '#e2e8f0', fontSize: 12, fontWeight: 600 }}>{f.target_url}</span>
                    <Badge s={f.status} />
                  </div>
                  <div style={{ color: '#475569', fontSize: 11 }}>{f.results?.length ?? 0} endpoint(s)</div>
                </div>
              ))}
            </div>

            {/* Detail panel */}
            {selected && (
              <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 22, position: 'sticky', top: 20, alignSelf: 'start', maxHeight: '85vh', overflowY: 'auto' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                  <h3 style={{ color: '#60a5fa', fontSize: 14 }}>
                    {'checks' in selected ? '🎣 Phishing Report'
                      : 'verdict' in selected ? '⚡ Stress Test'
                      : 'findings' in selected ? '🔍 Scan'
                      : '🕸 Fuzz'}
                  </h3>
                  <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: '#475569', cursor: 'pointer', fontSize: 16 }}>✕</button>
                </div>

                <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 14, wordBreak: 'break-all' }}>
                  {'domain' in selected ? selected.domain : selected.target_url}
                </div>

                {/* Phishing detail */}
                {'checks' in selected && (
                  <div>
                    {selected.status === 'running' && (
                      <div style={{ color: '#60a5fa', fontSize: 13, marginBottom: 16 }}>⟳ Vérification DNS + HTTP en cours...</div>
                    )}
                    {selected.status === 'completed' && (
                      <>
                        <ScoreRing score={selected.risk_score} level={selected.risk_level} />
                        {selected.summary && (
                          <div style={{ background: `${RISK_COLOR[selected.risk_level] ?? '#475569'}18`, border: `1px solid ${RISK_COLOR[selected.risk_level] ?? '#475569'}40`, borderRadius: 8, padding: '12px 16px', marginBottom: 18, fontSize: 13, color: RISK_COLOR[selected.risk_level] ?? '#e2e8f0', fontWeight: 600 }}>
                            {selected.summary}
                          </div>
                        )}
                        <DemoEmailPanel assessmentId={selected.id} domain={selected.domain} />

                        {/* Group by category */}
                        {(['email', 'http', 'dns'] as const).map(cat => {
                          const catChecks = selected.checks.filter(c => c.category === cat);
                          if (!catChecks.length) return null;
                          return (
                            <div key={cat} style={{ marginBottom: 16 }}>
                              <div style={{ color: '#475569', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
                                {CAT_ICON[cat]} {cat === 'email' ? 'Email (SPF / DMARC / DKIM)' : cat === 'http' ? 'HTTP Headers' : 'DNS'}
                              </div>
                              {catChecks.map(c => <CheckRow key={c.id} c={c} />)}
                            </div>
                          );
                        })}
                      </>
                    )}
                  </div>
                )}

                {/* Load test detail */}
                {'verdict' in selected && (
                  <div>
                    {selected.status === 'running' && <p style={{ color: '#60a5fa', fontSize: 13 }}>⟳ Test en cours...</p>}
                    {selected.verdict && (
                      <div style={{ background: '#ffffff0a', border: '1px solid #1e293b', borderRadius: 8, padding: '14px 18px', marginBottom: 16, fontSize: 14, fontWeight: 700, color: selected.verdict.startsWith('✅') ? '#60d394' : selected.verdict.startsWith('⚠️') ? '#fbbf24' : '#ff3b5c' }}>
                        {selected.verdict}
                      </div>
                    )}
                    {selected.status === 'completed' && (
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                        {[['Total req.', selected.total_requests], ['Succès', selected.successful_requests], ['Échecs', selected.failed_requests], ['Req/s', selected.requests_per_second], ['Moy.', `${selected.avg_response_ms}ms`], ['Crash', selected.server_crash ? '💥 OUI' : '✅ NON']].map(([k, v]) => (
                          <div key={String(k)} style={{ background: '#0a0e1a', borderRadius: 6, padding: '10px 12px' }}>
                            <div style={{ color: '#475569', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 3 }}>{k}</div>
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
                    {f.fix && <div style={{ color: '#60d394', fontSize: 11, marginTop: 3 }}>↳ {f.fix}</div>}
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

                {selected.status === 'running' && !('checks' in selected) && !('verdict' in selected) && (
                  <p style={{ color: '#60a5fa', fontSize: 13 }}>⟳ En cours...</p>
                )}
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
