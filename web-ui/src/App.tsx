import { useState, useEffect, useCallback, useRef } from 'react';
import { api, Scan, FuzzJob, LoadTest, PhishingAssessment, PhishingCheck, FintechFraudAudit, FraudCheck, Mandate, OsintScan, AuthAudit, AuthCheck, ExposedEndpoint } from './api';
import './app.css';

type Tab = 'phishing' | 'fraud' | 'loadtest' | 'scanner' | 'fuzzer' | 'history' | 'mandats' | 'osint' | 'authaudit';

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff3b5c', HIGH: '#ff6b35', MEDIUM: '#fbbf24', LOW: '#60d394', INFO: '#60a5fa',
};
const RISK_COLOR: Record<string, string> = {
  CRITIQUE: '#ff3b5c', ÉLEVÉ: '#ff6b35', MOYEN: '#fbbf24', FAIBLE: '#60d394', UNKNOWN: '#475569',
};
const CAT_ICON: Record<string, string> = { email: '📧', http: '🌐', dns: '🔗', ssl: '🔒' };
const FRAUD_CAT_ICON: Record<string, string> = {
  auth: '🔑', csrf: '🛡️', cors: '🌐', ratelimit: '⏱️', headers: '📋', exposure: '👁️',
};

function ClientConfirmPage({ token }: { token: string }) {
  const [mandate, setMandate] = useState<Mandate | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [signing, setSigning] = useState(false);
  const [signed, setSigned] = useState(false);
  const fetchedRef = useRef(false);

  useEffect(() => {
    if (fetchedRef.current) return;
    fetchedRef.current = true;
    api.getMandateByToken(token).then(m => {
      if ((m as any).error) setError((m as any).error);
      else { setMandate(m); if (m.status === 'authorized') setSigned(true); }
    }).catch(() => setError('Impossible de charger le mandat.')).finally(() => setLoading(false));
  }, [token]);

  async function handleSign() {
    setSigning(true);
    try {
      const r = await api.confirmMandate(token);
      if ((r as any).error) { setError((r as any).error); }
      else { setMandate(r); setSigned(true); }
    } catch { setError('Erreur lors de la signature.'); }
    finally { setSigning(false); }
  }

  const SCOPE_LABELS: Record<string, string> = {
    vuln_scan: '🔍 Scan de vulnérabilités', fuzzing: '🕸 Découverte d\'endpoints (Fuzzer)',
    load_test: '⚡ Test de charge', phishing: '🎣 Analyse anti-phishing', fintech_fraud: '💳 Audit fraude API fintech',
  };

  if (loading) return (
    <div style={{ minHeight: '100vh', background: '#0a0e1a', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ color: '#60a5fa', fontSize: 16 }}>⟳ Chargement du mandat...</div>
    </div>
  );

  if (error) return (
    <div style={{ minHeight: '100vh', background: '#0a0e1a', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>⚠️</div>
        <div style={{ color: '#ff6b35', fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Mandat introuvable</div>
        <div style={{ color: '#475569', fontSize: 14 }}>{error}</div>
      </div>
    </div>
  );

  if (!mandate) return null;

  return (
    <div style={{ minHeight: '100vh', background: '#0a0e1a', display: 'flex', alignItems: 'flex-start', justifyContent: 'center', padding: '40px 20px' }}>
      <div style={{ maxWidth: 680, width: '100%' }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ fontSize: 20, fontWeight: 800, color: '#60a5fa', letterSpacing: 3, marginBottom: 4 }}>⬡ INTEL</div>
          <div style={{ color: '#475569', fontSize: 12, letterSpacing: 1 }}>SECURITY PLATFORM</div>
        </div>

        {/* Document card */}
        <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 14, overflow: 'hidden' }}>
          {/* Title bar */}
          <div style={{ background: '#111827', borderBottom: '1px solid #1e293b', padding: '20px 28px', textAlign: 'center' }}>
            <div style={{ color: '#e2e8f0', fontSize: 18, fontWeight: 800, letterSpacing: 0.5, marginBottom: 4 }}>
              LETTRE D'AUTORISATION DE TEST DE SÉCURITÉ
            </div>
            <div style={{ color: '#475569', fontSize: 12 }}>Mandat officiel — à signer électroniquement</div>
          </div>

          <div style={{ padding: '28px 32px' }}>
            {/* Parties */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 24 }}>
              <div style={{ background: '#0a0e1a', borderRadius: 8, padding: '16px 18px', border: '1px solid #1e293b' }}>
                <div style={{ color: '#64748b', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>Testeur (prestataire)</div>
                <div style={{ color: '#e2e8f0', fontWeight: 700, fontSize: 14 }}>{mandate.tester_company}</div>
              </div>
              <div style={{ background: '#0a0e1a', borderRadius: 8, padding: '16px 18px', border: '1px solid #1e293b' }}>
                <div style={{ color: '#64748b', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>Client (propriétaire)</div>
                <div style={{ color: '#e2e8f0', fontWeight: 700, fontSize: 14 }}>{mandate.client_company}</div>
                <div style={{ color: '#64748b', fontSize: 12, marginTop: 2 }}>{mandate.client_name} · {mandate.client_email}</div>
              </div>
            </div>

            {/* Period */}
            <div style={{ background: '#0a0e1a', borderRadius: 8, padding: '14px 18px', border: '1px solid #1e293b', marginBottom: 20, display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ fontSize: 20 }}>📅</span>
              <div>
                <div style={{ color: '#64748b', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 3 }}>Période d'autorisation</div>
                <div style={{ color: '#e2e8f0', fontWeight: 600, fontSize: 14 }}>
                  Du {new Date(mandate.valid_from).toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' })} au {new Date(mandate.valid_until).toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' })}
                </div>
              </div>
            </div>

            {/* Target URLs */}
            <div style={{ marginBottom: 20 }}>
              <div style={{ color: '#64748b', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>Systèmes cibles autorisés</div>
              {mandate.target_urls.map((u, i) => (
                <div key={i} style={{ background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '8px 14px', marginBottom: 6, color: '#60a5fa', fontSize: 13, fontFamily: 'monospace' }}>
                  {u}
                </div>
              ))}
            </div>

            {/* Scope */}
            <div style={{ marginBottom: 20 }}>
              <div style={{ color: '#64748b', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>Types de tests autorisés</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {mandate.scope.map((s, i) => (
                  <span key={i} style={{ background: '#1d4ed820', border: '1px solid #1d4ed860', borderRadius: 6, padding: '6px 12px', fontSize: 12, color: '#60a5fa' }}>
                    {SCOPE_LABELS[s] ?? s}
                  </span>
                ))}
              </div>
            </div>

            {/* Notes */}
            {mandate.notes && (
              <div style={{ background: '#0a0e1a', border: '1px solid #fbbf2430', borderRadius: 8, padding: '14px 18px', marginBottom: 20 }}>
                <div style={{ color: '#fbbf24', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>⚠️ Restrictions & conditions</div>
                <div style={{ color: '#cbd5e1', fontSize: 13 }}>{mandate.notes}</div>
              </div>
            )}

            {/* Legal text */}
            <div style={{ border: '1px solid #1e293b', borderRadius: 8, padding: '16px 18px', marginBottom: 24, color: '#64748b', fontSize: 12, lineHeight: 1.7 }}>
              En signant ce mandat, <strong style={{ color: '#94a3b8' }}>{mandate.client_name}</strong> agissant au nom de <strong style={{ color: '#94a3b8' }}>{mandate.client_company}</strong>,
              déclare être propriétaire ou administrateur légitimement autorisé des systèmes cibles listés ci-dessus, et autorise expressément
              <strong style={{ color: '#94a3b8' }}> {mandate.tester_company}</strong> à effectuer les tests de sécurité définis dans le périmètre du présent mandat,
              pendant la période indiquée. Toute utilisation en dehors de ce cadre est strictement interdite.
            </div>

            {/* Action */}
            {signed ? (
              <div style={{ textAlign: 'center', padding: '20px 0' }}>
                <div style={{ fontSize: 48, marginBottom: 12 }}>✅</div>
                <div style={{ color: '#60d394', fontSize: 18, fontWeight: 800, marginBottom: 6 }}>Mandat signé avec succès</div>
                <div style={{ color: '#475569', fontSize: 13 }}>
                  {mandate.signed_at && `Signé le ${new Date(mandate.signed_at).toLocaleString('fr-FR')}`}
                </div>
                <div style={{ color: '#334155', fontSize: 12, marginTop: 8 }}>
                  Votre adresse IP a été enregistrée à titre de preuve d'engagement.
                </div>
              </div>
            ) : (
              <div>
                <button onClick={handleSign} disabled={signing}
                  style={{ width: '100%', padding: '16px 0', background: signing ? '#1e293b' : 'linear-gradient(135deg, #1d4ed8, #2563eb)', color: '#fff', border: 'none', borderRadius: 10, fontSize: 16, fontWeight: 800, cursor: signing ? 'not-allowed' : 'pointer', letterSpacing: 0.5, boxShadow: signing ? 'none' : '0 4px 20px #1d4ed840' }}>
                  {signing ? '⟳ Signature en cours...' : '✍️ J\'autorise les tests de sécurité'}
                </button>
                <div style={{ textAlign: 'center', color: '#334155', fontSize: 11, marginTop: 10 }}>
                  En cliquant, votre adresse IP et la date/heure seront enregistrées comme preuve.
                </div>
              </div>
            )}
          </div>
        </div>

        <div style={{ textAlign: 'center', color: '#1e293b', fontSize: 11, marginTop: 20 }}>
          INTEL Security Platform · Document légalement engageant
        </div>
      </div>
    </div>
  );
}

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
        <div style={{ color: '#475569', fontSize: 12 }}>Score de vulnérabilité</div>
      </div>
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  width: '100%', background: '#0d1424', border: '1px solid #1e293b',
  borderRadius: 5, padding: '8px 12px', color: '#e2e8f0',
  fontSize: 13, fontFamily: 'inherit', outline: 'none', boxSizing: 'border-box',
};
const labelStyle: React.CSSProperties = {
  display: 'block', color: '#64748b', fontSize: 11,
  marginBottom: 4, textTransform: 'uppercase', letterSpacing: 0.5,
};

function DemoEmailPanel({ assessmentId, domain }: { assessmentId: string; domain: string }) {
  const [to, setTo] = useState('');
  const [name, setName] = useState(`Support ${domain}`);
  const [message, setMessage] = useState(
    `Nous avons détecté une connexion suspecte sur votre compte depuis un appareil non reconnu. Par mesure de sécurité, votre accès a été temporairement restreint.\n\nVous devez vérifier votre identité dans les 24 heures pour éviter la suspension de votre compte.`
  );
  const [btnText, setBtnText] = useState('🔐 Vérifier mon identité');
  const [btnUrl, setBtnUrl] = useState('https://');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ ok?: boolean; error?: string; message?: string; setup?: boolean } | null>(null);

  async function send(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true); setResult(null);
    try {
      const r = await fetch('/api/demo-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assessment_id: assessmentId, to_email: to, spoof_name: name, custom_message: message, button_text: btnText, button_url: btnUrl }),
      });
      setResult(await r.json());
    } catch { setResult({ error: 'Erreur réseau' }); }
    finally { setLoading(false); }
  }

  return (
    <div style={{ background: '#0a0e1a', border: '1px solid #dc262640', borderRadius: 8, padding: '18px 20px', marginTop: 20 }}>
      <div style={{ color: '#fbbf24', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 16 }}>
        🎭 Envoyer l'email de preuve au client
      </div>
      <form onSubmit={send}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
          <div>
            <label style={labelStyle}>Email du client (destinataire)</label>
            <input value={to} onChange={e => setTo(e.target.value)} required type="email" placeholder="client@gmail.com" style={inputStyle} />
          </div>
          <div>
            <label style={labelStyle}>Nom expéditeur affiché</label>
            <input value={name} onChange={e => setName(e.target.value)} required style={inputStyle} />
          </div>
        </div>
        <div style={{ marginBottom: 10 }}>
          <label style={labelStyle}>Corps du message</label>
          <textarea value={message} onChange={e => setMessage(e.target.value)} rows={4} style={{ ...inputStyle, resize: 'vertical', lineHeight: 1.6 }} />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 10, marginBottom: 16 }}>
          <div>
            <label style={labelStyle}>Texte du bouton</label>
            <input value={btnText} onChange={e => setBtnText(e.target.value)} style={inputStyle} />
          </div>
          <div>
            <label style={labelStyle}>Lien du bouton</label>
            <input value={btnUrl} onChange={e => setBtnUrl(e.target.value)} placeholder="https://..." style={inputStyle} />
          </div>
        </div>
        <button type="submit" disabled={loading}
          style={{ background: loading ? '#4a1c1c' : '#dc2626', color: '#fff', border: 'none', borderRadius: 5, padding: '9px 24px', cursor: 'pointer', fontSize: 13, fontFamily: 'inherit', fontWeight: 700 }}>
          {loading ? '⟳ Envoi en cours...' : '📧 Envoyer l\'email'}
        </button>
      </form>
      {result?.ok && <div style={{ color: '#60d394', fontSize: 12, marginTop: 10 }}>✓ {result.message}</div>}
      {result?.error && (
        <div style={{ color: '#ff6b35', fontSize: 12, marginTop: 10 }}>
          ✗ {result.error}
          {result.setup && <div style={{ color: '#64748b', marginTop: 6 }}>→ Configure <code style={{ color: '#60a5fa' }}>SMTP_HOST</code>, <code style={{ color: '#60a5fa' }}>SMTP_USER</code>, <code style={{ color: '#60a5fa' }}>SMTP_PASS</code> dans les secrets Replit</div>}
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

function FraudCheckRow({ c }: { c: FraudCheck }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ borderLeft: `3px solid ${c.passed ? '#60d394' : SEV_COLOR[c.risk] ?? '#ff6b35'}`, background: '#0a0e1a', borderRadius: '0 6px 6px 0', marginBottom: 6, cursor: 'pointer' }} onClick={() => setOpen(o => !o)}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px' }}>
        <span style={{ fontSize: 14 }}>{FRAUD_CAT_ICON[c.category]}</span>
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

function AppInner() {
  const [tab, setTab] = useState<Tab>('phishing');
  const [scans, setScans] = useState<Scan[]>([]);
  const [fuzzes, setFuzzes] = useState<FuzzJob[]>([]);
  const [loadTests, setLoadTests] = useState<LoadTest[]>([]);
  const [phishings, setPhishings] = useState<PhishingAssessment[]>([]);
  const [fraudAudits, setFraudAudits] = useState<FintechFraudAudit[]>([]);
  const [selected, setSelected] = useState<Scan | FuzzJob | LoadTest | PhishingAssessment | FintechFraudAudit | null>(null);

  const [phTarget, setPhTarget] = useState('https://');
  const [phLoading, setPhLoading] = useState(false);

  const [scanTarget, setScanTarget] = useState('https://');
  const [scanDeep, setScanDeep] = useState(false);
  const [scanLoading, setScanLoading] = useState(false);

  const [fuzzTarget, setFuzzTarget] = useState('https://');
  const [fuzzConcurrency, setFuzzConcurrency] = useState(10);
  const [fuzzLoading, setFuzzLoading] = useState(false);
  const [activeFuzz, setActiveFuzz] = useState<FuzzJob | null>(null);

  const [ltTarget, setLtTarget] = useState('https://');
  const [ltUsers, setLtUsers] = useState(50);
  const [ltRps, setLtRps] = useState(10);
  const [ltDuration, setLtDuration] = useState(30);
  const [ltLoading, setLtLoading] = useState(false);

  const [fraudTarget, setFraudTarget] = useState('https://');
  const [fraudLoading, setFraudLoading] = useState(false);

  // Auth audit state
  const [authAudits, setAuthAudits] = useState<AuthAudit[]>([]);
  const [authTarget, setAuthTarget] = useState('https://');
  const [authLoading, setAuthLoading] = useState(false);
  const [activeAuthAudit, setActiveAuthAudit] = useState<AuthAudit | null>(null);

  // OSINT state
  const [osintScans, setOsintScans] = useState<OsintScan[]>([]);
  const [osintDomain, setOsintDomain] = useState('');
  const [osintLoading, setOsintLoading] = useState(false);
  const [activeOsint, setActiveOsint] = useState<OsintScan | null>(null);

  // Mandats state
  const [mandates, setMandates] = useState<Mandate[]>([]);
  const [mTesterCompany, setMTesterCompany] = useState('');
  const [mClientName, setMClientName] = useState('');
  const [mClientEmail, setMClientEmail] = useState('');
  const [mClientCompany, setMClientCompany] = useState('');
  const [mTargetUrls, setMTargetUrls] = useState('');
  const [mScope, setMScope] = useState<string[]>([]);
  const [mValidFrom, setMValidFrom] = useState(new Date().toISOString().split('T')[0]);
  const [mValidUntil, setMValidUntil] = useState(() => { const d = new Date(); d.setDate(d.getDate() + 30); return d.toISOString().split('T')[0]; });
  const [mNotes, setMNotes] = useState('');
  const [mLoading, setMLoading] = useState(false);
  const [mError, setMError] = useState('');
  const [mCopied, setMCopied] = useState<string | null>(null);

  const SCOPE_OPTIONS = [
    { id: 'vuln_scan', label: '🔍 Scan de vulnérabilités' },
    { id: 'fuzzing', label: '🕸 Découverte d\'endpoints (Fuzzer)' },
    { id: 'load_test', label: '⚡ Test de charge (stress test)' },
    { id: 'phishing', label: '🎣 Analyse anti-phishing' },
    { id: 'fintech_fraud', label: '💳 Audit fraude API fintech' },
  ];

  const refresh = useCallback(async () => {
    const [s, f, l, p, fa, m, os, aa] = await Promise.all([
      api.getScans(), api.getFuzzJobs(), api.getLoadTests(),
      api.getPhishingAssessments(), api.getFintechFraudAudits(),
      api.getMandates(), api.getOsintScans(), api.getAuthAudits(),
    ]);
    setScans(s); setFuzzes(f); setLoadTests(l); setPhishings(p); setFraudAudits(fa); setMandates(m); setOsintScans(os); setAuthAudits(aa);
    if (activeAuthAudit) {
      const fresh = aa.find(x => x.id === activeAuthAudit.id);
      if (fresh) setActiveAuthAudit(fresh);
    }
    if (activeOsint) {
      const fresh = os.find(x => x.id === activeOsint.id);
      if (fresh) setActiveOsint(fresh);
    }
    if (selected) {
      const fresh = [...s, ...f, ...l, ...p, ...fa].find(x => x.id === selected.id);
      if (fresh) setSelected(fresh);
    }
    if (activeFuzz) {
      const fresh = f.find(x => x.id === activeFuzz.id);
      if (fresh) setActiveFuzz(fresh);
    }
  }, [selected, activeFuzz, activeOsint]);

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
    e.preventDefault(); setFuzzLoading(true); setActiveFuzz(null);
    try {
      const r = await api.startFuzz(fuzzTarget, fuzzConcurrency);
      setActiveFuzz(r);
    } finally { setFuzzLoading(false); }
  }
  async function handleLoadTest(e: React.FormEvent) {
    e.preventDefault(); setLtLoading(true);
    try { const r = await api.startLoadTest(ltTarget, ltUsers, ltRps, ltDuration); setSelected(r); await refresh(); setTab('history'); } finally { setLtLoading(false); }
  }
  async function handleFraud(e: React.FormEvent) {
    e.preventDefault(); setFraudLoading(true);
    try { const r = await api.startFintechFraud(fraudTarget); setSelected(r); await refresh(); setTab('history'); } finally { setFraudLoading(false); }
  }
  async function handleAuthAudit(e: React.FormEvent) {
    e.preventDefault(); setAuthLoading(true); setActiveAuthAudit(null);
    try { const r = await api.startAuthAudit(authTarget); setActiveAuthAudit(r); } finally { setAuthLoading(false); }
  }
  async function handleOsint(e: React.FormEvent) {
    e.preventDefault(); setOsintLoading(true); setActiveOsint(null);
    try { const r = await api.startOsint(osintDomain); setActiveOsint(r); } finally { setOsintLoading(false); }
  }

  async function handleCreateMandate(e: React.FormEvent) {
    e.preventDefault(); setMLoading(true); setMError('');
    try {
      const urls = mTargetUrls.split('\n').map(u => u.trim()).filter(Boolean);
      if (!urls.length) { setMError('Entrez au moins une URL cible.'); return; }
      if (!mScope.length) { setMError('Sélectionnez au moins un type de test.'); return; }
      await api.createMandate({
        tester_company: mTesterCompany || 'INTEL Security',
        client_name: mClientName, client_email: mClientEmail,
        client_company: mClientCompany, target_urls: urls, scope: mScope,
        valid_from: mValidFrom, valid_until: mValidUntil,
        notes: mNotes || undefined,
      });
      setMClientName(''); setMClientEmail(''); setMClientCompany('');
      setMTargetUrls(''); setMScope([]); setMNotes('');
      await refresh();
    } catch { setMError('Erreur lors de la création du mandat.'); }
    finally { setMLoading(false); }
  }

  function mandateLink(token: string) {
    return `${window.location.origin}${window.location.pathname}?mandate=${token}`;
  }

  function copyLink(token: string) {
    navigator.clipboard.writeText(mandateLink(token));
    setMCopied(token);
    setTimeout(() => setMCopied(null), 2000);
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
    ['fraud', '💳 Fraude API'],
    ['authaudit', '🔐 Auth Audit'],
    ['loadtest', '⚡ Load Test'],
    ['scanner', '🔍 Scanner'],
    ['fuzzer', '🕸 Fuzzer'],
    ['history', '📋 History'],
    ['mandats', '✍️ Mandats'],
    ['osint', '🔎 OSINT'],
  ];

  return (
    <div style={{ minHeight: '100vh', background: '#0a0e1a' }}>
      <header style={{ background: '#0d1424', borderBottom: '1px solid #1e293b', padding: '14px 28px', display: 'flex', alignItems: 'center', gap: 14 }}>
        <span style={{ fontSize: 18, fontWeight: 700, color: '#60a5fa', letterSpacing: 2 }}>⬡ INTEL</span>
        <span style={{ color: '#475569', fontSize: 12 }}>Security Platform</span>
        <div className="nav-tabs">
          {TABS.map(([t, label]) => (
            <button key={t} onClick={() => setTab(t)} style={{
              background: tab === t ? (t === 'fraud' ? '#1a1040' : '#1e3a5f') : 'transparent',
              color: tab === t ? (t === 'fraud' ? '#a78bfa' : '#60a5fa') : '#94a3b8',
              border: tab === t ? `1px solid ${t === 'fraud' ? '#7c3aed' : '#2563eb'}` : '1px solid transparent',
              borderRadius: 6, padding: '5px 12px', cursor: 'pointer', fontSize: 12, fontFamily: 'inherit', fontWeight: 600,
              whiteSpace: 'nowrap', flexShrink: 0,
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
              Vérifie si le site client peut être usurpé — iframe, faux emails, absence de DMARC/SPF/DKIM.
            </p>
            <form onSubmit={handlePhishing} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 28, marginBottom: 24 }}>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>URL du site client</label>
              {urlInput(phTarget, setPhTarget)}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 20 }}>
                {[['🌐 En-têtes HTTP', 'X-Frame, CSP, HSTS'], ['📧 SPF / DMARC', 'Usurpation email'], ['🔗 DKIM', 'Signature email'], ['🔒 SSL/DNS', 'Infrastructure']].map(([icon, desc]) => (
                  <div key={String(icon)} style={{ background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 12px', textAlign: 'center' }}>
                    <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 2 }}>{icon}</div>
                    <div style={{ fontSize: 11, color: '#475569' }}>{desc}</div>
                  </div>
                ))}
              </div>
              <button type="submit" disabled={phLoading} style={{ background: phLoading ? '#3b1c5c' : 'linear-gradient(135deg, #dc2626, #7c3aed)', color: '#fff', border: 'none', borderRadius: 6, padding: '11px 28px', cursor: 'pointer', fontSize: 14, fontFamily: 'inherit', fontWeight: 700, letterSpacing: 1 }}>
                {phLoading ? '⟳ Analyse en cours...' : '🎣 LANCER L\'ANALYSE PHISHING'}
              </button>
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
                      {p.risk_level !== 'UNKNOWN' && <div style={{ color: RISK_COLOR[p.risk_level], fontWeight: 700, fontSize: 13 }}>{p.risk_score}% risque</div>}
                      <Badge s={p.status} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* 💳 FRAUDE API FINTECH */}
        {tab === 'fraud' && (
          <div>
            <h2 style={{ color: '#e2e8f0', marginBottom: 6, fontSize: 20 }}>💳 Audit Fraude API Fintech</h2>
            <p style={{ color: '#64748b', fontSize: 13, marginBottom: 24, lineHeight: 1.6 }}>
              Détecte si un attaquant peut déclencher des retraits / virements depuis votre site sans passer par votre interface —
              via CORS non sécurisé, absence d'authentification sur les endpoints de paiement, CSRF, ou replay d'API.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginBottom: 24 }}>
              {[
                ['🔑', 'Auth bypass', 'Endpoints de retrait sans token'],
                ['🌐', 'CORS hostile', 'Requêtes cross-origin non bloquées'],
                ['🛡️', 'CSRF', 'Falsification de virement inter-site'],
                ['⏱️', 'Rate limiting', 'Spam de retraits en masse'],
                ['👁️', 'Exposition admin', 'Interfaces internes accessibles'],
                ['🔐', 'Idempotence', 'Rejouer un paiement en double'],
              ].map(([icon, title, desc]) => (
                <div key={String(title)} style={{ background: '#0d1424', border: '1px solid #7c3aed30', borderRadius: 8, padding: '14px 16px' }}>
                  <div style={{ fontSize: 20, marginBottom: 6 }}>{icon}</div>
                  <div style={{ color: '#a78bfa', fontSize: 12, fontWeight: 700, marginBottom: 3 }}>{title}</div>
                  <div style={{ color: '#475569', fontSize: 11 }}>{desc}</div>
                </div>
              ))}
            </div>

            <form onSubmit={handleFraud} style={{ background: '#0d1424', border: '1px solid #7c3aed40', borderRadius: 10, padding: 28, marginBottom: 24 }}>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>URL du site client fintech</label>
              {urlInput(fraudTarget, setFraudTarget)}
              <div style={{ background: '#0a0e1a', border: '1px solid #7c3aed30', borderRadius: 6, padding: '10px 14px', marginBottom: 20, fontSize: 12, color: '#64748b', lineHeight: 1.6 }}>
                ⚠️ <strong style={{ color: '#a78bfa' }}>Audit passif + léger.</strong> Aucune transaction réelle n'est effectuée.
                L'outil sonde uniquement les en-têtes HTTP, CORS, DNS et l'accessibilité des endpoints courants.
                Utilisez uniquement sur des systèmes que vous êtes autorisé à tester.
              </div>
              <button type="submit" disabled={fraudLoading} style={{ background: fraudLoading ? '#2d1b4e' : 'linear-gradient(135deg, #7c3aed, #2563eb)', color: '#fff', border: 'none', borderRadius: 6, padding: '11px 28px', cursor: 'pointer', fontSize: 14, fontFamily: 'inherit', fontWeight: 700, letterSpacing: 1 }}>
                {fraudLoading ? '⟳ Audit en cours...' : '💳 LANCER L\'AUDIT FRAUDE'}
              </button>
            </form>

            {fraudAudits.length > 0 && (
              <div>
                <h3 style={{ color: '#94a3b8', fontSize: 12, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>Derniers audits</h3>
                {fraudAudits.slice(0, 5).map(fa => (
                  <div key={fa.id} onClick={() => { setSelected(fa); setTab('history'); }}
                    style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 8, padding: '14px 18px', marginBottom: 8, cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600, marginBottom: 4 }}>{fa.domain}</div>
                      {fa.summary && <div style={{ color: '#64748b', fontSize: 12 }}>{fa.summary}</div>}
                      {!fa.summary && <div style={{ color: '#a78bfa', fontSize: 12 }}>⟳ Audit des endpoints en cours...</div>}
                    </div>
                    <div style={{ textAlign: 'right', minWidth: 80 }}>
                      {fa.risk_level !== 'UNKNOWN' && <div style={{ color: RISK_COLOR[fa.risk_level], fontWeight: 700, fontSize: 13 }}>{fa.risk_score}% risque</div>}
                      <Badge s={fa.status} />
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
              <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
                {([
                  { label: '10k req', u: 100, r: 10, d: 10 },
                  { label: '25k req', u: 250, r: 10, d: 10 },
                  { label: '50k req', u: 500, r: 10, d: 10 },
                  { label: '50k rapide', u: 1000, r: 50, d: 1 },
                  { label: 'MAX', u: 2000, r: 500, d: 300 },
                ] as { label: string; u: number; r: number; d: number }[]).map(p => (
                  <button key={p.label} type="button" onClick={() => { setLtUsers(p.u); setLtRps(p.r); setLtDuration(p.d); }}
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
            <h2 style={{ color: '#e2e8f0', marginBottom: 6, fontSize: 18 }}>🕸 Endpoint Fuzzer</h2>
            <p style={{ color: '#64748b', fontSize: 13, marginBottom: 20 }}>Découvre les endpoints cachés/sensibles en testant des milliers de chemins courants.</p>
            <form onSubmit={handleFuzz} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 10, padding: 28, marginBottom: 20 }}>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Target URL</label>
              {urlInput(fuzzTarget, setFuzzTarget)}
              {slider('Concurrence', fuzzConcurrency, setFuzzConcurrency, 1, 50, ' threads')}
              <button type="submit" disabled={fuzzLoading} style={{ background: fuzzLoading ? '#1e3a5f' : '#0891b2', color: '#fff', border: 'none', borderRadius: 6, padding: '10px 24px', cursor: 'pointer', fontSize: 14, fontFamily: 'inherit', fontWeight: 600 }}>
                {fuzzLoading ? '⟳ Lancement...' : '▶ Lancer le fuzzing'}
              </button>
            </form>

            {/* Live results panel */}
            {activeFuzz && (
              <div style={{ background: '#0d1424', border: '1px solid #0891b240', borderRadius: 10, padding: 22 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                  <div>
                    <div style={{ color: '#0891b2', fontSize: 14, fontWeight: 700 }}>🕸 Résultats — {activeFuzz.target_url}</div>
                    <div style={{ color: '#475569', fontSize: 11, marginTop: 3 }}>
                      <Badge s={activeFuzz.status} /> · {activeFuzz.results?.length ?? 0} endpoint(s) découvert(s)
                    </div>
                  </div>
                  <button onClick={() => setActiveFuzz(null)} style={{ background: 'none', border: 'none', color: '#475569', cursor: 'pointer', fontSize: 16 }}>✕</button>
                </div>

                {activeFuzz.status === 'running' && (
                  <div style={{ color: '#60a5fa', fontSize: 13, marginBottom: 12 }}>
                    ⟳ Fuzzing en cours... Le binaire Rust teste les endpoints par lots de {activeFuzz.concurrency} threads simultanés.
                  </div>
                )}

                {activeFuzz.status === 'failed' && (
                  <div style={{ background: '#ff3b5c18', border: '1px solid #ff3b5c40', borderRadius: 6, padding: '10px 14px', marginBottom: 12, color: '#ff3b5c', fontSize: 13 }}>
                    ✗ Échec du fuzzing — le binaire Rust doit être compilé (lancez le workflow "Build" d'abord)
                  </div>
                )}

                {activeFuzz.status === 'completed' && activeFuzz.results?.length === 0 && (
                  <div style={{ color: '#60d394', fontSize: 13, padding: '10px 0' }}>✓ Aucun endpoint sensible découvert sur cette cible.</div>
                )}

                {(activeFuzz.results?.length ?? 0) > 0 && (
                  <div>
                    <div style={{ display: 'grid', gridTemplateColumns: '50px 1fr 60px 70px', gap: 0, marginBottom: 8, padding: '0 8px' }}>
                      <span style={{ color: '#475569', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1 }}>Code</span>
                      <span style={{ color: '#475569', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1 }}>Endpoint</span>
                      <span style={{ color: '#475569', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1 }}>Taille</span>
                      <span style={{ color: '#475569', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1, textAlign: 'right' }}>Temps</span>
                    </div>
                    <div style={{ maxHeight: 400, overflowY: 'auto' }}>
                      {activeFuzz.results.map((r, i) => (
                        <div key={i} style={{ display: 'grid', gridTemplateColumns: '50px 1fr 60px 70px', gap: 0, padding: '7px 8px', marginBottom: 3, background: '#0a0e1a', borderRadius: 5, borderLeft: `3px solid ${r.status < 300 ? '#60d394' : r.status < 400 ? '#fbbf24' : '#ff6b35'}` }}>
                          <span style={{ color: r.status < 300 ? '#60d394' : r.status < 400 ? '#fbbf24' : '#ff6b35', fontWeight: 700, fontSize: 12 }}>{r.status}</span>
                          <span style={{ color: '#e2e8f0', fontSize: 12, wordBreak: 'break-all' }}>{r.path}</span>
                          <span style={{ color: '#475569', fontSize: 11 }}>{r.size}b</span>
                          <span style={{ color: '#475569', fontSize: 11, textAlign: 'right' }}>{r.ms}ms</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Previous jobs */}
            {fuzzes.length > 0 && !activeFuzz && (
              <div>
                <h3 style={{ color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>Jobs précédents</h3>
                {fuzzes.slice(0, 10).map(f => (
                  <div key={f.id} onClick={() => setActiveFuzz(f)} style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 8, padding: '12px 16px', marginBottom: 7, cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ color: '#e2e8f0', fontSize: 12, fontWeight: 600, marginBottom: 3 }}>{f.target_url}</div>
                      <div style={{ color: '#475569', fontSize: 11 }}>{f.results?.length ?? 0} endpoint(s)</div>
                    </div>
                    <Badge s={f.status} />
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* 📋 HISTORY */}
        {tab === 'history' && (
          <div className={selected ? 'history-grid' : 'history-grid no-detail'}>
            <div>
              {/* Phishing */}
              <h3 style={{ color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>🎣 Analyses Phishing</h3>
              {phishings.length === 0 && <p style={{ color: '#334155', fontSize: 12, marginBottom: 16 }}>Aucune analyse lancée.</p>}
              {phishings.map(p => (
                <div key={p.id} onClick={() => setSelected(p)} style={{ background: '#0d1424', border: `1px solid ${selected?.id === p.id ? '#dc2626' : '#1e293b'}`, borderRadius: 8, padding: '12px 16px', marginBottom: 7, cursor: 'pointer' }}>
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

              {/* Fraude fintech */}
              <h3 style={{ color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, margin: '16px 0 8px' }}>💳 Audits Fraude Fintech</h3>
              {fraudAudits.length === 0 && <p style={{ color: '#334155', fontSize: 12, marginBottom: 16 }}>Aucun audit lancé.</p>}
              {fraudAudits.map(fa => (
                <div key={fa.id} onClick={() => setSelected(fa)} style={{ background: '#0d1424', border: `1px solid ${selected?.id === fa.id ? '#7c3aed' : '#1e293b'}`, borderRadius: 8, padding: '12px 16px', marginBottom: 7, cursor: 'pointer' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                    <span style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>{fa.domain}</span>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      {fa.risk_level !== 'UNKNOWN' && <span style={{ color: RISK_COLOR[fa.risk_level], fontSize: 11, fontWeight: 700 }}>{fa.risk_score}%</span>}
                      <Badge s={fa.status} />
                    </div>
                  </div>
                  {fa.summary && <div style={{ color: '#475569', fontSize: 11 }}>{fa.summary}</div>}
                </div>
              ))}

              {/* Load tests */}
              <h3 style={{ color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, margin: '16px 0 8px' }}>⚡ Stress Tests</h3>
              {loadTests.map(lt => (
                <div key={lt.id} onClick={() => setSelected(lt)} style={{ background: '#0d1424', border: `1px solid ${selected?.id === lt.id ? '#7c3aed' : '#1e293b'}`, borderRadius: 8, padding: '12px 16px', marginBottom: 7, cursor: 'pointer' }}>
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
                <div key={s.id} onClick={() => setSelected(s)} style={{ background: '#0d1424', border: `1px solid ${selected?.id === s.id ? '#2563eb' : '#1e293b'}`, borderRadius: 8, padding: '12px 16px', marginBottom: 7, cursor: 'pointer' }}>
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
                <div key={f.id} onClick={() => setSelected(f)} style={{ background: '#0d1424', border: `1px solid ${selected?.id === f.id ? '#0891b2' : '#1e293b'}`, borderRadius: 8, padding: '12px 16px', marginBottom: 7, cursor: 'pointer' }}>
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
              <div className="detail-panel">
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                  <h3 style={{ color: '#60a5fa', fontSize: 14 }}>
                    {'checks' in selected && 'domain' in selected && !('risk_level' in selected && 'category' in (selected as any).checks?.[0] && ['auth', 'csrf', 'cors'].includes((selected as any).checks?.[0]?.category))
                      ? '🎣 Phishing Report'
                      : 'checks' in selected ? '💳 Audit Fraude Fintech'
                      : 'verdict' in selected ? '⚡ Stress Test'
                      : 'findings' in selected ? '🔍 Scan'
                      : '🕸 Fuzz'}
                  </h3>
                  <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: '#475569', cursor: 'pointer', fontSize: 16 }}>✕</button>
                </div>

                <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 14, wordBreak: 'break-all' }}>
                  {'domain' in selected ? (selected as any).domain : (selected as any).target_url}
                </div>

                {/* Phishing detail */}
                {'checks' in selected && (selected as PhishingAssessment).checks?.[0] && ['email', 'http', 'dns', 'ssl'].includes((selected as PhishingAssessment).checks?.[0]?.category) && (
                  <div>
                    {selected.status === 'running' && <div style={{ color: '#60a5fa', fontSize: 13, marginBottom: 16 }}>⟳ Vérification DNS + HTTP en cours...</div>}
                    {selected.status === 'completed' && (
                      <>
                        <ScoreRing score={(selected as PhishingAssessment).risk_score} level={(selected as PhishingAssessment).risk_level} />
                        {(selected as PhishingAssessment).summary && (
                          <div style={{ background: `${RISK_COLOR[(selected as PhishingAssessment).risk_level] ?? '#475569'}18`, border: `1px solid ${RISK_COLOR[(selected as PhishingAssessment).risk_level] ?? '#475569'}40`, borderRadius: 8, padding: '12px 16px', marginBottom: 18, fontSize: 13, color: RISK_COLOR[(selected as PhishingAssessment).risk_level] ?? '#e2e8f0', fontWeight: 600 }}>
                            {(selected as PhishingAssessment).summary}
                          </div>
                        )}
                        <DemoEmailPanel assessmentId={selected.id} domain={(selected as PhishingAssessment).domain} />
                        {(['email', 'http', 'dns'] as const).map(cat => {
                          const catChecks = (selected as PhishingAssessment).checks.filter(c => c.category === cat);
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

                {/* Fraud audit detail */}
                {'checks' in selected && (selected as FintechFraudAudit).checks?.[0] && ['auth', 'csrf', 'cors', 'ratelimit', 'headers', 'exposure'].includes((selected as FintechFraudAudit).checks?.[0]?.category) && (
                  <div>
                    {selected.status === 'running' && <div style={{ color: '#a78bfa', fontSize: 13, marginBottom: 16 }}>⟳ Audit des endpoints de paiement en cours...</div>}
                    {selected.status === 'completed' && (
                      <>
                        <ScoreRing score={(selected as FintechFraudAudit).risk_score} level={(selected as FintechFraudAudit).risk_level} />
                        {(selected as FintechFraudAudit).summary && (
                          <div style={{ background: `${RISK_COLOR[(selected as FintechFraudAudit).risk_level] ?? '#475569'}18`, border: `1px solid ${RISK_COLOR[(selected as FintechFraudAudit).risk_level] ?? '#475569'}40`, borderRadius: 8, padding: '12px 16px', marginBottom: 18, fontSize: 13, color: RISK_COLOR[(selected as FintechFraudAudit).risk_level] ?? '#e2e8f0', fontWeight: 600 }}>
                            {(selected as FintechFraudAudit).summary}
                          </div>
                        )}
                        {(['auth', 'csrf', 'cors', 'ratelimit', 'headers', 'exposure'] as const).map(cat => {
                          const catChecks = (selected as FintechFraudAudit).checks.filter(c => c.category === cat);
                          if (!catChecks.length) return null;
                          const catLabel: Record<string, string> = { auth: 'Authentification', csrf: 'CSRF', cors: 'CORS', ratelimit: 'Rate Limiting / Idempotence', headers: 'En-têtes Sécurité', exposure: 'Exposition' };
                          return (
                            <div key={cat} style={{ marginBottom: 16 }}>
                              <div style={{ color: '#475569', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
                                {FRAUD_CAT_ICON[cat]} {catLabel[cat]}
                              </div>
                              {catChecks.map(c => <FraudCheckRow key={c.id} c={c as FraudCheck} />)}
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
                    {(selected as LoadTest).verdict && (
                      <div style={{ background: '#ffffff0a', border: '1px solid #1e293b', borderRadius: 8, padding: '14px 18px', marginBottom: 16, fontSize: 14, fontWeight: 700, color: (selected as LoadTest).verdict!.startsWith('✅') ? '#60d394' : (selected as LoadTest).verdict!.startsWith('⚠️') ? '#fbbf24' : '#ff3b5c' }}>
                        {(selected as LoadTest).verdict}
                      </div>
                    )}
                    {selected.status === 'completed' && (() => {
                      const lt = selected as LoadTest;
                      const geo = lt.results?.geo_breakdown ?? [];
                      const FLAG: Record<string, string> = { FR:'🇫🇷', US:'🇺🇸', GB:'🇬🇧', DE:'🇩🇪', BR:'🇧🇷', NG:'🇳🇬', MA:'🇲🇦', SN:'🇸🇳', KE:'🇰🇪', ZA:'🇿🇦', IN:'🇮🇳', CA:'🇨🇦' };
                      return (
                        <>
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 16 }}>
                            {[['Total req.', lt.total_requests], ['Succès', lt.successful_requests], ['Échecs', lt.failed_requests], ['Req/s', lt.requests_per_second], ['Moy.', `${lt.avg_response_ms}ms`], ['Crash', lt.server_crash ? '💥 OUI' : '✅ NON']].map(([k, v]) => (
                              <div key={String(k)} style={{ background: '#0a0e1a', borderRadius: 6, padding: '10px 12px' }}>
                                <div style={{ color: '#475569', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 3 }}>{k}</div>
                                <div style={{ color: '#e2e8f0', fontSize: 16, fontWeight: 700 }}>{v}</div>
                              </div>
                            ))}
                          </div>
                          {geo.length > 0 && (
                            <div>
                              <div style={{ color: '#475569', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
                                🌍 Distribution géographique — {geo.length} pays
                              </div>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                                {geo.filter(g => g.requests > 0).sort((a, b) => b.requests - a.requests).map(g => {
                                  const pct = lt.total_requests > 0 ? Math.round((g.requests / lt.total_requests) * 100) : 0;
                                  const successRate = g.requests > 0 ? Math.round((g.successful / g.requests) * 100) : 0;
                                  return (
                                    <div key={g.country_code} style={{ background: '#0a0e1a', borderRadius: 6, padding: '7px 10px' }}>
                                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                                        <span style={{ fontSize: 12, color: '#cbd5e1' }}>
                                          {FLAG[g.country_code] ?? '🌐'} {g.country}
                                        </span>
                                        <div style={{ display: 'flex', gap: 8, fontSize: 11 }}>
                                          <span style={{ color: '#475569' }}>{g.requests.toLocaleString()} req</span>
                                          <span style={{ color: successRate >= 80 ? '#60d394' : successRate >= 50 ? '#fbbf24' : '#ff6b35', fontWeight: 700 }}>{successRate}% ✓</span>
                                        </div>
                                      </div>
                                      <div style={{ background: '#1e293b', borderRadius: 3, height: 4, overflow: 'hidden' }}>
                                        <div style={{ width: `${pct}%`, height: '100%', background: successRate >= 80 ? '#60d394' : successRate >= 50 ? '#fbbf24' : '#ff6b35', borderRadius: 3, transition: 'width 0.3s' }} />
                                      </div>
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                          )}
                        </>
                      );
                    })()}
                  </div>
                )}

                {/* Scan findings */}
                {'findings' in selected && (selected as Scan).findings?.map((f, i) => (
                  <div key={i} style={{ borderLeft: `3px solid ${SEV_COLOR[f.severity] ?? '#60a5fa'}`, padding: '8px 12px', marginBottom: 8, background: '#0a0e1a', borderRadius: '0 6px 6px 0' }}>
                    <div style={{ display: 'flex', gap: 8, marginBottom: 3 }}>
                      <span style={{ color: SEV_COLOR[f.severity], fontSize: 10, fontWeight: 700 }}>{f.severity}</span>
                      <span style={{ color: '#e2e8f0', fontSize: 12, fontWeight: 600 }}>{f.title}</span>
                    </div>
                    <div style={{ color: '#94a3b8', fontSize: 11 }}>{f.description}</div>
                    {f.fix && <div style={{ color: '#60d394', fontSize: 11, marginTop: 3 }}>↳ {f.fix}</div>}
                  </div>
                ))}
                {'findings' in selected && selected.status === 'completed' && !(selected as Scan).findings?.length && (
                  <p style={{ color: '#60d394', fontSize: 13 }}>✓ Aucune vulnérabilité détectée</p>
                )}

                {/* Fuzz results */}
                {'results' in selected && (
                  <div>
                    {selected.status === 'running' && <p style={{ color: '#60a5fa', fontSize: 13 }}>⟳ Fuzzing en cours...</p>}
                    {selected.status === 'completed' && !(selected as FuzzJob).results?.length && (
                      <p style={{ color: '#60d394', fontSize: 13 }}>✓ Aucun endpoint sensible découvert.</p>
                    )}
                    {(selected as FuzzJob).results?.map((r, i) => (
                      <div key={i} style={{ display: 'flex', gap: 10, padding: '6px 10px', marginBottom: 4, background: '#0a0e1a', borderRadius: 5, fontSize: 11, borderLeft: `3px solid ${r.status < 300 ? '#60d394' : r.status < 400 ? '#fbbf24' : '#ff6b35'}` }}>
                        <span style={{ color: r.status < 300 ? '#60d394' : r.status < 400 ? '#fbbf24' : '#ff6b35', fontWeight: 700, width: 34 }}>{r.status}</span>
                        <span style={{ color: '#e2e8f0', flex: 1 }}>{r.path}</span>
                        <span style={{ color: '#475569' }}>{r.ms}ms</span>
                      </div>
                    ))}
                  </div>
                )}

                {selected.status === 'running' && !('checks' in selected) && !('verdict' in selected) && !('results' in selected) && (
                  <p style={{ color: '#60a5fa', fontSize: 13 }}>⟳ En cours...</p>
                )}
              </div>
            )}
          </div>
        )}

        {/* ===== MANDATS TAB ===== */}
        {tab === 'mandats' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, maxWidth: 1100, margin: '0 auto' }}>

            {/* Left: Create mandate form */}
            <div>
              <h2 style={{ color: '#e2e8f0', fontSize: 16, fontWeight: 700, marginBottom: 18, display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ color: '#60a5fa' }}>✍️</span> Nouvelle Lettre d'Autorisation
              </h2>
              <form onSubmit={handleCreateMandate}>
                <label style={{ display: 'block', color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
                  Votre société (testeur)
                </label>
                <input value={mTesterCompany} onChange={e => setMTesterCompany(e.target.value)} placeholder="INTEL Security"
                  style={{ width: '100%', background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 14, fontFamily: 'inherit', marginBottom: 14, outline: 'none', boxSizing: 'border-box' }} />

                <label style={{ display: 'block', color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
                  Nom du client *
                </label>
                <input value={mClientName} onChange={e => setMClientName(e.target.value)} required placeholder="Jean Dupont"
                  style={{ width: '100%', background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 14, fontFamily: 'inherit', marginBottom: 14, outline: 'none', boxSizing: 'border-box' }} />

                <label style={{ display: 'block', color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
                  Email du client *
                </label>
                <input type="email" value={mClientEmail} onChange={e => setMClientEmail(e.target.value)} required placeholder="client@societe.com"
                  style={{ width: '100%', background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 14, fontFamily: 'inherit', marginBottom: 14, outline: 'none', boxSizing: 'border-box' }} />

                <label style={{ display: 'block', color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
                  Société cliente *
                </label>
                <input value={mClientCompany} onChange={e => setMClientCompany(e.target.value)} required placeholder="Acme Corp"
                  style={{ width: '100%', background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 14, fontFamily: 'inherit', marginBottom: 14, outline: 'none', boxSizing: 'border-box' }} />

                <label style={{ display: 'block', color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
                  URLs cibles * (une par ligne)
                </label>
                <textarea value={mTargetUrls} onChange={e => setMTargetUrls(e.target.value)} required rows={3}
                  placeholder={"https://api.societe.com\nhttps://app.societe.com"}
                  style={{ width: '100%', background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 14, fontFamily: 'inherit', marginBottom: 14, outline: 'none', resize: 'vertical', boxSizing: 'border-box' }} />

                <label style={{ display: 'block', color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
                  Types de tests autorisés *
                </label>
                <div style={{ marginBottom: 16 }}>
                  {SCOPE_OPTIONS.map(opt => (
                    <label key={opt.id} style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#cbd5e1', fontSize: 13, marginBottom: 8, cursor: 'pointer' }}>
                      <input type="checkbox" checked={mScope.includes(opt.id)}
                        onChange={e => setMScope(e.target.checked ? [...mScope, opt.id] : mScope.filter(s => s !== opt.id))}
                        style={{ accentColor: '#60a5fa', width: 16, height: 16 }} />
                      {opt.label}
                    </label>
                  ))}
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
                  <div>
                    <label style={{ display: 'block', color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>Valide du *</label>
                    <input type="date" value={mValidFrom} onChange={e => setMValidFrom(e.target.value)} required
                      style={{ width: '100%', background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 14, fontFamily: 'inherit', outline: 'none', boxSizing: 'border-box' }} />
                  </div>
                  <div>
                    <label style={{ display: 'block', color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>Au *</label>
                    <input type="date" value={mValidUntil} onChange={e => setMValidUntil(e.target.value)} required
                      style={{ width: '100%', background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 14, fontFamily: 'inherit', outline: 'none', boxSizing: 'border-box' }} />
                  </div>
                </div>

                <label style={{ display: 'block', color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
                  Notes / restrictions
                </label>
                <textarea value={mNotes} onChange={e => setMNotes(e.target.value)} rows={2}
                  placeholder="Tests hors heures de bureau uniquement, pas de DoS, etc."
                  style={{ width: '100%', background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 14, fontFamily: 'inherit', marginBottom: 14, outline: 'none', resize: 'vertical', boxSizing: 'border-box' }} />

                {mError && <div style={{ color: '#ff6b35', fontSize: 13, marginBottom: 12 }}>{mError}</div>}

                <button type="submit" disabled={mLoading}
                  style={{ width: '100%', padding: '12px 0', background: mLoading ? '#1e293b' : '#1d4ed8', color: '#fff', border: 'none', borderRadius: 8, fontSize: 15, fontWeight: 700, cursor: mLoading ? 'not-allowed' : 'pointer', letterSpacing: 0.5 }}>
                  {mLoading ? 'Création...' : '⚡ Générer le mandat'}
                </button>
              </form>
            </div>

            {/* Right: Mandate list */}
            <div>
              <h2 style={{ color: '#e2e8f0', fontSize: 16, fontWeight: 700, marginBottom: 18, display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ color: '#60a5fa' }}>📋</span> Mandats émis ({mandates.length})
              </h2>
              {mandates.length === 0 && (
                <div style={{ color: '#334155', fontSize: 13, textAlign: 'center', padding: 40, border: '1px dashed #1e293b', borderRadius: 10 }}>
                  Aucun mandat créé.<br />Utilisez le formulaire pour générer le premier.
                </div>
              )}
              {mandates.map(m => {
                const statusColor = m.status === 'authorized' ? '#60d394' : m.status === 'expired' ? '#475569' : '#fbbf24';
                const statusLabel = m.status === 'authorized' ? '✓ Signé' : m.status === 'expired' ? '✕ Expiré' : '⏳ En attente';
                return (
                  <div key={m.id} style={{ background: '#0d1424', border: `1px solid ${m.status === 'authorized' ? '#1a4a2e' : '#1e293b'}`, borderRadius: 10, padding: '14px 16px', marginBottom: 10 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                      <div>
                        <div style={{ color: '#e2e8f0', fontWeight: 700, fontSize: 14 }}>{m.client_company}</div>
                        <div style={{ color: '#64748b', fontSize: 12 }}>{m.client_name} · {m.client_email}</div>
                      </div>
                      <span style={{ color: statusColor, fontSize: 12, fontWeight: 700, background: `${statusColor}18`, padding: '3px 8px', borderRadius: 20, whiteSpace: 'nowrap' }}>
                        {statusLabel}
                      </span>
                    </div>

                    <div style={{ fontSize: 11, color: '#475569', marginBottom: 8 }}>
                      📅 {new Date(m.valid_from).toLocaleDateString('fr-FR')} → {new Date(m.valid_until).toLocaleDateString('fr-FR')}
                    </div>

                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: 10 }}>
                      {m.target_urls.map((u, i) => (
                        <span key={i} style={{ background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 4, padding: '2px 7px', fontSize: 10, color: '#60a5fa' }}>{u}</span>
                      ))}
                    </div>

                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: 12 }}>
                      {m.scope.map((s, i) => {
                        const opt = SCOPE_OPTIONS.find(o => o.id === s);
                        return <span key={i} style={{ background: '#1e293b', borderRadius: 4, padding: '2px 7px', fontSize: 10, color: '#94a3b8' }}>{opt ? opt.label : s}</span>;
                      })}
                    </div>

                    {m.status === 'authorized' && m.signed_at && (
                      <div style={{ fontSize: 11, color: '#60d394', marginBottom: 10 }}>
                        ✓ Signé le {new Date(m.signed_at).toLocaleString('fr-FR')} · IP: {m.signed_ip}
                      </div>
                    )}

                    <div style={{ display: 'flex', gap: 8 }}>
                      {m.status === 'pending' && (
                        <button onClick={() => copyLink(m.token)}
                          style={{ flex: 1, padding: '7px 0', background: mCopied === m.token ? '#1a4a2e' : '#1e293b', color: mCopied === m.token ? '#60d394' : '#94a3b8', border: 'none', borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: 'pointer' }}>
                          {mCopied === m.token ? '✓ Lien copié !' : '🔗 Copier le lien client'}
                        </button>
                      )}
                      {m.status !== 'expired' && (
                        <button onClick={async () => { await api.revokeMandate(m.id); await refresh(); }}
                          style={{ padding: '7px 14px', background: 'transparent', color: '#ff3b5c', border: '1px solid #ff3b5c33', borderRadius: 6, fontSize: 12, cursor: 'pointer' }}>
                          Révoquer
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ===== AUTH AUDIT TAB ===== */}
        {tab === 'authaudit' && (
          <AuthAuditTab
            authTarget={authTarget} setAuthTarget={setAuthTarget}
            handleAuthAudit={handleAuthAudit} authLoading={authLoading}
            activeAuthAudit={activeAuthAudit} authAudits={authAudits}
            setActiveAuthAudit={setActiveAuthAudit}
          />
        )}

        {/* ===== OSINT TAB ===== */}
        {tab === 'osint' && (
          <OsintTab
            osintDomain={osintDomain} setOsintDomain={setOsintDomain}
            handleOsint={handleOsint} osintLoading={osintLoading}
            activeOsint={activeOsint} osintScans={osintScans}
            setActiveOsint={setActiveOsint}
          />
        )}
      </main>
    </div>
  );
}

const AUTH_CAT_ICON: Record<string, string> = {
  unauth_access: '🚪', cookie: '🍪', bypass: '🔓', admin: '👑', token: '🎫', header: '📋',
};
const AUTH_CAT_LABEL: Record<string, string> = {
  unauth_access: 'Accès non autorisé', cookie: 'Sécurité cookies', bypass: 'Contournement auth',
  admin: 'Exposition admin', token: 'Exposition token', header: 'Headers',
};

function AuthCheckRow({ c }: { c: AuthCheck }) {
  const [open, setOpen] = useState(false);
  const color = SEV_COLOR[c.risk] ?? '#60a5fa';
  return (
    <div style={{ borderLeft: `3px solid ${c.passed ? '#60d394' : color}`, background: '#0a0e1a', borderRadius: '0 6px 6px 0', marginBottom: 6, cursor: 'pointer' }} onClick={() => setOpen(o => !o)}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px' }}>
        <span style={{ fontSize: 14 }}>{AUTH_CAT_ICON[c.category] ?? '🔒'}</span>
        <span style={{ flex: 1, color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>{c.name}</span>
        {!c.passed && <span style={{ color, fontSize: 10, fontWeight: 700, background: `${color}22`, padding: '2px 8px', borderRadius: 4 }}>{c.risk}</span>}
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

function AuthAuditTab({ authTarget, setAuthTarget, handleAuthAudit, authLoading, activeAuthAudit, authAudits, setActiveAuthAudit }: {
  authTarget: string; setAuthTarget: (v: string) => void;
  handleAuthAudit: (e: React.FormEvent) => void; authLoading: boolean;
  activeAuthAudit: AuthAudit | null; authAudits: AuthAudit[];
  setActiveAuthAudit: (a: AuthAudit | null) => void;
}) {
  const display = activeAuthAudit ?? authAudits[0] ?? null;
  const RISK_C: Record<string, string> = { CRITIQUE: '#ff3b5c', ÉLEVÉ: '#ff6b35', MOYEN: '#fbbf24', FAIBLE: '#60d394', UNKNOWN: '#475569' };

  const cats = display?.checks
    ? Array.from(new Set(display.checks.map(c => c.category)))
    : [];

  const unprotected = display?.exposed_endpoints?.filter(e => !e.auth_required) ?? [];
  const protected_ = display?.exposed_endpoints?.filter(e => e.auth_required) ?? [];

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto' }}>
      <div style={{ display: 'grid', gridTemplateColumns: display ? '360px 1fr' : '1fr', gap: 24 }}>

        {/* Left: form + history */}
        <div>
          <h2 style={{ color: '#e2e8f0', fontSize: 16, fontWeight: 700, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: '#ef4444' }}>🔐</span> Audit Auth — Détection d'accès non autorisés
          </h2>
          <p style={{ color: '#475569', fontSize: 12, marginBottom: 18, lineHeight: 1.6 }}>
            Détecte les endpoints qui exposent des données sans token, les panels admin accessibles sans mot de passe,
            les bypass JWT (alg:none, Bearer null) et les mauvaises configurations de cookies de session.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 18 }}>
            {[
              ['🚪', 'Endpoints non protégés', 'Données accessibles sans token'],
              ['👑', 'Admin sans password', '/admin, /api/admin, /config'],
              ['🔓', 'Bypass JWT', 'alg:none, Bearer null, token vide'],
              ['🍪', 'Cookies non sécurisés', 'HttpOnly, Secure, SameSite manquants'],
            ].map(([icon, title, desc]) => (
              <div key={String(title)} style={{ background: '#0d1424', border: '1px solid #ef444420', borderRadius: 8, padding: '10px 12px' }}>
                <div style={{ fontSize: 16, marginBottom: 4 }}>{icon}</div>
                <div style={{ color: '#fca5a5', fontSize: 11, fontWeight: 700, marginBottom: 2 }}>{title}</div>
                <div style={{ color: '#475569', fontSize: 10 }}>{desc}</div>
              </div>
            ))}
          </div>

          <form onSubmit={handleAuthAudit} style={{ marginBottom: 20 }}>
            <label style={{ display: 'block', color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
              URL du site cible *
            </label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input value={authTarget} onChange={e => setAuthTarget(e.target.value)} required
                placeholder="https://api.client.com"
                style={{ flex: 1, background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 14, fontFamily: 'inherit', outline: 'none' }} />
              <button type="submit" disabled={authLoading}
                style={{ padding: '10px 16px', background: authLoading ? '#1e293b' : 'linear-gradient(135deg, #dc2626, #991b1b)', color: '#fff', border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 700, cursor: authLoading ? 'not-allowed' : 'pointer', whiteSpace: 'nowrap' }}>
                {authLoading ? '⟳' : '🔐 Auditer'}
              </button>
            </div>
            <div style={{ color: '#334155', fontSize: 11, marginTop: 8, lineHeight: 1.5 }}>
              ⚠️ Audit passif. Aucune donnée réelle n'est extraite — seuls les codes HTTP et tailles de réponse sont enregistrés.
            </div>
          </form>

          {/* History */}
          {authAudits.length > 0 && (
            <div>
              <div style={{ color: '#475569', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>Historique</div>
              {authAudits.map(a => (
                <div key={a.id} onClick={() => setActiveAuthAudit(a)}
                  style={{ background: '#0d1424', border: `1px solid ${display?.id === a.id ? '#dc2626' : '#1e293b'}`, borderRadius: 8, padding: '10px 14px', marginBottom: 6, cursor: 'pointer' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ color: '#e2e8f0', fontWeight: 600, fontSize: 13 }}>{a.domain}</span>
                    <span style={{ color: a.status === 'completed' ? (RISK_C[a.risk_level] ?? '#94a3b8') : a.status === 'running' ? '#60a5fa' : '#ff3b5c', fontSize: 11, fontWeight: 700 }}>
                      {a.status === 'running' ? '⟳ En cours' : a.status === 'completed' ? `${a.risk_score}% risque` : '✗ Erreur'}
                    </span>
                  </div>
                  {a.status === 'completed' && (
                    <div style={{ color: '#475569', fontSize: 11, marginTop: 3 }}>
                      {(a.exposed_endpoints ?? []).filter(e => !e.auth_required).length} endpoint(s) exposé(s) · {(a.checks ?? []).filter(c => !c.passed).length} problème(s)
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: results */}
        {display && (
          <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 12, padding: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
              <div>
                <div style={{ color: '#e2e8f0', fontWeight: 800, fontSize: 17 }}>{display.domain}</div>
                <div style={{ color: '#475569', fontSize: 12 }}>
                  {display.status === 'running' ? '⟳ Audit en cours...' : display.status === 'completed' ? `Terminé — ${new Date(display.completed_at!).toLocaleString('fr-FR')}` : '✗ Échec'}
                </div>
              </div>
              {display.status === 'completed' && display.risk_level !== 'UNKNOWN' && (
                <div style={{ textAlign: 'right' }}>
                  <div style={{ color: RISK_C[display.risk_level], fontSize: 22, fontWeight: 800 }}>{display.risk_score}%</div>
                  <div style={{ color: RISK_C[display.risk_level], fontSize: 12, fontWeight: 700 }}>Risque {display.risk_level}</div>
                </div>
              )}
            </div>

            {display.status === 'running' && (
              <div style={{ color: '#60a5fa', fontSize: 13, textAlign: 'center', padding: '30px 0' }}>
                ⟳ Sonde en cours — test des endpoints, cookies, bypass JWT...
              </div>
            )}

            {display.status === 'completed' && (
              <>
                {/* Summary */}
                {display.summary && (
                  <div style={{ background: '#0a0e1a', border: `1px solid ${RISK_C[display.risk_level] ?? '#1e293b'}30`, borderRadius: 8, padding: '12px 16px', marginBottom: 20, color: '#e2e8f0', fontSize: 13, lineHeight: 1.6 }}>
                    {display.summary}
                  </div>
                )}

                {/* Stats row */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginBottom: 20 }}>
                  {[
                    { label: 'Endpoints exposés', val: unprotected.length, color: unprotected.length > 0 ? '#ff3b5c' : '#60d394', icon: '🚪' },
                    { label: 'Protégés (401/403)', val: protected_.length, color: '#60d394', icon: '✅' },
                    { label: 'Checks échoués', val: (display.checks ?? []).filter(c => !c.passed).length, color: (display.checks ?? []).filter(c => !c.passed).length > 0 ? '#ff6b35' : '#60d394', icon: '⚠️' },
                  ].map(s => (
                    <div key={s.label} style={{ background: '#0a0e1a', borderRadius: 8, padding: '10px 12px', textAlign: 'center', border: '1px solid #1e293b' }}>
                      <div style={{ fontSize: 18, marginBottom: 4 }}>{s.icon}</div>
                      <div style={{ color: s.color, fontSize: 20, fontWeight: 800 }}>{s.val}</div>
                      <div style={{ color: '#475569', fontSize: 10 }}>{s.label}</div>
                    </div>
                  ))}
                </div>

                {/* Exposed endpoints */}
                {unprotected.length > 0 && (
                  <div style={{ marginBottom: 20 }}>
                    <div style={{ color: '#ff3b5c', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
                      🚨 Endpoints exposés sans authentification ({unprotected.length})
                    </div>
                    <div style={{ background: '#0a0e1a', borderRadius: 8, border: '1px solid #ff3b5c30', overflow: 'hidden' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '50px 1fr 60px 70px 50px', gap: 0, padding: '6px 12px', borderBottom: '1px solid #1e293b', fontSize: 10, color: '#475569', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                        <span>Méth.</span><span>Chemin</span><span>Status</span><span>Taille</span><span>JSON</span>
                      </div>
                      {unprotected.map((ep, i) => (
                        <div key={i} style={{ display: 'grid', gridTemplateColumns: '50px 1fr 60px 70px 50px', gap: 0, padding: '8px 12px', borderBottom: i < unprotected.length - 1 ? '1px solid #1e293b10' : 'none', fontSize: 12 }}>
                          <span style={{ color: '#60a5fa', fontWeight: 700, fontFamily: 'monospace' }}>{ep.method}</span>
                          <span style={{ color: '#fbbf24', fontFamily: 'monospace' }}>{ep.path}</span>
                          <span style={{ color: ep.status < 300 ? '#60d394' : '#fbbf24', fontWeight: 700 }}>{ep.status}</span>
                          <span style={{ color: '#94a3b8' }}>{ep.response_size > 1024 ? `${(ep.response_size / 1024).toFixed(1)}KB` : `${ep.response_size}B`}</span>
                          <span style={{ color: ep.has_json ? '#ff6b35' : '#475569' }}>{ep.has_json ? 'JSON' : '—'}</span>
                        </div>
                      ))}
                    </div>
                    <div style={{ color: '#475569', fontSize: 11, marginTop: 6 }}>
                      ℹ️ Seuls le code HTTP et la taille de réponse sont enregistrés. Le contenu des données n'est pas extrait.
                    </div>
                  </div>
                )}

                {/* Checks by category */}
                {cats.map(cat => {
                  const catChecks = (display.checks ?? []).filter(c => c.category === cat);
                  const hasFail = catChecks.some(c => !c.passed);
                  return (
                    <div key={cat} style={{ marginBottom: 16 }}>
                      <div style={{ color: hasFail ? '#94a3b8' : '#475569', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
                        {AUTH_CAT_ICON[cat]} {AUTH_CAT_LABEL[cat] ?? cat}
                      </div>
                      {catChecks.map(c => <AuthCheckRow key={c.id} c={c} />)}
                    </div>
                  );
                })}
              </>
            )}

            {display.status === 'failed' && (
              <div style={{ color: '#ff6b35', fontSize: 13 }}>✗ Audit échoué — {display.summary}</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function OsintTab({ osintDomain, setOsintDomain, handleOsint, osintLoading, activeOsint, osintScans, setActiveOsint }: {
  osintDomain: string; setOsintDomain: (v: string) => void;
  handleOsint: (e: React.FormEvent) => void; osintLoading: boolean;
  activeOsint: OsintScan | null; osintScans: OsintScan[];
  setActiveOsint: (s: OsintScan | null) => void;
}) {
  const SOURCE_ICON: Record<string, string> = {
    dns_mx: '📬', dns_spf: '🛡️', dns_dmarc: '📋', dns_caa: '🔒', subdomain: '🌐',
    header_server: '🖥️', header_powered: '⚙️', email_web: '📧', email_dmarc_rua: '📧',
    email_dmarc_ruf: '📧', email_security_txt: '📧', robots: '🤖', security_txt: '🔐',
  };

  const display = activeOsint ?? osintScans[0] ?? null;

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto' }}>
      <div style={{ display: 'grid', gridTemplateColumns: display ? '360px 1fr' : '1fr', gap: 24 }}>
        {/* Left: form + history */}
        <div>
          <h2 style={{ color: '#e2e8f0', fontSize: 16, fontWeight: 700, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: '#60a5fa' }}>🔎</span> OSINT — Reconnaissance passive
          </h2>
          <p style={{ color: '#475569', fontSize: 12, marginBottom: 18 }}>
            Découverte d'emails exposés, sous-domaines, enregistrements DNS, fichiers robots.txt et security.txt — sans authentification.
          </p>

          <form onSubmit={handleOsint} style={{ marginBottom: 24 }}>
            <label style={{ display: 'block', color: '#94a3b8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
              Domaine cible *
            </label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input value={osintDomain} onChange={e => setOsintDomain(e.target.value)} required
                placeholder="exemple.com ou https://exemple.com"
                style={{ flex: 1, background: '#0a0e1a', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 14px', color: '#e2e8f0', fontSize: 14, fontFamily: 'inherit', outline: 'none' }} />
              <button type="submit" disabled={osintLoading}
                style={{ padding: '10px 18px', background: osintLoading ? '#1e293b' : '#1d4ed8', color: '#fff', border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 700, cursor: osintLoading ? 'not-allowed' : 'pointer', whiteSpace: 'nowrap' }}>
                {osintLoading ? '⟳' : '🔎 Scanner'}
              </button>
            </div>
          </form>

          {/* History list */}
          {osintScans.length > 0 && (
            <div>
              <div style={{ color: '#475569', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>Historique</div>
              {osintScans.map(s => (
                <div key={s.id} onClick={() => setActiveOsint(s)}
                  style={{ background: '#0d1424', border: `1px solid ${display?.id === s.id ? '#1d4ed8' : '#1e293b'}`, borderRadius: 8, padding: '10px 14px', marginBottom: 6, cursor: 'pointer' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ color: '#e2e8f0', fontWeight: 600, fontSize: 13 }}>{s.domain}</span>
                    <span style={{ color: s.status === 'completed' ? '#60d394' : s.status === 'running' ? '#60a5fa' : '#ff3b5c', fontSize: 11, fontWeight: 700 }}>
                      {s.status === 'running' ? '⟳ En cours' : s.status === 'completed' ? `✓ ${s.emails_found.length} email(s)` : '✗ Erreur'}
                    </span>
                  </div>
                  {s.status === 'completed' && (
                    <div style={{ color: '#475569', fontSize: 11, marginTop: 3 }}>
                      {s.subdomains.length} sous-domaine(s) · {s.sources.length} source(s)
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: results */}
        {display && (
          <div style={{ background: '#0d1424', border: '1px solid #1e293b', borderRadius: 12, padding: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <div>
                <div style={{ color: '#e2e8f0', fontWeight: 800, fontSize: 17 }}>{display.domain}</div>
                <div style={{ color: '#475569', fontSize: 12 }}>
                  {display.status === 'running' ? '⟳ Analyse en cours...' : display.status === 'completed' ? `Terminé — ${new Date(display.completed_at!).toLocaleString('fr-FR')}` : '✗ Échec'}
                </div>
              </div>
              {display.status === 'running' && (
                <div style={{ color: '#60a5fa', fontSize: 12 }}>⟳ Scanning...</div>
              )}
            </div>

            {display.status === 'completed' && (
              <>
                {/* Stats row */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 20 }}>
                  {[
                    { label: 'Emails exposés', val: display.emails_found.length, color: display.emails_found.length > 0 ? '#ff6b35' : '#60d394', icon: '📧' },
                    { label: 'Sous-domaines', val: display.subdomains.length, color: '#60a5fa', icon: '🌐' },
                    { label: 'Sources OSINT', val: display.sources.length, color: '#94a3b8', icon: '🔎' },
                  ].map(s => (
                    <div key={s.label} style={{ background: '#0a0e1a', borderRadius: 8, padding: '12px 14px', textAlign: 'center', border: '1px solid #1e293b' }}>
                      <div style={{ fontSize: 20, marginBottom: 4 }}>{s.icon}</div>
                      <div style={{ color: s.color, fontSize: 22, fontWeight: 800 }}>{s.val}</div>
                      <div style={{ color: '#475569', fontSize: 11 }}>{s.label}</div>
                    </div>
                  ))}
                </div>

                {/* Emails found */}
                {display.emails_found.length > 0 && (
                  <div style={{ marginBottom: 20 }}>
                    <div style={{ color: '#ff6b35', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
                      📧 Emails exposés publiquement ({display.emails_found.length})
                    </div>
                    <div style={{ background: '#0a0e1a', borderRadius: 8, padding: '12px 16px', border: '1px solid #ff6b3530' }}>
                      {display.emails_found.map((e, i) => (
                        <div key={i} style={{ color: '#fbbf24', fontSize: 13, fontFamily: 'monospace', padding: '4px 0', borderBottom: i < display.emails_found.length - 1 ? '1px solid #1e293b' : 'none' }}>
                          {e}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Subdomains */}
                {display.subdomains.length > 0 && (
                  <div style={{ marginBottom: 20 }}>
                    <div style={{ color: '#60a5fa', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
                      🌐 Sous-domaines actifs ({display.subdomains.length})
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {display.subdomains.map((s, i) => (
                        <span key={i} style={{ background: '#1d4ed820', border: '1px solid #1d4ed840', borderRadius: 6, padding: '4px 10px', fontSize: 12, color: '#60a5fa', fontFamily: 'monospace' }}>
                          {s}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* DNS Records */}
                {Object.keys(display.dns_records).length > 0 && (
                  <div style={{ marginBottom: 20 }}>
                    <div style={{ color: '#94a3b8', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
                      🔗 Enregistrements DNS
                    </div>
                    <div style={{ background: '#0a0e1a', borderRadius: 8, padding: '12px 16px', border: '1px solid #1e293b' }}>
                      {Object.entries(display.dns_records).map(([k, v]) => (
                        <div key={k} style={{ display: 'flex', gap: 12, padding: '4px 0', borderBottom: '1px solid #1e293b10', fontSize: 12 }}>
                          <span style={{ color: '#475569', width: 40, textTransform: 'uppercase', fontWeight: 700 }}>{k}</span>
                          <span style={{ color: '#94a3b8', fontFamily: 'monospace', flex: 1 }}>
                            {Array.isArray(v) ? v.join(', ') : JSON.stringify(v)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* All sources */}
                <div>
                  <div style={{ color: '#64748b', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
                    🔎 Toutes les sources ({display.sources.length})
                  </div>
                  <div style={{ maxHeight: 300, overflowY: 'auto' }}>
                    {display.sources.map((s, i) => (
                      <div key={i} style={{ display: 'flex', gap: 10, padding: '7px 10px', marginBottom: 4, background: '#0a0e1a', borderRadius: 6, fontSize: 12, borderLeft: `3px solid ${s.type.includes('email') ? '#ff6b35' : s.type === 'subdomain' ? '#60a5fa' : '#1e293b'}` }}>
                        <span style={{ fontSize: 14, width: 20 }}>{SOURCE_ICON[s.type] ?? '•'}</span>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ color: '#e2e8f0', fontWeight: 600 }}>{s.value}</div>
                          <div style={{ color: '#475569', fontSize: 11, marginTop: 1 }}>{s.detail}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default function App() {
  const mandateToken = new URLSearchParams(window.location.search).get('mandate');
  if (mandateToken) return <ClientConfirmPage token={mandateToken} />;
  return <AppInner />;
}
