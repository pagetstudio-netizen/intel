/**
 * OSINT — Reconnaissance passive enrichie
 * DNS complet (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV)
 * Zone transfer (AXFR), Certificate Transparency (crt.sh),
 * détection cloud, risques de subdomain takeover
 */
import { Router, Request, Response } from 'express';
import { pool } from '../db';
import dns from 'dns/promises';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const router = Router();

router.get('/', async (_req, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM osint_scans ORDER BY created_at DESC LIMIT 50');
    res.json(rows);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

router.post('/', async (req: Request, res: Response) => {
  const { domain: rawDomain } = req.body;
  if (!rawDomain) return res.status(400).json({ error: 'Domaine requis' });

  const domain = rawDomain.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase().trim();
  if (!domain || domain.length < 3) return res.status(400).json({ error: 'Domaine invalide' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO osint_scans (domain, status) VALUES ($1, 'running') RETURNING *`,
      [domain]
    );
    const scan = rows[0];
    runOsintScan(scan.id, domain).catch(console.error);
    res.status(201).json(scan);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/:id', async (req, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM osint_scans WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Scan introuvable' });
    res.json(rows[0]);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

// ── Cloud provider detection from CNAME / IP ─────────────────────────────────
const CLOUD_CNAME_MAP: [RegExp, string][] = [
  [/\.cloudfront\.net$/i, 'AWS CloudFront'],
  [/\.amazonaws\.com$/i, 'AWS S3 / EC2'],
  [/\.azurewebsites\.net$/i, 'Azure App Service'],
  [/\.azure\.com$/i, 'Microsoft Azure'],
  [/\.cloudflare\.net$/i, 'Cloudflare'],
  [/\.pages\.dev$/i, 'Cloudflare Pages'],
  [/\.netlify\.app$/i, 'Netlify'],
  [/\.vercel\.app$/i, 'Vercel'],
  [/\.firebaseapp\.com$/i, 'Firebase (Google)'],
  [/\.web\.app$/i, 'Firebase Hosting'],
  [/\.github\.io$/i, 'GitHub Pages'],
  [/\.gitlab\.io$/i, 'GitLab Pages'],
  [/\.herokuapp\.com$/i, 'Heroku'],
  [/\.render\.com$/i, 'Render'],
  [/\.fly\.dev$/i, 'Fly.io'],
  [/\.railway\.app$/i, 'Railway'],
  [/\.squarespace\.com$/i, 'Squarespace'],
  [/\.wpengine\.com$/i, 'WP Engine'],
  [/\.shopify\.com$/i, 'Shopify'],
  [/\.fastly\.net$/i, 'Fastly CDN'],
  [/\.akamaiedge\.net$/i, 'Akamai CDN'],
  [/\.edgesuite\.net$/i, 'Akamai CDN'],
];

// Cloudflare IP ranges (simplified)
const CF_RANGES = ['104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.', '172.64.', '172.65.', '172.66.', '172.67.', '162.158.', '198.41.'];

function detectCloudFromIp(ip: string): string | null {
  if (CF_RANGES.some(r => ip.startsWith(r))) return 'Cloudflare (proxy)';
  return null;
}

function detectCloudFromCname(cname: string): string | null {
  for (const [pattern, provider] of CLOUD_CNAME_MAP) {
    if (pattern.test(cname)) return provider;
  }
  return null;
}

// ── Subdomain takeover patterns ───────────────────────────────────────────────
const TAKEOVER_SIGNATURES: { cname: RegExp; service: string; fingerprint?: string }[] = [
  { cname: /\.github\.io$/i, service: 'GitHub Pages', fingerprint: "There isn't a GitHub Pages site here" },
  { cname: /\.s3\.amazonaws\.com$/i, service: 'AWS S3', fingerprint: 'NoSuchBucket' },
  { cname: /\.azurewebsites\.net$/i, service: 'Azure App Service', fingerprint: "doesn't exist" },
  { cname: /\.netlify\.app$/i, service: 'Netlify', fingerprint: 'Not Found' },
  { cname: /\.vercel\.app$/i, service: 'Vercel', fingerprint: 'DEPLOYMENT_NOT_FOUND' },
  { cname: /\.herokuapp\.com$/i, service: 'Heroku', fingerprint: 'No such app' },
  { cname: /\.firebaseapp\.com$/i, service: 'Firebase', fingerprint: 'Site Not Found' },
  { cname: /\.shopify\.com$/i, service: 'Shopify', fingerprint: 'Sorry, this shop is currently unavailable' },
  { cname: /\.squarespace\.com$/i, service: 'Squarespace', fingerprint: 'No Such Account' },
];

async function checkTakeoverRisk(subdomain: string, cname: string): Promise<{ risk: boolean; service: string; reason: string } | null> {
  for (const sig of TAKEOVER_SIGNATURES) {
    if (sig.cname.test(cname)) {
      // Try to fetch the subdomain and look for takeover fingerprint
      try {
        const ctrl = new AbortController();
        setTimeout(() => ctrl.abort(), 5000);
        const resp = await fetch(`https://${subdomain}`, { signal: ctrl.signal });
        const body = await resp.text().catch(() => '');
        if (sig.fingerprint && body.includes(sig.fingerprint)) {
          return { risk: true, service: sig.service, reason: `CNAME → ${cname} (${sig.service} non revendiqué — subdomain takeover possible)` };
        }
      } catch {}
      return { risk: false, service: sig.service, reason: `CNAME → ${cname} (${sig.service})` };
    }
  }
  return null;
}

// ── crt.sh Certificate Transparency ──────────────────────────────────────────
async function fetchCrtSh(domain: string): Promise<string[]> {
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 10000);
    const resp = await fetch(
      `https://crt.sh/?q=%.${domain}&output=json`,
      { signal: ctrl.signal, headers: { 'Accept': 'application/json' } }
    );
    if (!resp.ok) return [];
    const data = (await resp.json()) as { name_value: string }[];
    const names = new Set<string>();
    for (const entry of data) {
      for (const name of entry.name_value.split('\n')) {
        const clean = name.trim().toLowerCase().replace(/^\*\./, '');
        if (clean.endsWith(`.${domain}`) || clean === domain) names.add(clean);
      }
    }
    return Array.from(names).sort();
  } catch { return []; }
}

// ── Zone Transfer (AXFR) ──────────────────────────────────────────────────────
async function tryZoneTransfer(domain: string, nameservers: string[]): Promise<{ possible: boolean; message: string; records?: string[] }> {
  for (const ns of nameservers.slice(0, 3)) {
    try {
      const { stdout } = await execAsync(`dig axfr @${ns} ${domain} 2>&1`, { timeout: 8000 });
      if (stdout.includes('Transfer failed') || stdout.includes('REFUSED') || stdout.includes('NOTAUTH')) {
        return { possible: false, message: `Zone transfer refusé par ${ns} (correctement configuré)` };
      }
      if (stdout.includes('XFR size') || (stdout.split('\n').filter(l => l.trim() && !l.startsWith(';')).length > 5)) {
        const records = stdout.split('\n').filter(l => l.trim() && !l.startsWith(';') && !l.startsWith('//'));
        return { possible: true, message: `🚨 Zone transfer autorisé sur ${ns} — tous les enregistrements DNS exposés !`, records: records.slice(0, 50) };
      }
    } catch {
      // dig not available or timeout
    }
  }
  return { possible: false, message: 'Zone transfer non autorisé (AXFR refusé ou DNS not reachable)' };
}

// ── Main OSINT scan ───────────────────────────────────────────────────────────
async function runOsintScan(id: string, domain: string) {
  const emails: Set<string> = new Set();
  const subdomains: Set<string> = new Set();
  const sources: { type: string; value: string; detail: string }[] = [];
  const dnsRecords: Record<string, any> = {};

  try {
    // ── 1. A records + cloud detection ───────────────────────────────────────
    const aRecords = await dns.resolve4(domain).catch(() => [] as string[]);
    if (aRecords.length) {
      dnsRecords.a = aRecords;
      const cloudFromIp = detectCloudFromIp(aRecords[0]);
      if (cloudFromIp) {
        dnsRecords.cloud_providers = [...(dnsRecords.cloud_providers ?? []), cloudFromIp];
        sources.push({ type: 'cloud', value: cloudFromIp, detail: `Détecté via IP ${aRecords[0]}` });
      }
    }

    // ── 2. AAAA records (IPv6) ────────────────────────────────────────────────
    const aaaaRecords = await dns.resolve6(domain).catch(() => [] as string[]);
    if (aaaaRecords.length) dnsRecords.aaaa = aaaaRecords;

    // ── 3. CNAME ─────────────────────────────────────────────────────────────
    const cnameRecords = await dns.resolveCname(domain).catch(() => [] as string[]);
    if (cnameRecords.length) {
      dnsRecords.cname = cnameRecords;
      for (const cname of cnameRecords) {
        const cloud = detectCloudFromCname(cname);
        if (cloud) {
          dnsRecords.cloud_providers = [...new Set([...(dnsRecords.cloud_providers ?? []), cloud])];
          sources.push({ type: 'cloud', value: cloud, detail: `Détecté via CNAME → ${cname}` });
        }
      }
    }

    // ── 4. NS records ─────────────────────────────────────────────────────────
    const nsRecords = await dns.resolveNs(domain).catch(() => [] as string[]);
    if (nsRecords.length) {
      dnsRecords.ns = nsRecords;
      const nsCloud = detectCloudFromCname(nsRecords[0] ?? '');
      if (nsCloud) sources.push({ type: 'dns_ns_cloud', value: nsCloud, detail: `DNS géré par ${nsCloud}` });
    }

    // ── 5. MX records ────────────────────────────────────────────────────────
    const mx = await dns.resolveMx(domain).catch(() => []);
    if (mx.length) {
      dnsRecords.mx = mx.sort((a, b) => a.priority - b.priority).map(r => `${r.priority} ${r.exchange}`);
      sources.push({ type: 'dns_mx', value: 'MX Records', detail: `${mx.length} serveur(s) mail: ${mx.map(r => r.exchange).join(', ')}` });

      // Email provider detection from MX
      const mxStr = mx.map(r => r.exchange).join(' ').toLowerCase();
      if (mxStr.includes('google') || mxStr.includes('gmail')) sources.push({ type: 'mail_provider', value: 'Google Workspace', detail: 'Emails hébergés sur Google' });
      else if (mxStr.includes('outlook') || mxStr.includes('microsoft')) sources.push({ type: 'mail_provider', value: 'Microsoft 365', detail: 'Emails hébergés sur Microsoft' });
      else if (mxStr.includes('amazon') || mxStr.includes('amazonaws')) sources.push({ type: 'mail_provider', value: 'Amazon SES', detail: 'Emails via AWS SES' });
      else if (mxStr.includes('mailgun')) sources.push({ type: 'mail_provider', value: 'Mailgun', detail: 'Emails via Mailgun' });
      else if (mxStr.includes('sendgrid')) sources.push({ type: 'mail_provider', value: 'SendGrid', detail: 'Emails via SendGrid' });
      else if (mxStr.includes('protonmail')) sources.push({ type: 'mail_provider', value: 'ProtonMail', detail: 'Emails sécurisés ProtonMail' });
    }

    // ── 6. TXT records (SPF, DMARC, DKIM, etc.) ──────────────────────────────
    const txtAll = await dns.resolveTxt(domain).catch(() => [] as string[][]);
    dnsRecords.txt = txtAll.flat();
    const spf = txtAll.flat().find(r => r.startsWith('v=spf1'));
    if (spf) {
      sources.push({ type: 'dns_spf', value: 'SPF Record', detail: spf });
      // Parse SPF includes
      const includes = [...spf.matchAll(/include:([^\s]+)/g)].map(m => m[1]);
      if (includes.length) sources.push({ type: 'spf_includes', value: 'SPF includes', detail: `Services autorisés à envoyer des emails: ${includes.join(', ')}` });
    }

    const dmarcTxt = await dns.resolveTxt(`_dmarc.${domain}`).catch(() => [] as string[][]);
    const dmarc = dmarcTxt.flat().find(r => r.startsWith('v=DMARC1'));
    if (dmarc) {
      sources.push({ type: 'dns_dmarc', value: 'DMARC Record', detail: dmarc });
      const ruaMatch = dmarc.match(/rua=mailto:([^\s;]+)/i);
      if (ruaMatch) { emails.add(ruaMatch[1]); sources.push({ type: 'email_dmarc_rua', value: ruaMatch[1], detail: 'Email DMARC rua (rapports de politique)' }); }
      const rufMatch = dmarc.match(/ruf=mailto:([^\s;]+)/i);
      if (rufMatch) { emails.add(rufMatch[1]); sources.push({ type: 'email_dmarc_ruf', value: rufMatch[1], detail: 'Email DMARC ruf (rapports forensiques)' }); }
    }

    // Other TXT: Google site verification, etc.
    for (const r of txtAll.flat()) {
      if (r.startsWith('google-site-verification=')) sources.push({ type: 'google_verify', value: 'Google Site Verification', detail: 'Site vérifié Google Search Console' });
      if (r.startsWith('MS=')) sources.push({ type: 'ms_verify', value: 'Microsoft Domain Verification', detail: 'Domaine vérifié Microsoft 365' });
      if (r.startsWith('docusign=')) sources.push({ type: 'docusign', value: 'DocuSign', detail: 'Service DocuSign utilisé' });
      if (r.startsWith('atlassian-domain-verification=')) sources.push({ type: 'atlassian', value: 'Atlassian (Jira/Confluence)', detail: 'Services Atlassian utilisés' });
      if (r.startsWith('stripe-verification=')) sources.push({ type: 'stripe', value: 'Stripe', detail: 'Stripe configuré sur ce domaine' });
    }

    // ── 7. SOA record (admin email exposé) ───────────────────────────────────
    try {
      const soa = await dns.resolveSoa(domain);
      dnsRecords.soa = { nsname: soa.nsname, hostmaster: soa.hostmaster.replace('.', '@', ), serial: soa.serial };
      // SOA hostmaster is often an email (dots replaced with @)
      const adminEmail = soa.hostmaster.replace(/\.$/, '').replace('.', '@');
      if (adminEmail.includes('@')) {
        emails.add(adminEmail.toLowerCase());
        sources.push({ type: 'email_soa', value: adminEmail.toLowerCase(), detail: 'Email administrateur DNS (enregistrement SOA)' });
      }
      sources.push({ type: 'dns_soa', value: `SOA: ${soa.nsname}`, detail: `Serveur DNS primaire: ${soa.nsname} · Serial: ${soa.serial}` });
    } catch {}

    // ── 8. CAA records ────────────────────────────────────────────────────────
    const caa = await dns.resolveCaa(domain).catch(() => []);
    if (caa.length) {
      dnsRecords.caa = caa.map(r => `${r.critical} ${r.issue ?? r.issuewild ?? ''}`);
      sources.push({ type: 'dns_caa', value: 'CAA Record', detail: `CA(s) autorisée(s): ${caa.map(r => r.issue ?? r.issuewild ?? r.iodef ?? '').join(', ')}` });
    } else {
      sources.push({ type: 'dns_caa_missing', value: '⚠️ Pas de CAA', detail: 'Toute CA peut émettre un certificat SSL pour ce domaine — risque de faux certificat' });
    }

    // ── 9. Zone transfer attempt (AXFR) ──────────────────────────────────────
    if (nsRecords.length) {
      const zt = await tryZoneTransfer(domain, nsRecords);
      dnsRecords.zone_transfer = zt;
      if (zt.possible) {
        sources.push({ type: 'zone_transfer', value: '🚨 ZONE TRANSFER POSSIBLE', detail: zt.message });
      } else {
        sources.push({ type: 'zone_transfer_blocked', value: 'Zone transfer bloqué', detail: zt.message });
      }
    }

    // ── 10. DKIM selector discovery ──────────────────────────────────────────
    const dkimSelectors = ['default', 'google', 'mail', 'smtp', 'k1', 'dkim', 'selector1', 'selector2', 'mandrill', 'mailjet', 'sendgrid', 'postmaster', 'email'];
    const dkimFound: string[] = [];
    for (const sel of dkimSelectors) {
      const dkimTxt = await dns.resolveTxt(`${sel}._domainkey.${domain}`).catch(() => null);
      if (dkimTxt) {
        dkimFound.push(sel);
        const val = dkimTxt.flat().join('');
        sources.push({ type: 'dkim_selector', value: `DKIM: ${sel}._domainkey`, detail: val.substring(0, 100) });
      }
    }
    if (dkimFound.length) dnsRecords.dkim_selectors = dkimFound;

    // ── 11. Subdomain enumeration (DNS brute-force) ───────────────────────────
    const commonSubdomains = [
      'www', 'mail', 'smtp', 'imap', 'pop', 'api', 'app', 'dev', 'staging',
      'test', 'admin', 'dashboard', 'portal', 'login', 'secure', 'vpn', 'remote',
      'docs', 'help', 'support', 'status', 'monitoring', 'cdn', 'static', 'assets',
      'ftp', 'sftp', 'git', 'gitlab', 'jenkins', 'sonar', 'jira', 'confluence',
      'payment', 'pay', 'billing', 'checkout', 'shop', 'store', 'blog', 'news',
      'api2', 'v2', 'v1', 'beta', 'alpha', 'preprod', 'prod', 'old', 'backup',
      'mx', 'ns1', 'ns2', 'webmail', 'mail2', 'exchange', 'autodiscover',
    ];

    const subResults = await Promise.allSettled(
      commonSubdomains.map(async sub => {
        const full = `${sub}.${domain}`;
        const addrs = await dns.resolve4(full).catch(() => [] as string[]);
        if (!addrs.length) return null;
        const cname = await dns.resolveCname(full).catch(() => [] as string[]);
        return { sub: full, ip: addrs[0], cname: cname[0] ?? null };
      })
    );

    const takeoverRisks: { subdomain: string; cname: string; service: string; risk: boolean; reason: string }[] = [];

    for (const r of subResults) {
      if (r.status !== 'fulfilled' || !r.value) continue;
      const { sub, ip, cname: subCname } = r.value;
      subdomains.add(sub);
      const cloudIp = detectCloudFromIp(ip);
      const cloudCname = subCname ? detectCloudFromCname(subCname) : null;
      const cloud = cloudCname ?? cloudIp;
      sources.push({
        type: 'subdomain',
        value: sub,
        detail: `IP: ${ip}${subCname ? ` · CNAME: ${subCname}` : ''}${cloud ? ` · ${cloud}` : ''}`,
      });

      // Check takeover risk
      if (subCname) {
        const takeover = await checkTakeoverRisk(sub, subCname);
        if (takeover) {
          takeoverRisks.push({ subdomain: sub, cname: subCname, ...takeover });
          if (takeover.risk) {
            sources.push({ type: 'takeover_risk', value: `⚠️ Takeover: ${sub}`, detail: takeover.reason });
          }
        }
      }
    }
    if (takeoverRisks.length) dnsRecords.takeover_risks = takeoverRisks;

    // ── 12. Certificate Transparency (crt.sh) ────────────────────────────────
    const crtNames = await fetchCrtSh(domain);
    if (crtNames.length) {
      dnsRecords.crt_subdomains = crtNames;
      for (const name of crtNames) {
        if (name !== domain && !subdomains.has(name)) subdomains.add(name);
      }
      sources.push({ type: 'crt_sh', value: `${crtNames.length} sous-domaine(s) via crt.sh`, detail: `Certificate Transparency — historique SSL: ${crtNames.slice(0, 5).join(', ')}${crtNames.length > 5 ? `… +${crtNames.length - 5}` : ''}` });
    }

    // ── 13. HTTP headers + email extraction ──────────────────────────────────
    for (const url of [`https://${domain}`, `https://www.${domain}`]) {
      try {
        const ctrl = new AbortController();
        setTimeout(() => ctrl.abort(), 8000);
        const resp = await fetch(url, { signal: ctrl.signal, redirect: 'follow', headers: { 'User-Agent': 'INTEL-SecurityScanner/1.0' } });

        const server = resp.headers.get('server');
        if (server) sources.push({ type: 'header_server', value: server, detail: `En-tête Server: ${server} exposé sur ${url}` });
        const xPowered = resp.headers.get('x-powered-by');
        if (xPowered) sources.push({ type: 'header_powered', value: xPowered, detail: `X-Powered-By: ${xPowered} exposé sur ${url}` });
        const via = resp.headers.get('via');
        if (via) sources.push({ type: 'header_via', value: via, detail: `En-tête Via (proxy/CDN): ${via}` });
        const cf = resp.headers.get('cf-ray');
        if (cf && !dnsRecords.cloud_providers?.includes('Cloudflare (proxy)')) {
          dnsRecords.cloud_providers = [...new Set([...(dnsRecords.cloud_providers ?? []), 'Cloudflare (proxy)'])];
          sources.push({ type: 'cloud', value: 'Cloudflare (proxy)', detail: 'Détecté via header CF-Ray' });
        }

        const body = await resp.text().then(t => t.slice(0, 100_000)).catch(() => '');
        const emailRegex = /\b[a-zA-Z0-9._%+\-]+@(?!.*\.(png|jpg|svg|gif|webp|css|js))[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;
        for (const email of body.match(emailRegex) ?? []) {
          const e = email.toLowerCase();
          if (!emails.has(e)) { emails.add(e); sources.push({ type: 'email_web', value: e, detail: `Email trouvé dans le HTML de ${url}` }); }
        }
        break;
      } catch {}
    }

    // ── 14. robots.txt ────────────────────────────────────────────────────────
    try {
      const ctrl = new AbortController();
      setTimeout(() => ctrl.abort(), 5000);
      const resp = await fetch(`https://${domain}/robots.txt`, { signal: ctrl.signal });
      if (resp.ok) {
        const txt = await resp.text();
        const disallowed = txt.split('\n').filter(l => l.toLowerCase().startsWith('disallow:')).map(l => l.replace(/disallow:\s*/i, '').trim()).filter(Boolean);
        if (disallowed.length) sources.push({ type: 'robots', value: `${disallowed.length} chemin(s) dans robots.txt`, detail: disallowed.slice(0, 15).join(', ') + (disallowed.length > 15 ? '…' : '') });
        for (const e of txt.match(/\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g) ?? []) emails.add(e.toLowerCase());
      }
    } catch {}

    // ── 15. security.txt ──────────────────────────────────────────────────────
    for (const path of ['/.well-known/security.txt', '/security.txt']) {
      try {
        const ctrl = new AbortController();
        setTimeout(() => ctrl.abort(), 4000);
        const resp = await fetch(`https://${domain}${path}`, { signal: ctrl.signal });
        if (resp.ok) {
          const txt = await resp.text();
          sources.push({ type: 'security_txt', value: 'security.txt trouvé ✅', detail: txt.slice(0, 300) });
          for (const e of txt.match(/\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g) ?? []) {
            emails.add(e.toLowerCase());
            sources.push({ type: 'email_security_txt', value: e.toLowerCase(), detail: 'Email de contact sécurité (security.txt)' });
          }
          break;
        }
      } catch {}
    }

    await pool.query(
      `UPDATE osint_scans SET status='completed', emails_found=$1, sources=$2, subdomains=$3, dns_records=$4, completed_at=NOW() WHERE id=$5`,
      [Array.from(emails), JSON.stringify(sources), Array.from(subdomains), JSON.stringify(dnsRecords), id]
    );

  } catch (err) {
    console.error('OSINT scan error:', err);
    await pool.query("UPDATE osint_scans SET status='failed' WHERE id=$1", [id]);
  }
}

export default router;
