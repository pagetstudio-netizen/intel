/**
 * OSINT — Découverte passive d'informations exposées publiquement
 * Techniques : DNS, headers HTTP, robots.txt, sitemap, meta tags
 * IMPORTANT : uniquement des requêtes passives/publiques, aucune tentative d'authentification
 */
import { Router, Request, Response } from 'express';
import { pool } from '../db';
import dns from 'dns/promises';

const router = Router();

// GET /api/osint
router.get('/', async (_req, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM osint_scans ORDER BY created_at DESC LIMIT 50');
    res.json(rows);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

// POST /api/osint  — lance un scan OSINT passif sur un domaine
router.post('/', async (req: Request, res: Response) => {
  const { domain: rawDomain } = req.body;
  if (!rawDomain) return res.status(400).json({ error: 'Domaine requis' });

  let domain = rawDomain.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase().trim();
  if (!domain) return res.status(400).json({ error: 'Domaine invalide' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO osint_scans (domain, status) VALUES ($1, 'running') RETURNING *`,
      [domain]
    );
    const scan = rows[0];

    // Run async
    runOsintScan(scan.id, domain).catch(console.error);

    res.status(201).json(scan);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/osint/:id
router.get('/:id', async (req, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM osint_scans WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Scan introuvable' });
    res.json(rows[0]);
  } catch { res.status(500).json({ error: 'Database error' }); }
});

async function runOsintScan(id: string, domain: string) {
  const emails: Set<string> = new Set();
  const subdomains: Set<string> = new Set();
  const sources: { type: string; value: string; detail: string }[] = [];
  const dnsRecords: Record<string, any> = {};

  try {
    // ── 1. DNS Records ────────────────────────────────────────────
    try {
      const mx = await dns.resolveMx(domain).catch(() => []);
      if (mx.length) {
        dnsRecords.mx = mx.map(r => r.exchange);
        sources.push({ type: 'dns_mx', value: 'MX Records', detail: `${mx.length} serveur(s) mail trouvé(s)` });
      }
    } catch {}

    try {
      const txt = await dns.resolveTxt(domain).catch(() => []);
      dnsRecords.txt = txt.flat();
      const spf = txt.flat().find(r => r.startsWith('v=spf1'));
      if (spf) sources.push({ type: 'dns_spf', value: 'SPF Record', detail: spf });
      const dmarc = txt.flat().find(r => r.startsWith('v=DMARC1'));
      if (dmarc) {
        sources.push({ type: 'dns_dmarc', value: 'DMARC Record', detail: dmarc });
        const ruaMatch = dmarc.match(/rua=mailto:([^\s;]+)/i);
        if (ruaMatch) { emails.add(ruaMatch[1]); sources.push({ type: 'email_dmarc_rua', value: ruaMatch[1], detail: 'Email DMARC rua (rapports de politique)' }); }
        const rufMatch = dmarc.match(/ruf=mailto:([^\s;]+)/i);
        if (rufMatch) { emails.add(rufMatch[1]); sources.push({ type: 'email_dmarc_ruf', value: rufMatch[1], detail: 'Email DMARC ruf (rapports forensiques)' }); }
      }
    } catch {}

    try {
      const ns = await dns.resolveNs(domain).catch(() => []);
      if (ns.length) dnsRecords.ns = ns;
    } catch {}

    try {
      const caa = await dns.resolveCaa(domain).catch(() => []);
      if (caa.length) { dnsRecords.caa = caa; sources.push({ type: 'dns_caa', value: 'CAA Record', detail: `Autorité de certification : ${caa.map(r => r.value).join(', ')}` }); }
    } catch {}

    try {
      const a = await dns.resolve4(domain).catch(() => []);
      if (a.length) dnsRecords.a = a;
    } catch {}

    // ── 2. Sous-domaines courants (DNS brute-force passif) ────────
    const commonSubdomains = ['www','mail','smtp','imap','pop','api','app','dev','staging',
      'test','admin','dashboard','portal','login','secure','vpn','remote',
      'docs','help','support','status','monitoring','cdn','static','assets',
      'ftp','sftp','git','gitlab','jenkins','sonar','jira','confluence',
      'payment','pay','billing','checkout','shop','store','blog','news'];

    const subResults = await Promise.allSettled(
      commonSubdomains.map(async sub => {
        const full = `${sub}.${domain}`;
        try {
          const addrs = await dns.resolve4(full);
          if (addrs.length) return { sub: full, ip: addrs[0] };
        } catch {}
        return null;
      })
    );
    for (const r of subResults) {
      if (r.status === 'fulfilled' && r.value) {
        subdomains.add(r.value.sub);
        sources.push({ type: 'subdomain', value: r.value.sub, detail: `IP: ${r.value.ip}` });
      }
    }

    // ── 3. Headers HTTP + extraction d'emails ────────────────────
    const urlsToCheck = [`https://${domain}`, `https://www.${domain}`];
    for (const url of urlsToCheck) {
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 8000);
        const resp = await fetch(url, { signal: ctrl.signal, redirect: 'follow', headers: { 'User-Agent': 'INTEL-SecurityScanner/1.0' } });
        clearTimeout(timer);

        // Server header
        const server = resp.headers.get('server');
        if (server) sources.push({ type: 'header_server', value: server, detail: `En-tête Server exposé sur ${url}` });

        const xPowered = resp.headers.get('x-powered-by');
        if (xPowered) sources.push({ type: 'header_powered', value: xPowered, detail: `X-Powered-By exposé sur ${url}` });

        // Parse body for emails (first 100kb only)
        const body = await resp.text().then(t => t.slice(0, 100_000)).catch(() => '');
        const emailRegex = /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;
        const found = body.match(emailRegex) ?? [];
        for (const email of found) {
          if (!email.endsWith('.png') && !email.endsWith('.jpg') && !email.endsWith('.svg')) {
            emails.add(email.toLowerCase());
            if (!sources.find(s => s.value === email.toLowerCase())) {
              sources.push({ type: 'email_web', value: email.toLowerCase(), detail: `Email trouvé sur ${url}` });
            }
          }
        }
      } catch {}
    }

    // ── 4. robots.txt — chemins cachés ───────────────────────────
    try {
      const ctrl = new AbortController();
      setTimeout(() => ctrl.abort(), 5000);
      const resp = await fetch(`https://${domain}/robots.txt`, { signal: ctrl.signal });
      if (resp.ok) {
        const txt = await resp.text();
        const disallowed = txt.split('\n').filter(l => l.toLowerCase().startsWith('disallow:')).map(l => l.replace(/disallow:\s*/i, '').trim()).filter(Boolean);
        if (disallowed.length) {
          sources.push({ type: 'robots', value: `${disallowed.length} chemin(s) dans robots.txt`, detail: disallowed.slice(0, 10).join(', ') + (disallowed.length > 10 ? '…' : '') });
        }
        // Extract emails from robots.txt too
        const emails2 = txt.match(/\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g) ?? [];
        for (const e of emails2) { emails.add(e.toLowerCase()); }
      }
    } catch {}

    // ── 5. security.txt ───────────────────────────────────────────
    for (const path of ['/.well-known/security.txt', '/security.txt']) {
      try {
        const ctrl = new AbortController();
        setTimeout(() => ctrl.abort(), 4000);
        const resp = await fetch(`https://${domain}${path}`, { signal: ctrl.signal });
        if (resp.ok) {
          const txt = await resp.text();
          sources.push({ type: 'security_txt', value: 'security.txt trouvé', detail: txt.slice(0, 300) });
          const emailsInSec = txt.match(/\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g) ?? [];
          for (const e of emailsInSec) { emails.add(e.toLowerCase()); sources.push({ type: 'email_security_txt', value: e.toLowerCase(), detail: 'Email dans security.txt' }); }
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
