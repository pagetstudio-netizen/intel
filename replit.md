# INTEL — Pentest & Security Auditing Platform

Plateforme d'audit de sécurité pour les tests de pénétration autorisés. Conçue pour les audits fintech et la conformité OWASP Top 10.

## Stack

| Couche | Technologie |
|---|---|
| Frontend | React + TypeScript + Vite (port 5000) |
| Backend | Node.js + TypeScript + Express (port 3000) |
| Moteur sécurité | Rust (`security-core/`) — compilé en binaire |
| Base de données | PostgreSQL (`DATABASE_URL`) |

## Modules

- **Phishing** — analyse anti-phishing (DMARC, SPF, DKIM, headers HTTP)
- **Fraude API** — audit de conformité fintech
- **Auth Audit** — analyse des endpoints d'authentification
- **Load Test** — tests de charge / crash serveur
- **Scanner** — scan de vulnérabilités (SAST, CVE, dépendances)
- **Fuzzer** — découverte d'endpoints
- **OSINT** — collecte d'informations publiques
- **Mandats** — gestion des mandats de test (avec signature client)

## Lancer le projet (développement)

```bash
# Backend (port 3000)
cd backend && npm install && npm run dev

# Frontend (port 5000)
cd web-ui && npm install && npm run dev

# Build Rust
cd security-core && cargo build --release
```

## Déploiement Plesk

1. Push sur GitHub
2. Dans Plesk : **Pull** → **Deploy Now** → **Restart**
3. Le script `deploy.sh` s'exécute automatiquement :
   - `npm install` backend + frontend
   - `npm run build` frontend (génère `web-ui/dist/`)
   - `cargo build --release` (si Rust installé sur le serveur)

### Première installation sur Plesk

Appliquer le schéma PostgreSQL **une seule fois** :
```bash
psql "$DATABASE_URL" -f deploy/schema.sql
```

### Variables d'environnement requises (Plesk > Node.js > Variables)

| Variable | Obligatoire | Description |
|---|---|---|
| `DATABASE_URL` | ✅ | Connection string PostgreSQL |
| `JWT_SECRET` | ✅ | Clé secrète JWT (générer avec `openssl rand -hex 32`) |
| `NODE_ENV` | ✅ | Mettre `production` sur Plesk |
| `PORT` | ✅ | Port Node.js (ex: `3000`) |
| `RESEND_API_KEY` | ⬜ | Pour l'envoi d'emails de rapports |
| `EMAIL_FROM` | ⬜ | Adresse d'expédition des emails |

### Vérifier l'état de santé

```
GET /api/health
```
Retourne l'état de la DB, du binaire Rust, et du build frontend.

## Structure du projet

```
intel/
├── backend/          # API Node.js/TypeScript
│   └── src/
│       ├── index.ts  # Point d'entrée (port 3000)
│       ├── db.ts     # Pool PostgreSQL
│       └── routes/   # phishing, fuzz, scans, osint, mandates...
├── web-ui/           # Frontend React/Vite
│   ├── src/
│   └── dist/         # Build de production (généré par npm run build)
├── security-core/    # Moteur Rust
│   └── target/release/intel  # Binaire compilé (non versionné dans git)
├── deploy/
│   └── schema.sql    # Schéma PostgreSQL à appliquer une seule fois
└── deploy.sh         # Script de déploiement Plesk
```

## Notes importantes

- Le binaire Rust (`target/release/intel`) est exclu de git — il doit être recompilé sur chaque serveur cible
- `web-ui/dist/` doit être dans `.gitignore` ou regénéré à chaque déploiement via `deploy.sh`
- N'utiliser que sur des systèmes pour lesquels vous avez une autorisation écrite

## User preferences

- Langue de communication : Français
