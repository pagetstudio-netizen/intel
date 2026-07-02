# INTEL - Pentest & Security Auditing Platform

Suite complète d'outils de test de pénétration et d'audit de sécurité pour **pentest autorisé** sur vos propres applications.

## 🎯 Modules

### 1. Scanner de Vulnérabilités
- ✅ Analyse des dépendances (npm, cargo, python)
- ✅ SAST (Static Application Security Testing)
- ✅ Vérification des configurations sensibles
- ✅ Base de données de CVE

### 2. Proxy HTTP/HTTPS (Style Burp Suite)
- ✅ Interception des requêtes/réponses
- ✅ Modification en temps réel
- ✅ Historique complet
- ✅ SSL/TLS stripping optionnel (autorisé)
- ✅ Replay de requêtes

### 3. Analyseur de Trafic Réseau
- ✅ Capture de paquets (pcap)
- ✅ Analyse des protocoles
- ✅ Détection d'anomalies
- ✅ Export des données

### 4. Fuzzer & Scanner de Routes
- ✅ Découverte d'endpoints
- ✅ Fuzzing paramètres
- ✅ Brute-force intelligent
- ✅ Détection de routes sensibles
- ✅ Wordlists personnalisables

## 🛠 Stack Technique

```
intel/
├── backend/              # Node.js/TypeScript API
├── security-core/        # Rust (performance critique)
├── proxy/                # MITM Proxy (TypeScript)
├── web-ui/               # React/TypeScript Dashboard
├── docker-compose.yml    # Orchestration
├── .env.example          # Config template
└── docs/                 # Documentation
```

## 🚀 Quick Start

### Avec Docker (Recommandé)

```bash
git clone https://github.com/pagetstudio-netizen/intel.git
cd intel
cp .env.example .env
docker-compose build
docker-compose up -d
```

### Accès

- **Dashboard**: http://localhost:3001
- **API**: http://localhost:3000
- **Proxy**: localhost:8080

## 📖 Documentation

- [Setup & Installation](./docs/setup.md)
- [API Reference](./docs/api.md)
- [Déploiement Plesk](./docs/deployment.md)
- [Audit Fintech - Guide Complet](./docs/fintech-audit.md)

## 🔐 Sécurité

⚠️ **IMPORTANT** :
- ✅ À utiliser **UNIQUEMENT sur des systèmes autorisés**
- ✅ Pentest éthique et légal
- ✅ Conformité OWASP Top 10

## 📋 Prérequis

- Node.js 18+
- Rust 1.70+
- Docker & Docker Compose
- PostgreSQL 14+

## 👥 Auteur

**pagetstudio-netizen** - Pentest & Security Auditing Platform
