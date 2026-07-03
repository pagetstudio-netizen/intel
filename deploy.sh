#!/bin/bash
# ─────────────────────────────────────────────────────────────
# INTEL — Script de déploiement Plesk
# Exécuté automatiquement après chaque git pull
# NE PAS utiliser PM2 ici (chroot Plesk ne le supporte pas)
# Plesk redémarre Node.js automatiquement après ce script
# ─────────────────────────────────────────────────────────────

set -e

echo "🚀 [INTEL] Déploiement démarré — $(date)"

# ── 1. Dépendances backend ────────────────────────────────────
echo "📦 Installation backend..."
cd backend
npm install --production=false
cd ..

# ── 2. Dépendances + Build frontend ──────────────────────────
echo "🏗️  Build frontend React..."
cd web-ui
npm install
npx vite build
cd ..

echo "✅ [INTEL] Build terminé — $(date)"
echo "   → web-ui/dist/ prêt"
echo "   → Plesk va redémarrer Node.js automatiquement"
