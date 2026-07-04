#!/bin/bash
# ─────────────────────────────────────────────────────────────
# INTEL — Script de déploiement Plesk
# Exécuté automatiquement après chaque git pull
# NE PAS utiliser PM2 ici (chroot Plesk ne le supporte pas)
# Plesk redémarre Node.js automatiquement après ce script
# ─────────────────────────────────────────────────────────────

set -e

echo "🚀 [INTEL] Déploiement démarré — $(date)"

# ── 0. Dépendances racine (server.js nécessite tsx via backend) ──
echo "📦 Installation dépendances racine..."
npm install --production=false

# ── 1. Dépendances backend ────────────────────────────────────
echo "📦 Installation backend..."
cd backend
npm ci
cd ..

# ── 2. Dépendances + Build frontend ──────────────────────────
echo "🏗️  Build frontend React..."
cd web-ui
npm ci
npx vite build
cd ..

# ── 3. Build du moteur Rust (security-core) ──────────────────
# Requis pour les fonctionnalités scan / fuzz / load-test.
# Le binaire n'est PAS versionné dans Git (lié à la glibc du système
# de build) : il doit être recompilé sur CHAQUE serveur cible.
if command -v cargo >/dev/null 2>&1; then
  echo "🦀 Build du moteur Rust (security-core)..."
  cd security-core
  cargo build --release
  cd ..
  chmod +x security-core/target/release/intel
  echo "   → security-core/target/release/intel prêt"
else
  echo "⚠️  [INTEL] cargo introuvable sur ce serveur — le binaire 'intel' n'a pas pu être compilé."
  echo "   → Les fonctionnalités Scan / Fuzz / Load-test échoueront tant que Rust n'est pas installé."
  echo "   → Installez Rust sur le VPS Plesk : curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
fi

echo "✅ [INTEL] Build terminé — $(date)"
echo "   → web-ui/dist/ prêt"
echo "   → Plesk va redémarrer Node.js automatiquement"
