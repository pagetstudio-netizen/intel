#!/bin/bash
# ─────────────────────────────────────────────────────────────
# INTEL — Script de déploiement automatique Plesk
# Plesk l'exécute après chaque git push → git pull
# ─────────────────────────────────────────────────────────────

set -e  # Arrêter si une commande échoue

echo "🚀 [INTEL] Déploiement démarré — $(date)"

# ── 1. Dépendances ────────────────────────────────────────────
echo "📦 Installation des dépendances..."
cd backend && npm install --production=false && cd ..
cd web-ui  && npm install && cd ..

# ── 2. Build frontend ─────────────────────────────────────────
echo "🏗️  Build du frontend React..."
cd web-ui && npx vite build && cd ..
echo "✅ Frontend buildé → web-ui/dist/"

# ── 3. Redémarrer le backend ──────────────────────────────────
echo "🔄 Redémarrage du backend..."

if command -v pm2 &> /dev/null; then
  # PM2 disponible
  if pm2 list | grep -q "intel-api"; then
    pm2 restart intel-api
    echo "✅ PM2 intel-api redémarré"
  else
    mkdir -p logs
    pm2 start ecosystem.config.js
    pm2 save
    echo "✅ PM2 intel-api démarré (premier lancement)"
  fi
else
  echo "⚠️  PM2 non trouvé — installer avec : npm install -g pm2 tsx"
  echo "    Puis relancer : pm2 start ecosystem.config.js && pm2 save"
fi

echo "✅ [INTEL] Déploiement terminé — $(date)"
echo "   Frontend : web-ui/dist/"
echo "   API      : http://localhost:3000/api/health"
