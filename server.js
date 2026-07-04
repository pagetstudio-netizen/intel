/**
 * INTEL Security Platform — Application Startup File (racine du projet)
 * Plesk > Node.js > Application Startup File = server.js
 * Application Root doit être la racine du projet (httpdocs/)
 *
 * Ce fichier :
 *  1. Vérifie si web-ui/dist est absent ou plus vieux que web-ui/src
 *  2. Reconstruit le frontend si nécessaire (npm install + vite build)
 *  3. Lance le backend (backend/src/index.ts via tsx)
 */

'use strict';

process.env.NODE_ENV = process.env.NODE_ENV || 'production';

const path    = require('path');
const fs      = require('fs');
const { execSync } = require('child_process');

const ROOT     = path.resolve(__dirname);
const DIST     = path.join(ROOT, 'web-ui', 'dist', 'index.html');
const SRC_DIR  = path.join(ROOT, 'web-ui', 'src');

process.chdir(ROOT);

// ── Vérifie si un répertoire contient un fichier plus récent qu'une date ──────
function newerThan(dir, since) {
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (newerThan(full, since)) return true;
      } else {
        if (fs.statSync(full).mtimeMs > since) return true;
      }
    }
  } catch { /* ignore */ }
  return false;
}

// ── Décide s'il faut rebuilder ─────────────────────────────────────────────────
function needsBuild() {
  if (!fs.existsSync(DIST)) {
    console.log('[INTEL] web-ui/dist absent — build nécessaire');
    return true;
  }
  const distTime = fs.statSync(DIST).mtimeMs;
  if (newerThan(SRC_DIR, distTime)) {
    console.log('[INTEL] web-ui/src modifié depuis le dernier build — rebuild');
    return true;
  }
  return false;
}

// ── Build frontend si nécessaire ───────────────────────────────────────────────
if (needsBuild()) {
  console.log('[INTEL] Installation des dépendances web-ui...');
  try {
    execSync('npm ci', {
      cwd: path.join(ROOT, 'web-ui'),
      stdio: 'inherit',
    });
    console.log('[INTEL] Build React/Vite en cours...');
    execSync('npx vite build', {
      cwd: path.join(ROOT, 'web-ui'),
      stdio: 'inherit',
    });
    console.log('[INTEL] ✅ Frontend buildé avec succès');
  } catch (err) {
    console.error('[INTEL] ⚠️  Build frontend échoué :', err.message);
    console.error('[INTEL]    Le backend démarre quand même sans le frontend.');
  }
} else {
  console.log('[INTEL] web-ui/dist à jour — pas de rebuild nécessaire');
}

// ── Vérifie aussi que backend/node_modules est présent ────────────────────────
const backendModules = path.join(ROOT, 'backend', 'node_modules');
if (!fs.existsSync(backendModules)) {
  console.log('[INTEL] Installation des dépendances backend...');
  try {
    execSync('npm ci', {
      cwd: path.join(ROOT, 'backend'),
      stdio: 'inherit',
    });
  } catch (err) {
    console.error('[INTEL] ⚠️  npm install backend échoué :', err.message);
  }
}

// ── Démarre le backend ─────────────────────────────────────────────────────────
require('./backend/node_modules/tsx/cjs');
require('./backend/src/index.ts');
