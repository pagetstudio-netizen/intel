# Déploiement INTEL sur Plesk

## Prérequis
- VPS Linux x86_64 (Ubuntu 20.04+ ou Debian 11+)
- Plesk avec extensions : **Node.js**, **PostgreSQL**
- Accès SSH root ou sudo

---

## Étape 1 — Préparer le projet

Sur Replit, dans le terminal :

```bash
# Build le frontend
cd web-ui && npx vite build && cd ..
```

Télécharge tout le projet (git clone ou archive ZIP) sur ton serveur.

---

## Étape 2 — Créer le domaine dans Plesk

1. Plesk → **Ajouter un domaine** → ex: `intel.tondomaine.com`
2. Répertoire racine : `/var/www/vhosts/intel.tondomaine.com/httpdocs`

---

## Étape 3 — Configurer Node.js dans Plesk

1. Plesk → ton domaine → **Node.js**
2. Activer Node.js
3. Version : **20.x**
4. Document root : `httpdocs`
5. Fichier de démarrage : `server.js`
6. Variables d'environnement (dans l'interface Plesk) :
   ```
   NODE_ENV=production
   PORT=3000
   DATABASE_URL=postgresql://user:password@localhost/intel_db
   SESSION_SECRET=ton_secret_ici
   RESEND_API_KEY=re_xxxxxxxxxxxx
   RESEND_FROM_EMAIL=demo@tondomaine.com
   ```

---

## Étape 4 — Créer la base de données PostgreSQL

1. Plesk → **Bases de données** → **Ajouter une base de données**
2. Nom : `intel_db`
3. Type : PostgreSQL
4. Créer un utilisateur dédié
5. Copie le DATABASE_URL dans les variables d'environnement

---

## Étape 5 — Uploader les fichiers

```bash
# Sur ton serveur via SSH
cd /var/www/vhosts/intel.tondomaine.com/httpdocs

# Clone ou upload le projet
git clone https://github.com/ton-repo/intel.git .

# Installer les dépendances
npm install

# Donner les droits d'exécution au binaire Rust
chmod +x security-core/target/release/intel
```

---

## Étape 6 — Créer les tables en base de données

```bash
# Via SSH
psql $DATABASE_URL < deploy/schema.sql
```

---

## Étape 7 — Configurer Nginx (proxy + frontend)

Dans Plesk → ton domaine → **Paramètres Apache & Nginx** → 
Ajouter dans la section **Directives Nginx supplémentaires** :

```nginx
# Proxy API vers le backend Node.js
location /api {
    proxy_pass http://localhost:3000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host $host;
    proxy_cache_bypass $http_upgrade;
}

# Frontend React (build statique)
location / {
    root /var/www/vhosts/intel.tondomaine.com/httpdocs/web-ui/dist;
    try_files $uri $uri/ /index.html;
    expires 1d;
    add_header Cache-Control "public";
}
```

---

## Étape 8 — Démarrer

Dans Plesk → Node.js → **Redémarrer l'application**

✅ Ton INTEL sera accessible sur `https://intel.tondomaine.com`

---

## Mises à jour futures

```bash
# Sur le serveur via SSH
cd /var/www/vhosts/intel.tondomaine.com/httpdocs
git pull
npm install
# Rebuild frontend si changements UI
cd web-ui && npx vite build && cd ..
# Redémarrer via Plesk ou :
pkill -f "node server.js" && node server.js &
```
