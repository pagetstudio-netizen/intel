# Déploiement INTEL sur Plesk (scénario alternatif : Nginx statique + PM2)

> ⚠️ **Ce n'est pas le scénario recommandé.** Le guide principal et à jour est
> [`plesk-setup.md`](./plesk-setup.md) : il utilise le mode Node.js natif de Plesk (Passenger via
> `server.js`), sans PM2, ce qui évite les soucis de permissions liés au chroot Plesk. Ne suis ce
> document que si tu préfères gérer toi-même Nginx + PM2 en dehors de l'intégration Node.js de
> Plesk.

## Prérequis
- Node.js 18+ installé sur le serveur Plesk
- PostgreSQL 14+ disponible
- Rust installé (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`) — requis pour
  compiler `security-core` (scan / fuzz / load-test)
- PM2 installé globalement : `npm install -g pm2 tsx`
- Accès SSH au serveur

---

## 1. Préparer le dépôt GitHub

```bash
# Sur votre machine locale — commandes à exécuter une fois
git init
git add .
git commit -m "Initial commit — INTEL Security Platform"
git remote add origin https://github.com/VOTRE_USER/intel.git
git push -u origin main
```

---

## 2. Créer la base de données PostgreSQL dans Plesk

Dans **Plesk > Bases de données > Ajouter une base de données** :
- Nom : `intel_db`
- Utilisateur : `intel_user`
- Mot de passe : (générez-en un fort)
- Notez la chaîne de connexion : `postgresql://intel_user:MOT_DE_PASSE@localhost:5432/intel_db`

---

## 3. Configurer le domaine dans Plesk

Dans **Plesk > votre domaine > Hébergement Node.js** :
- Mode Node.js : **activé**
- Version Node.js : 18.x ou 20.x
- Document Root : `web-ui/dist`
- Fichier de démarrage : `backend/src/index.ts`

---

## 4. Premier déploiement (via SSH)

```bash
# Se connecter au serveur
ssh user@votreserveur.com

# Aller dans le dossier du domaine
cd /var/www/vhosts/votredomaine.com/httpdocs

# Cloner le dépôt
git clone https://github.com/VOTRE_USER/intel.git .

# Copier et configurer l'environnement
cp .env.example .env
nano .env   # ← remplissez DATABASE_URL et les autres variables

# Installer les dépendances
npm run install:all

# Créer le schéma de la base de données
psql "$DATABASE_URL" -f deploy/schema.sql

# Builder le frontend
npm run build:frontend

# Démarrer le backend avec PM2
pm2 start ecosystem.config.js
pm2 save
pm2 startup   # ← exécutez la commande affichée pour le démarrage automatique
```

---

## 5. Configurer Nginx dans Plesk

Dans **Plesk > votre domaine > Apache & Nginx > Nginx** :
- Copiez le contenu de `nginx.plesk.conf` dans **"Directives Nginx supplémentaires (zone HTTPS)"**
- Remplacez `votredomaine.com` par votre vrai domaine
- Cliquez **OK**

---

## 6. Déploiement continu (après chaque `git push`)

Dans **Plesk > votre domaine > Git** (ou via webhook GitHub) :
1. Connectez le dépôt GitHub
2. Activez le déploiement automatique sur push
3. Ou manuellement via SSH :

```bash
cd /var/www/vhosts/votredomaine.com/httpdocs
git pull origin main
npm run build:frontend
pm2 restart intel-api
```

---

## 7. Vérifications

```bash
# Santé de l'API
curl https://votredomaine.com/api/health

# Statut PM2
pm2 status

# Logs en temps réel
pm2 logs intel-api
```

---

## Variables d'environnement obligatoires

| Variable | Description | Exemple |
|----------|-------------|---------|
| `DATABASE_URL` | Connexion PostgreSQL | `postgresql://user:pass@localhost/intel_db` |
| `PORT` | Port du backend | `3000` |
| `NODE_ENV` | Environnement | `production` |

## Variables optionnelles (email)

| Variable | Description |
|----------|-------------|
| `RESEND_API_KEY` | Clé API Resend pour envoyer les rapports |
| `SMTP_HOST` / `SMTP_USER` / `SMTP_PASS` | Gmail SMTP alternatif |

---

## Schéma PostgreSQL

Le schéma complet est dans `deploy/schema.sql`.  
Pour l'appliquer : `psql "$DATABASE_URL" -f deploy/schema.sql`
