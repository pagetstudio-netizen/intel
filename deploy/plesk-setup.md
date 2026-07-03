# Déploiement INTEL sur Plesk

## Prérequis
- VPS Linux x86_64 (Ubuntu 20.04+ ou Debian 11+)
- Plesk avec extensions : **Node.js**, **PostgreSQL**, **Git**
- **Rust** installé sur le serveur (requis pour compiler `security-core`) :
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
  ```
  ⚠️ Le binaire compilé sur Replit (`security-core/target/release/intel`) **ne fonctionnera pas**
  sur ton VPS Plesk : il est lié à l'environnement Nix de Replit. Il doit être **recompilé sur le
  serveur Plesk lui-même**, ce que fait automatiquement `deploy.sh`.
- Accès SSH root ou sudo

---

## Étape 1 — Créer le domaine dans Plesk

1. Plesk → **Ajouter un domaine** → ex: `voltatrucks.online`
2. Répertoire racine : `/var/www/vhosts/voltatrucks.online/httpdocs`

---

## Étape 2 — Configurer Node.js dans Plesk

Dans **Plesk → ton domaine → Node.js** :

| Champ | Valeur |
|---|---|
| Mode Node.js | activé |
| Version Node.js | 20.x |
| Racine du document (Document Root) | `/` (la racine du domaine, **pas** `web-ui/src`) |
| Racine de l'application (Application Root) | `/` (la racine du projet, **pas** `web-ui`) |
| Fichier de démarrage (Application Startup File) | `server.js` |

> ⚠️ Utilise bien le `server.js` **de la racine du projet**, pas celui de `web-ui/`. Les deux
> fichiers font la même chose (ils lancent `backend/src/index.ts` qui sert aussi le frontend
> buildé), mais garder Application Root = racine évite toute confusion sur les chemins relatifs
> et sur le Document Root.

Variables d'environnement (section **Variables d'environnement personnalisées**) :
```
NODE_ENV=production
PORT=3000
DATABASE_URL=postgresql://user:password@localhost/intel_db
JWT_SECRET=une_valeur_aleatoire_longue
# Optionnel — envoi d'emails de démo phishing
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=...
SMTP_PASS=...
```

---

## Étape 3 — Créer la base de données PostgreSQL

1. Plesk → **Bases de données** → **Ajouter une base de données**
2. Nom : `intel_db`, type : PostgreSQL
3. Créer un utilisateur dédié et reporter la chaîne de connexion dans `DATABASE_URL` ci-dessus

---

## Étape 4 — Connecter le dépôt Git

Dans **Plesk → ton domaine → Git** :
1. **Ajouter un dépôt** → colle l'URL GitHub → branche `main`
2. Chemin de déploiement : la racine du domaine (`httpdocs`)
3. Dans **Actions de déploiement supplémentaires**, mets :
   ```bash
   bash deploy.sh
   ```
   Ce script installe les dépendances, build le frontend (`web-ui/dist`) **et compile le moteur
   Rust** (`security-core/target/release/intel`).

   ⚠️ Si Plesk affiche un avertissement du type *"user with id=XXXX and name=... not found in
   chrooted passwd file"* pendant le déploiement : c'est un souci de configuration système Plesk
   (l'utilisateur système associé à l'abonnement n'existe pas dans le chroot utilisé pour exécuter
   les actions de déploiement), pas un bug de l'application. Corrige-le en réattribuant
   l'abonnement au bon utilisateur système dans **Plesk → Abonnements → [ton domaine] →
   Paramètres d'hébergement Web**, ou exécute `bash deploy.sh` manuellement en SSH à la place tant
   que ce n'est pas résolu.
4. Clique **Pull + Deploy** pour le premier déploiement

---

## Étape 5 — Créer les tables en base de données (une seule fois)

```bash
# Via SSH, à la racine du projet
psql "$DATABASE_URL" -f deploy/schema.sql
```

---

## Étape 6 — Configurer Nginx (proxy uniquement si tu ne passes pas par Passenger)

Si le Node.js Plesk (Passenger) est activé comme ci-dessus, **aucune configuration Nginx
supplémentaire n'est nécessaire** : Passenger route déjà tout le trafic vers `server.js`, qui sert
à la fois l'API (`/api/*`) et le frontend buildé (`web-ui/dist`).

Le fichier `nginx.plesk.conf` n'est utile que si tu choisis une architecture alternative sans
Passenger (Nginx statique + backend Node séparé via PM2) — voir `PLESK_DEPLOY.md` pour ce
scénario.

---

## Étape 7 — Démarrer / redémarrer

Dans **Plesk → Node.js → Redémarrer l'application**.

✅ Ton INTEL sera accessible sur `https://voltatrucks.online`

---

## Mises à jour futures

Après chaque `git push` sur GitHub :
1. Plesk → ton domaine → Git → **Pull + Deploy Now**
2. Plesk → Node.js → **Restart App**

Ou manuellement en SSH :
```bash
cd /var/www/vhosts/voltatrucks.online/httpdocs
git pull
bash deploy.sh
# Puis redémarrer l'app Node.js depuis l'interface Plesk
```

---

## Dépannage

| Symptôme | Cause probable | Solution |
|---|---|---|
| Page Plesk par défaut ("Something New Is Happening Here!") au lieu de l'app | Document Root pointe vers un dossier sans `index.html` (ex: `web-ui/src`), ou l'app Node n'a jamais démarré | Mets Document Root et Application Root sur la racine du projet, vérifie que `bash deploy.sh` s'est bien terminé, puis redémarre l'app Node.js |
| `{"status":"error",...}` ou 404 sur `/api/...` | Le backend n'est pas démarré ou `DATABASE_URL` est invalide | Vérifie les logs Node.js dans Plesk, vérifie les tables via l'étape 5 |
| Scan / Fuzz / Load-test échouent silencieusement | Le binaire Rust n'a pas été (re)compilé sur ce serveur | Vérifie que Rust est installé (`cargo --version`), relance `bash deploy.sh` |
| Avertissement "user ... not found in chrooted passwd file" pendant le déploiement Git | Compte système Plesk mal associé à l'abonnement | Voir étape 4 ci-dessus |
