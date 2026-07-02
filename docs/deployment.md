# INTEL Deployment Guide

## Déploiement sur Plesk

### Méthode 1: Docker (Recommandée)

#### 1.1 Préparer le serveur

```bash
# SSH dans Plesk
ssh user@your-plesk-server

# Installer Docker (si pas déjà installé)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

#### 1.2 Cloner le repository

```bash
cd /var/www
git clone https://github.com/pagetstudio-netizen/intel.git
cd intel
```

#### 1.3 Configuration

```bash
cp .env.example .env

# Édite la configuration
nano .env

# Important pour production:
# - Changer NODE_ENV à "production"
# - Générer des secrets JWT forts
# - Configurer la DB avec credentials sécurisés
```

#### 1.4 Builder et déployer

```bash
# Build les images Docker
docker-compose build

# Démarrer les services
docker-compose up -d

# Vérifier le status
docker-compose ps
```

#### 1.5 Configurer le domaine dans Plesk

1. **Domains** → **Add Domain**
2. Entrer `intel.example.com`
3. **Web Hosting**
   - **Document root**: `/var/www/intel`
4. **SSL/TLS Certificates**
   - Générer ou importer un certificat

### Méthode 2: Installation Manuelle (Node.js via Plesk)

#### 2.1 Prérequis

- Node.js 18+ installé sur le serveur
- PostgreSQL configuré

#### 2.2 Déployer le backend

```bash
# Clone
cd /var/www
git clone https://github.com/pagetstudio-netizen/intel.git
cd intel/backend

# Install
npm install --production

# Build
npm run build
```

#### 2.3 Configuration Plesk

1. **Domains** → Votre domaine
2. **Node.js**
   - **Application mode**: production
   - **Application root**: `/var/www/intel/backend`
   - **Application startup file**: `dist/index.js`

#### 2.4 Configurer la base de données

```bash
# Dans Plesk: Databases → Create Database
# Database name: intel_db
# User: intel_user
# Password: [strong password]

# SSH et appliquer les migrations
cd /var/www/intel/backend
npm run db:migrate
```

## Configuration Production

### Nginx Reverse Proxy

```nginx
upstream intel_api {
    server 127.0.0.1:3000;
}

upstream intel_ui {
    server 127.0.0.1:3001;
}

server {
    listen 443 ssl http2;
    server_name intel.example.com;

    ssl_certificate /etc/ssl/certs/intel.crt;
    ssl_certificate_key /etc/ssl/private/intel.key;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # API
    location /api {
        proxy_pass http://intel_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }

    # Web UI
    location / {
        proxy_pass http://intel_ui;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Proxy
    location /proxy {
        proxy_pass http://127.0.0.1:8080;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name intel.example.com;
    return 301 https://$server_name$request_uri;
}
```

### Environment Variables Production

```bash
NODE_ENV=production
PORT=3000

# Database
DB_HOST=your-db-host
DB_PORT=5432
DB_NAME=intel_db
DB_USER=intel_user
DB_PASSWORD=secure_password_here

# JWT
JWT_SECRET=very_long_random_secret_key_here

# Security
ENABLE_DEEP_SCAN=false
MAX_CONCURRENT_SCANS=3

# Logging
LOG_LEVEL=info
```

### Database Backup

```bash
# Backup automatique (cron job)
0 2 * * * pg_dump -U intel_user intel_db | gzip > /backups/intel_$(date +\%Y\%m\%d).sql.gz

# Restore
gunzip /backups/intel_YYYYMMDD.sql.gz
psql -U intel_user intel_db < /backups/intel_YYYYMMDD.sql
```

### Monitoring et Logs

```bash
# Vérifier les logs
docker-compose logs -f backend
docker-compose logs -f proxy

# Monitoring avec Plesk
# Tools & Settings → Log Files

# Setup alertes
# - CPU usage
# - Memory usage
# - Disk space
```

### SSL/TLS

```bash
# Vérifier le certificat
openssl x509 -in /etc/ssl/certs/intel.crt -text -noout

# Renouveler Let's Encrypt
certbot renew --dry-run
```

### Performance Tuning

```bash
# Vérifier PostgreSQL
psql -U postgres
SHOW max_connections;
SHOW shared_buffers;

# Optimiser pour production
max_connections = 200
shared_buffers = 256MB
effective_cache_size = 1GB
```

## Troubleshooting Deployment

### Services ne démarrent pas

```bash
docker-compose logs
docker-compose restart
```

### Problèmes de port

```bash
# Vérifier les ports occupés
netstat -tlnp

# Modifier les ports dans .env et docker-compose.yml
```

### Database connection refused

```bash
# Vérifier PostgreSQL
systemctl status postgresql

# Restart
systemctl restart postgresql
```

### SSL/TLS errors

```bash
# Vérifier le certificat
curl -v https://intel.example.com
```

## Mise à jour

```bash
# Pull les dernières modifications
git pull origin main

# Rebuild
docker-compose build

# Restart
docker-compose restart

# Appliquer les migrations
npm run db:migrate
```
