/// Wordlist Manager
/// Manages fuzzing wordlists and patterns

use crate::Result;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

pub struct WordlistManager {
    wordlists: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl WordlistManager {
    pub fn new() -> Self {
        let mut w = HashMap::new();

        // ── Common directories ────────────────────────────────────
        w.insert("common".to_string(), vec![
            "admin","api","app","auth","backup","config","dashboard","debug",
            "test","tmp","upload","user","users","health","status","metrics",
            "logs","settings","internal","private","secret","hidden","dev",
            "staging","beta","old","legacy","v1","v2","v3","api/v1","api/v2",
            "api/v3","api/internal","api/admin","api/private","console","panel",
            "manage","management","monitoring","grafana","kibana","elastic",
        ].into_iter().map(String::from).collect());

        // ── Hidden / sensitive files ──────────────────────────────
        w.insert("files".to_string(), vec![
            ".env",".env.local",".env.production",".env.staging",".env.backup",
            ".git",".git/config",".git/HEAD",".gitignore",".gitconfig",
            ".htaccess",".htpasswd","web.config","web.config.bak",
            "robots.txt","sitemap.xml","crossdomain.xml","clientaccesspolicy.xml",
            "package.json","package-lock.json","composer.json","composer.lock",
            "yarn.lock","Gemfile","Gemfile.lock","requirements.txt","Pipfile",
            "README.md","CHANGELOG.md","Makefile","Dockerfile","docker-compose.yml",
            ".travis.yml",".github/workflows/deploy.yml",
            "config.php","config.yml","config.yaml","config.json","settings.py",
            "database.yml","database.php","db.php","wp-config.php",
            "application.properties","application.yml","application.yaml",
            "appsettings.json","appsettings.Production.json",
            "backup.sql","dump.sql","database.sql","db_backup.sql",
            "backup.zip","backup.tar.gz","site-backup.zip",
            "id_rsa","id_rsa.pub","private.key","server.key","ssl.key",
            "phpinfo.php","info.php","test.php","debug.php",
            "server-status","server-info","nginx_status",
        ].into_iter().map(String::from).collect());

        // ── API endpoints ─────────────────────────────────────────
        w.insert("api".to_string(), vec![
            "api/auth/login","api/auth/logout","api/auth/register","api/auth/refresh",
            "api/auth/reset-password","api/auth/forgot-password","api/auth/verify",
            "api/users","api/users/me","api/users/list","api/users/export",
            "api/admin","api/admin/users","api/admin/settings","api/admin/logs",
            "api/products","api/orders","api/payments","api/transactions",
            "api/settings","api/reports","api/export","api/import","api/search",
            "api/health","api/status","api/version","api/docs","api/swagger",
            "api/graphql","graphql","api/debug","api/metrics","api/ping",
            "api/internal","api/private","api/secret","api/keys","api/tokens",
            "api/webhooks","api/callbacks","api/notifications",
            "swagger.json","openapi.json","openapi.yaml","api-docs","swagger-ui",
        ].into_iter().map(String::from).collect());

        // ── Fintech / paiements spécifiques ──────────────────────
        w.insert("fintech".to_string(), vec![
            "api/payments","api/payment","api/pay","api/checkout","api/billing",
            "api/transactions","api/transaction","api/transfer","api/transfers",
            "api/wallet","api/wallets","api/balance","api/account","api/accounts",
            "api/bank","api/bank-accounts","api/cards","api/card","api/iban",
            "api/kyc","api/aml","api/compliance","api/fraud","api/fraud-check",
            "api/verify","api/verification","api/identity","api/onboarding",
            "api/webhooks/stripe","api/webhooks/paypal","api/webhooks/payment",
            "api/refund","api/refunds","api/dispute","api/disputes","api/chargeback",
            "api/invoice","api/invoices","api/subscription","api/subscriptions",
            "api/payout","api/payouts","api/deposit","api/deposits","api/withdraw",
            "api/crypto","api/exchange","api/rates","api/fees","api/limits",
            "api/reports/financial","api/reports/transactions","api/reports/export",
            "admin/payments","admin/transactions","admin/users/financial",
            "admin/kyc","admin/compliance","finance","treasury","backoffice",
            "payment-service","billing-service","wallet-service",
        ].into_iter().map(String::from).collect());

        // ── Sections admin / back-office ──────────────────────────
        w.insert("admin".to_string(), vec![
            "admin","admin/login","admin/panel","admin/dashboard","admin/console",
            "administrator","administrator/login","wp-admin","wp-login.php",
            "phpmyadmin","pma","mysql","adminer","dbadmin",
            "cpanel","plesk","whm","webmin","directadmin",
            "manager","management","manage","control","controlpanel",
            "superadmin","super-admin","root","backend","backoffice","back-office",
            "staff","team","internal/admin","internal/dashboard",
        ].into_iter().map(String::from).collect());

        // ── Répertoires de données exposées ───────────────────────
        w.insert("data".to_string(), vec![
            "exports","export","data","dataset","datasets","dumps","dump",
            "reports","report","logs","log","archive","archives",
            "uploads","files","documents","docs","static","assets","media",
            "images","img","public","shared","common","resources",
            "cdn","storage","bucket","s3","cache",
        ].into_iter().map(String::from).collect());

        Self {
            wordlists: Arc::new(RwLock::new(w)),
        }
    }

    /// Retourne la wordlist combinée optimale pour un scan fintech
    pub fn get_fintech_combined(&self) -> Vec<String> {
        let w = self.wordlists.read();
        let mut combined = Vec::new();
        for key in &["files", "admin", "fintech", "api", "data"] {
            if let Some(list) = w.get(*key) {
                combined.extend(list.clone());
            }
        }
        combined.dedup();
        combined
    }

    pub async fn load_wordlist(&mut self, name: &str) -> Result<Vec<String>> {
        let wordlists = self.wordlists.read();
        if let Some(list) = wordlists.get(name) {
            log::debug!("Loaded wordlist: {} ({} entries)", name, list.len());
            Ok(list.clone())
        } else {
            log::warn!("Wordlist not found: {}", name);
            Ok(Vec::new())
        }
    }

    pub fn get_wordlist(&self, name: &str) -> Option<Vec<String>> {
        let wordlists = self.wordlists.read();
        wordlists.get(name).cloned()
    }

    pub fn get_all_paths(&self) -> Vec<String> {
        let wordlists = self.wordlists.read();
        let mut all: Vec<String> = wordlists.values().flatten().cloned().collect();
        all.dedup();
        all
    }

    pub fn add_wordlist(&self, name: String, wordlist: Vec<String>) {
        let mut wordlists = self.wordlists.write();
        wordlists.insert(name, wordlist);
    }

    pub fn list_wordlists(&self) -> Vec<String> {
        let wordlists = self.wordlists.read();
        wordlists.keys().cloned().collect()
    }
}

impl Default for WordlistManager {
    fn default() -> Self {
        Self::new()
    }
}
