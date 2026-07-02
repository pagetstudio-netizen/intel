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
        let mut default_wordlists = HashMap::new();

        // Common directories
        default_wordlists.insert(
            "common".to_string(),
            vec![
                "admin", "api", "app", "auth", "backup", "config", "dashboard",
                "debug", "test", "tmp", "upload", "user", "users", "api/v1",
                "api/v2", "health", "status", "metrics", "logs", "settings",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        );

        // Common files
        default_wordlists.insert(
            "files".to_string(),
            vec![
                ".env", ".git", ".gitignore", ".htaccess", "web.config",
                "robots.txt", "sitemap.xml", "package.json", "composer.json",
                "README.md", "LICENSE", "Makefile", "Dockerfile",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        );

        // API endpoints
        default_wordlists.insert(
            "api".to_string(),
            vec![
                "api/auth/login", "api/auth/register", "api/users",
                "api/products", "api/orders", "api/admin", "api/settings",
                "api/reports", "api/export", "api/import", "api/search",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        );

        // Sensitive paths
        default_wordlists.insert(
            "sensitive".to_string(),
            vec![
                "admin/login", "admin/panel", "phpmyadmin", "cpanel",
                "database", "backup", "private", "secret", "keys",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        );

        Self {
            wordlists: Arc::new(RwLock::new(default_wordlists)),
        }
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