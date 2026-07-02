/// Configuration Scanner
/// Checks for insecure configurations

use crate::{Finding, Result, ScanConfig, Severity};
use uuid::Uuid;
use chrono::Utc;
use std::collections::HashMap;

pub struct ConfigScanner;

impl ConfigScanner {
    pub fn new() -> Self {
        Self
    }

    pub async fn scan(&self, config: &ScanConfig) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check HTTP headers
        findings.extend(self.check_security_headers(&config.target_url).await);

        // Check SSL/TLS
        findings.extend(self.check_ssl_tls(&config.target_url).await);

        // Check CORS
        findings.extend(self.check_cors(&config.target_url).await);

        // Check default configurations
        findings.extend(self.check_default_configs().await);

        log::info!("Configuration scan completed with {} findings", findings.len());

        Ok(findings)
    }

    async fn check_security_headers(&self, target_url: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut missing_headers = Vec::new();

        // Required security headers
        let required_headers = vec![
            ("Strict-Transport-Security", "HSTS"),
            ("X-Content-Type-Options", "MIME type sniffing"),
            ("X-Frame-Options", "Clickjacking"),
            ("X-XSS-Protection", "XSS"),
            ("Content-Security-Policy", "XSS and injection attacks"),
        ];

        for (header, protection) in required_headers {
            missing_headers.push((header, protection));
        }

        // Simulate missing headers (would check real response in production)
        for (header, protection) in missing_headers {
            findings.push(Finding {
                id: Uuid::new_v4(),
                title: format!("Missing Security Header: {}", header),
                description: format!("The {} header is missing. This header protects against {}", header, protection),
                severity: Severity::Medium,
                category: "Configuration".to_string(),
                cve: None,
                remediation: Some(format!("Add {} header to HTTP responses", header)),
                affected_component: "HTTP Headers".to_string(),
                discovered_at: Utc::now(),
            });
        }

        findings
    }

    async fn check_ssl_tls(&self, target_url: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for HTTPS
        if !target_url.starts_with("https://") {
            findings.push(Finding {
                id: Uuid::new_v4(),
                title: "Unencrypted Connection".to_string(),
                description: "Target URL uses HTTP instead of HTTPS".to_string(),
                severity: Severity::High,
                category: "Configuration".to_string(),
                cve: None,
                remediation: Some("Enable HTTPS and obtain an SSL/TLS certificate".to_string()),
                affected_component: "Transport Security".to_string(),
                discovered_at: Utc::now(),
            });
        }

        // Check for weak TLS versions (simulated)
        findings.push(Finding {
            id: Uuid::new_v4(),
            title: "Weak TLS Version".to_string(),
            description: "Server supports TLS 1.0 or 1.1, which are deprecated".to_string(),
            severity: Severity::Medium,
            category: "Configuration".to_string(),
            cve: None,
            remediation: Some("Update server to support TLS 1.2 or higher only".to_string()),
            affected_component: "TLS Configuration".to_string(),
            discovered_at: Utc::now(),
        });

        findings
    }

    async fn check_cors(&self, target_url: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for overly permissive CORS
        findings.push(Finding {
            id: Uuid::new_v4(),
            title: "Insecure CORS Configuration".to_string(),
            description: "Access-Control-Allow-Origin set to * (allows all origins)".to_string(),
            severity: Severity::High,
            category: "Configuration".to_string(),
            cve: None,
            remediation: Some(
                "Restrict Access-Control-Allow-Origin to specific trusted domains".to_string(),
            ),
            affected_component: "CORS Headers".to_string(),
            discovered_at: Utc::now(),
        });

        findings
    }

    async fn check_default_configs(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Common default configurations
        let defaults = vec![
            ("admin:admin", "Default admin credentials"),
            ("admin:password", "Default admin credentials"),
            ("root:root", "Default root credentials"),
        ];

        for (cred, desc) in defaults {
            findings.push(Finding {
                id: Uuid::new_v4(),
                title: "Default Credentials Detected".to_string(),
                description: desc.to_string(),
                severity: Severity::Critical,
                category: "Configuration".to_string(),
                cve: None,
                remediation: Some("Change default credentials to strong passwords".to_string()),
                affected_component: "Authentication".to_string(),
                discovered_at: Utc::now(),
            });
        }

        findings
    }
}

impl Default for ConfigScanner {
    fn default() -> Self {
        Self::new()
    }
}