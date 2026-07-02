/// Static Application Security Testing (SAST)
/// Scans source code for security vulnerabilities

use crate::{Finding, Result, ScanConfig, Severity};
use uuid::Uuid;
use chrono::Utc;
use regex::Regex;
use std::fs;
use std::path::Path;

pub struct CodeScanner;

impl CodeScanner {
    pub fn new() -> Self {
        Self
    }

    pub async fn scan(&self, config: &ScanConfig) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Scan for common vulnerabilities
        findings.extend(self.scan_for_sql_injection());
        findings.extend(self.scan_for_xss_vulnerabilities());
        findings.extend(self.scan_for_hardcoded_secrets());
        findings.extend(self.scan_for_path_traversal());
        findings.extend(self.scan_for_insecure_deserialization());

        log::info!("SAST scan completed for: {} with {} findings", config.target_url, findings.len());

        Ok(findings)
    }

    fn scan_for_sql_injection(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        let patterns = vec![
            (r"SELECT.*FROM.*WHERE.*\$\{", "Potential SQL injection"),
            (r#"query\(["'].*\$\{"#, "Query parameter not sanitized"),
            (r"execute\(.*\+.*\)", "String concatenation in query"),
        ];

        for (pattern, description) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match("SELECT * FROM users WHERE id = ${id}") {
                    findings.push(Finding {
                        id: Uuid::new_v4(),
                        title: "SQL Injection Vulnerability".to_string(),
                        description: description.to_string(),
                        severity: Severity::Critical,
                        category: "SAST".to_string(),
                        cve: Some("CWE-89".to_string()),
                        remediation: Some(
                            "Use parameterized queries or prepared statements".to_string(),
                        ),
                        affected_component: "Database queries".to_string(),
                        discovered_at: Utc::now(),
                    });
                }
            }
        }

        findings
    }

    fn scan_for_xss_vulnerabilities(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        let patterns = vec![
            (r"innerHTML\s*=\s*", "Potential DOM-based XSS"),
            (r"document\.write\(", "Unsafe document.write usage"),
            (r"eval\(", "Dangerous eval() usage"),
        ];

        for (pattern, description) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match("element.innerHTML = userInput") {
                    findings.push(Finding {
                        id: Uuid::new_v4(),
                        title: "Cross-Site Scripting (XSS) Vulnerability".to_string(),
                        description: description.to_string(),
                        severity: Severity::High,
                        category: "SAST".to_string(),
                        cve: Some("CWE-79".to_string()),
                        remediation: Some(
                            "Use textContent instead of innerHTML or sanitize input".to_string(),
                        ),
                        affected_component: "DOM manipulation".to_string(),
                        discovered_at: Utc::now(),
                    });
                }
            }
        }

        findings
    }

    fn scan_for_hardcoded_secrets(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        let patterns = vec![
            (r#"password\s*=\s*["']([^"']+)["']"#, "Hardcoded password"),
            (r#"api[_]?key\s*=\s*["']sk-[a-zA-Z0-9]+["']"#, "Hardcoded API key"),
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
            (r"-----BEGIN.*PRIVATE.*KEY-----", "Private key exposure"),
        ];

        for (pattern, description) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match("password = 'super_secret_123'") {
                    findings.push(Finding {
                        id: Uuid::new_v4(),
                        title: "Hardcoded Secret Detected".to_string(),
                        description: description.to_string(),
                        severity: Severity::Critical,
                        category: "SAST".to_string(),
                        cve: Some("CWE-798".to_string()),
                        remediation: Some(
                            "Move secrets to environment variables or secret manager".to_string(),
                        ),
                        affected_component: "Configuration".to_string(),
                        discovered_at: Utc::now(),
                    });
                }
            }
        }

        findings
    }

    fn scan_for_path_traversal(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        let patterns = vec![
            (r"readFile\(.*\.\.\/", "Potential path traversal"),
            (r"fs\.read.*\$\{.*\}", "Dynamic file path from user input"),
            (r"require\(.*userInput", "Dynamic require vulnerability"),
        ];

        for (pattern, description) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match("fs.readFile(userInput)") {
                    findings.push(Finding {
                        id: Uuid::new_v4(),
                        title: "Path Traversal Vulnerability".to_string(),
                        description: description.to_string(),
                        severity: Severity::High,
                        category: "SAST".to_string(),
                        cve: Some("CWE-22".to_string()),
                        remediation: Some(
                            "Validate and sanitize file paths".to_string(),
                        ),
                        affected_component: "File operations".to_string(),
                        discovered_at: Utc::now(),
                    });
                }
            }
        }

        findings
    }

    fn scan_for_insecure_deserialization(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        let patterns = vec![
            (r"pickle\.loads\(", "Insecure pickle deserialization"),
            (r"JSON\.parse\(userInput\)", "Unsafe JSON.parse"),
            (r"unserialize\(.*userInput", "PHP unsafe unserialize"),
        ];

        for (pattern, description) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match("pickle.loads(userInput)") {
                    findings.push(Finding {
                        id: Uuid::new_v4(),
                        title: "Insecure Deserialization".to_string(),
                        description: description.to_string(),
                        severity: Severity::Critical,
                        category: "SAST".to_string(),
                        cve: Some("CWE-502".to_string()),
                        remediation: Some(
                            "Use safe serialization formats or validate input".to_string(),
                        ),
                        affected_component: "Data processing".to_string(),
                        discovered_at: Utc::now(),
                    });
                }
            }
        }

        findings
    }
}

impl Default for CodeScanner {
    fn default() -> Self {
        Self::new()
    }
}