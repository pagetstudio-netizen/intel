/// Dependency Scanner
/// Scans npm and cargo dependency files for known vulnerabilities

use crate::{Finding, Result, ScanConfig, Severity, IntelError};
use uuid::Uuid;
use chrono::Utc;
use std::process::Command;
use serde_json::json;

pub struct DependencyScanner;

impl DependencyScanner {
    pub fn new() -> Self {
        Self
    }

    pub async fn scan(&self, config: &ScanConfig) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Scan npm dependencies
        findings.extend(self.scan_npm().await?);

        // Scan cargo dependencies
        findings.extend(self.scan_cargo().await?);

        // Scan Python dependencies (if applicable)
        findings.extend(self.scan_python().await?);

        log::info!("Dependency scan completed for: {}", config.target_url);

        Ok(findings)
    }

    async fn scan_npm(&self) -> Result<Vec<Finding>> {
        log::debug!("Scanning npm dependencies...");
        let mut findings = Vec::new();

        // Check if npm audit is available
        match Command::new("npm").arg("audit").arg("--json").output() {
            Ok(output) => {
                if let Ok(audit_data) = String::from_utf8(output.stdout) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&audit_data) {
                        if let Some(vulnerabilities) = json.get("vulnerabilities").and_then(|v| v.as_object()) {
                            for (package, vuln_data) in vulnerabilities {
                                if let Some(via) = vuln_data.get("via").and_then(|v| v.as_array()) {
                                    for vuln in via {
                                        let severity = self.parse_severity(
                                            vuln.get("severity").and_then(|s| s.as_str()).unwrap_or("low")
                                        );

                                        let cve = vuln.get("cves")
                                            .and_then(|c| c.as_array())
                                            .and_then(|arr| arr.first())
                                            .and_then(|c| c.as_str())
                                            .map(|s| s.to_string());

                                        findings.push(Finding {
                                            id: Uuid::new_v4(),
                                            title: format!("NPM Vulnerability in {}", package),
                                            description: vuln.get("title").and_then(|t| t.as_str())
                                                .unwrap_or("Unknown vulnerability")
                                                .to_string(),
                                            severity,
                                            category: "dependency".to_string(),
                                            cve,
                                            remediation: Some(format!("Update {} to a patched version", package)),
                                            affected_component: package.clone(),
                                            discovered_at: Utc::now(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log::debug!("npm audit not available: {}", e);
            }
        }

        Ok(findings)
    }

    async fn scan_cargo(&self) -> Result<Vec<Finding>> {
        log::debug!("Scanning cargo dependencies...");
        let mut findings = Vec::new();

        // Check if cargo-audit is available
        match Command::new("cargo").arg("audit").arg("--json").output() {
            Ok(output) => {
                if let Ok(audit_data) = String::from_utf8(output.stdout) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&audit_data) {
                        if let Some(vulnerabilities) = json.get("vulnerabilities").and_then(|v| v.as_array()) {
                            for vuln in vulnerabilities {
                                let package = vuln.get("package")
                                    .and_then(|p| p.get("name"))
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("unknown");

                                let severity_str = vuln.get("vulnerability")
                                    .and_then(|v| v.get("severity"))
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("low");

                                findings.push(Finding {
                                    id: Uuid::new_v4(),
                                    title: format!("Cargo Vulnerability in {}", package),
                                    description: vuln.get("vulnerability")
                                        .and_then(|v| v.get("title"))
                                        .and_then(|t| t.as_str())
                                        .unwrap_or("Security vulnerability")
                                        .to_string(),
                                    severity: self.parse_severity(severity_str),
                                    category: "dependency".to_string(),
                                    cve: vuln.get("vulnerability")
                                        .and_then(|v| v.get("cve"))
                                        .and_then(|c| c.as_str())
                                        .map(|s| s.to_string()),
                                    remediation: Some(format!("Update {} via cargo update", package)),
                                    affected_component: package.to_string(),
                                    discovered_at: Utc::now(),
                                });
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log::debug!("cargo audit not available: {}", e);
            }
        }

        Ok(findings)
    }

    async fn scan_python(&self) -> Result<Vec<Finding>> {
        log::debug!("Scanning Python dependencies...");
        let mut findings = Vec::new();

        // Check if safety is available
        match Command::new("safety").arg("check").arg("--json").output() {
            Ok(output) => {
                if let Ok(check_data) = String::from_utf8(output.stdout) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&check_data) {
                        if let Some(vulns) = json.as_array() {
                            for vuln in vulns {
                                findings.push(Finding {
                                    id: Uuid::new_v4(),
                                    title: format!("Python Package Vulnerability"),
                                    description: vuln.get("advisory")
                                        .and_then(|a| a.as_str())
                                        .unwrap_or("Security issue")
                                        .to_string(),
                                    severity: Severity::High,
                                    category: "dependency".to_string(),
                                    cve: vuln.get("cve").and_then(|c| c.as_str()).map(|s| s.to_string()),
                                    remediation: Some("Update package to latest version".to_string()),
                                    affected_component: vuln.get("package")
                                        .and_then(|p| p.as_str())
                                        .unwrap_or("unknown")
                                        .to_string(),
                                    discovered_at: Utc::now(),
                                });
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log::debug!("safety check not available: {}", e);
            }
        }

        Ok(findings)
    }

    fn parse_severity(&self, severity: &str) -> Severity {
        match severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

impl Default for DependencyScanner {
    fn default() -> Self {
        Self::new()
    }
}