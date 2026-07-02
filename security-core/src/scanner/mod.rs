/// Vulnerability Scanner Module
/// - Dependency scanning (npm, cargo)
/// - SAST (Static code analysis)
/// - Configuration review
/// - CVE database lookup

pub mod dependency;
pub mod sast;
pub mod config;
pub mod cve;

pub use dependency::DependencyScanner;
pub use sast::CodeScanner;
pub use config::ConfigScanner;
pub use cve::CveDatabase;

use crate::{Result, ScanConfig, ScanResult, Finding, ScanStatus};
use uuid::Uuid;
use chrono::Utc;
use std::time::Instant;

/// Main vulnerability scanner
pub struct VulnerabilityScanner {
    dep_scanner: DependencyScanner,
    code_scanner: CodeScanner,
    config_scanner: ConfigScanner,
    cve_db: CveDatabase,
}

impl VulnerabilityScanner {
    pub fn new() -> Self {
        Self {
            dep_scanner: DependencyScanner::new(),
            code_scanner: CodeScanner::new(),
            config_scanner: ConfigScanner::new(),
            cve_db: CveDatabase::new(),
        }
    }

    /// Run complete vulnerability scan
    pub async fn scan(&self, config: ScanConfig) -> Result<ScanResult> {
        let scan_id = Uuid::new_v4();
        let started_at = Utc::now();
        let start_timer = Instant::now();

        log::info!("Starting vulnerability scan: {}", config.target_url);

        let mut findings = Vec::new();

        // Run dependency scan
        if config.include_dependencies {
            log::info!("Running dependency scan...");
            match self.dep_scanner.scan(&config).await {
                Ok(deps) => {
                    log::info!("Found {} dependency findings", deps.len());
                    findings.extend(deps);
                }
                Err(e) => log::warn!("Dependency scan failed: {}", e),
            }
        }

        // Run code scan (SAST)
        if config.include_code_scan {
            log::info!("Running SAST code scan...");
            match self.code_scanner.scan(&config).await {
                Ok(code_findings) => {
                    log::info!("Found {} code security issues", code_findings.len());
                    findings.extend(code_findings);
                }
                Err(e) => log::warn!("Code scan failed: {}", e),
            }
        }

        // Run config scan
        log::info!("Running configuration scan...");
        match self.config_scanner.scan(&config).await {
            Ok(config_findings) => {
                log::info!("Found {} configuration issues", config_findings.len());
                findings.extend(config_findings);
            }
            Err(e) => log::warn!("Config scan failed: {}", e),
        }

        // Sort by severity
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        let completed_at = Utc::now();
        let duration_secs = start_timer.elapsed().as_secs();

        log::info!(
            "Scan completed in {}s with {} findings",
            duration_secs,
            findings.len()
        );

        Ok(ScanResult {
            id: scan_id,
            config,
            findings,
            status: ScanStatus::Completed,
            started_at,
            completed_at: Some(completed_at),
            duration_secs: Some(duration_secs),
        })
    }
}

impl Default for VulnerabilityScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scanner_creation() {
        let scanner = VulnerabilityScanner::new();
        let config = ScanConfig {
            target_url: "http://localhost:3000".to_string(),
            timeout_secs: 60,
            deep_scan: false,
            include_dependencies: false,
            include_code_scan: false,
        };
        let result = scanner.scan(config).await;
        assert!(result.is_ok());
    }
}