/// INTEL Security Core - Shared types and modules

pub mod fuzzer;
pub mod scanner;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Custom error type
#[derive(Debug)]
pub enum IntelError {
    Http(reqwest::Error),
    Io(std::io::Error),
    Parse(String),
    Scan(String),
}

impl std::fmt::Display for IntelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntelError::Http(e) => write!(f, "HTTP error: {}", e),
            IntelError::Io(e) => write!(f, "IO error: {}", e),
            IntelError::Parse(s) => write!(f, "Parse error: {}", s),
            IntelError::Scan(s) => write!(f, "Scan error: {}", s),
        }
    }
}

impl std::error::Error for IntelError {}

impl From<reqwest::Error> for IntelError {
    fn from(e: reqwest::Error) -> Self {
        IntelError::Http(e)
    }
}

impl From<std::io::Error> for IntelError {
    fn from(e: std::io::Error) -> Self {
        IntelError::Io(e)
    }
}

/// Crate-wide Result type
pub type Result<T> = std::result::Result<T, IntelError>;

/// Severity levels for findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: String,
    pub cve: Option<String>,
    pub remediation: Option<String>,
    pub affected_component: String,
    pub discovered_at: DateTime<Utc>,
}

/// Scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub target_url: String,
    pub timeout_secs: u64,
    pub deep_scan: bool,
    pub include_dependencies: bool,
    pub include_code_scan: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            target_url: "http://localhost:3000".to_string(),
            timeout_secs: 60,
            deep_scan: false,
            include_dependencies: true,
            include_code_scan: true,
        }
    }
}

/// Status of a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanStatus {
    Running,
    Completed,
    Failed,
}

/// Completed scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: Uuid,
    pub config: ScanConfig,
    pub findings: Vec<Finding>,
    pub status: ScanStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_secs: Option<u64>,
}

/// A fuzzing job definition
#[derive(Debug, Clone)]
pub struct FuzzJob {
    pub target_url: String,
    pub wordlist: Vec<String>,
    pub method: String,
    pub concurrent_requests: usize,
    pub timeout_ms: u64,
}

impl FuzzJob {
    pub fn new(target_url: impl Into<String>) -> Self {
        Self {
            target_url: target_url.into(),
            wordlist: vec![
                "admin".into(), "api".into(), "login".into(), "dashboard".into(),
                "config".into(), "backup".into(), "test".into(), "debug".into(),
                "health".into(), "metrics".into(), "status".into(), "version".into(),
                "robots.txt".into(), ".env".into(), "swagger.json".into(),
                "api/v1".into(), "api/v2".into(), "admin/panel".into(),
            ],
            method: "GET".into(),
            concurrent_requests: 10,
            timeout_ms: 5000,
        }
    }
}

/// A single fuzz result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub path: String,
    pub status_code: u16,
    pub response_size: u64,
    pub response_time_ms: u64,
}

/// Load test report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestReport {
    pub target_url: String,
    pub duration_seconds: u64,
    pub concurrent_users: usize,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub requests_per_second: u64,
    pub average_response_time_ms: u64,
    pub status: String,
    pub server_crash: bool,
}
