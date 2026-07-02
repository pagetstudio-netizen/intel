/// Load Testing and Stress Testing Module
/// Simulates high-traffic scenarios to test server stability

use crate::{Finding, Result, Severity, IntelError};
use uuid::Uuid;
use chrono::Utc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::task::JoinSet;
use std::time::Instant;

pub struct LoadTester {
    requests_sent: Arc<AtomicU64>,
    requests_failed: Arc<AtomicU64>,
    requests_successful: Arc<AtomicU64>,
}

impl LoadTester {
    pub fn new() -> Self {
        Self {
            requests_sent: Arc::new(AtomicU64::new(0)),
            requests_failed: Arc::new(AtomicU64::new(0)),
            requests_successful: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Run load test with specified parameters
    pub async fn run_load_test(
        &self,
        target_url: &str,
        concurrent_users: usize,
        requests_per_second: usize,
        duration_seconds: u64,
    ) -> Result<LoadTestReport> {
        log::info!(
            "Starting load test: {} users, {} req/s, {} seconds",
            concurrent_users, requests_per_second, duration_seconds
        );

        let start_time = Instant::now();
        let mut tasks = JoinSet::new();
        let client = Arc::new(reqwest::Client::new());

        // Spawn worker tasks
        for user_id in 0..concurrent_users {
            let url = target_url.to_string();
            let client_clone = Arc::clone(&client);
            let sent = Arc::clone(&self.requests_sent);
            let failed = Arc::clone(&self.requests_failed);
            let successful = Arc::clone(&self.requests_successful);

            tasks.spawn(async move {
                let end_time = Instant::now() + std::time::Duration::from_secs(duration_seconds);
                let mut response_times = Vec::new();

                while Instant::now() < end_time {
                    let req_start = Instant::now();

                    match client_clone.get(&url).send().await {
                        Ok(response) => {
                            if response.status().is_success() {
                                successful.fetch_add(1, Ordering::SeqCst);
                            } else {
                                failed.fetch_add(1, Ordering::SeqCst);
                            }
                            response_times.push(req_start.elapsed().as_millis() as u64);
                        }
                        Err(_) => {
                            failed.fetch_add(1, Ordering::SeqCst);
                        }
                    }

                    sent.fetch_add(1, Ordering::SeqCst);

                    // Rate limiting
                    tokio::time::sleep(std::time::Duration::from_millis(
                        1000 / requests_per_second as u64,
                    ))
                    .await;
                }
            });
        }

        // Wait for all tasks
        while let Some(_) = tasks.join_next().await {}

        let total_time = start_time.elapsed().as_secs();
        let total_requests = self.requests_sent.load(Ordering::SeqCst);
        let successful = self.requests_successful.load(Ordering::SeqCst);
        let failed = self.requests_failed.load(Ordering::SeqCst);

        Ok(LoadTestReport {
            target_url: target_url.to_string(),
            duration_seconds,
            concurrent_users,
            total_requests,
            successful_requests: successful,
            failed_requests: failed,
            requests_per_second: total_requests / total_time,
            average_response_time_ms: 0, // Would need to track
            status: if failed as f64 / total_requests as f64 > 0.5 {
                "FAILED - High error rate".to_string()
            } else {
                "SUCCESS".to_string()
            },
            server_crash: failed > (successful / 2),
            recovery_time_seconds: 0,
            timestamp: Utc::now(),
        })
    }

    /// Simulate gradual load increase (Ramp-up)
    pub async fn ramp_up_test(
        &self,
        target_url: &str,
        max_users: usize,
        ramp_up_duration_seconds: u64,
    ) -> Result<LoadTestReport> {
        log::info!(
            "Starting ramp-up test: max {} users over {} seconds",
            max_users, ramp_up_duration_seconds
        );

        let step_size = max_users / (ramp_up_duration_seconds as usize);
        let mut current_users = 0;

        for second in 0..ramp_up_duration_seconds {
            current_users = std::cmp::min(current_users + step_size, max_users);
            log::info!("Ramp-up: {} users at second {}", current_users, second);

            self.run_load_test(target_url, current_users, 100, 1).await?;
        }

        self.run_load_test(target_url, max_users, 100, 10).await
    }

    /// Test specific endpoints with different payloads
    pub async fn targeted_load_test(
        &self,
        target_url: &str,
        endpoints: Vec<&str>,
        concurrent_requests: usize,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut tasks = JoinSet::new();
        let client = Arc::new(reqwest::Client::new());

        for endpoint in endpoints {
            let url = format!("{}{}", target_url, endpoint);
            let client_clone = Arc::clone(&client);

            tasks.spawn(async move {
                let mut failed = 0;
                let mut response_times = Vec::new();

                for _ in 0..concurrent_requests {
                    let start = Instant::now();
                    match client_clone.get(&url).send().await {
                        Ok(response) => {
                            if !response.status().is_success() {
                                failed += 1;
                            }
                            response_times.push(start.elapsed().as_millis() as u64);
                        }
                        Err(_) => failed += 1,
                    }
                }

                (url, failed, response_times)
            });
        }

        while let Some(result) = tasks.join_next().await {
            if let Ok((url, failed, response_times)) = result {
                if failed as f64 / concurrent_requests as f64 > 0.1 {
                    findings.push(Finding {
                        id: Uuid::new_v4(),
                        title: format!("Endpoint unstable under load: {}", url),
                        description: format!(
                            "Endpoint failed {} out of {} requests under concurrent load",
                            failed, concurrent_requests
                        ),
                        severity: Severity::High,
                        category: "Load Test".to_string(),
                        cve: None,
                        remediation: Some(
                            "Optimize endpoint performance or add caching".to_string()
                        ),
                        affected_component: "API Endpoint".to_string(),
                        discovered_at: Utc::now(),
                    });
                }
            }
        }

        Ok(findings)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
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
    pub recovery_time_seconds: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Default for LoadTester {
    fn default() -> Self {
        Self::new()
    }
}