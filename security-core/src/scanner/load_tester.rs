/// Load Testing and Stress Testing Module
/// Simulates high-traffic scenarios to test server stability

use crate::{Finding, Result, Severity};
use uuid::Uuid;
use chrono::Utc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use tokio::sync::Semaphore;

pub struct LoadTester {
    requests_sent:       Arc<AtomicU64>,
    requests_failed:     Arc<AtomicU64>,
    requests_successful: Arc<AtomicU64>,
    total_response_ms:   Arc<AtomicU64>,
}

// Realistic browser User-Agents to vary traffic (mimics real user load)
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
];

impl LoadTester {
    pub fn new() -> Self {
        Self {
            requests_sent:       Arc::new(AtomicU64::new(0)),
            requests_failed:     Arc::new(AtomicU64::new(0)),
            requests_successful: Arc::new(AtomicU64::new(0)),
            total_response_ms:   Arc::new(AtomicU64::new(0)),
        }
    }

    /// Run load test — fires `concurrent_users × requests_per_second` req/s
    /// for `duration_seconds`. Each user slot fires requests in a tight loop
    /// with a semaphore cap on in-flight requests to avoid OOM.
    pub async fn run_load_test(
        &self,
        target_url: &str,
        concurrent_users: usize,
        requests_per_second: usize,
        duration_seconds: u64,
    ) -> Result<LoadTestReport> {
        log::info!(
            "Starting load test: {} users, {} req/s/user, {}s — target: {}",
            concurrent_users, requests_per_second, duration_seconds, target_url
        );

        // Build a shared client with realistic timeout + headers
        let client: Arc<reqwest::Client> = Arc::new(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .connect_timeout(Duration::from_secs(5))
                .danger_accept_invalid_certs(false)
                .tcp_keepalive(Duration::from_secs(15))
                .pool_max_idle_per_host(concurrent_users)
                .build()
                .map_err(|e| crate::IntelError::Scan(e.to_string()))?
        );

        // Cap total in-flight requests to prevent OOM
        let max_inflight = std::cmp::min(concurrent_users * 4, 800);
        let semaphore = Arc::new(Semaphore::new(max_inflight));

        let deadline = Instant::now() + Duration::from_secs(duration_seconds);

        let sent       = Arc::clone(&self.requests_sent);
        let failed     = Arc::clone(&self.requests_failed);
        let successful = Arc::clone(&self.requests_successful);
        let resp_ms    = Arc::clone(&self.total_response_ms);

        let mut tasks: JoinSet<()> = JoinSet::new();

        // Each "user" is a task that fires requests at `requests_per_second`
        let interval_ms = 1000u64
            .checked_div(requests_per_second as u64)
            .unwrap_or(100)
            .max(10); // minimum 10ms between sends per user

        for user_id in 0..concurrent_users {
            let url       = target_url.to_string();
            let client_c  = Arc::clone(&client);
            let sem_c     = Arc::clone(&semaphore);
            let sent_c    = Arc::clone(&sent);
            let failed_c  = Arc::clone(&failed);
            let succ_c    = Arc::clone(&successful);
            let resp_c    = Arc::clone(&resp_ms);
            let ua        = USER_AGENTS[user_id % USER_AGENTS.len()];

            tasks.spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    ticker.tick().await;
                    if Instant::now() >= deadline { break; }

                    // Acquire semaphore slot (backpressure)
                    let permit = match sem_c.clone().try_acquire_owned() {
                        Ok(p)  => p,
                        Err(_) => {
                            // In-flight cap reached — count as failed (server too slow)
                            failed_c.fetch_add(1, Ordering::Relaxed);
                            sent_c.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };

                    // Fire request without blocking the tick loop
                    let url_c    = url.clone();
                    let client_r = Arc::clone(&client_c);
                    let sent_r   = Arc::clone(&sent_c);
                    let failed_r = Arc::clone(&failed_c);
                    let succ_r   = Arc::clone(&succ_c);
                    let resp_r   = Arc::clone(&resp_c);

                    tokio::spawn(async move {
                        let _permit = permit; // released when this task drops
                        let t0 = Instant::now();
                        sent_r.fetch_add(1, Ordering::Relaxed);

                        let result = client_r
                            .get(&url_c)
                            .header("User-Agent", ua)
                            .header("Accept", "text/html,application/xhtml+xml,*/*;q=0.9")
                            .header("Accept-Language", "fr-FR,fr;q=0.9,en;q=0.8")
                            .header("Cache-Control", "no-cache")
                            .header("Pragma", "no-cache")
                            .send()
                            .await;

                        let elapsed = t0.elapsed().as_millis() as u64;
                        resp_r.fetch_add(elapsed, Ordering::Relaxed);

                        match result {
                            Ok(r) if r.status().as_u16() < 500 => {
                                succ_r.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {
                                failed_r.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    });
                }
            });
        }

        // Wait for all user tasks to exit (they stop at deadline)
        while tasks.join_next().await.is_some() {}

        // Give in-flight requests a brief grace period to complete
        tokio::time::sleep(Duration::from_millis(500)).await;

        let wall_secs  = Instant::now().duration_since(deadline - Duration::from_secs(duration_seconds)).as_secs().max(1);
        let total      = sent.load(Ordering::SeqCst);
        let ok         = successful.load(Ordering::SeqCst);
        let fail       = failed.load(Ordering::SeqCst);
        let rps_actual = total / wall_secs.max(1);
        let avg_ms     = if total > 0 { resp_ms.load(Ordering::SeqCst) / total } else { 0 };
        let crash      = total > 0 && (fail as f64 / total as f64) > 0.5;

        let status = if crash {
            "HIGH_ERROR_RATE".to_string()
        } else {
            "SUCCESS".to_string()
        };

        Ok(LoadTestReport {
            target_url: target_url.to_string(),
            duration_seconds,
            concurrent_users,
            total_requests: total,
            successful_requests: ok,
            failed_requests: fail,
            requests_per_second: rps_actual,
            average_response_time_ms: avg_ms,
            status,
            server_crash: crash,
            recovery_time_seconds: 0,
            timestamp: Utc::now(),
        })
    }

    /// Simulate gradual ramp-up
    pub async fn ramp_up_test(
        &self,
        target_url: &str,
        max_users: usize,
        ramp_up_duration_seconds: u64,
    ) -> Result<LoadTestReport> {
        let step_size = (max_users / ramp_up_duration_seconds.max(1) as usize).max(1);
        let mut current_users = 0;

        for _second in 0..ramp_up_duration_seconds {
            current_users = std::cmp::min(current_users + step_size, max_users);
            self.run_load_test(target_url, current_users, 10, 1).await?;
        }

        self.run_load_test(target_url, max_users, 10, 10).await
    }

    /// Targeted endpoint test
    pub async fn targeted_load_test(
        &self,
        target_url: &str,
        endpoints: Vec<&str>,
        concurrent_requests: usize,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut tasks: JoinSet<(String, usize, Vec<u64>)> = JoinSet::new();
        let client = Arc::new(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap()
        );

        for endpoint in endpoints {
            let url         = format!("{}{}", target_url, endpoint);
            let client_c    = Arc::clone(&client);

            tasks.spawn(async move {
                let mut failed = 0usize;
                let mut response_times = Vec::new();

                for _ in 0..concurrent_requests {
                    let start = Instant::now();
                    match client_c.get(&url).send().await {
                        Ok(r) if r.status().as_u16() < 500 => {}
                        _ => failed += 1,
                    }
                    response_times.push(start.elapsed().as_millis() as u64);
                }
                (url, failed, response_times)
            });
        }

        while let Some(result) = tasks.join_next().await {
            if let Ok((url, fail_count, _times)) = result {
                if fail_count as f64 / concurrent_requests as f64 > 0.1 {
                    findings.push(Finding {
                        id: Uuid::new_v4(),
                        title: format!("Endpoint instable sous charge : {}", url),
                        description: format!(
                            "{}/{} requêtes ont échoué sous charge simultanée",
                            fail_count, concurrent_requests
                        ),
                        severity: Severity::High,
                        category: "Load Test".to_string(),
                        cve: None,
                        remediation: Some("Optimiser les performances ou ajouter du cache".to_string()),
                        affected_component: "API Endpoint".to_string(),
                        discovered_at: Utc::now(),
                    });
                }
            }
        }

        Ok(findings)
    }
}

impl Default for LoadTester {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LoadTestReport {
    pub target_url:             String,
    pub duration_seconds:       u64,
    pub concurrent_users:       usize,
    pub total_requests:         u64,
    pub successful_requests:    u64,
    pub failed_requests:        u64,
    pub requests_per_second:    u64,
    pub average_response_time_ms: u64,
    pub status:                 String,
    pub server_crash:           bool,
    pub recovery_time_seconds:  u64,
    pub timestamp:              chrono::DateTime<chrono::Utc>,
}
