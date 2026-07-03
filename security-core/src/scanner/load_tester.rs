/// Load Testing — Multi-Geographic Distribution Module
/// Simulates realistic global traffic from multiple continents.
/// Each virtual user gets a geographic profile (IP range, language, UA).

use crate::{Finding, Result, Severity};
use uuid::Uuid;
use chrono::Utc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use tokio::sync::Semaphore;

// ─── Geographic Profiles ─────────────────────────────────────────────────────
// Each profile represents a realistic origin: public IP blocks, language,
// and browser UA strings typical for that country/region.
// IP ranges used are public ISP ranges (not private/RFC-1918).

struct GeoProfile {
    country:        &'static str,
    country_code:   &'static str,
    // Representative public IPs from major ISPs in each country
    ip_pool:        &'static [&'static str],
    accept_language: &'static str,
    user_agents:    &'static [&'static str],
}

static GEO_PROFILES: &[GeoProfile] = &[
    // ── France ───────────────────────────────────────────────────
    GeoProfile {
        country: "France", country_code: "FR",
        ip_pool: &[
            "2.22.61.43","90.74.12.108","176.143.44.12","109.190.64.78",
            "82.64.12.33","88.121.45.17","213.245.129.42","78.250.44.18",
        ],
        accept_language: "fr-FR,fr;q=0.9,en;q=0.8",
        user_agents: &[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
        ],
    },
    // ── United States ────────────────────────────────────────────
    GeoProfile {
        country: "United States", country_code: "US",
        ip_pool: &[
            "71.190.44.23","98.234.56.78","50.203.12.44","24.17.45.90",
            "76.102.23.55","173.79.44.12","162.158.0.44","104.28.12.33",
        ],
        accept_language: "en-US,en;q=0.9",
        user_agents: &[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        ],
    },
    // ── United Kingdom ───────────────────────────────────────────
    GeoProfile {
        country: "United Kingdom", country_code: "GB",
        ip_pool: &[
            "86.7.44.12","92.29.45.77","81.130.12.44","82.44.56.90",
            "109.154.44.22","217.44.55.12","51.140.44.33","20.90.44.12",
        ],
        accept_language: "en-GB,en;q=0.9",
        user_agents: &[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
        ],
    },
    // ── Germany ──────────────────────────────────────────────────
    GeoProfile {
        country: "Germany", country_code: "DE",
        ip_pool: &[
            "84.119.44.12","217.229.45.33","85.179.12.44","91.65.44.78",
            "188.100.44.23","46.223.45.12","185.220.44.55","141.30.44.11",
        ],
        accept_language: "de-DE,de;q=0.9,en;q=0.8",
        user_agents: &[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        ],
    },
    // ── Brazil ───────────────────────────────────────────────────
    GeoProfile {
        country: "Brazil", country_code: "BR",
        ip_pool: &[
            "177.23.44.12","191.7.45.33","200.148.44.78","189.62.12.44",
            "187.73.44.23","170.83.45.12","45.235.44.55","138.0.44.11",
        ],
        accept_language: "pt-BR,pt;q=0.9,en;q=0.8",
        user_agents: &[
            "Mozilla/5.0 (Linux; Android 14; Samsung Galaxy S23) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        ],
    },
    // ── Nigeria ──────────────────────────────────────────────────
    GeoProfile {
        country: "Nigeria", country_code: "NG",
        ip_pool: &[
            "41.190.44.12","105.112.45.33","41.184.12.44","197.210.44.78",
            "41.204.44.23","102.89.45.12","41.206.44.55","196.216.44.11",
        ],
        accept_language: "en-NG,en;q=0.9",
        user_agents: &[
            "Mozilla/5.0 (Linux; Android 13; Tecno Camon 19) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 12; Samsung Galaxy A53) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
        ],
    },
    // ── Morocco ──────────────────────────────────────────────────
    GeoProfile {
        country: "Morocco", country_code: "MA",
        ip_pool: &[
            "41.140.44.12","196.200.45.33","41.248.12.44","196.12.44.78",
            "196.217.44.23","105.190.45.12","41.141.44.55","105.71.44.11",
        ],
        accept_language: "fr-MA,fr;q=0.9,ar;q=0.8,en;q=0.7",
        user_agents: &[
            "Mozilla/5.0 (Linux; Android 13; Infinix Hot 30) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        ],
    },
    // ── Senegal ──────────────────────────────────────────────────
    GeoProfile {
        country: "Senegal", country_code: "SN",
        ip_pool: &[
            "41.82.44.12","196.202.45.33","41.214.12.44","212.98.44.78",
            "196.207.44.23","154.120.45.12","41.85.44.55","105.241.44.11",
        ],
        accept_language: "fr-SN,fr;q=0.9,wo;q=0.8,en;q=0.7",
        user_agents: &[
            "Mozilla/5.0 (Linux; Android 12; Infinix Hot 20) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 11; Tecno Spark 7) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
        ],
    },
    // ── Kenya ────────────────────────────────────────────────────
    GeoProfile {
        country: "Kenya", country_code: "KE",
        ip_pool: &[
            "41.90.44.12","196.207.45.33","41.80.12.44","105.163.44.78",
            "196.201.44.23","154.123.45.12","41.89.44.55","196.43.44.11",
        ],
        accept_language: "en-KE,en;q=0.9,sw;q=0.8",
        user_agents: &[
            "Mozilla/5.0 (Linux; Android 13; Samsung Galaxy A14) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 12; Tecno Pova 4) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
        ],
    },
    // ── South Africa ─────────────────────────────────────────────
    GeoProfile {
        country: "South Africa", country_code: "ZA",
        ip_pool: &[
            "41.160.44.12","196.215.45.33","41.204.12.44","196.25.44.78",
            "105.26.44.23","196.223.45.12","41.163.44.55","197.189.44.11",
        ],
        accept_language: "en-ZA,en;q=0.9,af;q=0.8",
        user_agents: &[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Samsung Galaxy A23) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
        ],
    },
    // ── India ────────────────────────────────────────────────────
    GeoProfile {
        country: "India", country_code: "IN",
        ip_pool: &[
            "103.21.44.12","49.204.45.33","122.161.12.44","117.196.44.78",
            "59.180.44.23","14.139.45.12","103.68.44.55","27.60.44.11",
        ],
        accept_language: "hi-IN,hi;q=0.9,en-IN;q=0.8,en;q=0.7",
        user_agents: &[
            "Mozilla/5.0 (Linux; Android 14; Redmi Note 13) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Vivo V27) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
        ],
    },
    // ── Canada ───────────────────────────────────────────────────
    GeoProfile {
        country: "Canada", country_code: "CA",
        ip_pool: &[
            "99.225.44.12","142.116.45.33","70.31.12.44","64.228.44.78",
            "24.222.44.23","206.167.45.12","147.253.44.55","192.197.44.11",
        ],
        accept_language: "en-CA,en;q=0.9,fr-CA;q=0.8",
        user_agents: &[
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
        ],
    },
];

// ─── Counters per country ─────────────────────────────────────────────────────
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct GeoStat {
    pub country:      String,
    pub country_code: String,
    pub requests:     u64,
    pub successful:   u64,
    pub failed:       u64,
}

pub struct LoadTester {
    requests_sent:       Arc<AtomicU64>,
    requests_failed:     Arc<AtomicU64>,
    requests_successful: Arc<AtomicU64>,
    total_response_ms:   Arc<AtomicU64>,
}

impl LoadTester {
    pub fn new() -> Self {
        Self {
            requests_sent:       Arc::new(AtomicU64::new(0)),
            requests_failed:     Arc::new(AtomicU64::new(0)),
            requests_successful: Arc::new(AtomicU64::new(0)),
            total_response_ms:   Arc::new(AtomicU64::new(0)),
        }
    }

    /// Run multi-geo load test.
    /// Virtual users are distributed evenly across all geographic profiles.
    /// Each user sends requests using headers from its assigned country.
    pub async fn run_load_test(
        &self,
        target_url: &str,
        concurrent_users: usize,
        requests_per_second: usize,
        duration_seconds: u64,
    ) -> Result<LoadTestReport> {
        log::info!(
            "Starting multi-geo load test: {} users across {} countries, {} req/s, {}s — target: {}",
            concurrent_users, GEO_PROFILES.len(), requests_per_second, duration_seconds, target_url
        );

        let client: Arc<reqwest::Client> = Arc::new(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .connect_timeout(Duration::from_secs(5))
                .danger_accept_invalid_certs(false)
                .tcp_keepalive(Duration::from_secs(15))
                .pool_max_idle_per_host(concurrent_users.min(200))
                .build()
                .map_err(|e| crate::IntelError::Scan(e.to_string()))?
        );

        let max_inflight = std::cmp::min(concurrent_users * 4, 800);
        let semaphore    = Arc::new(Semaphore::new(max_inflight));
        let deadline     = Instant::now() + Duration::from_secs(duration_seconds);

        let sent       = Arc::clone(&self.requests_sent);
        let failed     = Arc::clone(&self.requests_failed);
        let successful = Arc::clone(&self.requests_successful);
        let resp_ms    = Arc::clone(&self.total_response_ms);

        // Per-country atomic counters (sent / ok / fail)
        let n_geo = GEO_PROFILES.len();
        let geo_sent: Arc<Vec<AtomicU64>> = Arc::new((0..n_geo).map(|_| AtomicU64::new(0)).collect());
        let geo_ok:   Arc<Vec<AtomicU64>> = Arc::new((0..n_geo).map(|_| AtomicU64::new(0)).collect());
        let geo_fail: Arc<Vec<AtomicU64>> = Arc::new((0..n_geo).map(|_| AtomicU64::new(0)).collect());

        let interval_ms = 1000u64
            .checked_div(requests_per_second as u64)
            .unwrap_or(100)
            .max(10);

        let mut tasks: JoinSet<()> = JoinSet::new();

        for user_id in 0..concurrent_users {
            let geo_idx  = user_id % n_geo;
            let geo      = &GEO_PROFILES[geo_idx];
            let ip       = geo.ip_pool[user_id % geo.ip_pool.len()];
            let lang     = geo.accept_language;
            let ua       = geo.user_agents[user_id % geo.user_agents.len()];
            let cc       = geo.country_code;

            let url       = target_url.to_string();
            let client_c  = Arc::clone(&client);
            let sem_c     = Arc::clone(&semaphore);
            let sent_c    = Arc::clone(&sent);
            let failed_c  = Arc::clone(&failed);
            let succ_c    = Arc::clone(&successful);
            let resp_c    = Arc::clone(&resp_ms);
            let gs_c      = Arc::clone(&geo_sent);
            let go_c      = Arc::clone(&geo_ok);
            let gf_c      = Arc::clone(&geo_fail);

            // Convert &'static str to owned Strings for the async move block
            let ip_s   = ip.to_string();
            let lang_s = lang.to_string();
            let ua_s   = ua.to_string();
            let cc_s   = cc.to_string();

            tasks.spawn(async move {
                let _ = cc_s; // used for naming only
                let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    ticker.tick().await;
                    if Instant::now() >= deadline { break; }

                    let permit = match sem_c.clone().try_acquire_owned() {
                        Ok(p)  => p,
                        Err(_) => {
                            failed_c.fetch_add(1, Ordering::Relaxed);
                            sent_c.fetch_add(1, Ordering::Relaxed);
                            gf_c[geo_idx].fetch_add(1, Ordering::Relaxed);
                            gs_c[geo_idx].fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };

                    let url_r    = url.clone();
                    let client_r = Arc::clone(&client_c);
                    let sent_r   = Arc::clone(&sent_c);
                    let failed_r = Arc::clone(&failed_c);
                    let succ_r   = Arc::clone(&succ_c);
                    let resp_r   = Arc::clone(&resp_c);
                    let gs_r     = Arc::clone(&gs_c);
                    let go_r     = Arc::clone(&go_c);
                    let gf_r     = Arc::clone(&gf_c);
                    let ip_r     = ip_s.clone();
                    let lang_r   = lang_s.clone();
                    let ua_r     = ua_s.clone();

                    tokio::spawn(async move {
                        let _permit = permit;
                        let t0 = Instant::now();
                        sent_r.fetch_add(1, Ordering::Relaxed);
                        gs_r[geo_idx].fetch_add(1, Ordering::Relaxed);

                        let result = client_r
                            .get(&url_r)
                            // Geographic identity headers
                            .header("User-Agent",        &ua_r)
                            .header("Accept-Language",   &lang_r)
                            .header("X-Forwarded-For",   &ip_r)
                            .header("X-Real-IP",         &ip_r)
                            .header("CF-Connecting-IP",  &ip_r)
                            // Standard browser headers
                            .header("Accept",            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                            .header("Accept-Encoding",   "gzip, deflate, br")
                            .header("Cache-Control",     "no-cache")
                            .header("Pragma",            "no-cache")
                            .header("Connection",        "keep-alive")
                            .send()
                            .await;

                        let elapsed = t0.elapsed().as_millis() as u64;
                        resp_r.fetch_add(elapsed, Ordering::Relaxed);

                        match result {
                            Ok(r) if r.status().as_u16() < 500 => {
                                succ_r.fetch_add(1, Ordering::Relaxed);
                                go_r[geo_idx].fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {
                                failed_r.fetch_add(1, Ordering::Relaxed);
                                gf_r[geo_idx].fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    });
                }
            });
        }

        while tasks.join_next().await.is_some() {}
        tokio::time::sleep(Duration::from_millis(500)).await;

        let wall_secs  = duration_seconds.max(1);
        let total      = sent.load(Ordering::SeqCst);
        let ok         = successful.load(Ordering::SeqCst);
        let fail       = failed.load(Ordering::SeqCst);
        let rps_actual = total / wall_secs;
        let avg_ms     = if total > 0 { resp_ms.load(Ordering::SeqCst) / total } else { 0 };
        let crash      = total > 0 && (fail as f64 / total as f64) > 0.5;

        // Build per-country breakdown
        let geo_breakdown: Vec<GeoStat> = GEO_PROFILES.iter().enumerate().map(|(i, p)| {
            GeoStat {
                country:      p.country.to_string(),
                country_code: p.country_code.to_string(),
                requests:     geo_sent[i].load(Ordering::SeqCst),
                successful:   geo_ok[i].load(Ordering::SeqCst),
                failed:       geo_fail[i].load(Ordering::SeqCst),
            }
        }).collect();

        let status = if crash { "HIGH_ERROR_RATE".to_string() } else { "SUCCESS".to_string() };

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
            geo_breakdown,
            countries_used: GEO_PROFILES.len() as u64,
            timestamp: Utc::now(),
        })
    }

    /// Ramp-up test (gradual load increase)
    pub async fn ramp_up_test(
        &self,
        target_url: &str,
        max_users: usize,
        ramp_up_duration_seconds: u64,
    ) -> Result<LoadTestReport> {
        let step = (max_users / ramp_up_duration_seconds.max(1) as usize).max(1);
        let mut current = 0;
        for _ in 0..ramp_up_duration_seconds {
            current = std::cmp::min(current + step, max_users);
            self.run_load_test(target_url, current, 10, 1).await?;
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
            reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap()
        );

        for endpoint in endpoints {
            let url = format!("{}{}", target_url, endpoint);
            let client_c = Arc::clone(&client);
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
            if let Ok((url, fail_count, _)) = result {
                if fail_count as f64 / concurrent_requests as f64 > 0.1 {
                    findings.push(Finding {
                        id: Uuid::new_v4(),
                        title: format!("Endpoint instable sous charge : {}", url),
                        description: format!("{}/{} requêtes échouées sous charge simultanée", fail_count, concurrent_requests),
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
    pub target_url:               String,
    pub duration_seconds:         u64,
    pub concurrent_users:         usize,
    pub total_requests:           u64,
    pub successful_requests:      u64,
    pub failed_requests:          u64,
    pub requests_per_second:      u64,
    pub average_response_time_ms: u64,
    pub status:                   String,
    pub server_crash:             bool,
    pub recovery_time_seconds:    u64,
    pub geo_breakdown:            Vec<GeoStat>,
    pub countries_used:           u64,
    pub timestamp:                chrono::DateTime<chrono::Utc>,
}
