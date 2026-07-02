/// Endpoint Discovery Fuzzer
/// Discovers hidden/sensitive endpoints using wordlists and patterns

use crate::{FuzzJob, FuzzResult, Result};
use reqwest::Client;
use std::time::Instant;
use tokio::task::JoinSet;

pub struct EndpointFuzzer {
    client: Client,
}

impl EndpointFuzzer {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    pub async fn fuzz(&self, job: &FuzzJob) -> Result<Vec<FuzzResult>> {
        log::info!(
            "Fuzzing endpoints on {} with {} wordlist entries",
            job.target_url,
            job.wordlist.len()
        );

        let mut results = Vec::new();
        let mut tasks = JoinSet::new();

        let base_url = job.target_url.clone();
        let method = job.method.clone();
        let timeout_ms = job.timeout_ms;
        let max_requests = job.concurrent_requests * 100;
        let wordlist: Vec<String> = job.wordlist.clone();

        // Spawn concurrent fuzz tasks
        for (idx, path) in wordlist.into_iter().enumerate() {
            if idx >= max_requests {
                break; // Limit total requests
            }

            let url = format!("{}/{}", base_url, path);
            let method_clone = method.clone();
            let client = self.client.clone();
            let timeout = std::time::Duration::from_millis(timeout_ms);

            tasks.spawn(async move {
                let start = Instant::now();
                let result = match method_clone.as_str() {
                    "GET" => client.get(&url).timeout(timeout).send().await,
                    "POST" => client.post(&url).timeout(timeout).send().await,
                    "HEAD" => client.head(&url).timeout(timeout).send().await,
                    _ => client.get(&url).timeout(timeout).send().await,
                };

                match result {
                    Ok(response) => {
                        let status = response.status().as_u16();
                        let content_length = response
                            .content_length()
                            .unwrap_or(0)
                            .try_into()
                            .unwrap_or(0);
                        let response_time_ms = start.elapsed().as_millis() as u64;

                        // Filter out 404s and common noise
                        if status != 404 && response_time_ms < timeout_ms {
                            Some(FuzzResult {
                                path,
                                status_code: status,
                                response_size: content_length,
                                response_time_ms,
                            })
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        log::debug!("Fuzzing error for {}: {}", url, e);
                        None
                    }
                }
            });
        }

        // Collect results
        while let Some(result) = tasks.join_next().await {
            if let Ok(Some(fuzz_result)) = result {
                results.push(fuzz_result);
            }
        }

        // Sort by status code and response time
        results.sort_by_key(|r| (r.status_code, r.response_time_ms));

        log::info!("Fuzzing completed: {} endpoints discovered", results.len());

        Ok(results)
    }
}

impl Default for EndpointFuzzer {
    fn default() -> Self {
        Self::new()
    }
}