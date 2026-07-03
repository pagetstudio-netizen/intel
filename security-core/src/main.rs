/// INTEL Security Core - CLI Entry Point

use clap::{Parser, Subcommand};
use intel_security_core::{
    fuzzer::EndpointFuzzer,
    scanner::{LoadTester, VulnerabilityScanner},
    FuzzJob, ScanConfig,
};

#[derive(Parser)]
#[command(name = "intel", about = "INTEL — Pentest & Security Auditing Platform", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Vulnerability scan
    Scan {
        #[arg(short, long)] target: String,
        #[arg(short, long, default_value_t = false)] deep: bool,
        #[arg(long, default_value_t = true)] deps: bool,
        #[arg(long, default_value_t = true)] sast: bool,
        #[arg(long, default_value_t = 60)] timeout: u64,
    },
    /// Endpoint fuzzer
    Fuzz {
        #[arg(short, long)] target: String,
        #[arg(short, long, default_value_t = 10)] concurrency: usize,
        #[arg(long, default_value_t = 5000)] timeout_ms: u64,
    },
    /// Load / stress test
    LoadTest {
        #[arg(short, long)] target: String,
        #[arg(short, long, default_value_t = 50)] users: usize,
        #[arg(short, long, default_value_t = 10)] rps: usize,
        #[arg(short, long, default_value_t = 30)] duration: u64,
    },
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { target, deep, deps, sast, timeout } => {
            println!("🔍 INTEL Vulnerability Scanner");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Target : {}", target);
            println!("Mode   : {}", if deep { "Deep" } else { "Standard" });
            println!();

            let config = ScanConfig { target_url: target, timeout_secs: timeout, deep_scan: deep, include_dependencies: deps, include_code_scan: sast };
            let scanner = VulnerabilityScanner::new();
            match scanner.scan(config).await {
                Ok(result) => {
                    println!("✅ Scan complete — {} finding(s)", result.findings.len());
                    println!();
                    for f in &result.findings {
                        println!("[{}] {} — {}", f.severity, f.title, f.affected_component);
                        println!("    {}", f.description);
                        if let Some(ref r) = f.remediation { println!("    ↳ Fix: {}", r); }
                        if let Some(ref c) = f.cve { println!("    ↳ Ref: {}", c); }
                        println!();
                    }
                    if let Some(d) = result.duration_secs { println!("⏱  Duration: {}s", d); }
                }
                Err(e) => { eprintln!("❌ Scan failed: {}", e); std::process::exit(1); }
            }
        }

        Commands::Fuzz { target, concurrency, timeout_ms } => {
            println!("🕸  INTEL Endpoint Fuzzer");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Target      : {}", target);
            println!("Concurrency : {}", concurrency);
            println!();
            let mut job = FuzzJob::new(&target);
            job.concurrent_requests = concurrency;
            job.timeout_ms = timeout_ms;
            let fuzzer = EndpointFuzzer::new();
            match fuzzer.fuzz(&job).await {
                Ok(results) => {
                    println!("✅ {} endpoint(s) discovered", results.len());
                    println!();
                    for r in &results {
                        println!("[{}] {} — {}b in {}ms", r.status_code, r.path, r.response_size, r.response_time_ms);
                    }
                }
                Err(e) => { eprintln!("❌ Fuzzing failed: {}", e); std::process::exit(1); }
            }
        }

        Commands::LoadTest { target, users, rps, duration } => {
            println!("⚡ INTEL Multi-Geo Load Tester");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Target   : {}", target);
            println!("Users    : {}", users);
            println!("Req/s    : {}", rps);
            println!("Duration : {}s", duration);
            println!();

            let tester = LoadTester::new();
            match tester.run_load_test(&target, users, rps, duration).await {
                Ok(report) => {
                    // Machine-readable block for backend parsing
                    println!("TOTAL_REQUESTS={}", report.total_requests);
                    println!("SUCCESSFUL={}", report.successful_requests);
                    println!("FAILED={}", report.failed_requests);
                    println!("RPS={}", report.requests_per_second);
                    println!("AVG_MS={}", report.average_response_time_ms);
                    println!("STATUS={}", report.status);
                    println!("CRASH={}", report.server_crash);
                    println!("COUNTRIES={}", report.countries_used);
                    // Geo breakdown as JSON line for backend
                    if let Ok(geo_json) = serde_json::to_string(&report.geo_breakdown) {
                        println!("GEO_BREAKDOWN={}", geo_json);
                    }
                }
                Err(e) => { eprintln!("❌ Load test failed: {}", e); std::process::exit(1); }
            }
        }
    }
}
