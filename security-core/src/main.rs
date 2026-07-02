/// INTEL Security Core - CLI Entry Point

use clap::{Parser, Subcommand};
use intel_security_core::{
    fuzzer::EndpointFuzzer,
    scanner::VulnerabilityScanner,
    FuzzJob, ScanConfig,
};

#[derive(Parser)]
#[command(
    name = "intel",
    about = "INTEL - Pentest & Security Auditing Platform",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a vulnerability scan against a target
    Scan {
        /// Target URL to scan
        #[arg(short, long)]
        target: String,

        /// Enable deep scan mode
        #[arg(short, long, default_value_t = false)]
        deep: bool,

        /// Include dependency scanning
        #[arg(long, default_value_t = true)]
        deps: bool,

        /// Include SAST code scanning
        #[arg(long, default_value_t = true)]
        sast: bool,

        /// Timeout in seconds
        #[arg(long, default_value_t = 60)]
        timeout: u64,
    },
    /// Discover endpoints via fuzzing
    Fuzz {
        /// Target URL to fuzz
        #[arg(short, long)]
        target: String,

        /// Number of concurrent threads
        #[arg(short, long, default_value_t = 10)]
        concurrency: usize,

        /// Timeout per request in milliseconds
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u64,
    },
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            deep,
            deps,
            sast,
            timeout,
        } => {
            println!("🔍 INTEL Vulnerability Scanner");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Target : {}", target);
            println!("Mode   : {}", if deep { "Deep" } else { "Standard" });
            println!();

            let config = ScanConfig {
                target_url: target,
                timeout_secs: timeout,
                deep_scan: deep,
                include_dependencies: deps,
                include_code_scan: sast,
            };

            let scanner = VulnerabilityScanner::new();
            match scanner.scan(config).await {
                Ok(result) => {
                    println!("✅ Scan complete — {} finding(s)", result.findings.len());
                    println!();
                    for finding in &result.findings {
                        println!(
                            "[{}] {} — {}",
                            finding.severity, finding.title, finding.affected_component
                        );
                        println!("    {}", finding.description);
                        if let Some(ref rem) = finding.remediation {
                            println!("    ↳ Fix: {}", rem);
                        }
                        if let Some(ref cve) = finding.cve {
                            println!("    ↳ Ref: {}", cve);
                        }
                        println!();
                    }
                    if let Some(dur) = result.duration_secs {
                        println!("⏱  Duration: {}s", dur);
                    }
                }
                Err(e) => {
                    eprintln!("❌ Scan failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Fuzz {
            target,
            concurrency,
            timeout_ms,
        } => {
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
                        println!(
                            "[{}] {} — {}b in {}ms",
                            r.status_code, r.path, r.response_size, r.response_time_ms
                        );
                    }
                }
                Err(e) => {
                    eprintln!("❌ Fuzzing failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
