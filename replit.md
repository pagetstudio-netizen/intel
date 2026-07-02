# INTEL - Pentest & Security Auditing Platform

A suite of security tools for authorized penetration testing and security auditing.

## Stack

- **Language**: Rust (security-core engine)
- **Modules**: Vulnerability scanner, SAST, dependency scanner, endpoint fuzzer, load tester, fintech compliance scanner

## How to Build

```bash
cd security-core
cargo build --release
```

The compiled binary will be at `security-core/target/release/intel`.

## How to Run

### Vulnerability Scan
```bash
./security-core/target/release/intel scan --target http://your-app.com
./security-core/target/release/intel scan --target http://your-app.com --deep --timeout 120
```

### Endpoint Fuzzer
```bash
./security-core/target/release/intel fuzz --target http://your-app.com
./security-core/target/release/intel fuzz --target http://your-app.com --concurrency 20
```

## Project Structure

```
intel/
├── security-core/          # Rust engine (compiled CLI binary)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs          # Shared types (Finding, ScanConfig, FuzzJob, etc.)
│       ├── main.rs         # CLI entry point
│       ├── scanner/        # Vulnerability scanners
│       │   ├── dependency.rs
│       │   ├── sast.rs
│       │   ├── config.rs
│       │   ├── cve.rs
│       │   ├── fintech.rs
│       │   └── load_tester.rs
│       └── fuzzer/         # Endpoint discovery
│           ├── endpoints.rs
│           └── wordlist.rs
└── docs/                   # Documentation and audit guides
```

## Notes

- Use ONLY on systems you are authorized to test
- The backend/frontend/proxy components referenced in the README are not yet implemented (see project tasks)
