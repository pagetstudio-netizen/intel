/// CVE Database
/// Lookups for known vulnerabilities

use crate::Result;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

#[derive(Clone, Debug)]
pub struct CveEntry {
    pub id: String,
    pub package: String,
    pub version_affected: Vec<String>,
    pub severity: String,
    pub description: String,
}

pub struct CveDatabase {
    cache: Arc<RwLock<HashMap<String, Vec<CveEntry>>>>,
}

impl CveDatabase {
    pub fn new() -> Self {
        let mut cache = HashMap::new();
        // Pre-populate with some known CVEs
        cache.insert(
            "express".to_string(),
            vec![
                CveEntry {
                    id: "CVE-2022-24999".to_string(),
                    package: "express".to_string(),
                    version_affected: vec!["<4.17.1".to_string()],
                    severity: "medium".to_string(),
                    description: "Regular expression Denial of Service (ReDoS)".to_string(),
                },
            ],
        );

        Self {
            cache: Arc::new(RwLock::new(cache)),
        }
    }

    pub async fn lookup(&self, package_name: &str, version: &str) -> Result<Vec<CveEntry>> {
        let cache = self.cache.read();

        if let Some(entries) = cache.get(package_name) {
            // Filter entries that match this version
            let matching: Vec<_> = entries
                .iter()
                .filter(|entry| self.version_matches(version, &entry.version_affected))
                .cloned()
                .collect();

            log::debug!(
                "CVE lookup for: {} v{} - found {} matches",
                package_name,
                version,
                matching.len()
            );

            Ok(matching)
        } else {
            log::debug!("No CVE entries for package: {}", package_name);
            Ok(Vec::new())
        }
    }

    fn version_matches(&self, version: &str, affected: &[String]) -> bool {
        // Simplified version matching
        for affected_spec in affected {
            if affected_spec.contains('<') {
                // Extract version from "<X.Y.Z"
                let affected_version = affected_spec.trim_start_matches('<');
                if self.compare_versions(version, affected_version) < 0 {
                    return true;
                }
            } else if affected_spec == version {
                return true;
            }
        }
        false
    }

    fn compare_versions(&self, v1: &str, v2: &str) -> i32 {
        let v1_parts: Vec<u32> = v1
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();
        let v2_parts: Vec<u32> = v2
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();

        for i in 0..std::cmp::max(v1_parts.len(), v2_parts.len()) {
            let p1 = v1_parts.get(i).copied().unwrap_or(0);
            let p2 = v2_parts.get(i).copied().unwrap_or(0);

            if p1 < p2 {
                return -1;
            } else if p1 > p2 {
                return 1;
            }
        }
        0
    }

    pub fn add_cve(&self, entry: CveEntry) {
        let mut cache = self.cache.write();
        cache
            .entry(entry.package.clone())
            .or_insert_with(Vec::new)
            .push(entry);
    }
}

impl Default for CveDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cve_lookup() {
        let db = CveDatabase::new();
        let results = db.lookup("express", "4.17.0").await.unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn test_version_comparison() {
        let db = CveDatabase::new();
        assert!(db.compare_versions("1.0.0", "2.0.0") < 0);
        assert!(db.compare_versions("2.0.0", "1.0.0") > 0);
        assert_eq!(db.compare_versions("1.0.0", "1.0.0"), 0);
    }
}