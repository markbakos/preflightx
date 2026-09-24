use crate::model::{Confidence, DependencyRecord, Finding, Severity};
use flate2::read::GzDecoder;
use serde::Deserialize;
use std::{collections::HashMap, io::Read, sync::OnceLock};

const SNAPSHOT: &[u8] = include_bytes!("../threat-db/snapshot.json.gz");
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

static DATABASE: OnceLock<Result<Database, String>> = OnceLock::new();

#[derive(Debug, Deserialize)]
struct Database {
    format_version: u32,
    version: String,
    snapshot_date: String,
    sources: Vec<String>,
    records: Vec<PackageRecord>,
    hashes: Vec<HashRecord>,
    domains: Vec<String>,
    urls: Vec<String>,
    #[serde(skip)]
    package_index: HashMap<(String, String, String), usize>,
    #[serde(skip)]
    hash_index: HashMap<String, usize>,
}

#[derive(Debug, Deserialize)]
struct PackageRecord {
    provider: String,
    record_id: String,
    ecosystem: String,
    name: String,
    versions: Vec<String>,
    record_modified: String,
    summary: String,
    provenance: String,
}

#[derive(Debug, Deserialize)]
struct HashRecord {
    provider: String,
    record_id: String,
    sha256: String,
    provenance: String,
}

fn database() -> Result<&'static Database, String> {
    DATABASE
        .get_or_init(load_database)
        .as_ref()
        .map_err(Clone::clone)
}

fn load_database() -> Result<Database, String> {
    let decoder = GzDecoder::new(SNAPSHOT);
    let mut content = Vec::new();
    decoder
        .take((MAX_SNAPSHOT_BYTES + 1) as u64)
        .read_to_end(&mut content)
        .map_err(|error| format!("cannot decompress embedded threat database: {error}"))?;
    if content.len() > MAX_SNAPSHOT_BYTES {
        return Err("embedded threat database exceeds its 64 MiB limit".to_owned());
    }
    let database: Database = serde_json::from_slice(&content)
        .map_err(|error| format!("embedded threat database is malformed: {error}"))?;
    if database.format_version != 1
        || database.records.len() > 1_000_000
        || database.hashes.len() > 1_000_000
        || database.domains.len().saturating_add(database.urls.len()) > 1_000_000
    {
        return Err("embedded threat database header or record count is unsupported".to_owned());
    }
    if !valid_text(&database.version, 128)
        || !valid_text(&database.snapshot_date, 32)
        || database.sources.len() > 64
        || database
            .sources
            .iter()
            .any(|source| !valid_text(source, 128))
        || database.records.iter().any(|record| {
            !valid_text(&record.provider, 128)
                || !valid_text(&record.record_id, 128)
                || !valid_text(&record.ecosystem, 64)
                || !valid_text(&record.name, 256)
                || !valid_text(&record.summary, 512)
                || !valid_text(&record.record_modified, 32)
                || !valid_text(&record.provenance, 2_048)
                || !record.provenance.starts_with("https://")
                || record.versions.len() > 10_000
                || record
                    .versions
                    .iter()
                    .any(|version| !valid_text(version, 128))
        })
        || database.hashes.iter().any(|record| {
            !valid_text(&record.provider, 128)
                || !valid_text(&record.record_id, 128)
                || record.sha256.len() != 64
                || !record.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !valid_text(&record.provenance, 2_048)
                || !record.provenance.starts_with("https://")
        })
        || database
            .domains
            .iter()
            .chain(&database.urls)
            .any(|value| !valid_text(value, 2_048))
    {
        return Err("embedded threat database contains an invalid record".to_owned());
    }
    let mut package_index = HashMap::new();
    for (index, record) in database.records.iter().enumerate() {
        for version in &record.versions {
            package_index
                .entry((
                    record.ecosystem.to_ascii_lowercase(),
                    record.name.to_ascii_lowercase(),
                    version.clone(),
                ))
                .or_insert(index);
        }
    }
    let hash_index = database
        .hashes
        .iter()
        .enumerate()
        .map(|(index, record)| (record.sha256.to_ascii_lowercase(), index))
        .collect();
    Ok(Database {
        package_index,
        hash_index,
        ..database
    })
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

pub fn package_finding(dependency: &DependencyRecord) -> Result<Option<Finding>, String> {
    let Some(version) = dependency.version.as_deref() else {
        return Ok(None);
    };
    let database = database()?;
    let key = (
        dependency.ecosystem.to_ascii_lowercase(),
        dependency.name.to_ascii_lowercase(),
        version.to_owned(),
    );
    let matched = database
        .package_index
        .get(&key)
        .map(|index| &database.records[*index]);
    Ok(matched.map(|record| Finding {
        id: "THREAT-KNOWN-MALICIOUS-PACKAGE".to_owned(),
        severity: Severity::Critical,
        confidence: Confidence::VeryHigh,
        score: 100,
        title: "Exact dependency version is in the local malicious-package database".to_owned(),
        message: format!(
            "{}@{} matches an exact affected version from {}.",
            dependency.name, version, record.provider
        ),
        file: Some(dependency.source_file.clone()),
        line: None,
        evidence: vec![
            format!("ecosystem: {}", record.ecosystem),
            format!("record: {}", record.record_id),
            format!("affected version: {version}"),
            format!("record modified: {}", record.record_modified),
            format!("summary: {}", record.summary),
            format!("provenance: {}", record.provenance),
        ],
    }))
}

pub fn hash_finding(path: &str, sha256: &str) -> Result<Option<Finding>, String> {
    let database = database()?;
    let matched = database
        .hash_index
        .get(&sha256.to_ascii_lowercase())
        .map(|index| &database.hashes[*index]);
    Ok(matched.map(|record| Finding {
        id: "THREAT-KNOWN-MALICIOUS-HASH".to_owned(),
        severity: Severity::Critical,
        confidence: Confidence::VeryHigh,
        score: 100,
        title: "File hash is in the local malicious-artifact database".to_owned(),
        message: format!(
            "The SHA-256 matches a hash reported by {}.",
            record.provider
        ),
        file: Some(path.to_owned()),
        line: None,
        evidence: vec![
            format!("record: {}", record.record_id),
            format!("SHA-256: {}", record.sha256),
            format!("provenance: {}", record.provenance),
        ],
    }))
}

pub fn status() -> Result<String, String> {
    let database = database()?;
    Ok(format!(
        "Threat database {}\nSnapshot date: {}\nRecords: {} package records, {} hashes, {} domains, {} URLs\nSources: {}\nVerification: embedded in this PreflightX build\nCoverage: seed snapshot; not a complete OpenSSF feed\n",
        database.version,
        database.snapshot_date,
        database.records.len(),
        database.hashes.len(),
        database.domains.len(),
        database.urls.len(),
        database.sources.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::{package_finding, status};
    use crate::model::DependencyRecord;

    fn dependency(name: &str, version: &str) -> DependencyRecord {
        DependencyRecord {
            ecosystem: "npm".to_owned(),
            name: name.to_owned(),
            version: Some(version.to_owned()),
            integrity: None,
            resolved: None,
            source_file: "package-lock.json".to_owned(),
        }
    }

    #[test]
    fn matches_only_explicit_open_ssf_affected_versions() {
        assert_eq!(
            package_finding(&dependency("node-slot", "1.0.7"))
                .unwrap()
                .unwrap()
                .id,
            "THREAT-KNOWN-MALICIOUS-PACKAGE"
        );
        assert!(
            package_finding(&dependency("node-slot", "1.0.6"))
                .unwrap()
                .is_none()
        );
        assert!(
            package_finding(&dependency("not-node-slot", "1.0.7"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn reports_embedded_database_metadata() {
        let status = status().unwrap();
        assert!(status.contains("OpenSSF Malicious Packages"));
        assert!(status.contains("1 package records"));
    }
}
