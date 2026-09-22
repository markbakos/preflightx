use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    #[default]
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "info" | "informational" => Some(Self::Informational),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Informational => "INFORMATIONAL",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
    VeryHigh,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Complete,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Special,
}

#[derive(Clone, Debug, Serialize)]
pub struct FileRecord {
    pub path: String,
    pub kind: FileKind,
    pub size: u64,
    pub readonly: bool,
    pub mode: Option<u32>,
    pub sha256: Option<String>,
    pub extension: Option<String>,
    pub detected_mime: Option<String>,
    pub encoding: Option<String>,
    pub entropy: Option<f64>,
    pub line_count: Option<u64>,
    pub max_line_length: Option<u64>,
    pub symlink_target: Option<String>,
    pub roles: Vec<String>,
    pub raw_signals: Vec<String>,
    pub content_scanned: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct DependencyRecord {
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
    pub integrity: Option<String>,
    pub resolved: Option<String>,
    pub source_file: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub score: u8,
    pub title: String,
    pub message: String,
    pub file: Option<String>,
    pub line: Option<u64>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ScanSummary {
    pub entries: u64,
    pub files: u64,
    pub directories: u64,
    pub symlinks: u64,
    pub special_files: u64,
    pub content_bytes: u64,
    pub dependencies: u64,
    pub findings: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Risk {
    pub severity: Severity,
    pub score: u8,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub scanner: String,
    pub scanner_version: String,
    pub target: String,
    pub status: ScanStatus,
    pub network_access: String,
    pub risk: Risk,
    pub summary: ScanSummary,
    pub files: Vec<FileRecord>,
    pub dependencies: Vec<DependencyRecord>,
    pub findings: Vec<Finding>,
    pub incomplete_reasons: Vec<String>,
}

impl ScanReport {
    pub fn failed_policy(&self, threshold: Severity) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity >= threshold)
    }
}
