#[derive(Clone, Debug)]
pub struct ScanLimits {
    pub max_depth: usize,
    pub max_entries: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_findings: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_entries: 200_000,
            max_file_bytes: 64 * 1024 * 1024,
            max_total_bytes: 2 * 1024 * 1024 * 1024,
            max_findings: 20_000,
        }
    }
}
