use flate2::read::GzDecoder;
use std::{
    io::{Cursor, Read},
    path::Path,
    time::{Duration, Instant},
};

const MAX_MEMBER_BYTES: u64 = 32 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MEMBERS: usize = 50_000;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_COMPRESSION_RATIO: u64 = 1_000;

pub struct Limits {
    pub depth: usize,
    pub members: usize,
    pub expanded_bytes: u64,
    pub member_bytes: u64,
    pub time_limit: Duration,
}

pub struct VirtualFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Default)]
pub struct ResultSet {
    pub files: Vec<VirtualFile>,
    pub incomplete_reasons: Vec<String>,
}

struct Budget {
    limits: Limits,
    expanded: u64,
    deadline: Instant,
}

pub fn extract(path: &str, bytes: &[u8], limits: Limits) -> ResultSet {
    let deadline = Instant::now() + limits.time_limit;
    let mut result = ResultSet::default();
    let mut budget = Budget {
        limits,
        expanded: 0,
        deadline,
    };
    expand(path.to_owned(), bytes, 0, &mut budget, &mut result);
    result
}

fn expand(path: String, bytes: &[u8], depth: usize, budget: &mut Budget, result: &mut ResultSet) {
    let kind = if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        1
    } else if bytes.starts_with(&[0x1f, 0x8b]) {
        2
    } else if bytes.len() >= 512 && &bytes[257..262] == b"ustar" {
        3
    } else {
        return;
    };
    if depth >= budget.limits.depth {
        result
            .incomplete_reasons
            .push(format!("archive recursion limit reached at {path}"));
        return;
    }
    match kind {
        1 => expand_zip(&path, bytes, depth, budget, result),
        2 => expand_gzip(&path, bytes, depth, budget, result),
        _ => expand_tar(&path, bytes, depth, budget, result),
    }
}

fn expand_zip(path: &str, bytes: &[u8], depth: usize, budget: &mut Budget, result: &mut ResultSet) {
    let mut archive = match zip::ZipArchive::new(Cursor::new(bytes)) {
        Ok(archive) => archive,
        Err(error) => {
            result
                .incomplete_reasons
                .push(format!("cannot parse ZIP archive {path}: {error}"));
            return;
        }
    };
    let member_limit = budget.limits.members.min(MAX_MEMBERS);
    let count = archive.len();
    if count > member_limit.saturating_sub(result.files.len()) {
        result.incomplete_reasons.push(format!(
            "archive member limit of {} reached at {path}",
            budget.limits.members
        ));
    }
    for index in 0..count.min(member_limit.saturating_sub(result.files.len())) {
        if time_limit_reached(path, budget, result) {
            break;
        }
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(error) => {
                result
                    .incomplete_reasons
                    .push(format!("cannot read ZIP member {index} in {path}: {error}"));
                continue;
            }
        };
        let member_path = match safe_member_path(entry.name_raw()) {
            Ok(member_path) => member_path,
            Err(reason) => {
                result
                    .incomplete_reasons
                    .push(format!("{reason} in {path}"));
                continue;
            }
        };
        let child_path = format!("{path}!/{member_path}");
        if entry.is_dir() {
            continue;
        }
        if entry.is_symlink() {
            result
                .incomplete_reasons
                .push(format!("ZIP symlink member skipped: {child_path}"));
            continue;
        }
        let uncompressed = entry.size();
        let compressed = entry.compressed_size();
        if over_ratio(uncompressed, compressed) {
            result
                .incomplete_reasons
                .push(format!("ZIP compression ratio limit reached: {child_path}"));
            continue;
        }
        if uncompressed > budget.limits.member_bytes.min(MAX_MEMBER_BYTES) {
            result
                .incomplete_reasons
                .push(format!("archive member exceeds byte limit: {child_path}"));
            continue;
        }
        if !reserve(uncompressed, &child_path, budget, result) {
            continue;
        }
        let mut content = Vec::with_capacity(uncompressed as usize);
        if let Err(error) = entry.read_to_end(&mut content) {
            result
                .incomplete_reasons
                .push(format!("cannot decompress {child_path}: {error}"));
            continue;
        }
        if content.len() as u64 != uncompressed {
            result
                .incomplete_reasons
                .push(format!("ZIP member size mismatch: {child_path}"));
            continue;
        }
        if time_limit_reached(&child_path, budget, result) {
            continue;
        }
        push_file(child_path, content, depth, budget, result);
    }
}

fn expand_tar(path: &str, bytes: &[u8], depth: usize, budget: &mut Budget, result: &mut ResultSet) {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(error) => {
            result
                .incomplete_reasons
                .push(format!("cannot read TAR archive {path}: {error}"));
            return;
        }
    };
    for (index, item) in entries.enumerate() {
        if time_limit_reached(path, budget, result) {
            break;
        }
        if result.files.len() >= budget.limits.members.min(MAX_MEMBERS) {
            result.incomplete_reasons.push(format!(
                "archive member limit of {} reached at {path}",
                budget.limits.members
            ));
            break;
        }
        let mut entry = match item {
            Ok(entry) => entry,
            Err(error) => {
                result
                    .incomplete_reasons
                    .push(format!("cannot read TAR member {index} in {path}: {error}"));
                continue;
            }
        };
        let entry_type = entry.header().entry_type();
        let member_path = match safe_member_path(&entry.path_bytes()) {
            Ok(member_path) => member_path,
            Err(reason) => {
                result
                    .incomplete_reasons
                    .push(format!("{reason} in {path}"));
                continue;
            }
        };
        let child_path = format!("{path}!/{member_path}");
        if entry_type.is_dir() {
            continue;
        }
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            result
                .incomplete_reasons
                .push(format!("TAR link member skipped: {child_path}"));
            continue;
        }
        if !entry_type.is_file() && !entry_type.is_contiguous() {
            result
                .incomplete_reasons
                .push(format!("unsupported TAR member skipped: {child_path}"));
            continue;
        }
        let size = entry.size();
        if size > budget.limits.member_bytes.min(MAX_MEMBER_BYTES) {
            result
                .incomplete_reasons
                .push(format!("archive member exceeds byte limit: {child_path}"));
            continue;
        }
        if !reserve(size, &child_path, budget, result) {
            continue;
        }
        let mut content = Vec::with_capacity(size as usize);
        if let Err(error) = entry.read_to_end(&mut content) {
            result
                .incomplete_reasons
                .push(format!("cannot read {child_path}: {error}"));
            continue;
        }
        if content.len() as u64 != size {
            result
                .incomplete_reasons
                .push(format!("TAR member size mismatch: {child_path}"));
            continue;
        }
        if time_limit_reached(&child_path, budget, result) {
            continue;
        }
        push_file(child_path, content, depth, budget, result);
    }
}

fn expand_gzip(
    path: &str,
    bytes: &[u8],
    depth: usize,
    budget: &mut Budget,
    result: &mut ResultSet,
) {
    if time_limit_reached(path, budget, result) {
        return;
    }
    let child_path = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".gz"))
        .filter(|name| !name.is_empty())
        .map_or_else(
            || format!("{path}!/content"),
            |name| format!("{path}!/{name}"),
        );
    let maximum = budget
        .limits
        .member_bytes
        .min(MAX_MEMBER_BYTES)
        .min(budget.limits.expanded_bytes.saturating_sub(budget.expanded));
    let mut decoder = GzDecoder::new(bytes);
    let mut content = Vec::new();
    if let Err(error) = decoder
        .by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut content)
    {
        result
            .incomplete_reasons
            .push(format!("cannot decompress gzip archive {path}: {error}"));
        return;
    }
    if content.len() as u64 > maximum {
        result
            .incomplete_reasons
            .push(format!("gzip member exceeds byte limit: {child_path}"));
        return;
    }
    if over_ratio(content.len() as u64, bytes.len() as u64) {
        result.incomplete_reasons.push(format!(
            "gzip compression ratio limit reached: {child_path}"
        ));
        return;
    }
    if time_limit_reached(&child_path, budget, result) {
        return;
    }
    if !reserve(content.len() as u64, &child_path, budget, result) {
        return;
    }
    push_file(child_path, content, depth, budget, result);
}

fn push_file(
    path: String,
    bytes: Vec<u8>,
    depth: usize,
    budget: &mut Budget,
    result: &mut ResultSet,
) {
    if result.files.len() >= budget.limits.members.min(MAX_MEMBERS) {
        result
            .incomplete_reasons
            .push(format!("archive member limit reached at {path}"));
        return;
    }
    expand(path.clone(), &bytes, depth + 1, budget, result);
    result.files.push(VirtualFile { path, bytes });
}

fn reserve(size: u64, path: &str, budget: &mut Budget, result: &mut ResultSet) -> bool {
    if time_limit_reached(path, budget, result) {
        return false;
    }
    if budget.expanded.saturating_add(size) > budget.limits.expanded_bytes.min(MAX_EXPANDED_BYTES) {
        result
            .incomplete_reasons
            .push(format!("archive expanded byte limit reached before {path}"));
        return false;
    }
    budget.expanded += size;
    true
}

fn time_limit_reached(path: &str, budget: &Budget, result: &mut ResultSet) -> bool {
    if Instant::now() < budget.deadline {
        return false;
    }
    if !result
        .incomplete_reasons
        .iter()
        .any(|reason| reason.starts_with("archive time limit reached"))
    {
        result
            .incomplete_reasons
            .push(format!("archive time limit reached at {path}"));
    }
    true
}

fn over_ratio(size: u64, compressed: u64) -> bool {
    compressed == 0 && size > 0
        || compressed > 0 && size > compressed.saturating_mul(MAX_COMPRESSION_RATIO)
}

fn safe_member_path(raw: &[u8]) -> Result<String, String> {
    if raw.is_empty() || raw.len() > MAX_PATH_BYTES {
        return Err("archive member has an invalid path length".to_owned());
    }
    let path = std::str::from_utf8(raw)
        .map_err(|_| "archive member path is not valid UTF-8".to_owned())?;
    let normalized = path.replace('\\', "/");
    if normalized.starts_with('/')
        || normalized.starts_with("//")
        || normalized.chars().any(char::is_control)
        || normalized
            .split('/')
            .any(|component| component == ".." || component.contains(':'))
    {
        return Err(format!("archive traversal path rejected: {path}"));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::{Limits, extract, safe_member_path};
    use std::io::{Cursor, Write};
    use std::time::Duration;
    use zip::{ZipWriter, write::SimpleFileOptions};

    fn limits() -> Limits {
        Limits {
            depth: 4,
            members: 128,
            expanded_bytes: 1024 * 1024,
            member_bytes: 64 * 1024,
            time_limit: Duration::from_secs(5),
        }
    }

    #[test]
    fn rejects_traversal_and_absolute_paths() {
        for path in ["../escape", "/absolute", "C:\\outside", "a/../../b"] {
            assert!(safe_member_path(path.as_bytes()).is_err());
        }
        assert_eq!(
            safe_member_path(b"folder/file.js").unwrap(),
            "folder/file.js"
        );
    }

    #[test]
    fn malformed_zip_is_incomplete() {
        let result = extract("bad.zip", b"PK\x03\x04broken", limits());
        assert!(result.files.is_empty());
        assert!(!result.incomplete_reasons.is_empty());
    }

    fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (path, content) in entries {
            writer
                .start_file(*path, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn scans_members_and_reports_traversal_and_depth_limits() {
        let nested = zip(&[(
            "payload.ps1",
            b"DownloadString FromBase64String Invoke-Expression",
        )]);
        let outer = zip(&[("../escape.ps1", b"ignored"), ("nested.zip", &nested)]);
        let result = extract(
            "outer.zip",
            &outer,
            Limits {
                depth: 1,
                ..limits()
            },
        );
        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].path.ends_with("nested.zip"));
        assert!(
            result
                .incomplete_reasons
                .iter()
                .any(|reason| reason.contains("traversal path"))
        );
        assert!(
            result
                .incomplete_reasons
                .iter()
                .any(|reason| reason.contains("recursion limit"))
        );
    }

    #[test]
    fn enforces_member_count_before_extracting_more_content() {
        let archive = zip(&[("one.txt", b"1"), ("two.txt", b"2")]);
        let result = extract(
            "many.zip",
            &archive,
            Limits {
                members: 1,
                ..limits()
            },
        );
        assert_eq!(result.files.len(), 1);
        assert!(!result.incomplete_reasons.is_empty());
    }

    #[test]
    fn reports_an_expired_archive_time_budget() {
        let archive = zip(&[("one.txt", b"1")]);
        let result = extract(
            "slow.zip",
            &archive,
            Limits {
                time_limit: Duration::ZERO,
                ..limits()
            },
        );
        assert!(result.files.is_empty());
        assert!(
            result
                .incomplete_reasons
                .iter()
                .any(|reason| reason.contains("time limit"))
        );
    }
}
