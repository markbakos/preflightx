use super::limits::ScanLimits;
use crate::model::{Confidence, FileKind, FileRecord, Finding, Severity};
use std::{
    collections::VecDeque,
    fs::{self, File, Metadata},
    io::Read,
    path::{Component, Path, PathBuf},
};

pub struct FileInput {
    pub path: PathBuf,
    pub relative: String,
    pub metadata: Metadata,
    pub bytes: Option<Vec<u8>>,
}

pub struct WalkResult {
    pub root: PathBuf,
    pub other_records: Vec<FileRecord>,
    pub findings: Vec<Finding>,
    pub incomplete_reasons: Vec<String>,
    pub entries: u64,
    pub files: u64,
    pub directories: u64,
    pub symlinks: u64,
    pub special_files: u64,
    pub content_bytes: u64,
}

impl WalkResult {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            other_records: Vec::new(),
            findings: Vec::new(),
            incomplete_reasons: Vec::new(),
            entries: 0,
            files: 0,
            directories: 0,
            symlinks: 0,
            special_files: 0,
            content_bytes: 0,
        }
    }

    fn incomplete(&mut self, reason: String) {
        if !self.incomplete_reasons.contains(&reason) {
            self.incomplete_reasons.push(reason);
        }
    }
}

pub fn walk(
    requested_root: &Path,
    limits: &ScanLimits,
    mut on_file: impl FnMut(FileInput),
) -> WalkResult {
    let root = match fs::canonicalize(requested_root) {
        Ok(root) => root,
        Err(error) => {
            let mut result = WalkResult::new(requested_root.to_path_buf());
            result.incomplete(format!(
                "cannot resolve scan root {}: {error}",
                display_path(requested_root)
            ));
            return result;
        }
    };
    let mut result = WalkResult::new(root.clone());
    let root_metadata = match fs::metadata(&root) {
        Ok(metadata) if metadata.is_dir() => metadata,
        Ok(_) => {
            result.incomplete("scan root is not a directory".to_owned());
            return result;
        }
        Err(error) => {
            result.incomplete(format!("cannot inspect scan root: {error}"));
            return result;
        }
    };
    if !root_metadata.is_dir() {
        result.incomplete("scan root is not a directory".to_owned());
        return result;
    }

    let mut pending = VecDeque::from([(root.clone(), 0_usize)]);
    result.directories = 1;

    while let Some((directory, depth)) = pending.pop_front() {
        if depth > limits.max_depth {
            result.incomplete(format!(
                "maximum directory depth {} reached at {}",
                limits.max_depth,
                relative_path(&root, &directory)
            ));
            continue;
        }

        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                result.incomplete(format!(
                    "cannot read directory {}: {error}",
                    relative_path(&root, &directory)
                ));
                continue;
            }
        };

        let remaining = limits
            .max_entries
            .saturating_sub(result.entries)
            .saturating_add(1)
            .min(usize::MAX as u64) as usize;
        let mut entries = match entries.take(remaining).collect::<Result<Vec<_>, _>>() {
            Ok(entries) => entries,
            Err(error) => {
                result.incomplete(format!(
                    "cannot enumerate directory {}: {error}",
                    relative_path(&root, &directory)
                ));
                continue;
            }
        };
        entries.sort_by_key(|entry| entry.file_name());

        for entry in entries {
            if result.entries >= limits.max_entries {
                result.incomplete(format!(
                    "maximum entry count {} reached",
                    limits.max_entries
                ));
                pending.clear();
                break;
            }

            result.entries += 1;
            let path = entry.path();
            let relative = relative_path(&root, &path);
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    result.incomplete(format!("cannot inspect file type for {relative}: {error}"));
                    continue;
                }
            };

            if file_type.is_symlink() {
                inspect_symlink(&root, &path, relative, &mut result);
            } else if file_type.is_dir() {
                result.directories += 1;
                if depth == limits.max_depth {
                    result.incomplete(format!(
                        "maximum directory depth {} reached at {}",
                        limits.max_depth,
                        relative_path(&root, &path)
                    ));
                } else {
                    pending.push_back((path, depth + 1));
                }
            } else if file_type.is_file() {
                inspect_file(&root, path, relative, limits, &mut result, &mut on_file);
            } else {
                inspect_special(path, relative, &mut result);
            }
        }
    }

    result
}

fn inspect_file(
    root: &Path,
    path: PathBuf,
    relative: String,
    limits: &ScanLimits,
    result: &mut WalkResult,
    on_file: &mut impl FnMut(FileInput),
) {
    result.files += 1;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => {
            result.incomplete(format!("file type changed while scanning {relative}"));
            return;
        }
        Err(error) => {
            result.incomplete(format!("cannot inspect {relative}: {error}"));
            return;
        }
    };

    if metadata.len() > limits.max_file_bytes {
        result.incomplete(format!(
            "file exceeds {} byte limit: {relative}",
            limits.max_file_bytes
        ));
        on_file(FileInput {
            path,
            relative,
            metadata,
            bytes: None,
        });
        return;
    }

    if result.content_bytes.saturating_add(metadata.len()) > limits.max_total_bytes {
        result.incomplete(format!(
            "total content byte limit {} reached before {relative}",
            limits.max_total_bytes
        ));
        on_file(FileInput {
            path,
            relative,
            metadata,
            bytes: None,
        });
        return;
    }

    let resolved = match fs::canonicalize(&path) {
        Ok(resolved) if resolved.starts_with(root) => resolved,
        Ok(_) => {
            result.incomplete(format!("path escaped scan root while opening {relative}"));
            result.findings.push(Finding {
                id: "FS-PATH-ESCAPE".to_owned(),
                severity: Severity::High,
                confidence: Confidence::High,
                score: 80,
                title: "Path escaped repository root".to_owned(),
                message: "A repository entry resolved outside the scan root and was not read."
                    .to_owned(),
                file: Some(relative),
                line: None,
                evidence: Vec::new(),
            });
            return;
        }
        Err(error) => {
            result.incomplete(format!("cannot resolve {relative}: {error}"));
            return;
        }
    };

    let mut file = match File::open(&resolved) {
        Ok(file) => file,
        Err(error) => {
            result.incomplete(format!("cannot open {relative}: {error}"));
            on_file(FileInput {
                path,
                relative,
                metadata,
                bytes: None,
            });
            return;
        }
    };
    let opened_metadata = match file.metadata() {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => {
            result.incomplete(format!("{relative} changed to a non-file while scanning"));
            return;
        }
        Err(error) => {
            result.incomplete(format!("cannot inspect opened file {relative}: {error}"));
            return;
        }
    };
    let mut bytes = Vec::with_capacity(opened_metadata.len().min(limits.max_file_bytes) as usize);
    let read_limit = limits.max_file_bytes.saturating_add(1);
    match file.by_ref().take(read_limit).read_to_end(&mut bytes) {
        Ok(_)
            if bytes.len() as u64 <= limits.max_file_bytes
                && result.content_bytes.saturating_add(bytes.len() as u64)
                    <= limits.max_total_bytes =>
        {
            result.content_bytes += bytes.len() as u64;
            on_file(FileInput {
                path,
                relative,
                metadata: opened_metadata,
                bytes: Some(bytes),
            });
        }
        Ok(_) => {
            result.incomplete(format!(
                "file growth exceeded a content byte limit while scanning {relative}"
            ));
            on_file(FileInput {
                path,
                relative,
                metadata: opened_metadata,
                bytes: None,
            });
        }
        Err(error) => {
            result.incomplete(format!("cannot read {relative}: {error}"));
            on_file(FileInput {
                path,
                relative,
                metadata: opened_metadata,
                bytes: None,
            });
        }
    }
}

fn inspect_symlink(root: &Path, path: &Path, relative: String, result: &mut WalkResult) {
    result.symlinks += 1;
    let target = match fs::read_link(path) {
        Ok(target) => target,
        Err(error) => {
            result.incomplete(format!("cannot read symlink {relative}: {error}"));
            return;
        }
    };
    let absolute = target.is_absolute();
    let resolved = lexical_normalize(&path.parent().unwrap_or(root).join(&target));
    let escapes = !resolved.starts_with(root);
    let target_text = display_path(&target);
    result.other_records.push(FileRecord {
        path: relative.clone(),
        kind: FileKind::Symlink,
        size: 0,
        readonly: false,
        mode: None,
        sha256: None,
        extension: path
            .extension()
            .map(|value| value.to_string_lossy().to_ascii_lowercase()),
        detected_mime: None,
        encoding: None,
        entropy: None,
        line_count: None,
        max_line_length: None,
        symlink_target: Some(target_text.clone()),
        roles: Vec::new(),
        raw_signals: Vec::new(),
        content_scanned: false,
        parsed_language: None,
    });

    if escapes {
        result.findings.push(Finding {
            id: "FS-SYMLINK-ESCAPE".to_owned(),
            severity: Severity::High,
            confidence: Confidence::VeryHigh,
            score: 80,
            title: "Symlink escapes repository root".to_owned(),
            message: "The symlink target is outside the repository and was not read.".to_owned(),
            file: Some(relative),
            line: None,
            evidence: vec![format!("target: {target_text}")],
        });
    } else if absolute {
        result.findings.push(Finding {
            id: "FS-ABSOLUTE-SYMLINK".to_owned(),
            severity: Severity::Medium,
            confidence: Confidence::VeryHigh,
            score: 40,
            title: "Repository contains an absolute symlink".to_owned(),
            message: "Absolute symlinks are not followed during scanning.".to_owned(),
            file: Some(relative),
            line: None,
            evidence: vec![format!("target: {target_text}")],
        });
    }
}

fn inspect_special(path: PathBuf, relative: String, result: &mut WalkResult) {
    result.special_files += 1;
    result.incomplete(format!("special file was not read: {relative}"));
    result.other_records.push(FileRecord {
        path: relative.clone(),
        kind: FileKind::Special,
        size: 0,
        readonly: false,
        mode: None,
        sha256: None,
        extension: path
            .extension()
            .map(|value| value.to_string_lossy().to_ascii_lowercase()),
        detected_mime: None,
        encoding: None,
        entropy: None,
        line_count: None,
        max_line_length: None,
        symlink_target: None,
        roles: Vec::new(),
        raw_signals: Vec::new(),
        content_scanned: false,
        parsed_language: None,
    });
    result.findings.push(Finding {
        id: "FS-SPECIAL-FILE".to_owned(),
        severity: Severity::Medium,
        confidence: Confidence::VeryHigh,
        score: 45,
        title: "Repository contains a special file".to_owned(),
        message: "Devices, FIFOs, and sockets are never opened by the scanner.".to_owned(),
        file: Some(relative),
        line: None,
        evidence: Vec::new(),
    });
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(display_path)
        .unwrap_or_else(|_| display_path(path))
}

fn display_path(path: &Path) -> String {
    let value = path.to_string_lossy().replace('\\', "/");
    if value.is_empty() {
        ".".to_owned()
    } else {
        value
    }
}

pub fn mode(metadata: &Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(metadata.permissions().mode())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}
