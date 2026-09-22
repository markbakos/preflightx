use super::{raw, walker};
use crate::model::{Confidence, FileKind, FileRecord, Finding, Severity};
use sha2::{Digest, Sha256};
use std::{fmt::Write, fs::Metadata, path::Path};

pub struct Classification {
    pub record: FileRecord,
    pub findings: Vec<Finding>,
    pub text: Option<String>,
}

pub fn classify(relative: &str, path: &Path, metadata: &Metadata, bytes: &[u8]) -> Classification {
    let extension = path
        .extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase());
    let detected_mime = infer::get(bytes).map(|kind| kind.mime_type().to_owned());
    let (encoding, text) = decode_text(bytes);
    let raw = raw::analyze(relative, bytes, text.as_deref());
    let mut findings = raw.findings;

    if let Some(finding) = mismatch_finding(
        relative,
        extension.as_deref(),
        detected_mime.as_deref(),
        text.as_deref(),
    ) {
        findings.push(finding);
    }

    if is_non_code_extension(extension.as_deref())
        && text.as_deref().is_some_and(looks_like_executable_text)
    {
        findings.push(Finding {
            id: "FILE-EXECUTABLE-CONTENT".to_owned(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            score: 45,
            title: "Executable-looking text uses a non-code extension".to_owned(),
            message: "The file contains multiple source-code indicators despite its declared asset or data extension."
                .to_owned(),
            file: Some(relative.to_owned()),
            line: None,
            evidence: extension
                .as_ref()
                .map(|value| vec![format!("extension: .{value}")])
                .unwrap_or_default(),
        });
    }

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let sha256 = hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a string cannot fail");
            output
        });

    Classification {
        record: FileRecord {
            path: relative.to_owned(),
            kind: FileKind::File,
            size: metadata.len(),
            readonly: metadata.permissions().readonly(),
            mode: walker::mode(metadata),
            sha256: Some(sha256),
            extension,
            detected_mime,
            encoding,
            entropy: Some(raw.entropy),
            line_count: Some(raw.line_count),
            max_line_length: Some(raw.max_line_length),
            symlink_target: None,
            roles: roles(relative),
            raw_signals: raw.signals,
            content_scanned: true,
        },
        findings,
        text,
    }
}

pub fn unscanned_record(relative: &str, path: &Path, metadata: &Metadata) -> FileRecord {
    FileRecord {
        path: relative.to_owned(),
        kind: FileKind::File,
        size: metadata.len(),
        readonly: metadata.permissions().readonly(),
        mode: walker::mode(metadata),
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
        roles: roles(relative),
        raw_signals: Vec::new(),
        content_scanned: false,
    }
}

fn decode_text(bytes: &[u8]) -> (Option<String>, Option<String>) {
    if let Some(bytes) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return match std::str::from_utf8(bytes) {
            Ok(text) => (Some("utf-8-bom".to_owned()), Some(text.to_owned())),
            Err(_) => (Some("unknown".to_owned()), None),
        };
    }
    if let Some(bytes) = bytes.strip_prefix(&[0xff, 0xfe]) {
        if bytes.len() % 2 != 0 {
            return (Some("unknown".to_owned()), None);
        }
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        return match String::from_utf16(&units) {
            Ok(text) => (Some("utf-16le".to_owned()), Some(text)),
            Err(_) => (Some("unknown".to_owned()), None),
        };
    }
    if let Some(bytes) = bytes.strip_prefix(&[0xfe, 0xff]) {
        if bytes.len() % 2 != 0 {
            return (Some("unknown".to_owned()), None);
        }
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        return match String::from_utf16(&units) {
            Ok(text) => (Some("utf-16be".to_owned()), Some(text)),
            Err(_) => (Some("unknown".to_owned()), None),
        };
    }
    if bytes.iter().take(8_192).any(|byte| *byte == 0) {
        return (Some("binary".to_owned()), None);
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => (Some("utf-8".to_owned()), Some(text.to_owned())),
        Err(_) => (Some("unknown".to_owned()), None),
    }
}

fn mismatch_finding(
    path: &str,
    extension: Option<&str>,
    detected_mime: Option<&str>,
    text: Option<&str>,
) -> Option<Finding> {
    let expected = match extension? {
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "pdf" => Some("application/pdf"),
        "zip" => Some("application/zip"),
        "gz" | "gzip" => Some("application/gzip"),
        "woff" => Some("font/woff"),
        "woff2" => Some("font/woff2"),
        _ => None,
    };
    let svg_mismatch = extension == Some("svg")
        && text.is_some_and(|value| {
            let value = value.trim_start_matches('\u{feff}').trim_start();
            !value.starts_with("<svg") && !value.starts_with("<?xml")
        });
    let signature_mismatch = expected.is_some_and(|expected| detected_mime != Some(expected));
    if !svg_mismatch && !signature_mismatch {
        return None;
    }
    let severity = if detected_mime.is_some_and(is_executable_mime) {
        Severity::High
    } else {
        Severity::Medium
    };
    Some(Finding {
        id: "FILE-TYPE-MISMATCH".to_owned(),
        severity,
        confidence: Confidence::High,
        score: if severity == Severity::High { 80 } else { 45 },
        title: "File extension does not match its content".to_owned(),
        message: "The declared file type disagrees with byte signatures or expected structure."
            .to_owned(),
        file: Some(path.to_owned()),
        line: None,
        evidence: vec![
            format!("extension: .{}", extension.unwrap_or_default()),
            format!("detected MIME: {}", detected_mime.unwrap_or("unknown")),
        ],
    })
}

fn is_executable_mime(value: &str) -> bool {
    value.contains("executable")
        || value.contains("x-elf")
        || value.contains("x-msdownload")
        || value.contains("portable-executable")
}

fn is_non_code_extension(extension: Option<&str>) -> bool {
    matches!(
        extension,
        Some(
            "svg"
                | "woff"
                | "woff2"
                | "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "json"
                | "data"
                | "txt"
                | "md"
                | "lock"
        )
    )
}

fn looks_like_executable_text(text: &str) -> bool {
    let markers = [
        "require(",
        "child_process",
        "process.env",
        "eval(",
        "new Function",
        "function ",
        "const ",
        "import ",
        "Invoke-Expression",
        "#!/bin/",
    ];
    markers
        .iter()
        .filter(|marker| text.contains(**marker))
        .count()
        >= 2
}

fn roles(path: &str) -> Vec<String> {
    let normalized = path.replace('\\', "/");
    let name = normalized.rsplit('/').next().unwrap_or(&normalized);
    let mut roles = Vec::new();
    if name == "package.json" {
        roles.push("npm_manifest".to_owned());
    }
    if matches!(
        name,
        "package-lock.json" | "npm-shrinkwrap.json" | "yarn.lock" | "pnpm-lock.yaml"
    ) {
        roles.push("dependency_lockfile".to_owned());
    }
    if normalized.starts_with(".vscode/") || normalized == ".devcontainer/devcontainer.json" {
        roles.push("developer_tool_config".to_owned());
    }
    if is_executable_config(name) {
        roles.push("executable_config".to_owned());
    }
    if normalized.starts_with(".github/workflows/")
        || name == ".gitlab-ci.yml"
        || name == "Jenkinsfile"
    {
        roles.push("ci_config".to_owned());
    }
    if matches!(
        name,
        "Makefile" | "Dockerfile" | "justfile" | "Taskfile" | "Taskfile.yml"
    ) || name.starts_with("docker-compose")
    {
        roles.push("build_script".to_owned());
    }
    roles
}

fn is_executable_config(name: &str) -> bool {
    [
        "vite.config.",
        "webpack.config.",
        "tailwind.config.",
        "postcss.config.",
        "eslint.config.",
        "next.config.",
        "babel.config.",
        "jest.config.",
        "rollup.config.",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::{decode_text, mismatch_finding};

    #[test]
    fn flags_javascript_disguised_as_svg() {
        assert!(
            mismatch_finding(
                "asset.svg",
                Some("svg"),
                None,
                Some("const cp = require('child_process');")
            )
            .is_some()
        );
    }

    #[test]
    fn accepts_structural_svg_text() {
        assert!(
            mismatch_finding(
                "asset.svg",
                Some("svg"),
                None,
                Some("<svg xmlns='http://www.w3.org/2000/svg'></svg>")
            )
            .is_none()
        );
    }

    #[test]
    fn classifies_nul_bytes_as_binary() {
        let (encoding, text) = decode_text(b"\0\0\0\0");
        assert_eq!(encoding.as_deref(), Some("binary"));
        assert!(text.is_none());
    }
}
