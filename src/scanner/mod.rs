mod analyzers;
mod archives;
mod classifier;
mod dependencies;
mod graph;
mod js;
mod languages;
mod limits;
mod raw;
mod walker;
mod yara;

pub use limits::ScanLimits;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanOptions {
    pub quick: bool,
    pub deep: bool,
    pub history: bool,
    pub dependencies: bool,
    pub online: bool,
}

const MAX_SEMANTIC_MODULES: usize = 20_000;
const MAX_SEMANTIC_BYTES: usize = 64 * 1024 * 1024;
const MAX_ONLINE_PACKAGES: usize = 1_000;
const MAX_ONLINE_ARCHIVE_FILES: usize = 20_000;
const MAX_ONLINE_EXPANDED_BYTES: u64 = 512 * 1024 * 1024;

use crate::model::{Risk, ScanReport, ScanStatus, ScanSummary, Severity};
use std::{
    collections::BTreeMap,
    path::Path,
    time::{Duration, Instant},
};

pub fn scan(path: &Path, limits: &ScanLimits) -> ScanReport {
    scan_with_options(path, limits, &ScanOptions::default())
}

pub(crate) fn doctor() -> Result<(), String> {
    yara::doctor()
}

pub fn scan_with_options(path: &Path, limits: &ScanLimits, options: &ScanOptions) -> ScanReport {
    let mut bounded_limits = limits.clone();
    if options.quick {
        bounded_limits.max_depth = bounded_limits.max_depth.min(32);
        bounded_limits.max_entries = bounded_limits.max_entries.min(20_000);
        bounded_limits.max_file_bytes = bounded_limits.max_file_bytes.min(16 * 1024 * 1024);
        bounded_limits.max_total_bytes = bounded_limits.max_total_bytes.min(512 * 1024 * 1024);
        bounded_limits.max_dependencies = bounded_limits.max_dependencies.min(50_000);
    }
    let limits = &bounded_limits;
    let mut files = Vec::new();
    let mut dependencies = Vec::new();
    let mut findings = Vec::new();
    let mut analyzer_incomplete = Vec::new();
    let mut modules = Vec::new();
    let mut roots = Vec::new();
    let mut semantic_bytes = 0usize;
    let mut semantic_limit_reported = false;
    let mut archive_file_count = 0_u64;
    let mut archive_content_bytes = 0_u64;
    let mut archive_incomplete = Vec::new();
    let archive_time_limit = if options.quick {
        Duration::from_secs(5)
    } else if options.deep {
        Duration::from_secs(60)
    } else {
        Duration::from_secs(30)
    };
    let archive_deadline = Instant::now() + archive_time_limit;

    let mut walk = walker::walk(path, limits, |input| {
        let Some(bytes) = input.bytes else {
            files.push(classifier::unscanned_record(
                &input.relative,
                &input.path,
                &input.metadata,
            ));
            return;
        };
        let mut classification =
            classifier::classify(&input.relative, &input.path, &input.metadata, &bytes);
        analyzer_incomplete.append(&mut classification.incomplete_reasons);
        if let Some(sha256) = classification.record.sha256.as_deref() {
            match crate::threat_db::hash_finding(&input.relative, sha256) {
                Ok(Some(finding)) => classification.findings.push(finding),
                Ok(None) => {}
                Err(error) => analyzer_incomplete.push(error),
            }
        }
        let metadata = analyzers::analyze(&input.relative, classification.text.as_deref());
        let javascript = js::analyze(&input.relative, classification.text.as_deref());
        let language = languages::analyze(&input.relative, classification.text.as_deref());
        if roots.len() < graph::MAX_EXECUTION_ROOTS {
            let root_analysis = graph::roots(
                &input.relative,
                classification.text.as_deref(),
                &classification.record.roles,
            );
            if root_analysis.incomplete {
                analyzer_incomplete.push(format!(
                    "JS/TS execution root extraction limit reached: {}",
                    input.relative
                ));
            }
            let available = graph::MAX_EXECUTION_ROOTS.saturating_sub(roots.len());
            if root_analysis.roots.len() >= available {
                analyzer_incomplete.push(format!(
                    "JS/TS global execution root limit of {} reached; remaining roots omitted",
                    graph::MAX_EXECUTION_ROOTS
                ));
            }
            roots.extend(root_analysis.roots.into_iter().take(available));
        }
        for embedded in javascript.embedded_roots {
            if roots.len() == graph::MAX_EXECUTION_ROOTS {
                analyzer_incomplete.push(format!(
                    "JS/TS global execution root limit of {} reached; embedded scripts omitted",
                    graph::MAX_EXECUTION_ROOTS
                ));
                break;
            }
            roots.push(graph::Root {
                file: embedded.module_id,
                trigger: format!("inline script in HTML document {}", input.relative),
                line: Some(embedded.line),
            });
        }
        for module in javascript.modules {
            let size = module.source_bytes;
            if modules.len() >= MAX_SEMANTIC_MODULES
                || semantic_bytes.saturating_add(size) > MAX_SEMANTIC_BYTES
            {
                if !semantic_limit_reported {
                    analyzer_incomplete.push(format!(
                        "JS/TS global semantic analysis limit of {MAX_SEMANTIC_MODULES} modules or {MAX_SEMANTIC_BYTES} source bytes reached before {}; additional modules were omitted",
                        input.relative
                    ));
                    semantic_limit_reported = true;
                }
            } else {
                semantic_bytes += size;
                modules.push(module);
            }
        }
        classification.record.parsed_language = javascript.language.or(language.language);
        if !javascript.findings.is_empty() {
            classification
                .findings
                .retain(|finding| finding.id != "FILE-EXECUTABLE-CONTENT");
        }
        append_limited(
            &mut findings,
            classification.findings,
            limits.max_findings,
            "finding limit reached",
            &mut analyzer_incomplete,
        );
        append_limited(
            &mut findings,
            metadata.findings,
            limits.max_findings,
            "finding limit reached",
            &mut analyzer_incomplete,
        );
        append_limited(
            &mut findings,
            javascript.findings,
            limits.max_findings,
            "finding limit reached",
            &mut analyzer_incomplete,
        );
        append_limited(
            &mut findings,
            language.findings,
            limits.max_findings,
            "finding limit reached",
            &mut analyzer_incomplete,
        );
        append_limited(
            &mut dependencies,
            metadata.dependencies,
            limits.max_dependencies,
            "dependency record limit reached",
            &mut analyzer_incomplete,
        );
        analyzer_incomplete.extend(metadata.incomplete_reasons);
        analyzer_incomplete.extend(javascript.incomplete_reasons);
        analyzer_incomplete.extend(language.incomplete_reasons);
        files.push(classification.record);

        if bytes.starts_with(b"PK\x03\x04")
            || bytes.starts_with(b"PK\x05\x06")
            || bytes.starts_with(&[0x1f, 0x8b])
            || (bytes.len() >= 512 && &bytes[257..262] == b"ustar")
        {
            let archive_depth = if options.quick {
                1
            } else if options.deep {
                6
            } else {
                3
            };
            let member_limit: usize = if options.quick {
                5_000
            } else if options.deep {
                50_000
            } else {
                20_000
            };
            let byte_limit: u64 = if options.quick {
                64 * 1024 * 1024
            } else if options.deep {
                512 * 1024 * 1024
            } else {
                256 * 1024 * 1024
            };
            let scan = archives::extract(
                &input.relative,
                &bytes,
                archives::Limits {
                    depth: archive_depth,
                    members: member_limit.saturating_sub(archive_file_count as usize),
                    expanded_bytes: byte_limit.saturating_sub(archive_content_bytes),
                    member_bytes: if options.deep {
                        32 * 1024 * 1024
                    } else {
                        16 * 1024 * 1024
                    },
                    time_limit: archive_deadline.saturating_duration_since(Instant::now()),
                },
            );
            for virtual_file in scan.files {
                archive_file_count += 1;
                archive_content_bytes =
                    archive_content_bytes.saturating_add(virtual_file.bytes.len() as u64);
                analyze_virtual_file(
                    virtual_file.path,
                    &virtual_file.bytes,
                    &mut files,
                    &mut dependencies,
                    &mut findings,
                    &mut modules,
                    &mut roots,
                    &mut semantic_bytes,
                    &mut semantic_limit_reported,
                    &mut analyzer_incomplete,
                    limits,
                );
            }
            archive_incomplete.extend(scan.incomplete_reasons);
        }
    });

    walk.entries = walk.entries.saturating_add(archive_file_count);
    walk.files = walk.files.saturating_add(archive_file_count);
    walk.content_bytes = walk.content_bytes.saturating_add(archive_content_bytes);
    walk.incomplete_reasons.append(&mut archive_incomplete);
    dependencies = deduplicate_dependencies(dependencies);
    let mut online_incomplete = Vec::new();
    let mut online_file_count = 0_u64;
    let mut online_content_bytes = 0_u64;
    if options.online {
        let agent = dependencies::npm_agent();
        let online_dependencies = dependencies.clone();
        let online_limit = if options.quick {
            50
        } else {
            MAX_ONLINE_PACKAGES
        };
        let online_deadline =
            Instant::now() + Duration::from_secs(if options.quick { 60 } else { 5 * 60 });
        for (index, dependency) in online_dependencies.iter().enumerate() {
            if index >= online_limit {
                online_incomplete.push(format!(
                    "online npm artifact limit of {online_limit} reached"
                ));
                break;
            }
            if Instant::now() >= online_deadline {
                online_incomplete.push(format!(
                    "online dependency time limit of {} seconds reached",
                    if options.quick { 60 } else { 300 }
                ));
                break;
            }
            match dependencies::download_npm(&agent, dependency) {
                Ok(bytes) => {
                    let artifact_path = artifact_path(dependency);
                    analyze_virtual_file(
                        artifact_path.clone(),
                        &bytes,
                        &mut files,
                        &mut dependencies,
                        &mut findings,
                        &mut modules,
                        &mut roots,
                        &mut semantic_bytes,
                        &mut semantic_limit_reported,
                        &mut online_incomplete,
                        limits,
                    );
                    let remaining_files =
                        MAX_ONLINE_ARCHIVE_FILES.saturating_sub(online_file_count as usize);
                    let remaining_bytes =
                        MAX_ONLINE_EXPANDED_BYTES.saturating_sub(online_content_bytes);
                    let expanded = archives::extract(
                        &artifact_path,
                        &bytes,
                        archives::Limits {
                            depth: 4,
                            members: remaining_files,
                            expanded_bytes: remaining_bytes,
                            member_bytes: 16 * 1024 * 1024,
                            time_limit: online_deadline.saturating_duration_since(Instant::now()),
                        },
                    );
                    for file in expanded.files {
                        online_file_count += 1;
                        online_content_bytes =
                            online_content_bytes.saturating_add(file.bytes.len() as u64);
                        analyze_virtual_file(
                            file.path,
                            &file.bytes,
                            &mut files,
                            &mut dependencies,
                            &mut findings,
                            &mut modules,
                            &mut roots,
                            &mut semantic_bytes,
                            &mut semantic_limit_reported,
                            &mut online_incomplete,
                            limits,
                        );
                    }
                    online_incomplete.extend(expanded.incomplete_reasons);
                }
                Err(error) => online_incomplete.push(error),
            }
        }
    }
    walk.entries = walk.entries.saturating_add(online_file_count);
    walk.files = walk.files.saturating_add(online_file_count);
    walk.content_bytes = walk.content_bytes.saturating_add(online_content_bytes);
    walk.incomplete_reasons.append(&mut online_incomplete);
    files.append(&mut walk.other_records);
    let graph = graph::build(&modules, &roots, &files);
    let flows = js::analyze_flows(&modules, &graph.reachable);
    append_limited(
        &mut findings,
        graph.findings,
        limits.max_findings,
        "finding limit reached",
        &mut analyzer_incomplete,
    );
    analyzer_incomplete.extend(graph.incomplete_reasons);
    append_limited(
        &mut findings,
        flows.findings,
        limits.max_findings,
        "finding limit reached",
        &mut analyzer_incomplete,
    );
    analyzer_incomplete.extend(flows.incomplete_reasons);
    append_limited(
        &mut findings,
        walk.findings,
        limits.max_findings,
        "finding limit reached",
        &mut analyzer_incomplete,
    );
    let mut threat_findings = Vec::new();
    for dependency in &dependencies {
        match crate::threat_db::package_finding(dependency) {
            Ok(Some(finding)) => threat_findings.push(finding),
            Ok(None) => {}
            Err(error) => analyzer_incomplete.push(error),
        }
    }
    append_limited(
        &mut findings,
        threat_findings,
        limits.max_findings,
        "finding limit reached",
        &mut analyzer_incomplete,
    );
    if options.history {
        match crate::git_analysis::history(&walk.root, options.quick) {
            Ok(history) => {
                append_limited(
                    &mut findings,
                    history.findings,
                    limits.max_findings,
                    "finding limit reached",
                    &mut analyzer_incomplete,
                );
                analyzer_incomplete.extend(history.incomplete_reasons);
            }
            Err(error) => analyzer_incomplete.push(format!("Git history analysis failed: {error}")),
        }
    }
    walk.incomplete_reasons.append(&mut analyzer_incomplete);

    files.sort_by(|left, right| left.path.cmp(&right.path));
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.file.cmp(&right.file))
            .then_with(|| left.id.cmp(&right.id))
    });
    walk.incomplete_reasons.sort();
    walk.incomplete_reasons.dedup();

    let score = findings
        .iter()
        .map(|finding| finding.score)
        .max()
        .unwrap_or(0);
    let severity = findings
        .iter()
        .map(|finding| finding.severity)
        .max()
        .unwrap_or(Severity::Informational);
    let status = if walk.incomplete_reasons.is_empty() {
        ScanStatus::Complete
    } else {
        ScanStatus::Incomplete
    };

    ScanReport {
        schema_version: 1,
        scanner: "preflightx".to_owned(),
        scanner_version: env!("CARGO_PKG_VERSION").to_owned(),
        target: display_path(&walk.root),
        profile: if options.quick {
            "quick"
        } else if options.deep {
            "deep"
        } else {
            "default"
        }
        .to_owned(),
        status,
        network_access: if options.online {
            "enabled for HTTPS npm registry artifact downloads".to_owned()
        } else {
            "disabled".to_owned()
        },
        risk: Risk { severity, score },
        summary: ScanSummary {
            entries: walk.entries,
            files: walk.files,
            directories: walk.directories,
            symlinks: walk.symlinks,
            special_files: walk.special_files,
            content_bytes: walk.content_bytes,
            dependencies: dependencies.len() as u64,
            findings: findings.len() as u64,
        },
        files,
        dependencies,
        findings,
        unresolved_edges: graph.unresolved,
        incomplete_reasons: walk.incomplete_reasons,
    }
}

pub(crate) fn analyze_git_blob(
    path: &str,
    bytes: &[u8],
) -> (Vec<crate::model::Finding>, Vec<String>) {
    let mut classification = classifier::classify_virtual(path, bytes);
    let metadata = analyzers::analyze(path, classification.text.as_deref());
    let javascript = js::analyze(path, classification.text.as_deref());
    let language = languages::analyze(path, classification.text.as_deref());
    for dependency in &metadata.dependencies {
        match crate::threat_db::package_finding(dependency) {
            Ok(Some(finding)) => classification.findings.push(finding),
            Ok(None) => {}
            Err(error) => classification.incomplete_reasons.push(error),
        }
    }
    classification.findings.extend(metadata.findings);
    classification.findings.extend(javascript.findings);
    classification.findings.extend(language.findings);
    if let Some(sha256) = classification.record.sha256.as_deref() {
        match crate::threat_db::hash_finding(path, sha256) {
            Ok(Some(finding)) => classification.findings.push(finding),
            Ok(None) => {}
            Err(error) => classification.incomplete_reasons.push(error),
        }
    }
    classification
        .incomplete_reasons
        .extend(metadata.incomplete_reasons);
    classification
        .incomplete_reasons
        .extend(javascript.incomplete_reasons);
    classification
        .incomplete_reasons
        .extend(language.incomplete_reasons);
    (classification.findings, classification.incomplete_reasons)
}

fn artifact_path(dependency: &crate::model::DependencyRecord) -> String {
    let name = dependency
        .name
        .split('/')
        .map(safe_path_component)
        .collect::<Vec<_>>()
        .join("/");
    let version = dependency
        .version
        .as_deref()
        .map(safe_path_component)
        .unwrap_or_else(|| "unknown".to_owned());
    format!("artifacts/npm/{name}/{version}.tgz")
}

fn safe_path_component(value: &str) -> String {
    let mut component = value
        .chars()
        .take(128)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '@' | '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if component.is_empty() || component == "." || component == ".." {
        component = "unknown".to_owned();
    }
    component
}

// One virtual member updates the scanner's shared finding, coverage, and graph collections.
#[allow(clippy::too_many_arguments)]
fn analyze_virtual_file(
    path: String,
    bytes: &[u8],
    files: &mut Vec<crate::model::FileRecord>,
    dependencies: &mut Vec<crate::model::DependencyRecord>,
    findings: &mut Vec<crate::model::Finding>,
    modules: &mut Vec<js::ModuleFacts>,
    roots: &mut Vec<graph::Root>,
    semantic_bytes: &mut usize,
    semantic_limit_reported: &mut bool,
    incomplete: &mut Vec<String>,
    limits: &ScanLimits,
) {
    let mut classification = classifier::classify_virtual(&path, bytes);
    incomplete.append(&mut classification.incomplete_reasons);
    if let Some(sha256) = classification.record.sha256.as_deref() {
        match crate::threat_db::hash_finding(&path, sha256) {
            Ok(Some(finding)) => classification.findings.push(finding),
            Ok(None) => {}
            Err(error) => incomplete.push(error),
        }
    }
    let metadata = analyzers::analyze(&path, classification.text.as_deref());
    let javascript = js::analyze(&path, classification.text.as_deref());
    let language = languages::analyze(&path, classification.text.as_deref());
    let root_analysis = graph::roots(
        &path,
        classification.text.as_deref(),
        &classification.record.roles,
    );
    if root_analysis.incomplete {
        incomplete.push(format!(
            "JS/TS execution root extraction limit reached: {path}"
        ));
    }
    let available = graph::MAX_EXECUTION_ROOTS.saturating_sub(roots.len());
    if root_analysis.roots.len() > available {
        incomplete.push(format!(
            "JS/TS global execution root limit of {} reached; archive roots omitted",
            graph::MAX_EXECUTION_ROOTS
        ));
    }
    roots.extend(root_analysis.roots.into_iter().take(available));
    for embedded in javascript.embedded_roots {
        if roots.len() == graph::MAX_EXECUTION_ROOTS {
            incomplete.push(format!(
                "JS/TS global execution root limit of {} reached; embedded archive scripts omitted",
                graph::MAX_EXECUTION_ROOTS
            ));
            break;
        }
        roots.push(graph::Root {
            file: embedded.module_id,
            trigger: format!("inline script in archive document {path}"),
            line: Some(embedded.line),
        });
    }
    for module in javascript.modules {
        if modules.len() >= MAX_SEMANTIC_MODULES
            || semantic_bytes.saturating_add(module.source_bytes) > MAX_SEMANTIC_BYTES
        {
            if !*semantic_limit_reported {
                incomplete.push(format!(
                    "JS/TS global semantic analysis limit of {MAX_SEMANTIC_MODULES} modules or {MAX_SEMANTIC_BYTES} source bytes reached before archive member {path}; additional modules were omitted"
                ));
                *semantic_limit_reported = true;
            }
        } else {
            *semantic_bytes += module.source_bytes;
            modules.push(module);
        }
    }
    classification.record.parsed_language = javascript.language.or(language.language);
    if !javascript.findings.is_empty() {
        classification
            .findings
            .retain(|finding| finding.id != "FILE-EXECUTABLE-CONTENT");
    }
    append_limited(
        findings,
        classification.findings,
        limits.max_findings,
        "finding limit reached",
        incomplete,
    );
    append_limited(
        findings,
        metadata.findings,
        limits.max_findings,
        "finding limit reached",
        incomplete,
    );
    append_limited(
        findings,
        javascript.findings,
        limits.max_findings,
        "finding limit reached",
        incomplete,
    );
    append_limited(
        findings,
        language.findings,
        limits.max_findings,
        "finding limit reached",
        incomplete,
    );
    append_limited(
        dependencies,
        metadata.dependencies,
        limits.max_dependencies,
        "dependency record limit reached",
        incomplete,
    );
    incomplete.extend(metadata.incomplete_reasons);
    incomplete.extend(javascript.incomplete_reasons);
    incomplete.extend(language.incomplete_reasons);
    files.push(classification.record);
}

fn deduplicate_dependencies(
    dependencies: Vec<crate::model::DependencyRecord>,
) -> Vec<crate::model::DependencyRecord> {
    let mut unique = BTreeMap::new();
    for dependency in dependencies {
        let key = (
            dependency.ecosystem.clone(),
            dependency.name.clone(),
            dependency.version.clone(),
            dependency.source_file.clone(),
        );
        unique.entry(key).or_insert(dependency);
    }
    unique.into_values().collect()
}

fn append_limited<T>(
    target: &mut Vec<T>,
    source: Vec<T>,
    limit: usize,
    reason: &str,
    incomplete_reasons: &mut Vec<String>,
) {
    let available = limit.saturating_sub(target.len());
    if source.len() > available {
        incomplete_reasons.push(reason.to_owned());
    }
    target.extend(source.into_iter().take(available));
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::{ScanLimits, ScanOptions, scan, scan_with_options};
    use crate::model::ScanStatus;
    use std::{
        fs,
        io::{Cursor, Write},
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };
    use zip::{ZipWriter, write::SimpleFileOptions};

    #[test]
    fn scan_does_not_modify_target_files() {
        let root = temporary_directory("read-only");
        let file = root.join("package.json");
        let content = br#"{"name":"fixture","scripts":{"start":"node app.js"}}"#;
        fs::write(&file, content).unwrap();

        let report = scan(&root, &ScanLimits::default());

        assert_eq!(report.status, ScanStatus::Complete);
        assert_eq!(fs::read(&file).unwrap(), content);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn reports_escaping_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let root = temporary_directory("symlink");
        symlink("/", root.join("outside")).unwrap();

        let report = scan(&root, &ScanLimits::default());

        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "FS-SYMLINK-ESCAPE")
        );
        assert_eq!(report.summary.files, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn skips_named_pipes_without_opening_them() {
        use std::process::Command;

        let root = temporary_directory("fifo");
        let fifo = root.join("input.pipe");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );

        let report = scan(&root, &ScanLimits::default());

        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(report.summary.special_files, 1);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "FS-SPECIAL-FILE")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn entry_limit_makes_the_scan_incomplete() {
        let root = temporary_directory("entry-limit");
        fs::write(root.join("one"), b"one").unwrap();
        fs::write(root.join("two"), b"two").unwrap();
        let limits = ScanLimits {
            max_entries: 1,
            ..ScanLimits::default()
        };

        let report = scan(&root, &limits);

        assert_eq!(report.status, ScanStatus::Incomplete);
        assert!(
            report
                .incomplete_reasons
                .iter()
                .any(|reason| reason.contains("maximum entry count"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_size_limit_makes_the_scan_incomplete() {
        let root = temporary_directory("file-limit");
        fs::write(root.join("large.bin"), b"12345").unwrap();
        let limits = ScanLimits {
            max_file_bytes: 4,
            ..ScanLimits::default()
        };

        let report = scan(&root, &limits);

        assert_eq!(report.status, ScanStatus::Incomplete);
        assert!(!report.files[0].content_scanned);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn gitignore_does_not_hide_files_from_the_scanner() {
        let root = temporary_directory("ignored");
        fs::write(root.join(".gitignore"), b"hidden.js\n").unwrap();
        fs::write(root.join("hidden.js"), b"export const visible = true;\n").unwrap();

        let report = scan(&root, &ScanLimits::default());

        assert_eq!(report.summary.files, 2);
        assert!(report.files.iter().any(|file| file.path == "hidden.js"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_are_deterministic_for_unchanged_bytes() {
        let root = temporary_directory("deterministic");
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("nested/b.txt"), b"b").unwrap();
        fs::write(root.join("a.txt"), b"a").unwrap();

        let first = serde_json::to_string(&scan(&root, &ScanLimits::default())).unwrap();
        let second = serde_json::to_string(&scan(&root, &ScanLimits::default())).unwrap();

        assert_eq!(first, second);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn finding_limit_makes_the_scan_incomplete() {
        let root = temporary_directory("finding-limit");
        fs::write(
            root.join("package.json"),
            br#"{"scripts":{"install":"node one.js","postinstall":"node two.js"}}"#,
        )
        .unwrap();
        let limits = ScanLimits {
            max_findings: 1,
            ..ScanLimits::default()
        };

        let report = scan(&root, &limits);

        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(report.findings.len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scans_zip_member_content_and_reports_traversal() {
        let root = temporary_directory("archive");
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("../outside.ps1", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"ignored").unwrap();
        writer
            .start_file("package/install.ps1", SimpleFileOptions::default())
            .unwrap();
        writer
            .write_all(b"DownloadString FromBase64String Invoke-Expression")
            .unwrap();
        fs::write(
            root.join("bundle.zip"),
            writer.finish().unwrap().into_inner(),
        )
        .unwrap();

        let report = scan(&root, &ScanLimits::default());

        assert_eq!(report.status, ScanStatus::Incomplete);
        assert!(
            report
                .files
                .iter()
                .any(|file| file.path.ends_with("!/package/install.ps1"))
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "YARA-POWERSHELL-DOWNLOAD-EXEC")
        );
        assert!(
            report
                .incomplete_reasons
                .iter()
                .any(|reason| reason.contains("traversal path"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn requested_history_without_a_git_repository_is_incomplete() {
        let root = temporary_directory("history-missing");
        let report = scan_with_options(
            &root,
            &ScanLimits::default(),
            &ScanOptions {
                history: true,
                ..ScanOptions::default()
            },
        );
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert!(
            report
                .incomplete_reasons
                .iter()
                .any(|reason| reason.contains("Git history analysis failed"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("preflightx-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        path
    }
}
