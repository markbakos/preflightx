mod analyzers;
mod classifier;
mod graph;
mod js;
mod limits;
mod raw;
mod walker;

pub use limits::ScanLimits;

use crate::model::{Risk, ScanReport, ScanStatus, ScanSummary, Severity};
use std::{collections::BTreeMap, path::Path};

pub fn scan(path: &Path, limits: &ScanLimits) -> ScanReport {
    let mut files = Vec::new();
    let mut dependencies = Vec::new();
    let mut findings = Vec::new();
    let mut analyzer_incomplete = Vec::new();
    let mut modules = Vec::new();
    let mut roots = Vec::new();
    let mut semantic_bytes = 0usize;
    let mut semantic_limit_reported = false;

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
        let metadata = analyzers::analyze(&input.relative, classification.text.as_deref());
        let javascript = js::analyze(&input.relative, classification.text.as_deref());
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
            if modules.len() >= 10_000 || semantic_bytes.saturating_add(size) > 64 * 1024 * 1024 {
                if !semantic_limit_reported {
                    analyzer_incomplete.push(format!(
                        "JS/TS global semantic analysis limit reached before {}; additional modules were omitted",
                        input.relative
                    ));
                    semantic_limit_reported = true;
                }
            } else {
                semantic_bytes += size;
                modules.push(module);
            }
        }
        classification.record.parsed_language = javascript.language;
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
            &mut dependencies,
            metadata.dependencies,
            limits.max_dependencies,
            "dependency record limit reached",
            &mut analyzer_incomplete,
        );
        analyzer_incomplete.extend(metadata.incomplete_reasons);
        analyzer_incomplete.extend(javascript.incomplete_reasons);
        files.push(classification.record);
    });

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
    walk.incomplete_reasons.append(&mut analyzer_incomplete);

    files.sort_by(|left, right| left.path.cmp(&right.path));
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.file.cmp(&right.file))
            .then_with(|| left.id.cmp(&right.id))
    });
    dependencies = deduplicate_dependencies(dependencies);
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
        status,
        network_access: "disabled".to_owned(),
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
    use super::{ScanLimits, scan};
    use crate::model::ScanStatus;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

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
