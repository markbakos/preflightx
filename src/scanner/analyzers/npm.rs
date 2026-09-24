use super::{MetadataAnalysis, bounded};
use crate::model::{Confidence, Finding, Severity};
use serde_json::Value;

pub fn analyze(path: &str, text: &str) -> MetadataAnalysis {
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(error) => return parse_failure(path, error.to_string()),
    };
    let mut analysis = MetadataAnalysis::default();
    if let Some(scripts) = value.get("scripts").and_then(Value::as_object) {
        // ponytail: omit source lines for large manifests to avoid quadratic scans; use a token-position parser if they need exact locations.
        let line_evidence = scripts.len() <= 64;
        for (name, command) in scripts {
            let Some(command) = command.as_str() else {
                continue;
            };
            let lifecycle = matches!(
                name.as_str(),
                "preinstall" | "install" | "postinstall" | "prepare"
            );
            let execution_root = lifecycle
                || matches!(name.as_str(), "start" | "dev" | "build" | "test")
                || name.starts_with("pre")
                || name.starts_with("post");
            if !execution_root {
                continue;
            }
            analysis.findings.push(Finding {
                id: if lifecycle {
                    "NPM-LIFECYCLE-SCRIPT"
                } else {
                    "NPM-EXECUTION-SCRIPT"
                }
                .to_owned(),
                severity: if lifecycle {
                    Severity::Medium
                } else {
                    Severity::Informational
                },
                confidence: Confidence::VeryHigh,
                score: if lifecycle { 35 } else { 10 },
                title: if lifecycle {
                    "Package lifecycle script can execute during installation"
                } else {
                    "Package script is an execution root"
                }
                .to_owned(),
                message: format!(
                    "The npm script '{name}' can execute repository-controlled commands."
                ),
                file: Some(path.to_owned()),
                line: line_evidence
                    .then(|| find_line(text, &format!("\"{name}\"")))
                    .flatten(),
                evidence: vec![format!("{name}: {}", bounded(command))],
            });
        }
    }
    analysis
}

fn parse_failure(path: &str, error: String) -> MetadataAnalysis {
    MetadataAnalysis {
        findings: vec![Finding {
            id: "CONFIG-PARSE-FAILED".to_owned(),
            severity: Severity::Medium,
            confidence: Confidence::VeryHigh,
            score: 45,
            title: "Security-relevant configuration could not be parsed".to_owned(),
            message: "The package manifest is malformed, so execution-root analysis is incomplete."
                .to_owned(),
            file: Some(path.to_owned()),
            line: None,
            evidence: vec![error.clone()],
        }],
        incomplete_reasons: vec![format!("could not parse package manifest {path}: {error}")],
    }
}

fn find_line(text: &str, needle: &str) -> Option<u64> {
    text.lines()
        .position(|line| line.contains(needle))
        .map(|line| line as u64 + 1)
}

#[cfg(test)]
mod tests {
    use super::analyze;

    #[test]
    fn finds_lifecycle_and_start_execution_roots_without_package_identity_analysis() {
        let analysis = analyze(
            "package.json",
            r#"{"name":"local-fixture","scripts":{"postinstall":"node setup.js","start":"node app.js"},"dependencies":{"local-fixture-dep":"1.2.3"}}"#,
        );
        assert_eq!(analysis.findings.len(), 2);
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.id == "NPM-LIFECYCLE-SCRIPT")
        );
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.id == "NPM-EXECUTION-SCRIPT")
        );
    }

    #[test]
    fn malformed_manifest_marks_execution_root_coverage_incomplete() {
        let analysis = analyze("package.json", "{ not valid JSON");
        assert_eq!(analysis.findings[0].id, "CONFIG-PARSE-FAILED");
        assert_eq!(analysis.incomplete_reasons.len(), 1);
    }
}
