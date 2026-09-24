use crate::model::{Finding, ScanReport, ScanStatus, Severity};
use std::collections::BTreeSet;

pub fn terminal(report: &ScanReport) -> String {
    let mut output = String::new();
    push_line(
        &mut output,
        &format!("preflightx {}", report.scanner_version),
    );
    push_line(
        &mut output,
        &format!("Scanning: {}", sanitize(&report.target)),
    );
    push_line(
        &mut output,
        &format!("Profile: {}", sanitize(&report.profile)),
    );
    output.push('\n');
    push_line(
        &mut output,
        &format!("Files        {}", report.summary.files),
    );
    push_line(
        &mut output,
        &format!("Directories  {}", report.summary.directories),
    );
    push_line(
        &mut output,
        &format!("Symlinks     {}", report.summary.symlinks),
    );
    push_line(
        &mut output,
        &format!("Content      {} bytes", report.summary.content_bytes),
    );

    for finding in &report.findings {
        output.push('\n');
        render_finding(&mut output, finding);
    }

    output.push('\n');
    push_line(
        &mut output,
        &format!(
            "Repository risk: {} — {}/100",
            report.risk.severity.label(),
            report.risk.score
        ),
    );
    push_line(
        &mut output,
        &format!("Scan status: {}", status_label(report.status)),
    );
    if report.status == ScanStatus::Incomplete {
        output.push('\n');
        push_line(&mut output, "SCAN INCOMPLETE");
        for reason in &report.incomplete_reasons {
            push_line(&mut output, &format!("  - {}", sanitize(reason)));
        }
    } else if report.findings.is_empty() {
        output.push('\n');
        push_line(
            &mut output,
            "No significant malicious indicators were identified by this version of preflightx.",
        );
    }
    if !report.unresolved_edges.is_empty() {
        output.push('\n');
        push_line(&mut output, "Unresolved execution edges:");
        for edge in &report.unresolved_edges {
            push_line(&mut output, &format!("  - {}", sanitize(edge)));
        }
    }
    output.push('\n');
    push_line(
        &mut output,
        "No repository code was executed during this scan.",
    );
    push_line(
        &mut output,
        &format!("Network access: {}", report.network_access),
    );
    output
}

pub fn json(report: &ScanReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report).map(|mut output| {
        output.push('\n');
        output
    })
}

pub fn markdown(report: &ScanReport) -> String {
    let mut output = format!(
        "<!-- PreflightX Markdown v2 -->\n\n# PreflightX {}\n\n- **Target:** `{}`\n- **Profile:** {}\n- **Status:** {}\n- **Files:** {}\n- **Risk:** {} ({}/100)\n- **Network:** {}\n\n",
        markdown_escape(&report.scanner_version),
        markdown_escape(&report.target),
        markdown_escape(&report.profile),
        status_label(report.status),
        report.summary.files,
        report.risk.severity.label(),
        report.risk.score,
        markdown_escape(&report.network_access),
    );
    if report.findings.is_empty() && report.status == ScanStatus::Complete {
        output.push_str(
            "No significant malicious indicators were identified by this version of PreflightX.\n",
        );
    }
    for finding in &report.findings {
        output.push_str(&format!(
            "## {} — {}\n\n{}\n\n",
            finding.severity.label(),
            markdown_escape(&finding.title),
            markdown_escape(&finding.message),
        ));
        if let Some(file) = &finding.file {
            let location = finding
                .line
                .map(|line| format!("{file}:{line}"))
                .unwrap_or_else(|| file.clone());
            output.push_str(&format!(
                "**Location:** `{}`\n\n",
                markdown_escape(&location)
            ));
        }
        output.push_str(&format!(
            "**Rule:** `{}`  \n**Confidence:** {:?}  \n**Risk:** {}/100\n",
            markdown_escape(&finding.id),
            finding.confidence,
            finding.score,
        ));
        for evidence in &finding.evidence {
            output.push_str(&format!("\n- `{}`", markdown_escape(evidence)));
        }
        output.push_str("\n\n");
    }
    if report.status == ScanStatus::Incomplete {
        output.push_str("## Scan incomplete\n\n");
        for reason in &report.incomplete_reasons {
            output.push_str(&format!("- {}\n", markdown_escape(reason)));
        }
        output.push('\n');
    }
    output.push_str("No repository code was executed during this scan.\n");
    output
}

pub fn sarif(report: &ScanReport) -> Result<String, serde_json::Error> {
    let rule_ids: BTreeSet<_> = report
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect();
    let rules: Vec<_> = rule_ids
        .iter()
        .map(|id| {
            let finding = report
                .findings
                .iter()
                .find(|finding| finding.id == **id)
                .expect("rule id came from a finding");
            serde_json::json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": finding.title },
                "defaultConfiguration": { "level": sarif_level(finding.severity) }
            })
        })
        .collect();
    let indexes: std::collections::BTreeMap<_, _> = rule_ids
        .iter()
        .enumerate()
        .map(|(index, id)| (*id, index))
        .collect();
    let results: Vec<_> = report
        .findings
        .iter()
        .map(|finding| {
            let mut result = serde_json::json!({
                "ruleId": finding.id,
                "ruleIndex": indexes[finding.id.as_str()],
                "level": sarif_level(finding.severity),
                "message": { "text": finding.message },
                "properties": {
                    "confidence": format!("{:?}", finding.confidence).to_ascii_lowercase(),
                    "riskScore": finding.score
                }
            });
            if let Some(file) = &finding.file {
                let mut physical = serde_json::json!({
                    "artifactLocation": { "uri": sarif_uri(file) }
                });
                if let Some(line) = finding.line {
                    physical["region"] = serde_json::json!({ "startLine": line });
                }
                result["locations"] = serde_json::json!([{
                    "physicalLocation": physical
                }]);
            }
            if !finding.evidence.is_empty() {
                result["relatedLocations"] = serde_json::json!(
                    finding
                        .evidence
                        .iter()
                        .enumerate()
                        .map(|(index, text)| serde_json::json!({
                            "id": index + 1,
                            "message": { "text": text }
                        }))
                        .collect::<Vec<_>>()
                );
            }
            result
        })
        .collect();
    let value = serde_json::json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "PreflightX",
                "version": report.scanner_version,
                "rules": rules
            }},
            "results": results,
            "properties": {
                "scanStatus": format!("{:?}", report.status).to_ascii_lowercase(),
                "networkAccess": report.network_access,
                "scanProfile": report.profile
            }
        }]
    });
    serde_json::to_string_pretty(&value).map(|mut output| {
        output.push('\n');
        output
    })
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Informational => "none",
    }
}

fn sarif_uri(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let mut output = String::new();
    for byte in normalized.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn markdown_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '`' => escaped.push_str("\\`"),
            '|' => escaped.push_str("\\|"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            character if character.is_control() => {
                escaped.extend(character.escape_default());
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn render_finding(output: &mut String, finding: &Finding) {
    push_line(
        output,
        &format!("{}  {}", finding.severity.label(), sanitize(&finding.id)),
    );
    push_line(output, &sanitize(&finding.title));
    if let Some(file) = &finding.file {
        let location = finding
            .line
            .map(|line| format!("{}:{line}", sanitize(file)))
            .unwrap_or_else(|| sanitize(file));
        push_line(output, &location);
    }
    push_line(output, &sanitize(&finding.message));
    for evidence in &finding.evidence {
        push_line(output, &format!("  {}", sanitize(evidence)));
    }
    push_line(
        output,
        &format!(
            "Confidence: {:?}  Risk: {}/100",
            finding.confidence, finding.score
        ),
    );
}

fn status_label(status: ScanStatus) -> &'static str {
    match status {
        ScanStatus::Complete => "COMPLETE",
        ScanStatus::Incomplete => "INCOMPLETE",
    }
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_control() {
                character.escape_default().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}

fn push_line(output: &mut String, line: &str) {
    output.push_str(line);
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use super::{markdown, sanitize, sarif};
    use crate::model::{Confidence, Finding, Risk, ScanReport, ScanStatus, ScanSummary, Severity};
    use serde_json::Value;

    #[test]
    fn escapes_terminal_control_characters() {
        assert_eq!(sanitize("file\x1b[31m\nname"), "file\\u{1b}[31m\\nname");
    }

    #[test]
    fn emits_sarif_21_with_rule_locations_and_risk_properties() {
        let report = sample_report();
        let value: serde_json::Value = serde_json::from_str(&sarif(&report).unwrap()).unwrap();
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(value["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "src/a%20b.js"
        );
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            9
        );
        assert_eq!(
            value["runs"][0]["results"][0]["properties"]["riskScore"],
            98
        );
    }

    #[test]
    fn json_report_matches_the_versioned_v2_schema() {
        let report = sample_report();
        let value = serde_json::to_value(&report).unwrap();
        assert_schema_valid(
            include_str!("../schemas/scan-report-v2.schema.json"),
            &value,
        );

        let mut unsupported_version = value.clone();
        unsupported_version["schema_version"] = serde_json::json!(3);
        assert_schema_invalid(
            include_str!("../schemas/scan-report-v2.schema.json"),
            &unsupported_version,
        );

        let mut removed_scope = value;
        removed_scope["dependencies"] = serde_json::json!([]);
        assert_schema_invalid(
            include_str!("../schemas/scan-report-v2.schema.json"),
            &removed_scope,
        );
    }

    #[test]
    fn sarif_report_matches_the_pinned_oasis_schema_without_remote_refs() {
        let schema = include_str!("../schemas/sarif-schema-2.1.0.json");
        let value: Value = serde_json::from_str(&sarif(&sample_report()).unwrap()).unwrap();
        assert_schema_valid(schema, &value);

        let mut wrong_version = value;
        wrong_version["version"] = serde_json::json!("2.0.0");
        assert_schema_invalid(schema, &wrong_version);
    }

    #[test]
    fn markdown_has_a_versioned_header_and_stable_report_sections() {
        let rendered = markdown(&sample_report());
        assert!(rendered.starts_with("<!-- PreflightX Markdown v2 -->\n\n# PreflightX"));
        for section in [
            "**Target:**",
            "**Profile:**",
            "**Status:**",
            "**Risk:**",
            "**Network:**",
            "**Rule:**",
        ] {
            assert!(
                rendered.contains(section),
                "missing Markdown section {section}"
            );
        }
    }

    fn assert_schema_valid(schema_text: &str, instance: &Value) {
        let schema: Value = serde_json::from_str(schema_text).unwrap();
        assert_schema_references_are_local(&schema);
        let validator = jsonschema::validator_for(&schema).unwrap();
        let errors = validator
            .iter_errors(instance)
            .map(|error| format!("{} at {}", error, error.instance_path))
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "schema validation failed: {errors:#?}");
    }

    fn assert_schema_invalid(schema_text: &str, instance: &Value) {
        let schema: Value = serde_json::from_str(schema_text).unwrap();
        assert_schema_references_are_local(&schema);
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(!validator.is_valid(instance));
    }

    fn assert_schema_references_are_local(value: &Value) {
        match value {
            Value::Object(properties) => {
                if let Some(reference) = properties.get("$ref") {
                    assert!(
                        reference
                            .as_str()
                            .is_some_and(|value| value.starts_with("#/")),
                        "schema contains a non-local reference: {reference}"
                    );
                }
                for value in properties.values() {
                    assert_schema_references_are_local(value);
                }
            }
            Value::Array(values) => {
                for value in values {
                    assert_schema_references_are_local(value);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn markdown_escapes_untrusted_text_and_mentions_incomplete_coverage() {
        let mut report = sample_report();
        report.findings[0].title = "bad <script> | `x`".to_owned();
        report.status = ScanStatus::Incomplete;
        report.incomplete_reasons.push("parser\nlimit".to_owned());
        let rendered = markdown(&report);
        assert!(rendered.contains("bad &lt;script&gt; \\| \\`x\\`"));
        assert!(rendered.contains("## Scan incomplete"));
        assert!(rendered.contains("parser\\nlimit"));
    }

    fn sample_report() -> ScanReport {
        ScanReport {
            schema_version: 2,
            scanner: "preflightx".to_owned(),
            scanner_version: "0.1.0".to_owned(),
            target: "fixture".to_owned(),
            profile: "default".to_owned(),
            status: ScanStatus::Complete,
            network_access: "disabled".to_owned(),
            risk: Risk {
                severity: Severity::Critical,
                score: 98,
            },
            summary: ScanSummary::default(),
            files: Vec::new(),
            findings: vec![Finding {
                id: "REMOTE-EXECUTION".to_owned(),
                severity: Severity::Critical,
                confidence: Confidence::VeryHigh,
                score: 98,
                title: "Remote data reaches code execution".to_owned(),
                message: "Network response reaches Function".to_owned(),
                file: Some("src/a b.js".to_owned()),
                line: Some(9),
                evidence: vec!["axios.get".to_owned()],
            }],
            unresolved_edges: Vec::new(),
            incomplete_reasons: Vec::new(),
        }
    }
}
