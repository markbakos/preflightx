use crate::model::{Finding, ScanReport, ScanStatus};

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
        &format!("Dependencies {}", report.summary.dependencies),
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
    use super::sanitize;

    #[test]
    fn escapes_terminal_control_characters() {
        assert_eq!(sanitize("file\x1b[31m\nname"), "file\\u{1b}[31m\\nname");
    }
}
