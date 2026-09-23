use crate::model::{Confidence, Finding, Severity};

pub struct RawAnalysis {
    pub entropy: f64,
    pub line_count: u64,
    pub max_line_length: u64,
    pub signals: Vec<String>,
    pub findings: Vec<Finding>,
}

pub fn analyze(path: &str, bytes: &[u8], text: Option<&str>) -> RawAnalysis {
    let entropy = entropy(bytes);
    let (line_count, max_line_length) = line_metrics(bytes);
    let mut signals = Vec::new();
    let mut findings = Vec::new();

    if max_line_length >= 10_000 {
        signals.push(format!("extreme line length: {max_line_length} bytes"));
        findings.push(Finding {
            id: "RAW-EXTREME-LINE".to_owned(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            score: 40,
            title: "Extremely long line".to_owned(),
            message: "Very long lines can conceal code outside the normal editor viewport."
                .to_owned(),
            file: Some(path.to_owned()),
            line: None,
            evidence: vec![format!("maximum line length: {max_line_length} bytes")],
        });
    }

    if let Some(text) = text {
        if let Some(offset) = content_after_marker(text, '\u{1a}') {
            signals.push("content follows an apparent logical EOF marker".to_owned());
            findings.push(Finding {
                id: "RAW-CONTENT-AFTER-EOF".to_owned(),
                severity: Severity::High,
                confidence: Confidence::High,
                score: 75,
                title: "Content follows an apparent logical EOF marker".to_owned(),
                message: "Printable content appears after a control character commonly treated as end-of-file."
                    .to_owned(),
                file: Some(path.to_owned()),
                line: None,
                evidence: vec![format!("content resumes after byte offset {offset}")],
            });
        }
        if let Some((line, run)) = hidden_after_whitespace(text, 512) {
            signals.push(format!("code follows {run} horizontal whitespace bytes"));
            findings.push(Finding {
                id: "RAW-HIDDEN-AFTER-WHITESPACE".to_owned(),
                severity: Severity::High,
                confidence: Confidence::High,
                score: 75,
                title: "Content hidden after extreme horizontal whitespace".to_owned(),
                message: "Non-whitespace content appears after a large horizontal gap on one line."
                    .to_owned(),
                file: Some(path.to_owned()),
                line: Some(line),
                evidence: vec![format!("horizontal whitespace run: {run} bytes")],
            });
        } else if let Some(run) = longest_horizontal_run(text).filter(|run| *run >= 512) {
            signals.push(format!("extreme horizontal whitespace: {run} bytes"));
        }

        let base64_run = longest_run(text.as_bytes(), is_base64_byte);
        if base64_run >= 512 {
            signals.push(format!("large base64-like sequence: {base64_run} bytes"));
        }
        let hex_run = longest_run(text.as_bytes(), |byte| byte.is_ascii_hexdigit());
        if hex_run >= 512 {
            signals.push(format!("large hexadecimal sequence: {hex_run} bytes"));
        }
        let unicode_escapes = text.matches("\\u").count();
        if unicode_escapes >= 32 {
            signals.push(format!("unicode escape sequences: {unicode_escapes}"));
        }
        if text.contains("String.fromCharCode") || text.contains("String['fromCharCode']") {
            signals.push("character-code string construction".to_owned());
        }
        if text.contains("charCodeAt") && text.contains('^') {
            signals.push("possible XOR string decoder".to_owned());
        }
        let hex_identifiers = text.matches("_0x").count();
        if hex_identifiers >= 8 {
            signals.push(format!("_0x-style identifiers: {hex_identifiers}"));
        }
        if text.contains("debugger;") || text.contains("navigator.webdriver") {
            signals.push("anti-debugging or automation check".to_owned());
        }
        if ["VirtualBox", "VMware", "QEMU", "Parallels"]
            .iter()
            .any(|marker| text.contains(marker))
        {
            signals.push("virtual-machine environment check".to_owned());
        }
        if text.contains("navigator.language")
            || text.contains("process.env.LANG")
            || text.contains("Intl.DateTimeFormat")
        {
            signals.push("locale or regional environment check".to_owned());
        }
        if ["tasklist", "Get-Process", "ps aux", "/proc/"]
            .iter()
            .any(|marker| text.contains(marker))
            && ["Wireshark", "ProcessHacker", "x64dbg", "OllyDbg", "Procmon"]
                .iter()
                .any(|marker| text.contains(marker))
        {
            signals.push("security-tool process enumeration check".to_owned());
        }
        if has_long_delay(text) {
            signals.push("long timer delay".to_owned());
        }
        if text.contains("Invoke-WebRequest") || text.contains("Invoke-Expression") {
            signals.push("PowerShell download or execution primitive".to_owned());
        }
        let urls = text.matches("http://").count() + text.matches("https://").count();
        if urls > 0 {
            signals.push(format!("URL occurrences: {urls}"));
        }
        let ips = text
            .split(|character: char| !character.is_ascii_digit() && character != '.')
            .filter(|token| looks_like_ipv4(token))
            .count();
        if ips > 0 {
            signals.push(format!("IPv4 address occurrences: {ips}"));
        }
        let wallets = text
            .split(|character: char| !character.is_ascii_alphanumeric())
            .filter(|token| looks_like_wallet(token))
            .count();
        if wallets > 0 {
            signals.push(format!("wallet-like identifiers: {wallets}"));
        }
        if text.contains("discord.com/api/webhooks") || text.contains("hooks.slack.com") {
            signals.push("webhook endpoint".to_owned());
        }
        if text.contains("bit.ly/") || text.contains("tinyurl.com/") || text.contains("t.co/") {
            signals.push("shortened URL".to_owned());
        }
        if bytes.len() >= 2_048 && entropy >= 5.5 {
            signals.push(format!("high-entropy text: {entropy:.2} bits per byte"));
        }
    }

    RawAnalysis {
        entropy,
        line_count,
        max_line_length,
        signals,
        findings,
    }
}

fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u64; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = count as f64 / bytes.len() as f64;
            -probability * probability.log2()
        })
        .sum()
}

fn line_metrics(bytes: &[u8]) -> (u64, u64) {
    if bytes.is_empty() {
        return (0, 0);
    }
    let mut lines = 1_u64;
    let mut current = 0_u64;
    let mut longest = 0_u64;
    for byte in bytes {
        if *byte == b'\n' {
            lines += 1;
            longest = longest.max(current);
            current = 0;
        } else {
            current += 1;
        }
    }
    if bytes.last() == Some(&b'\n') {
        lines -= 1;
    }
    (lines, longest.max(current))
}

fn hidden_after_whitespace(text: &str, threshold: usize) -> Option<(u64, usize)> {
    for (index, line) in text.lines().enumerate() {
        let bytes = line.as_bytes();
        let mut run = 0_usize;
        let mut longest = 0_usize;
        for (position, byte) in bytes.iter().enumerate() {
            if *byte == b' ' || *byte == b'\t' {
                run += 1;
            } else {
                if run >= threshold && position < bytes.len() {
                    return Some((index as u64 + 1, run));
                }
                longest = longest.max(run);
                run = 0;
            }
        }
        if longest >= threshold && run < threshold {
            return Some((index as u64 + 1, longest));
        }
    }
    None
}

fn longest_horizontal_run(text: &str) -> Option<usize> {
    text.lines()
        .map(|line| longest_run(line.as_bytes(), |byte| byte == b' ' || byte == b'\t'))
        .max()
}

fn content_after_marker(text: &str, marker: char) -> Option<usize> {
    let (offset, remainder) = text.split_once(marker)?;
    remainder
        .chars()
        .any(|character| !character.is_whitespace() && !character.is_control())
        .then_some(offset.len())
}

fn longest_run(bytes: &[u8], predicate: impl Fn(u8) -> bool) -> usize {
    let mut current = 0_usize;
    let mut longest = 0_usize;
    for byte in bytes {
        if predicate(*byte) {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

fn has_long_delay(text: &str) -> bool {
    let bytes = text.as_bytes();
    ["setTimeout", "setInterval"].iter().any(|name| {
        text.match_indices(name).any(|(offset, _)| {
            let end = (offset + name.len() + 128).min(bytes.len());
            let mut cursor = offset + name.len();
            while cursor < end {
                if !bytes[cursor].is_ascii_digit() {
                    cursor += 1;
                    continue;
                }
                let start = cursor;
                while cursor < end && bytes[cursor].is_ascii_digit() {
                    cursor += 1;
                }
                if cursor - start >= 4
                    && std::str::from_utf8(&bytes[start..cursor])
                        .ok()
                        .and_then(|digits| digits.parse::<u64>().ok())
                        .is_some_and(|delay| delay >= 5_000)
                {
                    return true;
                }
            }
            false
        })
    })
}

fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

fn looks_like_ipv4(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.parse::<u8>().is_ok())
}

fn looks_like_wallet(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::analyze;

    #[test]
    fn detects_content_after_large_horizontal_gap() {
        let text = format!("const safe = true;{}eval(payload)", " ".repeat(600));
        let analysis = analyze("route.js", text.as_bytes(), Some(&text));
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.id == "RAW-HIDDEN-AFTER-WHITESPACE")
        );
    }

    #[test]
    fn ordinary_text_has_no_raw_finding() {
        let text = "export const greeting = 'hello';\n";
        assert!(
            analyze("main.js", text.as_bytes(), Some(text))
                .findings
                .is_empty()
        );
    }

    #[test]
    fn detects_content_after_logical_eof() {
        let text = "visible\u{1a}hidden()";
        let analysis = analyze("route.js", text.as_bytes(), Some(text));
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.id == "RAW-CONTENT-AFTER-EOF")
        );
    }

    #[test]
    fn records_anti_analysis_signals_without_escalating_them_alone() {
        let text = "if (navigator.language !== 'en') debugger; if (navigator.webdriver) process.exit(); if (VirtualBox) Get-Process | x64dbg; setTimeout(run, 10000);";
        let analysis = analyze("main.js", text.as_bytes(), Some(text));
        assert!(
            analysis
                .signals
                .iter()
                .any(|signal| signal == "locale or regional environment check")
        );
        assert!(
            analysis
                .signals
                .iter()
                .any(|signal| signal == "anti-debugging or automation check")
        );
        assert!(
            analysis
                .signals
                .iter()
                .any(|signal| signal == "long timer delay")
        );
        assert!(
            analysis
                .signals
                .iter()
                .any(|signal| signal == "virtual-machine environment check")
        );
        assert!(
            analysis
                .signals
                .iter()
                .any(|signal| signal == "security-tool process enumeration check")
        );
        assert!(analysis.findings.is_empty());
    }
}
