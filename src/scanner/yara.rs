use crate::model::{Confidence, Finding, Severity};
use std::{sync::OnceLock, time::Duration};
use yara_x::{Compiler, Rules, Scanner};

const RULE_SOURCE: &str = include_str!("../../rules/preflightx.yar");

static RULES: OnceLock<Result<Rules, String>> = OnceLock::new();

pub fn analyze(path: &str, bytes: &[u8]) -> Result<Vec<Finding>, String> {
    let rules = RULES
        .get_or_init(|| {
            let mut compiler = Compiler::new();
            compiler
                .add_source(RULE_SOURCE)
                .map_err(|error| error.to_string())?;
            Ok(compiler.build())
        })
        .as_ref()
        .map_err(Clone::clone)?;
    let mut scanner = Scanner::new(rules);
    scanner.set_timeout(Duration::from_secs(1));
    scanner.max_matches_per_pattern(64);
    let matches = scanner
        .scan(bytes)
        .map_err(|error| error.to_string())?
        .matching_rules()
        .map(|rule| rule.identifier().to_owned())
        .collect::<Vec<_>>();
    Ok(matches
        .into_iter()
        .filter_map(|rule| finding(path, &rule))
        .collect())
}

pub fn doctor() -> Result<(), String> {
    analyze("doctor", &[]).map(|_| ())
}

fn finding(path: &str, rule: &str) -> Option<Finding> {
    let (id, title, message) = match rule {
        "PF_Encoded_PowerShell_Download_Execute" => (
            "YARA-POWERSHELL-DOWNLOAD-EXEC",
            "Encoded PowerShell download and execution pattern",
            "A file combines remote download, base64 decoding, and PowerShell expression execution indicators.",
        ),
        "PF_Aes_Encrypted_Function_Loader" => (
            "YARA-JS-ENCRYPTED-LOADER",
            "Encrypted JavaScript loader pattern",
            "A file combines AES decryption and dynamic JavaScript function construction indicators.",
        ),
        _ => return None,
    };
    Some(Finding {
        id: id.to_owned(),
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        score: 60,
        title: title.to_owned(),
        message: message.to_owned(),
        file: Some(path.to_owned()),
        line: None,
        evidence: vec![format!("matched YARA-X rule {rule}")],
    })
}

#[cfg(test)]
mod tests {
    use super::analyze;

    #[test]
    fn flags_encoded_remote_powershell_stager() {
        let text = b"DownloadString FromBase64String Invoke-Expression";
        let findings = analyze("install.ps1", text).unwrap();
        assert_eq!(findings[0].id, "YARA-POWERSHELL-DOWNLOAD-EXEC");
    }

    #[test]
    fn does_not_flag_incomplete_indicator_sets_or_clean_text() {
        for text in [
            b"DownloadString FromBase64String".as_slice(),
            b"createDecipheriv('aes-256-cbc', key, iv)".as_slice(),
            b"ordinary package documentation".as_slice(),
            b"Download + String FromBase64 + String Invoke + Expression".as_slice(),
        ] {
            assert!(analyze("readme.txt", text).unwrap().is_empty());
        }
    }

    #[test]
    fn retains_hits_after_case_and_layout_evasion_mutations() {
        for (path, text, expected) in [
            (
                "install.ps1",
                b"downloadstring\n# staging\nFROMBASE64STRING\ninvoke-expression".as_slice(),
                "YARA-POWERSHELL-DOWNLOAD-EXEC",
            ),
            (
                "loader.js",
                b"CREATEDECIPHERIV('AES-256-CBC', key, iv); return new\n\tFunction(code)"
                    .as_slice(),
                "YARA-JS-ENCRYPTED-LOADER",
            ),
        ] {
            let findings = analyze(path, text).unwrap();
            assert!(
                findings.iter().any(|finding| finding.id == expected),
                "evasion mutation was missed for {path}: {findings:?}"
            );
        }
    }

    #[test]
    fn flags_the_unmutated_encrypted_loader_pattern() {
        let findings = analyze(
            "loader.js",
            b"createDecipheriv('aes-256-cbc', key, iv); new Function(payload)",
        )
        .unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "YARA-JS-ENCRYPTED-LOADER")
        );
    }
}
