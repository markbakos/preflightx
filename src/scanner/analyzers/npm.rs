use super::{MetadataAnalysis, bounded};
use crate::model::{Confidence, DependencyRecord, Finding, Severity};
use serde_json::Value;
use std::collections::BTreeMap;

pub fn analyze(path: &str, name: &str, text: &str) -> MetadataAnalysis {
    match name {
        "package.json" => analyze_manifest(path, text),
        "package-lock.json" | "npm-shrinkwrap.json" => analyze_npm_lock(path, text),
        "yarn.lock" => analyze_yarn_lock(path, text),
        "pnpm-lock.yaml" => analyze_pnpm_lock(path, text),
        _ => MetadataAnalysis::default(),
    }
}

fn analyze_manifest(path: &str, text: &str) -> MetadataAnalysis {
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(error) => return parse_failure(path, "package manifest", error.to_string()),
    };
    let mut analysis = MetadataAnalysis::default();
    if let Some(scripts) = value.get("scripts").and_then(Value::as_object) {
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
                line: find_line(text, &format!("\"{name}\"")),
                evidence: vec![format!("{name}: {}", bounded(command))],
            });
        }
    }
    analysis
}

fn analyze_npm_lock(path: &str, text: &str) -> MetadataAnalysis {
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(error) => return parse_failure(path, "npm lockfile", error.to_string()),
    };
    let mut dependencies = BTreeMap::new();
    if let Some(packages) = value.get("packages").and_then(Value::as_object) {
        for (location, package) in packages {
            if location.is_empty() {
                continue;
            }
            let name = package
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| package_name_from_location(location));
            if let Some(name) = name {
                insert_dependency(&mut dependencies, path, name, package);
            }
        }
    } else if let Some(legacy) = value.get("dependencies").and_then(Value::as_object) {
        collect_legacy_dependencies(path, legacy, &mut dependencies);
    }
    MetadataAnalysis {
        dependencies: dependencies.into_values().collect(),
        ..MetadataAnalysis::default()
    }
}

fn collect_legacy_dependencies(
    path: &str,
    dependencies: &serde_json::Map<String, Value>,
    output: &mut BTreeMap<String, DependencyRecord>,
) {
    for (name, package) in dependencies {
        insert_dependency(output, path, name.to_owned(), package);
        if let Some(children) = package.get("dependencies").and_then(Value::as_object) {
            collect_legacy_dependencies(path, children, output);
        }
    }
}

fn insert_dependency(
    output: &mut BTreeMap<String, DependencyRecord>,
    path: &str,
    name: String,
    package: &Value,
) {
    let version = package
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let key = format!("{name}@{}", version.as_deref().unwrap_or_default());
    output.entry(key).or_insert_with(|| DependencyRecord {
        ecosystem: "npm".to_owned(),
        name,
        version,
        integrity: package
            .get("integrity")
            .and_then(Value::as_str)
            .map(str::to_owned),
        resolved: package
            .get("resolved")
            .and_then(Value::as_str)
            .map(str::to_owned),
        source_file: path.to_owned(),
    });
}

fn package_name_from_location(location: &str) -> Option<String> {
    location
        .rsplit("node_modules/")
        .next()
        .filter(|name| *name != location || location.starts_with("node_modules/"))
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

fn analyze_yarn_lock(path: &str, text: &str) -> MetadataAnalysis {
    let mut analysis = MetadataAnalysis::default();
    let mut selectors = Vec::new();
    let mut version = None;
    let mut resolved = None;
    let mut integrity = None;

    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) && line.ends_with(':') {
            flush_yarn(
                path,
                &selectors,
                version.take(),
                resolved.take(),
                integrity.take(),
                &mut analysis.dependencies,
            );
            selectors = line
                .trim_end_matches(':')
                .split(',')
                .map(|value| value.trim().trim_matches('"').to_owned())
                .collect();
        } else {
            let trimmed = line.trim();
            if let Some(value) = property_value(trimmed, "version") {
                version = Some(value);
            } else if let Some(value) = property_value(trimmed, "resolved") {
                resolved = Some(value);
            } else if let Some(value) = property_value(trimmed, "integrity") {
                integrity = Some(value);
            }
        }
    }
    flush_yarn(
        path,
        &selectors,
        version,
        resolved,
        integrity,
        &mut analysis.dependencies,
    );
    if !text.contains("yarn lockfile") && analysis.dependencies.is_empty() {
        analysis
            .incomplete_reasons
            .push(format!("could not parse Yarn lockfile {path}"));
    }
    analysis
}

fn flush_yarn(
    path: &str,
    selectors: &[String],
    version: Option<String>,
    resolved: Option<String>,
    integrity: Option<String>,
    output: &mut Vec<DependencyRecord>,
) {
    let Some(selector) = selectors.first() else {
        return;
    };
    let name = yarn_name(selector);
    if name.is_empty() {
        return;
    }
    output.push(DependencyRecord {
        ecosystem: "npm".to_owned(),
        name,
        version,
        integrity,
        resolved,
        source_file: path.to_owned(),
    });
}

fn yarn_name(selector: &str) -> String {
    let selector = selector.strip_prefix("npm:").unwrap_or(selector);
    if selector.starts_with('@') {
        selector
            .match_indices('@')
            .nth(1)
            .map(|(index, _)| selector[..index].to_owned())
            .unwrap_or_else(|| selector.to_owned())
    } else {
        selector
            .split_once('@')
            .map(|(name, _)| name.to_owned())
            .unwrap_or_else(|| selector.to_owned())
    }
}

fn analyze_pnpm_lock(path: &str, text: &str) -> MetadataAnalysis {
    let mut analysis = MetadataAnalysis::default();
    if !text
        .lines()
        .any(|line| line.starts_with("lockfileVersion:"))
    {
        analysis
            .incomplete_reasons
            .push(format!("pnpm lockfile has no lockfileVersion: {path}"));
        return analysis;
    }
    let mut in_packages = false;
    let mut current_dependency = None;
    for line in text.lines() {
        if line == "packages:" || line == "snapshots:" {
            in_packages = true;
            current_dependency = None;
            continue;
        }
        if in_packages && !line.starts_with(char::is_whitespace) && !line.is_empty() {
            in_packages = false;
            current_dependency = None;
        }
        if !in_packages {
            continue;
        }
        if line.starts_with("  ") && !line.starts_with("    ") {
            let key = line.trim().trim_end_matches(':').trim_matches(['\'', '"']);
            let Some((name, version)) = pnpm_package(key) else {
                current_dependency = None;
                continue;
            };
            analysis.dependencies.push(DependencyRecord {
                ecosystem: "npm".to_owned(),
                name,
                version: Some(version),
                integrity: None,
                resolved: None,
                source_file: path.to_owned(),
            });
            current_dependency = Some(analysis.dependencies.len() - 1);
        } else if let Some(index) = current_dependency {
            let trimmed = line.trim();
            if let Some(resolution) = trimmed.strip_prefix("resolution:") {
                analysis.dependencies[index].integrity = inline_yaml_value(resolution, "integrity");
                analysis.dependencies[index].resolved = inline_yaml_value(resolution, "tarball");
            } else if let Some(value) = trimmed.strip_prefix("integrity:") {
                analysis.dependencies[index].integrity = Some(yaml_scalar(value));
            } else if let Some(value) = trimmed.strip_prefix("tarball:") {
                analysis.dependencies[index].resolved = Some(yaml_scalar(value));
            }
        }
    }
    analysis
}

fn inline_yaml_value(value: &str, key: &str) -> Option<String> {
    let value = value.trim().trim_start_matches('{').trim_end_matches('}');
    value.split(',').find_map(|field| {
        let (field_key, field_value) = field.split_once(':')?;
        (field_key.trim() == key).then(|| yaml_scalar(field_value))
    })
}

fn yaml_scalar(value: &str) -> String {
    value.trim().trim_matches(['\'', '"']).to_owned()
}

fn pnpm_package(key: &str) -> Option<(String, String)> {
    let key = key.trim_start_matches('/');
    if let Some(split) = key.rfind('/')
        && !key[split + 1..].contains('@')
    {
        let name = key[..split].to_owned();
        let version = key[split + 1..]
            .split('(')
            .next()
            .unwrap_or_default()
            .to_owned();
        return (!name.is_empty() && !version.is_empty()).then_some((name, version));
    }
    let split = if key.starts_with('@') {
        key.match_indices('@').nth(1)?.0
    } else {
        key.rfind('@')?
    };
    let name = key[..split].to_owned();
    let version = key[split + 1..]
        .split('(')
        .next()
        .unwrap_or_default()
        .to_owned();
    (!name.is_empty() && !version.is_empty()).then_some((name, version))
}

fn property_value(line: &str, name: &str) -> Option<String> {
    line.strip_prefix(name)
        .map(str::trim)
        .map(|value| value.trim_matches('"').to_owned())
}

fn parse_failure(path: &str, kind: &str, error: String) -> MetadataAnalysis {
    MetadataAnalysis {
        findings: vec![Finding {
            id: "CONFIG-PARSE-FAILED".to_owned(),
            severity: Severity::Medium,
            confidence: Confidence::VeryHigh,
            score: 45,
            title: "Security-relevant configuration could not be parsed".to_owned(),
            message: format!("The {kind} is malformed or unsupported, so analysis is incomplete."),
            file: Some(path.to_owned()),
            line: None,
            evidence: vec![error.clone()],
        }],
        incomplete_reasons: vec![format!("could not parse {kind} {path}: {error}")],
        ..MetadataAnalysis::default()
    }
}

fn find_line(text: &str, needle: &str) -> Option<u64> {
    text.lines()
        .position(|line| line.contains(needle))
        .map(|line| line as u64 + 1)
}

#[cfg(test)]
mod tests {
    use super::{analyze_manifest, analyze_npm_lock, analyze_pnpm_lock, analyze_yarn_lock};

    #[test]
    fn finds_lifecycle_scripts() {
        let analysis = analyze_manifest(
            "package.json",
            r#"{"scripts":{"postinstall":"node setup.js","start":"node app.js"}}"#,
        );
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.id == "NPM-LIFECYCLE-SCRIPT")
        );
    }

    #[test]
    fn extracts_npm_lock_dependencies() {
        let analysis = analyze_npm_lock(
            "package-lock.json",
            r#"{"packages":{"node_modules/left-pad":{"version":"1.3.0","integrity":"sha512-x"}}}"#,
        );
        assert_eq!(analysis.dependencies.len(), 1);
        assert_eq!(analysis.dependencies[0].name, "left-pad");
    }

    #[test]
    fn extracts_pnpm_package_keys() {
        let analysis = analyze_pnpm_lock(
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\npackages:\n  '@scope/pkg@1.2.3':\n    resolution: {integrity: sha512-test}\n  left-pad@1.3.0: {}\n  /legacy/2.0.0: {}\n",
        );
        assert_eq!(analysis.dependencies.len(), 3);
        assert_eq!(
            analysis.dependencies[0].integrity.as_deref(),
            Some("sha512-test")
        );
    }

    #[test]
    fn extracts_last_yarn_entry() {
        let analysis = analyze_yarn_lock(
            "yarn.lock",
            "# yarn lockfile v1\n\nleft-pad@^1.0.0:\n  version \"1.3.0\"\n  resolved \"https://example.invalid/left-pad.tgz\"\n",
        );
        assert_eq!(analysis.dependencies.len(), 1);
        assert_eq!(analysis.dependencies[0].version.as_deref(), Some("1.3.0"));
    }
}
