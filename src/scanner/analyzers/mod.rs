mod ide;
mod npm;

use crate::model::{DependencyRecord, Finding};

#[derive(Default)]
pub struct MetadataAnalysis {
    pub findings: Vec<Finding>,
    pub dependencies: Vec<DependencyRecord>,
    pub incomplete_reasons: Vec<String>,
}

fn bounded(value: &str) -> String {
    const LIMIT: usize = 512;
    let mut output = value.chars().take(LIMIT).collect::<String>();
    if value.chars().count() > LIMIT {
        output.push('…');
    }
    output
}

pub fn analyze(path: &str, text: Option<&str>) -> MetadataAnalysis {
    let Some(text) = text else {
        return MetadataAnalysis::default();
    };
    let name = path.rsplit('/').next().unwrap_or(path);
    let npm = matches!(
        name,
        "package.json"
            | "package-lock.json"
            | "npm-shrinkwrap.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
    );
    let ide = path.starts_with(".vscode/") || path == ".devcontainer/devcontainer.json";
    if (npm || ide) && text.len() > 4 * 1024 * 1024 {
        return MetadataAnalysis {
            incomplete_reasons: vec![format!(
                "security-relevant configuration exceeds 4194304 byte parse limit: {path}"
            )],
            ..MetadataAnalysis::default()
        };
    }
    if npm {
        return npm::analyze(path, name, text);
    }
    if ide {
        return ide::analyze(path, name, text);
    }
    MetadataAnalysis::default()
}

#[cfg(test)]
mod tests {
    use super::analyze;

    #[test]
    fn rejects_oversized_security_configuration() {
        let text = " ".repeat(4 * 1024 * 1024 + 1);
        let analysis = analyze(".vscode/tasks.json", Some(&text));
        assert_eq!(analysis.incomplete_reasons.len(), 1);
    }
}
