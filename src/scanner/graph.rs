use super::js::{Capability, ModuleFacts};
use crate::model::{Confidence, FileRecord, Finding, Severity};
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::path::{Component, Path};

const MAX_EDGES: usize = 50_000;
pub const MAX_EXECUTION_ROOTS: usize = 50_000;
const MAX_ROOTS_PER_FILE: usize = 10_000;
const MAX_COMMAND_DEPTH: usize = 8;

#[derive(Clone, Debug)]
pub struct Root {
    pub file: String,
    pub trigger: String,
    pub line: Option<u64>,
}

pub struct RootAnalysis {
    pub roots: Vec<Root>,
    pub incomplete: bool,
}

pub struct GraphResult {
    pub findings: Vec<Finding>,
    pub unresolved: Vec<String>,
    pub incomplete_reasons: Vec<String>,
    pub reachable: BTreeMap<String, Vec<String>>,
}

pub fn roots(path: &str, text: Option<&str>, roles: &[String]) -> RootAnalysis {
    let mut roots = Vec::new();
    let mut limit_reached = false;
    if roles.iter().any(|role| role == "executable_config") {
        push_root(
            &mut roots,
            Root {
                file: path.to_owned(),
                trigger: format!("build config {path}"),
                line: None,
            },
            &mut limit_reached,
        );
    }
    if path.rsplit('/').next() == Some("package.json")
        && let Some(value) = text.and_then(|text| serde_json::from_str::<Value>(text).ok())
        && let Some(scripts) = value.get("scripts").and_then(Value::as_object)
    {
        // ponytail: keep exact line lookup for small manifests; use a token-position parser if large manifests need line evidence.
        let line_evidence = scripts.len() <= 64;
        for (name, command) in scripts {
            if let Some(command) = command.as_str() {
                let trigger = format!("npm {name} ({path})");
                let line = line_evidence
                    .then(|| text.and_then(|text| find_line(text, &format!("\"{name}\""))))
                    .flatten();
                let targets = script_targets(command, scripts, 0, &mut limit_reached);
                if targets.is_empty() {
                    push_root(
                        &mut roots,
                        Root {
                            file: String::new(),
                            trigger: trigger.clone(),
                            line,
                        },
                        &mut limit_reached,
                    );
                } else {
                    for target in targets {
                        push_root(
                            &mut roots,
                            Root {
                                file: resolve_from(path, &target),
                                trigger: trigger.clone(),
                                line,
                            },
                            &mut limit_reached,
                        );
                    }
                }
            }
        }
    }
    if path == ".vscode/tasks.json"
        && let Some(value) = text.and_then(|text| json5::from_str::<Value>(text).ok())
        && let Some(tasks) = value.get("tasks").and_then(Value::as_array)
    {
        let line = text.and_then(|text| find_line(text, "folderOpen"));
        for task in tasks {
            if task.pointer("/runOptions/runOn").and_then(Value::as_str) != Some("folderOpen") {
                continue;
            }
            let Some(command) = task.get("command").and_then(Value::as_str) else {
                continue;
            };
            let args = task
                .get("args")
                .and_then(Value::as_array)
                .map(|args| {
                    args.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            let targets = command_targets(&format!("{command} {args}"), &mut limit_reached);
            if targets.is_empty() {
                push_root(
                    &mut roots,
                    Root {
                        file: String::new(),
                        trigger: "VS Code folderOpen task".to_owned(),
                        line,
                    },
                    &mut limit_reached,
                );
            } else {
                for target in targets {
                    push_root(
                        &mut roots,
                        Root {
                            file: target.trim_start_matches("./").to_owned(),
                            trigger: "VS Code folderOpen task".to_owned(),
                            line,
                        },
                        &mut limit_reached,
                    );
                }
            }
        }
    }
    if path == ".devcontainer/devcontainer.json"
        && let Some(value) = text.and_then(|text| json5::from_str::<Value>(text).ok())
    {
        for hook in [
            "initializeCommand",
            "onCreateCommand",
            "updateContentCommand",
            "postCreateCommand",
            "postStartCommand",
            "postAttachCommand",
        ] {
            let Some(commands) = value.get(hook) else {
                continue;
            };
            let commands: Vec<&str> = match commands {
                Value::String(command) => vec![command],
                Value::Array(commands) => commands.iter().filter_map(Value::as_str).collect(),
                Value::Object(commands) => commands.values().filter_map(Value::as_str).collect(),
                _ => Vec::new(),
            };
            for command in commands {
                let targets = command_targets(command, &mut limit_reached);
                let trigger = format!("devcontainer {hook}");
                let line = text.and_then(|text| find_line(text, hook));
                if targets.is_empty() {
                    push_root(
                        &mut roots,
                        Root {
                            file: String::new(),
                            trigger: trigger.clone(),
                            line,
                        },
                        &mut limit_reached,
                    );
                } else {
                    for target in targets {
                        push_root(
                            &mut roots,
                            Root {
                                file: target.trim_start_matches("./").to_owned(),
                                trigger: trigger.clone(),
                                line,
                            },
                            &mut limit_reached,
                        );
                    }
                }
            }
        }
    }
    if roles
        .iter()
        .any(|role| role == "ci_config" || role == "build_script")
        && let Some(text) = text
    {
        for (index, line) in text.lines().enumerate() {
            let command = line
                .trim()
                .trim_start_matches("- ")
                .trim_start_matches("run:")
                .trim_start_matches("RUN ")
                .trim_start_matches("command:")
                .trim_start_matches("entrypoint:")
                .trim();
            let targets = command_targets(command, &mut limit_reached);
            let trigger = format!("build or CI command in {path}");
            if targets.is_empty() {
                continue;
            }
            for target in targets {
                push_root(
                    &mut roots,
                    Root {
                        file: if roles.iter().any(|role| role == "ci_config") {
                            target.trim_start_matches("./").to_owned()
                        } else {
                            resolve_from(path, &target)
                        },
                        trigger: trigger.clone(),
                        line: Some(index as u64 + 1),
                    },
                    &mut limit_reached,
                );
            }
        }
    }
    RootAnalysis {
        roots,
        incomplete: limit_reached,
    }
}

fn push_root(roots: &mut Vec<Root>, root: Root, limit_reached: &mut bool) {
    if roots.len() < MAX_ROOTS_PER_FILE {
        roots.push(root);
    } else {
        *limit_reached = true;
    }
}

fn script_targets(
    command: &str,
    scripts: &serde_json::Map<String, Value>,
    depth: usize,
    limit_reached: &mut bool,
) -> Vec<String> {
    if depth >= MAX_COMMAND_DEPTH {
        *limit_reached = true;
        return Vec::new();
    }
    let mut targets = Vec::new();
    for part in command.split([';', '|', '&', '\n']) {
        targets.extend(command_targets_at(part, 0, limit_reached));
        let parts: Vec<_> = part.split_ascii_whitespace().collect();
        let referenced = match parts.as_slice() {
            ["npm", "run", name, ..] | ["pnpm", "run", name, ..] | ["yarn", "run", name, ..] => {
                Some(*name)
            }
            _ => None,
        }
        .and_then(|name| scripts.get(name)?.as_str());
        if let Some(nested) = referenced {
            targets.extend(script_targets(nested, scripts, depth + 1, limit_reached));
        }
    }
    targets.sort();
    targets.dedup();
    targets
}

fn command_targets(command: &str, limit_reached: &mut bool) -> Vec<String> {
    command_targets_at(command, 0, limit_reached)
}

fn command_targets_at(command: &str, depth: usize, limit_reached: &mut bool) -> Vec<String> {
    if depth >= MAX_COMMAND_DEPTH {
        *limit_reached = true;
        return Vec::new();
    }
    // ponytail: separator splitting ignores quoting; use a shell parser if corpus scans show missed command boundaries.
    let mut targets = command
        .split([';', '|', '&', '\n'])
        .flat_map(|part| command_target(part, depth, limit_reached))
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    targets
}

fn command_target(command: &str, depth: usize, limit_reached: &mut bool) -> Vec<String> {
    let parts = command
        .split_ascii_whitespace()
        .map(|part| part.trim_matches(['"', '\'']))
        .collect::<Vec<_>>();
    let mut index = 0;
    let Some(mut executable) = parts.first().copied() else {
        return Vec::new();
    };
    if matches!(
        executable,
        "sh" | "bash" | "zsh" | "pwsh" | "powershell" | "cmd" | "cmd.exe"
    ) {
        let command_flag = parts
            .iter()
            .position(|part| matches!(*part, "-c" | "-Command" | "-command" | "/c"));
        let command = command_flag.map_or_else(
            || parts[1..].join(" "),
            |command_flag| parts[command_flag + 1..].join(" "),
        );
        return command_targets_at(&command, depth + 1, limit_reached);
    }
    if matches!(executable, "cross-env" | "cross-env-shell" | "env") {
        let Some(found) = parts
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(index, part)| (!part.contains('=')).then_some(index))
        else {
            return Vec::new();
        };
        index = found;
        executable = parts[index];
    }
    if matches!(executable, "npx" | "pnpm" | "yarn") {
        index += 1;
        let Some(next) = parts.get(index).copied() else {
            return Vec::new();
        };
        executable = next;
        if executable == "exec" {
            index += 1;
            let Some(next) = parts.get(index).copied() else {
                return Vec::new();
            };
            executable = next;
        }
    }
    if !matches!(
        executable,
        "node" | "node.exe" | "bun" | "deno" | "tsx" | "ts-node"
    ) {
        if matches!(
            executable,
            "sh" | "bash" | "zsh" | "pwsh" | "powershell" | "cmd" | "cmd.exe"
        ) {
            return command_target(&parts[index..].join(" "), depth, limit_reached);
        }
        return Vec::new();
    }
    let args = &parts[index + 1..];
    let mut skip_value = false;
    let mut targets = Vec::new();
    for argument in args {
        if skip_value {
            skip_value = false;
            if !argument.starts_with('-')
                && [".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx"]
                    .iter()
                    .any(|suffix| argument.ends_with(suffix))
            {
                targets.push((*argument).to_owned());
            }
            continue;
        }
        if matches!(*argument, "-e" | "--eval" | "-p" | "--print") {
            return targets;
        }
        if matches!(*argument, "-r" | "--require" | "--import" | "--loader") {
            skip_value = true;
            continue;
        }
        if !argument.starts_with('-')
            && [".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx"]
                .iter()
                .any(|suffix| argument.ends_with(suffix))
        {
            targets.push((*argument).to_owned());
        }
    }
    targets
}

fn find_line(text: &str, needle: &str) -> Option<u64> {
    text.find(needle)
        .map(|offset| text[..offset].bytes().filter(|byte| *byte == b'\n').count() as u64 + 1)
}

pub fn build(modules: &[ModuleFacts], roots: &[Root], files: &[FileRecord]) -> GraphResult {
    let by_id: BTreeMap<_, _> = modules
        .iter()
        .map(|module| (module.id.as_str(), module))
        .collect();
    let mut by_path = BTreeMap::new();
    let mut by_file: BTreeMap<&str, Vec<&ModuleFacts>> = BTreeMap::new();
    for module in modules {
        by_path.entry(module.path.as_str()).or_insert(module);
        by_file
            .entry(module.path.as_str())
            .or_default()
            .push(module);
    }
    let mut edges: BTreeMap<&str, Vec<(&str, u64)>> = BTreeMap::new();
    let mut unresolved = Vec::new();
    let mut incomplete_reasons = Vec::new();
    let mut edge_count = 0;
    for module in modules {
        for import in &module.imports {
            if edge_count + unresolved.len() >= MAX_EDGES {
                incomplete_reasons.push(format!("JS/TS graph edge limit of {MAX_EDGES} reached"));
                break;
            }
            if !import.specifier.starts_with('.') {
                if import.specifier.starts_with("<dynamic ") {
                    unresolved.push(format!(
                        "{}:{} -> {} (dynamic module target unresolved)",
                        module.path, import.line, import.specifier
                    ));
                    continue;
                }
                if !import.specifier.starts_with("node:")
                    && !matches!(
                        import.specifier.as_str(),
                        "fs" | "os"
                            | "path"
                            | "http"
                            | "https"
                            | "vm"
                            | "child_process"
                            | "crypto"
                            | "net"
                            | "tls"
                    )
                {
                    unresolved.push(format!(
                        "{}:{} -> {} (external package not inspected)",
                        module.path, import.line, import.specifier
                    ));
                }
                continue;
            }
            match resolve_import(&module.path, &import.specifier, &by_path) {
                Some(target_path) => {
                    for target in &by_file[target_path] {
                        if edge_count + unresolved.len() >= MAX_EDGES {
                            incomplete_reasons
                                .push(format!("JS/TS graph edge limit of {MAX_EDGES} reached"));
                            break;
                        }
                        edges
                            .entry(&module.id)
                            .or_default()
                            .push((&target.id, import.line));
                        edge_count += 1;
                    }
                }
                None => unresolved.push(format!(
                    "{}:{} -> {} (relative import unresolved)",
                    module.path, import.line, import.specifier
                )),
            }
        }
    }

    let mut reachable: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut queue = VecDeque::new();
    for root in roots {
        if let Some(module) = by_id.get(root.file.as_str()) {
            let route = vec![
                format!(
                    "trigger: {}{}",
                    root.trigger,
                    root.line
                        .map(|line| format!(" at line {line}"))
                        .unwrap_or_default()
                ),
                format!("entry: {}", module.path),
            ];
            if reachable.insert(&module.id, route.clone()).is_none() {
                queue.push_back((module.id.as_str(), route));
            }
        } else {
            unresolved.push(if root.file.is_empty() {
                format!("{} (command target unresolved)", root.trigger)
            } else {
                format!("{} -> {} (entry unresolved)", root.trigger, root.file)
            });
        }
    }
    while let Some((source, route)) = queue.pop_front() {
        for (target, line) in edges.get(source).into_iter().flatten() {
            let target = *target;
            if reachable.contains_key(target) {
                continue;
            }
            let mut next = route.clone();
            if next.len() >= 64 {
                incomplete_reasons
                    .push("JS/TS execution route depth limit of 64 reached".to_owned());
                continue;
            }
            let source_path = by_id
                .get(source)
                .map_or(source, |module| module.path.as_str());
            let target_path = by_id
                .get(target)
                .map_or(target, |module| module.path.as_str());
            next.push(format!("{source_path}:{line} imports {target_path}"));
            reachable.insert(target, next.clone());
            queue.push_back((target, next));
        }
    }

    let mut findings = Vec::new();
    let file_records: BTreeMap<_, _> = files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    for module in modules {
        let route = reachable.get(module.id.as_str());
        let disguised = !has_code_extension(&module.path);
        let mut called_functions = std::collections::BTreeSet::new();
        loop {
            let previous = called_functions.len();
            for call in &module.calls {
                if call
                    .function
                    .as_ref()
                    .is_none_or(|name| called_functions.contains(name))
                    && let Some(name) = call.name.strip_prefix("local:")
                {
                    called_functions.insert(name.to_owned());
                }
            }
            if called_functions.len() == previous {
                break;
            }
        }
        let dangerous = module.calls.iter().find(|call| {
            matches!(
                call.capability,
                Some(
                    Capability::DynamicCode
                        | Capability::Process
                        | Capability::Secret
                        | Capability::Network
                )
            ) && call
                .function
                .as_ref()
                .is_none_or(|name| called_functions.contains(name))
        });
        if let (Some(route), Some(call), Some(record)) =
            (route, dangerous, file_records.get(module.path.as_str()))
            && let Some(signal) = record.raw_signals.iter().find(|signal| {
                signal.starts_with("code follows ") || signal.contains("logical EOF")
            })
        {
            findings.push(Finding {
                    id: "JS-CONCEALED-EXECUTION".to_owned(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    score: 88,
                    title: "Reachable execution capability is visually concealed".to_owned(),
                    message: "Executable JavaScript combines an evidenced execution route, concealment, and a code or process execution capability.".to_owned(),
                    file: Some(module.path.clone()),
                    line: Some(call.line),
                    evidence: route.iter().cloned().chain([format!("concealment: {signal}"), format!("capability: {}", call.name)]).collect(),
                });
        }
        if disguised && let Some(route) = route {
            findings.push(Finding {
                    id: "JS-REACHABLE-DISGUISED-SOURCE".to_owned(),
                    severity: if dangerous.is_some() {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    confidence: Confidence::High,
                    score: if dangerous.is_some() { 95 } else { 80 },
                    title: "Executable source disguised as an asset is reachable".to_owned(),
                    message: "A repository execution root statically imports parseable JavaScript under a non-code extension.".to_owned(),
                    file: Some(module.path.clone()),
                    line: dangerous.map(|call| call.line),
                    evidence: route.iter().cloned().chain(dangerous.map(|call| format!("capability: {} at line {}", call.name, call.line))).collect(),
                });
        }
        for call in &module.calls {
            let Some(capability) = call.capability else {
                continue;
            };
            if !matches!(capability, Capability::DynamicCode | Capability::Process) {
                continue;
            }
            findings.push(Finding {
                id: match capability {
                    Capability::DynamicCode => "JS-DYNAMIC-EXECUTION",
                    Capability::Process => "JS-PROCESS-EXECUTION",
                    _ => unreachable!(),
                }.to_owned(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                score: 45,
                title: "JavaScript contains an execution capability".to_owned(),
                message: "This capability can execute code or a process; the call alone does not establish malicious intent.".to_owned(),
                file: Some(module.path.clone()),
                line: Some(call.line),
                evidence: route.filter(|_| call.function.as_ref().is_none_or(|name| called_functions.contains(name)))
                    .into_iter().flat_map(|route| route.iter().cloned()).chain([format!("call: {}", call.evidence)]).collect(),
            });
        }
    }
    unresolved.sort();
    unresolved.dedup();
    GraphResult {
        findings,
        unresolved,
        incomplete_reasons,
        reachable: reachable
            .into_iter()
            .map(|(path, route)| (path.to_owned(), route))
            .collect(),
    }
}

fn has_code_extension(path: &str) -> bool {
    [
        ".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx", ".html", ".htm", ".xhtml",
        ".vue", ".md", ".mdx",
    ]
    .iter()
    .any(|extension| path.ends_with(extension))
}

fn resolve_from(from: &str, specifier: &str) -> String {
    let directory = Path::new(from).parent().unwrap_or_else(|| Path::new(""));
    let mut components = Vec::new();
    for part in directory.join(specifier).components() {
        match part {
            Component::Normal(value) => components.push(value.to_string_lossy().into_owned()),
            Component::ParentDir => {
                if components.pop().is_none() {
                    return String::new();
                }
            }
            Component::CurDir => {}
            _ => return String::new(),
        }
    }
    components.join("/")
}

pub(super) fn resolve_import<'a>(
    from: &str,
    specifier: &str,
    modules: &BTreeMap<&'a str, &'a ModuleFacts>,
) -> Option<&'a str> {
    let target = resolve_from(from, specifier);
    if target.is_empty() {
        return None;
    }
    let candidates = std::iter::once(target.clone()).chain(
        [
            ".js",
            ".cjs",
            ".mjs",
            ".ts",
            ".cts",
            ".mts",
            ".jsx",
            ".tsx",
            "/index.js",
            "/index.ts",
        ]
        .into_iter()
        .map(|suffix| format!("{target}{suffix}")),
    );
    candidates.into_iter().find_map(|candidate| {
        modules
            .get_key_value(candidate.as_str())
            .map(|(path, _)| *path)
    })
}

#[cfg(test)]
mod tests {
    use super::{MAX_COMMAND_DEPTH, MAX_ROOTS_PER_FILE, roots};

    #[test]
    fn caps_roots_from_hostile_package_metadata() {
        let scripts = (0..=MAX_ROOTS_PER_FILE)
            .map(|index| format!("\"script{index}\":\"node {index}.js\""))
            .collect::<Vec<_>>()
            .join(",");
        let text = format!("{{\"scripts\":{{{scripts}}}}}");

        let result = roots("package.json", Some(&text), &[]);

        assert_eq!(result.roots.len(), MAX_ROOTS_PER_FILE);
        assert!(result.incomplete);
    }

    #[test]
    fn caps_recursive_shell_wrappers_from_hostile_package_metadata() {
        let command = (0..MAX_COMMAND_DEPTH).fold("node main.js".to_owned(), |command, _| {
            format!("sh -c {command}")
        });
        let text = format!(r#"{{"scripts":{{"start":"{command}"}}}}"#);

        let result = roots("package.json", Some(&text), &[]);

        assert!(result.incomplete);
    }

    #[test]
    fn includes_node_preload_and_entry_files_as_roots() {
        let text = r#"{"scripts":{"start":"node --require ./preload.js ./main.js"}}"#;

        let result = roots("package.json", Some(text), &[]);
        let files = result
            .roots
            .into_iter()
            .map(|root| root.file)
            .collect::<Vec<_>>();

        assert_eq!(files, ["main.js", "preload.js"]);
    }
}
