use super::js::{Capability, ModuleFacts};
use crate::model::{Confidence, Finding, Severity};
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::path::{Component, Path};

const MAX_EDGES: usize = 50_000;

#[derive(Clone, Debug)]
pub struct Root {
    pub file: String,
    pub trigger: String,
    pub line: Option<u64>,
}

pub struct GraphResult {
    pub findings: Vec<Finding>,
    pub unresolved: Vec<String>,
    pub incomplete_reasons: Vec<String>,
    pub reachable: BTreeMap<String, Vec<String>>,
}

pub fn roots(path: &str, text: Option<&str>, roles: &[String]) -> Vec<Root> {
    let mut roots = Vec::new();
    if roles.iter().any(|role| role == "executable_config") {
        roots.push(Root {
            file: path.to_owned(),
            trigger: format!("build config {path}"),
            line: None,
        });
    }
    if path.rsplit('/').next() == Some("package.json")
        && let Some(value) = text.and_then(|text| serde_json::from_str::<Value>(text).ok())
        && let Some(scripts) = value.get("scripts").and_then(Value::as_object)
    {
        for (name, command) in scripts {
            if let Some(command) = command.as_str()
                && let Some(target) = command_target(command)
            {
                roots.push(Root {
                    file: resolve_from(path, &target),
                    trigger: format!("npm {name} ({path})"),
                    line: text.and_then(|text| find_line(text, &format!("\"{name}\""))),
                });
            }
        }
    }
    if path == ".vscode/tasks.json"
        && let Some(value) = text.and_then(|text| json5::from_str::<Value>(text).ok())
        && let Some(tasks) = value.get("tasks").and_then(Value::as_array)
    {
        for task in tasks {
            if task.pointer("/runOptions/runOn").and_then(Value::as_str) != Some("folderOpen") {
                continue;
            }
            let Some(command) = task.get("command").and_then(Value::as_str) else {
                continue;
            };
            if let Some(target) = command_target(command) {
                roots.push(Root {
                    file: target.trim_start_matches("./").to_owned(),
                    trigger: "VS Code folderOpen task".to_owned(),
                    line: text.and_then(|text| find_line(text, "folderOpen")),
                });
            }
        }
    }
    roots
}

fn command_target(command: &str) -> Option<String> {
    let parts: Vec<_> = command.split_ascii_whitespace().collect();
    let executable = parts.first()?.trim_matches(['"', '\'']);
    if !matches!(
        executable,
        "node" | "node.exe" | "bun" | "deno" | "tsx" | "ts-node"
    ) {
        return None;
    }
    parts
        .iter()
        .skip(1)
        .map(|part| part.trim_matches(['"', '\'', ';']))
        .find(|part| {
            !part.starts_with('-')
                && [".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx"]
                    .iter()
                    .any(|suffix| part.ends_with(suffix))
        })
        .map(str::to_owned)
}

fn find_line(text: &str, needle: &str) -> Option<u64> {
    text.find(needle)
        .map(|offset| text[..offset].bytes().filter(|byte| *byte == b'\n').count() as u64 + 1)
}

pub fn build(modules: &[ModuleFacts], roots: &[Root]) -> GraphResult {
    let by_path: BTreeMap<_, _> = modules
        .iter()
        .map(|module| (module.path.as_str(), module))
        .collect();
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
                Some(target) => {
                    edges
                        .entry(&module.path)
                        .or_default()
                        .push((target, import.line));
                    edge_count += 1;
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
        if let Some((path, _)) = by_path.get_key_value(root.file.as_str()) {
            let route = vec![
                format!(
                    "trigger: {}{}",
                    root.trigger,
                    root.line
                        .map(|line| format!(" at line {line}"))
                        .unwrap_or_default()
                ),
                format!("entry: {path}"),
            ];
            if reachable.insert(path, route.clone()).is_none() {
                queue.push_back((*path, route));
            }
        } else {
            unresolved.push(format!(
                "{} -> {} (entry unresolved)",
                root.trigger, root.file
            ));
        }
    }
    while let Some((source, route)) = queue.pop_front() {
        for (target, line) in edges.get(source).into_iter().flatten() {
            if reachable.contains_key(target) {
                continue;
            }
            let mut next = route.clone();
            if next.len() >= 64 {
                incomplete_reasons
                    .push("JS/TS execution route depth limit of 64 reached".to_owned());
                continue;
            }
            next.push(format!("{source}:{line} imports {target}"));
            reachable.insert(target, next.clone());
            queue.push_back((target, next));
        }
    }

    let mut findings = Vec::new();
    for module in modules {
        let route = reachable.get(module.path.as_str());
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
                Some(Capability::DynamicCode | Capability::Process | Capability::Secret)
            ) && call
                .function
                .as_ref()
                .is_none_or(|name| called_functions.contains(name))
        });
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
    [".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx"]
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
