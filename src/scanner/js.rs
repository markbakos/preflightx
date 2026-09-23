use crate::model::{Confidence, Finding, Severity};
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use std::path::Path;

mod flow;
mod semantic;
pub use flow::analyze_flows;
pub use semantic::{Capability, ModuleFacts};

const MAX_PARSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_NESTING: usize = 256;

pub struct JsAnalysis {
    pub language: Option<String>,
    pub findings: Vec<Finding>,
    pub incomplete_reasons: Vec<String>,
    pub module: Option<ModuleFacts>,
}

pub fn analyze(path: &str, text: Option<&str>) -> JsAnalysis {
    let extension = Path::new(path).extension().and_then(|value| value.to_str());
    let supported = matches!(
        extension,
        Some("js" | "cjs" | "mjs" | "jsx" | "ts" | "cts" | "mts" | "tsx")
    );
    let suspicious = text.is_some_and(|text| {
        let shell_shebang = text
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("#!"))
            .is_some_and(|interpreter| !interpreter.to_ascii_lowercase().contains("node"));
        let source_start = text.trim_start();
        // ponytail: only parse source-led text; extracting embedded HTML/Vue/Markdown scripts needs format-aware boundaries.
        let source_led = [
            "#!",
            "//",
            "/*",
            "const ",
            "let ",
            "var ",
            "function ",
            "async ",
            "await ",
            "class ",
            "import ",
            "export ",
            "if ",
            "if(",
            "for ",
            "for(",
            "while ",
            "try ",
            "switch ",
            "throw ",
            "new ",
            "module.",
            "exports.",
            "require(",
            "eval(",
            "new Function",
            "global",
            "process.",
            "fetch(",
            "axios",
            "http.",
            "https.",
            "WebSocket",
            "console.",
            "setTimeout(",
            "setInterval(",
            "(",
            "\"use strict\"",
            "'use strict'",
        ]
        .iter()
        .any(|prefix| source_start.starts_with(prefix));
        !shell_shebang
            && source_led
            && (super::classifier::looks_like_executable_text(text)
                || (matches!(
                    extension,
                    Some("svg" | "woff" | "woff2" | "png" | "jpg" | "gif")
                ) && ["eval(", "require(", "module.exports", "const ", "function "]
                    .iter()
                    .any(|prefix| text.trim_start().starts_with(prefix))))
    });
    let mut result = JsAnalysis {
        language: None,
        findings: Vec::new(),
        incomplete_reasons: Vec::new(),
        module: None,
    };
    if !supported && !suspicious {
        return result;
    }
    let Some(text) = text else {
        result
            .incomplete_reasons
            .push(format!("cannot decode JS/TS source: {path}"));
        return result;
    };
    if text.len() > MAX_PARSE_BYTES {
        result.incomplete_reasons.push(format!(
            "JS/TS parse limit of {MAX_PARSE_BYTES} bytes exceeded: {path}"
        ));
        return result;
    }
    // ponytail: This conservative byte count may reject deep strings/comments; use token-aware limits if observed in real projects.
    let mut nesting = 0usize;
    for byte in text.bytes() {
        match byte {
            b'(' | b'[' | b'{' => nesting += 1,
            b')' | b']' | b'}' => nesting = nesting.saturating_sub(1),
            _ => {}
        }
        if nesting > MAX_NESTING {
            result.incomplete_reasons.push(format!(
                "JS/TS nesting limit of {MAX_NESTING} exceeded: {path}"
            ));
            return result;
        }
    }

    let source_type = if supported {
        SourceType::from_path(path).expect("supported JS/TS extension")
    } else {
        SourceType::default()
    };
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, text, source_type).parse();
    if parsed.fatal_error || !parsed.diagnostics.is_empty() {
        result.incomplete_reasons.push(format!(
            "JS/TS parser could not fully parse {path}: {} diagnostic(s)",
            parsed.diagnostics.len()
        ));
        return result;
    }
    if !supported && parsed.program.body.is_empty() {
        return result;
    }
    result.language = Some(
        if source_type.is_typescript() {
            "typescript"
        } else {
            "javascript"
        }
        .to_owned(),
    );
    let facts = semantic::collect(path, text, &parsed.program);
    result.incomplete_reasons.extend(facts.incomplete_reasons);
    result.module = facts.module;
    if !supported {
        result.findings.push(Finding {
            id: "FILE-PARSEABLE-JAVASCRIPT".to_owned(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            score: 45,
            title: "JavaScript parses under a non-code extension".to_owned(),
            message: "Oxc parsed executable-looking text as JavaScript. No execution path is established by this finding alone.".to_owned(),
            file: Some(path.to_owned()),
            line: None,
            evidence: vec![format!("extension: .{}", extension.unwrap_or("(none)"))],
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{MAX_NESTING, MAX_PARSE_BYTES, analyze};

    #[test]
    fn parses_supported_javascript_and_typescript() {
        for path in ["a.js", "a.cjs", "a.mjs", "a.jsx"] {
            let analysis = analyze(path, Some("const value = 1;"));
            assert_eq!(analysis.language.as_deref(), Some("javascript"), "{path}");
            assert!(analysis.incomplete_reasons.is_empty(), "{path}");
        }
        for path in ["a.ts", "a.cts", "a.mts", "a.tsx"] {
            let analysis = analyze(path, Some("const value: number = 1;"));
            assert_eq!(analysis.language.as_deref(), Some("typescript"), "{path}");
            assert!(analysis.incomplete_reasons.is_empty(), "{path}");
        }
    }

    #[test]
    fn fake_assets_need_parseable_code() {
        let positive = analyze(
            "fake.woff2",
            Some("module.exports = require('child_process');"),
        );
        assert_eq!(positive.findings[0].id, "FILE-PARSEABLE-JAVASCRIPT");
        let evasion = analyze("fake.svg", Some("   const cp = require('child_process');"));
        assert_eq!(evasion.language.as_deref(), Some("javascript"));
        let minimal = analyze("fake.svg", Some("eval('2 + 2');"));
        assert_eq!(minimal.language.as_deref(), Some("javascript"));
        let negative = analyze("real.svg", Some("<svg><text>const x = 1</text></svg>"));
        assert!(negative.findings.is_empty());
    }

    #[test]
    fn shell_shebang_is_not_sent_to_the_javascript_parser() {
        let analysis = analyze(
            ".git/hooks/push-to-checkout.sample",
            Some("#!/bin/sh\nfunction die() { echo failed; }\n"),
        );
        assert!(analysis.incomplete_reasons.is_empty());
        assert!(analysis.module.is_none());
    }

    #[test]
    fn embedded_document_examples_are_not_whole_file_javascript() {
        for (path, text) in [
            (
                "README.md",
                "# Examples\nconst value = 1; function run() {}",
            ),
            (
                "index.html",
                "<!doctype html><script>const value = 1;</script>",
            ),
            (
                "index.notjs",
                "<notjs>\nimport { value } from './value.js';\n</notjs>",
            ),
            ("App.vue", "<script>const value = 1;</script><template />"),
            ("config.yml", "name: example\nrun: node script.js"),
        ] {
            let analysis = analyze(path, Some(text));
            assert!(analysis.incomplete_reasons.is_empty(), "{path}");
            assert!(analysis.module.is_none(), "{path}");
        }

        let disguised = analyze("payload.md", Some("const payload = 1; function run() {}"));
        assert_eq!(disguised.language.as_deref(), Some("javascript"));
        let disguised_statement = analyze(
            "payload.data",
            Some("if (enabled) { const cp = require('child_process'); eval('payload'); }"),
        );
        assert_eq!(disguised_statement.language.as_deref(), Some("javascript"));
    }

    #[test]
    fn syntax_and_size_failures_are_incomplete() {
        let malformed = analyze("broken.js", Some("const = ;"));
        assert_eq!(malformed.incomplete_reasons.len(), 1);
        let disguised_malformed = analyze("broken.svg", Some("const = ; require('x');"));
        assert_eq!(disguised_malformed.incomplete_reasons.len(), 1);
        let oversized = analyze("large.js", Some(&" ".repeat(MAX_PARSE_BYTES + 1)));
        assert_eq!(oversized.incomplete_reasons.len(), 1);
        let nested = analyze("nested.js", Some(&"(".repeat(MAX_NESTING + 1)));
        assert_eq!(nested.incomplete_reasons.len(), 1);
    }

    #[test]
    fn resolves_imported_aliases_and_computed_constructor_without_shadowing() {
        let aliases = analyze(
            "entry.js",
            Some(
                "import { exec as run } from 'node:child_process'; run('id'); global['Fun' + 'ction']('return 1')();",
            ),
        );
        let module = aliases.module.unwrap();
        assert!(
            module
                .calls
                .iter()
                .any(|call| call.name == "node:child_process.exec")
        );
        assert!(
            module
                .calls
                .iter()
                .any(|call| call.name == "global.Function")
        );

        let shadowed = analyze("entry.js", Some("function run(eval) { eval('text'); }"));
        assert!(
            shadowed
                .module
                .unwrap()
                .calls
                .iter()
                .all(|call| call.capability.is_none())
        );
    }
}
