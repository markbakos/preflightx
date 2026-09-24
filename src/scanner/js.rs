use crate::model::{Confidence, Finding, Severity};
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use std::{collections::HashMap, ops::Range, path::Path};

mod flow;
mod semantic;
pub use flow::analyze_flows;
pub use semantic::{Capability, ModuleFacts};

const MAX_PARSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_NESTING: usize = 256;
const MAX_EMBEDDED_SCRIPTS: usize = 256;
const MAX_MARKDOWN_FENCES: usize = 4_096;
const MAX_MARKDOWN_CODE_SPANS: usize = 32_768;

#[derive(Clone, Debug)]
pub struct EmbeddedRoot {
    pub module_id: String,
    pub line: u64,
}

pub struct JsAnalysis {
    pub language: Option<String>,
    pub findings: Vec<Finding>,
    pub incomplete_reasons: Vec<String>,
    pub modules: Vec<ModuleFacts>,
    pub embedded_roots: Vec<EmbeddedRoot>,
}

pub fn analyze(path: &str, text: Option<&str>) -> JsAnalysis {
    let extension = Path::new(path).extension().and_then(|value| value.to_str());
    let supported = matches!(
        extension,
        Some("js" | "cjs" | "mjs" | "jsx" | "ts" | "cts" | "mts" | "tsx")
    );
    let mut result = JsAnalysis {
        language: None,
        findings: Vec::new(),
        incomplete_reasons: Vec::new(),
        modules: Vec::new(),
        embedded_roots: Vec::new(),
    };
    let Some(text) = text else {
        if supported {
            result
                .incomplete_reasons
                .push(format!("cannot decode JS/TS source: {path}"));
        }
        return result;
    };

    if let Some((is_html, is_markdown)) = document_kind(extension) {
        let extraction = extract_scripts(text, is_markdown);
        result.incomplete_reasons.extend(
            extraction
                .incomplete
                .into_iter()
                .map(|reason| format!("{reason}: {path}")),
        );
        let flow_enabled = !is_markdown;
        let mut fact_count = 0usize;
        for (index, block) in extraction.blocks.into_iter().enumerate() {
            let module_id = format!("{path}#embedded-script-{index}");
            let remaining_facts = semantic::MAX_FACTS_PER_FILE.saturating_sub(fact_count);
            if remaining_facts == 0 {
                result.incomplete_reasons.push(format!(
                    "JS/TS fact limit of {} reached: {path}",
                    semantic::MAX_FACTS_PER_FILE
                ));
                break;
            }
            let module = if let Some(specifier) = block.external_src {
                ModuleFacts {
                    id: module_id,
                    path: path.to_owned(),
                    flow_enabled,
                    source_bytes: 0,
                    imports: vec![semantic::ImportFact {
                        specifier,
                        line: block.line_offset + 1,
                    }],
                    calls: Vec::new(),
                    flow: flow::ModuleFlow {
                        imports: Default::default(),
                        exports: Default::default(),
                        reexports: Default::default(),
                        functions: Default::default(),
                        body: Vec::new(),
                    },
                }
            } else {
                match parse_source(
                    path,
                    &module_id,
                    block.source,
                    block.source_type,
                    block.line_offset,
                    flow_enabled,
                    remaining_facts,
                ) {
                    Ok(Some(module)) => module,
                    Ok(None) => continue,
                    Err(reason) => {
                        result.incomplete_reasons.push(format!(
                            "{reason} at line {}: {path}",
                            block.line_offset + 1
                        ));
                        continue;
                    }
                }
            };
            if is_html {
                result.embedded_roots.push(EmbeddedRoot {
                    module_id: module.id.clone(),
                    line: block.line_offset + 1,
                });
            }
            fact_count += module.imports.len() + module.calls.len();
            result.language.get_or_insert_with(|| {
                if block.source_type.is_typescript() {
                    "typescript"
                } else {
                    "javascript"
                }
                .to_owned()
            });
            result.modules.push(module);
        }
        if !result.modules.is_empty() || !result.incomplete_reasons.is_empty() {
            return result;
        }
    }

    let suspicious = {
        let shell_shebang = text
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("#!"))
            .is_some_and(|interpreter| !interpreter.to_ascii_lowercase().contains("node"));
        let mut source_start = text.trim_start();
        loop {
            if let Some(comment) = source_start.strip_prefix("//") {
                source_start = comment
                    .find('\n')
                    .map_or("", |end| &comment[end + 1..])
                    .trim_start();
            } else if let Some(comment) = source_start.strip_prefix("/*") {
                source_start = comment
                    .find("*/")
                    .map_or("", |end| &comment[end + 2..])
                    .trim_start();
            } else {
                break;
            }
        }
        // ponytail: only parse source-led text; extracting embedded HTML/Vue/Markdown scripts needs format-aware boundaries.
        let source_led = [
            "#!",
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
            "(()",
            "(function ",
            "(async ",
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
                    .any(|prefix| source_start.starts_with(prefix))))
    };
    if !supported && !suspicious {
        return result;
    }
    let source_type = if supported {
        SourceType::from_path(path).expect("supported JS/TS extension")
    } else {
        SourceType::default()
    };
    let module = match parse_source(
        path,
        path,
        text,
        source_type,
        0,
        true,
        semantic::MAX_FACTS_PER_FILE,
    ) {
        Ok(module) => module,
        Err(reason) => {
            result.incomplete_reasons.push(format!("{reason}: {path}"));
            return result;
        }
    };
    if module.is_none() {
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
    result.modules.extend(module);
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

fn parse_source(
    path: &str,
    id: &str,
    source: &str,
    source_type: SourceType,
    line_offset: u64,
    flow_enabled: bool,
    fact_limit: usize,
) -> Result<Option<ModuleFacts>, String> {
    if source.len() > MAX_PARSE_BYTES {
        return Err(format!(
            "JS/TS parse limit of {MAX_PARSE_BYTES} bytes exceeded"
        ));
    }
    // ponytail: This conservative byte count may reject deep strings/comments; use token-aware limits if observed in real projects.
    let mut nesting = 0usize;
    for byte in source.bytes() {
        match byte {
            b'(' | b'[' | b'{' => nesting += 1,
            b')' | b']' | b'}' => nesting = nesting.saturating_sub(1),
            _ => {}
        }
        if nesting > MAX_NESTING {
            return Err(format!("JS/TS nesting limit of {MAX_NESTING} exceeded"));
        }
    }
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type).parse();
    let parsed = if (parsed.fatal_error || !parsed.diagnostics.is_empty())
        && !parsed.is_flow_language
        && !source_type.is_typescript()
        && !source_type.is_jsx()
        && source.contains('<')
        && source.contains('>')
    {
        let jsx_parsed = Parser::new(&allocator, source, source_type.with_jsx(true)).parse();
        if !jsx_parsed.fatal_error && jsx_parsed.diagnostics.is_empty() {
            jsx_parsed
        } else {
            return Err(format!(
                "JS/TS parser could not fully parse: {} diagnostic(s)",
                parsed.diagnostics.len()
            ));
        }
    } else if parsed.fatal_error || !parsed.diagnostics.is_empty() {
        if parsed.is_flow_language {
            return Err("Flow syntax is unsupported by the JS/TS parser".to_owned());
        }
        return Err(format!(
            "JS/TS parser could not fully parse: {} diagnostic(s)",
            parsed.diagnostics.len()
        ));
    } else {
        parsed
    };
    if parsed.program.body.is_empty() {
        return Ok(None);
    }
    let facts = semantic::collect(
        path,
        id,
        source,
        &parsed.program,
        line_offset,
        flow_enabled,
        fact_limit,
    );
    if !facts.incomplete_reasons.is_empty() {
        return Err(facts.incomplete_reasons.join("; "));
    }
    Ok(facts.module)
}

fn document_kind(extension: Option<&str>) -> Option<(bool, bool)> {
    match extension {
        Some("html" | "htm" | "xhtml") => Some((true, false)),
        Some("vue" | "svg") => Some((false, false)),
        Some("md" | "mdx") => Some((false, true)),
        _ => None,
    }
}

struct ScriptBlock<'a> {
    source: &'a str,
    source_type: SourceType,
    line_offset: u64,
    external_src: Option<String>,
}

struct Extraction<'a> {
    blocks: Vec<ScriptBlock<'a>>,
    incomplete: Vec<String>,
}

fn extract_scripts(text: &str, markdown: bool) -> Extraction<'_> {
    let mut extraction = Extraction {
        blocks: Vec::new(),
        incomplete: Vec::new(),
    };
    let excluded = if markdown {
        let fences = markdown_fences(text, &mut extraction.incomplete);
        let spans = markdown_code_spans(text, &fences, &mut extraction.incomplete);
        let mut ranges = fences;
        ranges.extend(spans);
        ranges.sort_unstable_by_key(|range| range.start);
        ranges
    } else {
        Vec::new()
    };
    let mut cursor = 0;
    let mut total_bytes = 0usize;
    let mut fence_index = 0;
    while let Some(open) = find_ascii_case_insensitive(text.as_bytes(), b"<script", cursor) {
        if let Some(comment) = find_ascii_case_insensitive(text.as_bytes(), b"<!--", cursor)
            && comment < open
        {
            let Some(end) = find_ascii_case_insensitive(text.as_bytes(), b"-->", comment + 4)
            else {
                extraction
                    .incomplete
                    .push("unterminated HTML comment before embedded script".to_owned());
                break;
            };
            cursor = end + 3;
            continue;
        }
        cursor = open + b"<script".len();
        while excluded
            .get(fence_index)
            .is_some_and(|range| open >= range.end)
        {
            fence_index += 1;
        }
        if excluded
            .get(fence_index)
            .is_some_and(|range| range.contains(&open))
        {
            continue;
        }
        if text
            .as_bytes()
            .get(cursor)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && *byte != b'>')
        {
            continue;
        }
        let Some(tag_end) = find_tag_end(text.as_bytes(), cursor) else {
            extraction
                .incomplete
                .push("unterminated embedded script tag".to_owned());
            break;
        };
        let attributes = &text[cursor..tag_end];
        let script_type = embedded_source_type(attributes);
        let body_start = tag_end + 1;
        let Some(source_type) = script_type else {
            cursor = find_script_close(text.as_bytes(), body_start)
                .and_then(|close| find_tag_end(text.as_bytes(), close + b"</script".len()))
                .map_or(text.len(), |close_end| close_end + 1);
            continue;
        };
        let Some(close) = find_script_close(text.as_bytes(), body_start) else {
            extraction
                .incomplete
                .push("unterminated embedded JavaScript block".to_owned());
            break;
        };
        let Some(close_end) = find_tag_end(text.as_bytes(), close + b"</script".len()) else {
            extraction
                .incomplete
                .push("unterminated embedded script closing tag".to_owned());
            break;
        };
        if extraction.blocks.len() == MAX_EMBEDDED_SCRIPTS {
            extraction.incomplete.push(format!(
                "embedded script limit of {MAX_EMBEDDED_SCRIPTS} reached"
            ));
            break;
        }
        let source = &text[body_start..close];
        let line_offset = line_number(text, body_start) - 1;
        let external_src = attribute_value(attributes, "src").map(str::to_owned);
        if external_src.is_none() && source.len() > MAX_PARSE_BYTES {
            extraction.incomplete.push(format!(
                "embedded JS/TS parse limit of {MAX_PARSE_BYTES} bytes exceeded at line {}",
                line_offset + 1
            ));
        } else if external_src.is_none()
            && total_bytes.saturating_add(source.len()) > MAX_PARSE_BYTES
        {
            extraction.incomplete.push(format!(
                "embedded JS/TS total parse limit of {MAX_PARSE_BYTES} bytes reached at line {}",
                line_offset + 1
            ));
            break;
        } else {
            total_bytes = total_bytes.saturating_add(source.len());
            extraction.blocks.push(ScriptBlock {
                source,
                source_type,
                line_offset,
                external_src,
            });
        }
        cursor = close_end + 1;
    }
    extraction
}

fn embedded_source_type(attributes: &str) -> Option<SourceType> {
    let type_value = attribute_value(attributes, "type")
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let lang = attribute_value(attributes, "lang").unwrap_or_default();
    let typescript = type_value.contains("typescript")
        || type_value.contains("text/tsx")
        || matches!(
            lang.to_ascii_lowercase().as_str(),
            "ts" | "typescript" | "tsx"
        );
    let jsx = matches!(type_value.as_str(), "text/babel" | "text/jsx")
        || lang.eq_ignore_ascii_case("jsx");
    if !type_value.is_empty()
        && !typescript
        && !matches!(
            type_value.as_str(),
            "module"
                | "text/javascript"
                | "application/javascript"
                | "application/x-javascript"
                | "application/ecmascript"
                | "application/x-ecmascript"
                | "text/ecmascript"
                | "text/javascript1.0"
                | "text/javascript1.1"
                | "text/javascript1.2"
                | "text/javascript1.3"
                | "text/javascript1.4"
                | "text/javascript1.5"
                | "text/babel"
                | "text/jsx"
                | ""
        )
    {
        return None;
    }
    if typescript {
        Some(
            if type_value.contains("tsx") || lang.eq_ignore_ascii_case("tsx") {
                SourceType::tsx()
            } else {
                SourceType::ts()
            },
        )
    } else if jsx {
        Some(SourceType::jsx())
    } else {
        Some(SourceType::default())
    }
}

fn attribute_value<'a>(attributes: &'a str, name: &str) -> Option<&'a str> {
    let bytes = attributes.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        let start = cursor;
        while bytes
            .get(cursor)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && *byte != b'=')
        {
            cursor += 1;
        }
        if start == cursor {
            cursor += 1;
            continue;
        }
        let key = &attributes[start..cursor];
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'=') {
            continue;
        }
        cursor += 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        let &quote = bytes.get(cursor)?;
        let value = if quote == b'\'' || quote == b'"' {
            cursor += 1;
            let start = cursor;
            while bytes.get(cursor).is_some_and(|byte| *byte != quote) {
                cursor += 1;
            }
            let value = attributes.get(start..cursor)?;
            cursor = cursor.saturating_add(1);
            value
        } else {
            let start = cursor;
            while bytes
                .get(cursor)
                .is_some_and(|byte| !byte.is_ascii_whitespace() && *byte != b'>')
            {
                cursor += 1;
            }
            attributes.get(start..cursor)?
        };
        if key.eq_ignore_ascii_case(name) {
            return Some(value);
        }
    }
    None
}

fn find_tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut quote = None;
    for (offset, byte) in bytes.iter().enumerate().skip(start) {
        match (quote, *byte) {
            (Some(current), value) if current == value => quote = None,
            (None, b'\'' | b'"') => quote = Some(*byte),
            (None, b'>') => return Some(offset),
            _ => {}
        }
    }
    None
}

fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
        .map(|offset| offset + start)
}

fn find_script_close(haystack: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    while let Some(position) = find_ascii_case_insensitive(haystack, b"</script", cursor) {
        if haystack
            .get(position + b"</script".len())
            .is_none_or(|byte| byte.is_ascii_whitespace() || matches!(byte, b'>' | b'/'))
        {
            return Some(position);
        }
        cursor = position + 1;
    }
    None
}

fn line_number(text: &str, offset: usize) -> u64 {
    text.as_bytes()[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as u64
        + 1
}

fn markdown_fences(text: &str, incomplete: &mut Vec<String>) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut cursor = 0;
    let mut open: Option<(u8, usize, usize)> = None;
    for line in text.split_inclusive('\n') {
        let end = cursor + line.len();
        let trimmed = line.trim_start_matches([' ', '\t']);
        let indent = line.len() - trimmed.len();
        if indent <= 3
            && let Some(marker) = trimmed.as_bytes().first().copied()
            && matches!(marker, b'`' | b'~')
        {
            let run = trimmed.bytes().take_while(|byte| *byte == marker).count();
            if run >= 3 {
                if let Some((kind, length, start)) = open {
                    if marker == kind && run >= length && trimmed[run..].trim().is_empty() {
                        if !push_fence_range(&mut ranges, incomplete, start..end, text.len()) {
                            return ranges;
                        }
                        open = None;
                    }
                } else {
                    open = Some((marker, run, cursor));
                }
            }
        }
        cursor = end;
    }
    if let Some((_, _, start)) = open {
        push_fence_range(&mut ranges, incomplete, start..text.len(), text.len());
    }
    ranges
}

fn markdown_code_spans(
    text: &str,
    fences: &[Range<usize>],
    incomplete: &mut Vec<String>,
) -> Vec<Range<usize>> {
    let mut spans = Vec::new();
    let mut openings = HashMap::new();
    let mut fence_index = 0;
    let mut cursor = 0;
    let bytes = text.as_bytes();
    while cursor < bytes.len() {
        while fences
            .get(fence_index)
            .is_some_and(|range| cursor >= range.end)
        {
            fence_index += 1;
        }
        if let Some(fence) = fences
            .get(fence_index)
            .filter(|range| range.contains(&cursor))
        {
            cursor = fence.end;
            openings.clear();
            continue;
        }
        if matches!(bytes[cursor], b'\r' | b'\n') {
            let next_line = cursor
                + usize::from(bytes[cursor] == b'\r' && bytes.get(cursor + 1) == Some(&b'\n'))
                + 1;
            let mut next_content = next_line;
            while matches!(bytes.get(next_content), Some(b' ' | b'\t')) {
                next_content += 1;
            }
            if matches!(bytes.get(next_content), Some(b'\r' | b'\n')) {
                openings.clear();
            }
            cursor = next_line;
            continue;
        }
        if bytes[cursor] != b'`' {
            cursor += 1;
            continue;
        }
        let start = cursor;
        while bytes.get(cursor) == Some(&b'`') {
            cursor += 1;
        }
        let mut escapes = 0;
        let mut previous = start;
        while previous > 0 && bytes[previous - 1] == b'\\' {
            escapes += 1;
            previous -= 1;
        }
        if escapes % 2 == 1 {
            continue;
        }
        let length = cursor - start;
        if let Some(open) = openings.remove(&length) {
            if spans.len() == MAX_MARKDOWN_CODE_SPANS {
                incomplete.push(format!(
                    "Markdown code span limit of {MAX_MARKDOWN_CODE_SPANS} reached"
                ));
                spans.push(open..text.len());
                break;
            }
            spans.push(open..cursor);
        } else {
            openings.insert(length, start);
        }
    }
    spans
}

fn push_fence_range(
    ranges: &mut Vec<Range<usize>>,
    incomplete: &mut Vec<String>,
    range: Range<usize>,
    text_end: usize,
) -> bool {
    if ranges.len() == MAX_MARKDOWN_FENCES {
        incomplete.push(format!(
            "Markdown fence limit of {MAX_MARKDOWN_FENCES} reached"
        ));
        if let Some(last) = ranges.last_mut() {
            last.end = text_end;
        }
        return false;
    }
    ranges.push(range);
    true
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_EMBEDDED_SCRIPTS, MAX_MARKDOWN_CODE_SPANS, MAX_MARKDOWN_FENCES, MAX_NESTING,
        MAX_PARSE_BYTES, analyze,
    };

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
    fn retries_suspicious_javascript_with_jsx_grammar() {
        for (path, source) in [
            ("component.js", "const element = <div />;"),
            (
                "component.txt",
                "const element = <div />; module.exports = element;",
            ),
        ] {
            let analysis = analyze(path, Some(source));
            assert_eq!(analysis.language.as_deref(), Some("javascript"), "{path}");
            assert!(analysis.incomplete_reasons.is_empty(), "{path}");
            assert_eq!(analysis.modules.len(), 1, "{path}");
        }
    }

    #[test]
    fn reports_flow_as_unsupported_instead_of_a_generic_parse_failure() {
        let analysis = analyze("flow.js", Some("// @flow\nconst value: string = 'x';"));
        assert!(
            analysis.incomplete_reasons[0].contains("Flow syntax is unsupported"),
            "{:?}",
            analysis.incomplete_reasons
        );
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

        let commented = analyze(
            "payload.data",
            Some("/* ordinary banner */\n// second line\nconst cp = require('child_process');"),
        );
        assert_eq!(commented.language.as_deref(), Some("javascript"));
        for (path, source) in [
            (
                "gating.rs",
                "// mentions const and function\nuse crate::module;",
            ),
            ("module.wat", "(module (import \"const \" \"function \"))"),
            (
                "style.css",
                "/* const and function */\nbody { color: red; }",
            ),
        ] {
            let analysis = analyze(path, Some(source));
            assert!(analysis.incomplete_reasons.is_empty(), "{path}");
            assert!(analysis.modules.is_empty(), "{path}");
        }
    }

    #[test]
    fn shell_shebang_is_not_sent_to_the_javascript_parser() {
        let analysis = analyze(
            ".git/hooks/push-to-checkout.sample",
            Some("#!/bin/sh\nfunction die() { echo failed; }\n"),
        );
        assert!(analysis.incomplete_reasons.is_empty());
        assert!(analysis.modules.is_empty());
    }

    #[test]
    fn extracts_embedded_scripts_without_parsing_document_markup() {
        let html = analyze(
            "index.html",
            Some(
                "<!doctype html>\n<script type=\"module\">\nfetch('/config').then((r) => r.text()).then(eval);\n</script>",
            ),
        );
        assert!(html.incomplete_reasons.is_empty());
        assert_eq!(html.modules.len(), 1);
        assert_eq!(html.embedded_roots.len(), 1);
        assert_eq!(html.embedded_roots[0].line, 2);
        assert!(html.modules[0].calls.iter().any(|call| call.line == 3));

        let vue = analyze(
            "App.vue",
            Some(
                "<template />\n<script setup lang=\"ts\">\nconst value: number = 1; eval(String(value));\n</script>",
            ),
        );
        assert_eq!(vue.language.as_deref(), Some("typescript"));
        assert_eq!(vue.modules.len(), 1);
        assert!(vue.modules[0].calls.iter().any(|call| call.line == 3));
        assert!(vue.embedded_roots.is_empty());

        let multiple = analyze(
            "multi.html",
            Some("<script>const first = 1;</script>\n<script>const second = 2;</script>"),
        );
        assert_eq!(multiple.modules.len(), 2);
        assert_ne!(multiple.modules[0].id, multiple.modules[1].id);

        let commented = analyze(
            "comments.html",
            Some("<!-- <script>invalid(</script> -->\n<script>const live = 1;</script>"),
        );
        assert!(commented.incomplete_reasons.is_empty());
        assert_eq!(commented.modules.len(), 1);
        assert_eq!(commented.embedded_roots[0].line, 2);

        for (path, text) in [
            (
                "README.md",
                "# Examples\nconst value = 1; function run() {}",
            ),
            (
                "index.notjs",
                "<notjs>\nimport { value } from './value.js';\n</notjs>",
            ),
            ("config.yml", "name: example\nrun: node script.js"),
        ] {
            let analysis = analyze(path, Some(text));
            assert!(analysis.incomplete_reasons.is_empty(), "{path}");
            assert!(analysis.modules.is_empty(), "{path}");
        }

        let disguised = analyze("payload.md", Some("const payload = 1; function run() {}"));
        assert_eq!(disguised.language.as_deref(), Some("javascript"));
        let disguised_statement = analyze(
            "payload.data",
            Some("if (enabled) { const cp = require('child_process'); eval('payload'); }"),
        );
        assert_eq!(disguised_statement.language.as_deref(), Some("javascript"));

        let markdown = analyze(
            "README.md",
            Some(
                "```html\n<script>eval('example only')</script>\n```\n<script>const value = 1;</script>",
            ),
        );
        assert_eq!(markdown.modules.len(), 1);
        assert!(!markdown.modules[0].flow_enabled);
        assert!(markdown.embedded_roots.is_empty());

        let markdown_code = analyze(
            "README.md",
            Some(
                "Use `<script type=\"module\">` and `` `<script>` `` in docs.\n```html\n<script>eval('example only')</script>\n```\n<script type=\"module\">eval('source')</script>",
            ),
        );
        assert!(markdown_code.incomplete_reasons.is_empty());
        assert_eq!(markdown_code.modules.len(), 1);
        assert!(
            markdown_code.modules[0]
                .calls
                .iter()
                .any(|call| call.name == "eval")
        );

        let data_script = analyze(
            "index.html",
            Some("<script type=\"application/ld+json\">{\"ok\":true}</script>"),
        );
        assert!(data_script.modules.is_empty());

        let tag_evasion = analyze(
            "index.html",
            Some(
                "<SCRIPT TYPE='module' data-note='>'>const payload = fetch('/x'); eval(payload);</SCRIPT>",
            ),
        );
        assert_eq!(tag_evasion.modules.len(), 1);
        assert_eq!(tag_evasion.embedded_roots.len(), 1);

        let malformed = analyze("broken.html", Some("<script>const = ;</script>"));
        assert_eq!(malformed.incomplete_reasons.len(), 1);

        let many_scripts = "<script>const value = 1;</script>".repeat(MAX_EMBEDDED_SCRIPTS + 1);
        let capped = analyze("many.html", Some(&many_scripts));
        assert!(
            capped
                .incomplete_reasons
                .iter()
                .any(|reason| reason.contains("embedded script limit"))
        );

        let many_fences = "```\n```\n".repeat(MAX_MARKDOWN_FENCES + 1);
        let capped_markdown = analyze("many.md", Some(&many_fences));
        assert!(
            capped_markdown
                .incomplete_reasons
                .iter()
                .any(|reason| reason.contains("Markdown fence limit"))
        );

        let many_code_spans = "`x` ".repeat(MAX_MARKDOWN_CODE_SPANS + 1);
        let capped_code_spans = analyze("many.md", Some(&many_code_spans));
        assert!(
            capped_code_spans
                .incomplete_reasons
                .iter()
                .any(|reason| reason.contains("Markdown code span limit"))
        );
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
        let module = &aliases.modules[0];
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
            shadowed.modules[0]
                .calls
                .iter()
                .all(|call| call.capability.is_none())
        );
    }
}
