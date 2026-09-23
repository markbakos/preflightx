# preflightx

A local-first, static security scanner for inspecting untrusted source repositories before executing them.

> Development status: the safe scanning foundation and focused Stage 2 JS/TS behavior tracing are implemented locally. Stage 2 acceptance is still in progress; threat intelligence and archive analysis are later stages.

PreflightX is designed to remain offline by default, treat every target file as hostile, never execute target code, and never modify the repository being inspected.

## Usage

```sh
preflightx .
preflightx scan . --format json
preflightx . --fail-on high
preflightx rules
preflightx explain JS-REMOTE-CODE-EXECUTION
```

The current scanner inventories files, inspects symlinks without following them, enforces resource limits, classifies bytes independently of extensions, identifies concealment and anti-analysis clues, inspects npm and developer-tool metadata, and parses supported JS/TS with Oxc. It follows imports from recognized npm, VS Code folder-open, devcontainer, CI, and build-config roots, including bounded scripts embedded in HTML, Vue, Markdown raw HTML, and SVG; Markdown code examples are not treated as executable source.

For supported patterns, Stage 2 traces remote responses into `eval`, `Function`, VM APIs, dynamic imports, and process execution; tracks environment, credential-file, clipboard, and home-directory data into outbound requests; and links remote downloads to file writes followed by process launch or module loading. It follows common aliases, wrappers, ESM/CommonJS exports, callbacks, decoders, object/argument spread, and selected control-flow forms—including labeled, thrown, unary-wrapped, and reachable default-export expressions—across files. Findings explain the observed source, flow, sink, and trigger where available.

This is a bounded malware-focused model, not a complete JavaScript interpreter and not a verdict that a repository is safe. Dynamic module targets, unresolved imports, parser failures, and reached analysis limits are reported; parser or resource limits make a scan incomplete (exit code 2). Default scans remain offline and never execute or modify target code.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```
