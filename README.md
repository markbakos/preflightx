# preflightx

A local-first, static security scanner for inspecting untrusted source repositories before executing them.

> Development status: Stage 3 is complete for its local implementation and acceptance checks. It adds Markdown/SARIF, embedded YARA-X signatures, bounded scanning of archives already in the repository, isolated Rust Git history/diff analysis, initial same-file multi-language heuristics, and quick/default/deep profiles. Package reputation and registry artifact retrieval are outside PreflightX's scope. Full fuzz campaigns, broad corpus calibration, and observed macOS/Windows runtime results remain Stage 4 release gates; CI is configured for all three operating systems.

PreflightX is designed to remain offline by default, treat every target file as hostile, never execute target code, and never modify the repository being inspected.

## Usage

```sh
preflightx .
preflightx scan . --format json
preflightx . --fail-on high
preflightx . --format markdown
preflightx . --format sarif
preflightx . --quick
preflightx . --deep --history
preflightx doctor
preflightx diff <good-commit-id>..HEAD
preflightx rules
preflightx explain JS-REMOTE-CODE-EXECUTION
```

The current scanner inventories files, inspects symlinks without following them, enforces resource limits, classifies bytes independently of extensions, identifies concealment and anti-analysis clues, inspects execution metadata such as npm scripts and developer-tool tasks, and parses supported JS/TS with Oxc. Lockfiles are treated as ordinary untrusted files; PreflightX does not resolve package identities or fetch registry artifacts. It follows imports from recognized npm, VS Code folder-open, devcontainer, CI, and build-config roots, including bounded scripts embedded in HTML, Vue, Markdown raw HTML, and SVG; Markdown code examples are not treated as executable source.

For supported patterns, Stage 2 traces remote responses into `eval`, `Function`, VM APIs, dynamic imports, and process execution; tracks environment, credential-file, clipboard, and home-directory data into outbound requests; and links remote downloads to file writes followed by process launch or module loading. It follows common aliases, wrappers, ESM/CommonJS exports, callbacks, decoders, object/argument spread, and selected control-flow forms—including labeled, thrown/caught (including imported helpers), unary-wrapped, and reachable default-export expressions—across files. Findings explain the observed source, flow, sink, and trigger where available.

This is a bounded malware-focused model, not a complete JavaScript interpreter and not a verdict that a repository is safe. Dynamic module targets, unresolved imports, parser failures, and reached analysis limits are reported; parser or resource limits make a scan incomplete (exit code 2). Default scans remain offline and never execute or modify target code.

Scans are offline and read-only. The scanner inspects only the repository supplied to it and does not install, download, or execute target packages. It uses its existing static analysis, embedded YARA-X signatures, and bounded parsers to identify concealed code and evidence-backed execution chains; reports remain limited to what this version identifies.

## Development

```sh
cargo fmt --check
cargo clippy --locked --offline --all-targets --all-features -- -D warnings
cargo test --locked --offline
```
