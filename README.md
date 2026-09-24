# preflightx

A local-first, static security scanner for inspecting untrusted source repositories before executing them.

> Development status: Stage 3 is in progress. The current branch adds Markdown/SARIF, embedded YARA-X signatures, one OpenSSF seed record, bounded archive scanning, opt-in npm artifact inspection, initial multi-language heuristics, and isolated Rust Git history/diff analysis. It does not yet have a signed database update trust source or complete threat-feed coverage. Stage 2 and Stage 3 still need their broader corpus, evasion, and cross-platform acceptance gates.

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
preflightx . --dependencies --online
preflightx db status
preflightx doctor
preflightx diff <good-commit-id>..HEAD
preflightx rules
preflightx explain JS-REMOTE-CODE-EXECUTION
```

The current scanner inventories files, inspects symlinks without following them, enforces resource limits, classifies bytes independently of extensions, identifies concealment and anti-analysis clues, inspects npm and developer-tool metadata, and parses supported JS/TS with Oxc. It follows imports from recognized npm, VS Code folder-open, devcontainer, CI, and build-config roots, including bounded scripts embedded in HTML, Vue, Markdown raw HTML, and SVG; Markdown code examples are not treated as executable source.

For supported patterns, Stage 2 traces remote responses into `eval`, `Function`, VM APIs, dynamic imports, and process execution; tracks environment, credential-file, clipboard, and home-directory data into outbound requests; and links remote downloads to file writes followed by process launch or module loading. It follows common aliases, wrappers, ESM/CommonJS exports, callbacks, decoders, object/argument spread, and selected control-flow forms—including labeled, thrown/caught (including imported helpers), unary-wrapped, and reachable default-export expressions—across files. Findings explain the observed source, flow, sink, and trigger where available.

This is a bounded malware-focused model, not a complete JavaScript interpreter and not a verdict that a repository is safe. Dynamic module targets, unresolved imports, parser failures, and reached analysis limits are reported; parser or resource limits make a scan incomplete (exit code 2). Default scans remain offline and never execute or modify target code.

The embedded threat database is a single OpenSSF seed record, not a complete or current OpenSSF feed. `db update` remains unavailable until the project selects a trusted signed-manifest source and verification key. Online dependency inspection is restricted to exact npm lockfile artifacts on `registry.npmjs.org`, requires a supported lockfile SHA-512 integrity value, disables redirects, and scans downloaded bytes without installation.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```
