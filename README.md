# preflightx

A local-first, static security scanner for inspecting untrusted source repositories before executing them.

> Development status: the safe scanning foundation, bounded JS/TS parsing, local execution reachability, and initial cross-file source-to-sink tracing are implemented. Stage 2 remains in progress; threat intelligence is not implemented.

PreflightX is designed to remain offline by default, treat every target file as hostile, never execute target code, and never modify the repository being inspected.

## Usage

```sh
preflightx .
preflightx scan . --format json
preflightx . --fail-on high
preflightx rules
preflightx explain JS-REMOTE-CODE-EXECUTION
```

The current scanner inventories files without following symlinks, enforces resource limits, classifies bytes independently of extensions, identifies raw concealment signals, inspects npm and developer-tool metadata, and parses JS/TS or suspicious text with Oxc. It traces relative imports from recognized npm, VS Code, CI, and build-config roots; elevates reachable disguised JavaScript; and follows supported network and secret values through simple functions, imports, decoding, writes, and execution sinks. It also correlates matching exfiltration and remote-execution routes, reports startup-location writes, and exposes implemented rule descriptions. Unresolved imports and reached analysis limits are reported. These analyses cover evidenced patterns, not arbitrary JavaScript behavior.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```
