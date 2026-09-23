# preflightx

A local-first, static security scanner for inspecting untrusted source repositories before executing them.

> Development status: the safe scanning foundation and bounded JS/TS parsing are implemented. Capability rules, execution graphs, data flow, and threat intelligence are not implemented yet.

PreflightX is designed to remain offline by default, treat every target file as hostile, never execute target code, and never modify the repository being inspected.

## Usage

```sh
preflightx .
preflightx scan . --format json
preflightx . --fail-on high
```

The current scanner inventories files without following symlinks, enforces resource limits, classifies bytes independently of extensions, identifies raw concealment signals, inspects npm and developer-tool metadata, and parses JS/TS or suspicious text with Oxc. Parse failures for supported JS/TS files and reached 4 MiB or 256-level nesting limits are reported as incomplete.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```
