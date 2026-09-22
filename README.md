# preflightx

A local-first, static security scanner for inspecting untrusted source repositories before executing them.

> Development status: the safe scanning foundation is implemented. Semantic JavaScript analysis and threat intelligence are not implemented yet.

PreflightX is designed to remain offline by default, treat every target file as hostile, never execute target code, and never modify the repository being inspected.

## Usage

```sh
preflightx .
preflightx scan . --format json
preflightx . --fail-on high
```

The current scanner inventories files without following symlinks, enforces resource limits, classifies bytes independently of extensions, identifies raw concealment signals, and inspects npm and developer-tool metadata.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```
