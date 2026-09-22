# preflightx

A local-first, static security scanner for inspecting untrusted source repositories before executing them.

> Development status: project foundation only. Repository scanning is not implemented yet.

PreflightX is designed to remain offline by default, treat every target file as hostile, never execute target code, and never modify the repository being inspected.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

