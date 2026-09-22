use std::process::ExitCode;

fn main() -> ExitCode {
    preflightx::run(std::env::args_os())
}
