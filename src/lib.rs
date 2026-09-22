mod cli;

use std::{ffi::OsString, process::ExitCode};

pub fn run(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    match cli::parse(args.into_iter().skip(1)) {
        Ok(cli::Command::Help) => {
            println!("{}", cli::HELP);
            ExitCode::SUCCESS
        }
        Ok(cli::Command::Version) => {
            println!("preflightx {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(cli::Command::Scan(path)) => {
            eprintln!(
                "SCAN INCOMPLETE: repository scanning is not implemented yet: {}",
                path.display()
            );
            ExitCode::from(2)
        }
        Err(message) => {
            eprintln!("{message}\n\n{}", cli::HELP);
            ExitCode::from(3)
        }
    }
}
