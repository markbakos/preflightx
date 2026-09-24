mod cli;
pub mod model;
mod report;
mod rules;
pub mod scanner;

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
        Ok(cli::Command::Rules) => {
            print!("{}", rules::list());
            ExitCode::SUCCESS
        }
        Ok(cli::Command::Rule(id)) => match rules::show(&id) {
            Some(output) => {
                print!("{output}");
                ExitCode::SUCCESS
            }
            None => {
                eprintln!("unknown rule: {id}");
                ExitCode::from(3)
            }
        },
        Ok(cli::Command::Scan(arguments)) => {
            let report = scanner::scan(&arguments.path, &scanner::ScanLimits::default());
            match arguments.format {
                cli::Format::Terminal => print!("{}", report::terminal(&report)),
                cli::Format::Json => match report::json(&report) {
                    Ok(output) => print!("{output}"),
                    Err(error) => {
                        eprintln!("failed to serialize report: {error}");
                        return ExitCode::from(2);
                    }
                },
                cli::Format::Markdown => print!("{}", report::markdown(&report)),
                cli::Format::Sarif => match report::sarif(&report) {
                    Ok(output) => print!("{output}"),
                    Err(error) => {
                        eprintln!("failed to serialize SARIF report: {error}");
                        return ExitCode::from(2);
                    }
                },
            }
            if report.status == model::ScanStatus::Incomplete {
                ExitCode::from(2)
            } else if report.failed_policy(arguments.fail_on) {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(message) => {
            eprintln!("{message}\n\n{}", cli::HELP);
            ExitCode::from(3)
        }
    }
}
