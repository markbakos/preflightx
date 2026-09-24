mod cli;
mod git_analysis;
pub mod model;
mod report;
mod rules;
pub mod scanner;
mod threat_db;

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
        Ok(cli::Command::DbStatus) => match threat_db::status() {
            Ok(output) => {
                print!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("threat database is unavailable: {error}");
                ExitCode::from(2)
            }
        },
        Ok(cli::Command::DbUpdate) => {
            eprintln!(
                "signed threat database updates need an approved update endpoint and verification key"
            );
            ExitCode::from(3)
        }
        Ok(cli::Command::Doctor) => match threat_db::status() {
            Ok(database) => match scanner::doctor() {
                Ok(()) => {
                    println!("PreflightX doctor");
                    println!(
                        "Platform: {}-{}",
                        std::env::consts::OS,
                        std::env::consts::ARCH
                    );
                    println!("Scanner: {}", env!("CARGO_PKG_VERSION"));
                    println!("YARA-X: embedded signatures compile and scan");
                    print!("{database}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("YARA-X diagnostics failed: {error}");
                    ExitCode::from(2)
                }
            },
            Err(error) => {
                eprintln!("scanner diagnostics failed: {error}");
                ExitCode::from(2)
            }
        },
        Ok(cli::Command::Diff(range)) => {
            match git_analysis::diff(std::path::Path::new("."), &range) {
                Ok(output) => {
                    print!("{}", output.output);
                    if output.incomplete {
                        ExitCode::from(2)
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(error) => {
                    eprintln!("diff analysis failed: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Ok(cli::Command::Scan(arguments)) => {
            let report = scanner::scan_with_options(
                &arguments.path,
                &scanner::ScanLimits::default(),
                &scanner::ScanOptions {
                    quick: arguments.quick,
                    deep: arguments.deep,
                    history: arguments.history,
                    dependencies: arguments.dependencies,
                    online: arguments.online,
                },
            );
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
