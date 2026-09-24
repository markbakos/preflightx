mod cli;
mod git_analysis;
pub mod model;
mod report;
mod rules;
mod sandbox;
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
        Ok(cli::Command::Doctor) => match scanner::doctor() {
            Ok(()) => {
                println!("PreflightX doctor");
                println!(
                    "Platform: {}-{}",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                );
                println!("Scanner: {}", env!("CARGO_PKG_VERSION"));
                println!("YARA-X: embedded signatures compile and scan");
                println!("Sandbox backend: {}", sandbox::backend());
                println!("Scan sandbox availability is checked at runtime");
                println!("Repository scans: offline; target code is not executed");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("YARA-X diagnostics failed: {error}");
                ExitCode::from(2)
            }
        },
        Ok(cli::Command::Diff(arguments)) => {
            if let Err(error) = prepare_sandbox(std::path::Path::new("."), arguments.no_sandbox) {
                eprintln!("scan not started: {error}");
                return ExitCode::from(2);
            }
            match git_analysis::diff(std::path::Path::new("."), &arguments.range) {
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
            if let Err(error) = prepare_sandbox(&arguments.path, arguments.no_sandbox) {
                eprintln!("scan not started: {error}");
                return ExitCode::from(2);
            }
            let report = scanner::scan_with_options(
                &arguments.path,
                &scanner::ScanLimits::default(),
                &scanner::ScanOptions {
                    quick: arguments.quick,
                    deep: arguments.deep,
                    history: arguments.history,
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

fn prepare_sandbox(root: &std::path::Path, disabled: bool) -> Result<(), String> {
    if disabled {
        eprintln!("WARNING: OS sandbox disabled by explicit --no-sandbox option");
        return Ok(());
    }
    sandbox::apply(root).map_err(|error| format!("{error}; pass --no-sandbox to opt out"))?;
    eprintln!("OS sandbox enforced: {}", sandbox::backend());
    Ok(())
}
