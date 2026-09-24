use crate::model::Severity;
use std::{ffi::OsString, path::PathBuf};

pub const HELP: &str = "\
Pre-execution security scanner for untrusted source repositories

Usage:
  preflightx <path> [--format terminal|json|markdown|sarif] [--fail-on <severity>]
  preflightx scan <path> [--format terminal|json|markdown|sarif] [--fail-on <severity>]
  preflightx rules
  preflightx rules show <rule-id>
  preflightx explain <finding-id>
  preflightx version
  preflightx db status|update
  preflightx doctor
  preflightx diff <good-commit>..HEAD
  preflightx <path> [--quick|--deep] [--history] [--dependencies [--online]]
  preflightx --help
  preflightx --version

Severities: informational, low, medium, high, critical";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Format {
    #[default]
    Terminal,
    Json,
    Markdown,
    Sarif,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ScanArgs {
    pub path: PathBuf,
    pub format: Format,
    pub fail_on: Severity,
    pub quick: bool,
    pub deep: bool,
    pub history: bool,
    pub dependencies: bool,
    pub online: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Scan(ScanArgs),
    Help,
    Version,
    Rules,
    Rule(String),
    DbStatus,
    DbUpdate,
    Doctor,
    Diff(String),
}

pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut args = args.into_iter().peekable();
    let Some(first) = args.peek() else {
        return Ok(Command::Help);
    };
    if first == "--help" || first == "-h" {
        args.next();
        return no_extra(args, Command::Help);
    }
    if first == "version" || first == "--version" || first == "-V" {
        args.next();
        return no_extra(args, Command::Version);
    }
    if first == "rules" {
        args.next();
        return match args.next() {
            None => Ok(Command::Rules),
            Some(value) if value == "show" => {
                let id = args.next().ok_or("rules show requires a rule ID")?;
                no_extra(args, Command::Rule(id.to_string_lossy().into_owned()))
            }
            _ => Err("expected rules show <rule-id>".to_owned()),
        };
    }
    if first == "explain" {
        args.next();
        let id = args.next().ok_or("explain requires a finding ID")?;
        return no_extra(args, Command::Rule(id.to_string_lossy().into_owned()));
    }
    if first == "db" {
        args.next();
        return match args.next() {
            Some(command) if command == "status" => no_extra(args, Command::DbStatus),
            Some(command) if command == "update" => no_extra(args, Command::DbUpdate),
            _ => Err("expected db status or db update".to_owned()),
        };
    }
    if first == "doctor" {
        args.next();
        return no_extra(args, Command::Doctor);
    }
    if first == "diff" {
        args.next();
        let range = args.next().ok_or("diff requires <good-commit>..HEAD")?;
        let range = range.to_string_lossy().into_owned();
        let Some((base, head)) = range.split_once("..") else {
            return Err("diff requires <good-commit>..HEAD".to_owned());
        };
        if base.len() < 7
            || base.len() > 64
            || !base.bytes().all(|byte| byte.is_ascii_hexdigit())
            || head != "HEAD"
        {
            return Err("diff requires a hexadecimal commit ID followed by ..HEAD".to_owned());
        }
        return no_extra(args, Command::Diff(range));
    }
    if first == "scan" {
        args.next();
    }

    let mut path = None;
    let mut format = Format::Terminal;
    let mut fail_on = Severity::High;
    let mut quick = false;
    let mut deep = false;
    let mut history = false;
    let mut dependencies = false;
    let mut online = false;
    while let Some(argument) = args.next() {
        if argument == "--format" {
            format = parse_format(args.next().ok_or("--format requires a value")?)?;
        } else if let Some(value) = utf8_option(&argument, "--format=") {
            format = parse_format(OsString::from(value))?;
        } else if argument == "--fail-on" {
            fail_on = parse_severity(args.next().ok_or("--fail-on requires a value")?)?;
        } else if let Some(value) = utf8_option(&argument, "--fail-on=") {
            fail_on = parse_severity(OsString::from(value))?;
        } else if argument == "--quick" {
            quick = true;
        } else if argument == "--deep" {
            deep = true;
        } else if argument == "--history" {
            history = true;
        } else if argument == "--dependencies" {
            dependencies = true;
        } else if argument == "--online" {
            online = true;
        } else if argument.to_string_lossy().starts_with('-') {
            return Err(format!("unknown option: {}", argument.to_string_lossy()));
        } else if path.replace(PathBuf::from(argument)).is_some() {
            return Err("unexpected extra path argument".to_owned());
        }
    }

    if quick && deep {
        return Err("--quick and --deep cannot be combined".to_owned());
    }
    if online && !dependencies {
        return Err("--online requires --dependencies".to_owned());
    }

    Ok(Command::Scan(ScanArgs {
        path: path.ok_or("scan requires a path")?,
        format,
        fail_on,
        quick,
        deep,
        history,
        dependencies,
        online,
    }))
}

fn no_extra(mut args: impl Iterator<Item = OsString>, command: Command) -> Result<Command, String> {
    if args.next().is_some() {
        Err("unexpected argument".to_owned())
    } else {
        Ok(command)
    }
}

fn parse_format(value: OsString) -> Result<Format, String> {
    match value.to_str() {
        Some("terminal") => Ok(Format::Terminal),
        Some("json") => Ok(Format::Json),
        Some("markdown") => Ok(Format::Markdown),
        Some("sarif") => Ok(Format::Sarif),
        Some(value) => Err(format!("unsupported format: {value}")),
        None => Err("format must be valid UTF-8".to_owned()),
    }
}

fn parse_severity(value: OsString) -> Result<Severity, String> {
    let value = value
        .to_str()
        .ok_or("severity must be valid UTF-8")?
        .to_ascii_lowercase();
    Severity::parse(&value).ok_or_else(|| format!("unsupported severity: {value}"))
}

fn utf8_option<'a>(value: &'a OsString, prefix: &str) -> Option<&'a str> {
    value.to_str()?.strip_prefix(prefix)
}

#[cfg(test)]
mod tests {
    use super::{Command, Format, ScanArgs, parse};
    use crate::model::Severity;
    use std::{ffi::OsString, path::PathBuf};

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn accepts_short_and_explicit_scan_forms() {
        assert_eq!(
            parse(args(&["."])),
            Ok(Command::Scan(ScanArgs {
                path: PathBuf::from("."),
                format: Format::Terminal,
                fail_on: Severity::High,
                quick: false,
                deep: false,
                history: false,
                dependencies: false,
                online: false,
            }))
        );
        assert_eq!(
            parse(args(&[
                "scan",
                "repo",
                "--format",
                "json",
                "--fail-on=medium"
            ])),
            Ok(Command::Scan(ScanArgs {
                path: PathBuf::from("repo"),
                format: Format::Json,
                fail_on: Severity::Medium,
                quick: false,
                deep: false,
                history: false,
                dependencies: false,
                online: false,
            }))
        );
    }

    #[test]
    fn accepts_version_subcommand_and_flag() {
        assert_eq!(parse(args(&["version"])), Ok(Command::Version));
        assert_eq!(parse(args(&["--version"])), Ok(Command::Version));
    }

    #[test]
    fn rejects_missing_paths_and_unsupported_options() {
        assert_eq!(
            parse(args(&["scan"])),
            Err("scan requires a path".to_owned())
        );
        assert_eq!(
            parse(args(&["repo", "--online"])),
            Err("--online requires --dependencies".to_owned())
        );
    }

    #[test]
    fn accepts_markdown_and_sarif_output_formats() {
        for (value, format) in [("markdown", Format::Markdown), ("sarif", Format::Sarif)] {
            assert_eq!(
                parse(args(&["repo", "--format", value])),
                Ok(Command::Scan(ScanArgs {
                    path: PathBuf::from("repo"),
                    format,
                    fail_on: Severity::High,
                    quick: false,
                    deep: false,
                    history: false,
                    dependencies: false,
                    online: false,
                }))
            );
        }
    }

    #[test]
    fn parses_explicit_deep_history_and_online_dependency_modes() {
        assert!(matches!(
            parse(args(&["repo", "--deep", "--history"])),
            Ok(Command::Scan(ScanArgs {
                deep: true,
                history: true,
                ..
            }))
        ));
        assert!(matches!(
            parse(args(&["repo", "--dependencies", "--online"])),
            Ok(Command::Scan(ScanArgs {
                dependencies: true,
                online: true,
                ..
            }))
        ));
        assert_eq!(
            parse(args(&["repo", "--quick", "--deep"])),
            Err("--quick and --deep cannot be combined".to_owned())
        );
    }
}
