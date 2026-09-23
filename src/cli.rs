use crate::model::Severity;
use std::{ffi::OsString, path::PathBuf};

pub const HELP: &str = "\
Pre-execution security scanner for untrusted source repositories

Usage:
  preflightx <path> [--format terminal|json] [--fail-on <severity>]
  preflightx scan <path> [--format terminal|json] [--fail-on <severity>]
  preflightx rules
  preflightx rules show <rule-id>
  preflightx explain <finding-id>
  preflightx --help
  preflightx --version

Severities: informational, low, medium, high, critical";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Format {
    #[default]
    Terminal,
    Json,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ScanArgs {
    pub path: PathBuf,
    pub format: Format,
    pub fail_on: Severity,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Scan(ScanArgs),
    Help,
    Version,
    Rules,
    Rule(String),
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
    if first == "--version" || first == "-V" {
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
    if first == "scan" {
        args.next();
    }

    let mut path = None;
    let mut format = Format::Terminal;
    let mut fail_on = Severity::High;
    while let Some(argument) = args.next() {
        if argument == "--format" {
            format = parse_format(args.next().ok_or("--format requires a value")?)?;
        } else if let Some(value) = utf8_option(&argument, "--format=") {
            format = parse_format(OsString::from(value))?;
        } else if argument == "--fail-on" {
            fail_on = parse_severity(args.next().ok_or("--fail-on requires a value")?)?;
        } else if let Some(value) = utf8_option(&argument, "--fail-on=") {
            fail_on = parse_severity(OsString::from(value))?;
        } else if argument.to_string_lossy().starts_with('-') {
            return Err(format!("unknown option: {}", argument.to_string_lossy()));
        } else if path.replace(PathBuf::from(argument)).is_some() {
            return Err("unexpected extra path argument".to_owned());
        }
    }

    Ok(Command::Scan(ScanArgs {
        path: path.ok_or("scan requires a path")?,
        format,
        fail_on,
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
            }))
        );
    }

    #[test]
    fn rejects_missing_paths_and_unsupported_options() {
        assert_eq!(
            parse(args(&["scan"])),
            Err("scan requires a path".to_owned())
        );
        assert_eq!(
            parse(args(&["repo", "--online"])),
            Err("unknown option: --online".to_owned())
        );
    }
}
