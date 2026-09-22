use std::{ffi::OsString, path::PathBuf};

pub const HELP: &str = "\
Pre-execution security scanner for untrusted source repositories

Usage:
  preflightx <path>
  preflightx scan <path>
  preflightx --help
  preflightx --version";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Scan(PathBuf),
    Help,
    Version,
}

pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, &'static str> {
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Ok(Command::Help);
    };

    let command = if first == "--help" || first == "-h" {
        Command::Help
    } else if first == "--version" || first == "-V" {
        Command::Version
    } else if first == "scan" {
        Command::Scan(PathBuf::from(args.next().ok_or("scan requires a path")?))
    } else {
        Command::Scan(PathBuf::from(first))
    };

    if args.next().is_some() {
        return Err("unexpected extra argument");
    }

    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::{Command, parse};
    use std::{ffi::OsString, path::PathBuf};

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn accepts_short_and_explicit_scan_forms() {
        assert_eq!(parse(args(&["."])), Ok(Command::Scan(PathBuf::from("."))));
        assert_eq!(
            parse(args(&["scan", "repo"])),
            Ok(Command::Scan(PathBuf::from("repo")))
        );
    }

    #[test]
    fn rejects_missing_or_extra_scan_arguments() {
        assert_eq!(parse(args(&["scan"])), Err("scan requires a path"));
        assert_eq!(
            parse(args(&["scan", "repo", "extra"])),
            Err("unexpected extra argument")
        );
    }
}
