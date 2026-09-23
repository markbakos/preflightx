pub struct Rule {
    pub id: &'static str,
    pub description: &'static str,
}

pub const RULES: &[Rule] = &[
    Rule {
        id: "CONFIG-PARSE-FAILED",
        description: "Security-relevant configuration could not be parsed; scan coverage is incomplete.",
    },
    Rule {
        id: "DEVCONTAINER-EXECUTION-HOOK",
        description: "A devcontainer hook can execute repository-controlled commands.",
    },
    Rule {
        id: "FILE-EXECUTABLE-CONTENT",
        description: "Executable-looking text appears under a non-code extension.",
    },
    Rule {
        id: "FILE-PARSEABLE-JAVASCRIPT",
        description: "Oxc parses executable-looking text under a non-code extension as JavaScript.",
    },
    Rule {
        id: "FILE-TYPE-MISMATCH",
        description: "File extension and content signature or structure disagree.",
    },
    Rule {
        id: "FS-ABSOLUTE-SYMLINK",
        description: "An absolute symlink target was recorded without following it.",
    },
    Rule {
        id: "FS-PATH-ESCAPE",
        description: "A path resolved outside the scan root and was not read.",
    },
    Rule {
        id: "FS-SPECIAL-FILE",
        description: "A device, FIFO, socket, or other special file was not opened.",
    },
    Rule {
        id: "FS-SYMLINK-ESCAPE",
        description: "A symlink target escapes the scan root and was not followed.",
    },
    Rule {
        id: "IDE-AUTOMATIC-TASKS",
        description: "Workspace settings permit automatic tasks.",
    },
    Rule {
        id: "IDE-FOLDER-OPEN-DOWNLOAD-EXECUTE",
        description: "A VS Code folder-open task contains a download or execution command.",
    },
    Rule {
        id: "IDE-FOLDER-OPEN-TASK",
        description: "A VS Code task runs on folder open.",
    },
    Rule {
        id: "IDE-HIDDEN-SECURITY-FILES",
        description: "Workspace settings conceal security-relevant files.",
    },
    Rule {
        id: "IDE-PRELAUNCH-TASK",
        description: "A debug launch configuration invokes a workspace task.",
    },
    Rule {
        id: "JS-COMBINED-ATTACK-CHAIN",
        description: "One evidenced route contains secret exfiltration and remote execution chains.",
    },
    Rule {
        id: "JS-CONCEALED-EXECUTION",
        description: "Reachable code or process execution coincides with visual concealment.",
    },
    Rule {
        id: "JS-DOWNLOAD-WRITE-EXECUTE",
        description: "Remote bytes flow through a filesystem write into process execution.",
    },
    Rule {
        id: "JS-DYNAMIC-EXECUTION",
        description: "JavaScript contains a dynamic code execution capability; the call alone does not prove maliciousness.",
    },
    Rule {
        id: "JS-PROCESS-EXECUTION",
        description: "JavaScript contains a process execution capability; the call alone does not prove maliciousness.",
    },
    Rule {
        id: "JS-PERSISTENCE-COMMAND",
        description: "JavaScript invokes a recognized command that registers automatic startup.",
    },
    Rule {
        id: "JS-PERSISTENCE-WRITE",
        description: "JavaScript writes to a recognized automatic startup location.",
    },
    Rule {
        id: "JS-REACHABLE-DISGUISED-SOURCE",
        description: "An execution root imports parseable JavaScript under a non-code extension.",
    },
    Rule {
        id: "JS-REMOTE-CODE-EXECUTION",
        description: "Remote-controlled data reaches dynamic JavaScript execution.",
    },
    Rule {
        id: "JS-REMOTE-PROCESS-EXECUTION",
        description: "Remote-controlled data reaches a process execution API.",
    },
    Rule {
        id: "JS-SECRET-EXFILTRATION",
        description: "Sensitive environment, file, or clipboard data reaches an outbound request.",
    },
    Rule {
        id: "NPM-EXECUTION-SCRIPT",
        description: "An npm script is a possible execution root.",
    },
    Rule {
        id: "NPM-LIFECYCLE-SCRIPT",
        description: "An npm lifecycle hook can run during installation or preparation.",
    },
    Rule {
        id: "RAW-CONTENT-AFTER-EOF",
        description: "Printable content follows an apparent logical EOF marker.",
    },
    Rule {
        id: "RAW-EXTREME-LINE",
        description: "An extremely long line may conceal source outside an editor viewport.",
    },
    Rule {
        id: "RAW-HIDDEN-AFTER-WHITESPACE",
        description: "Content follows a large horizontal whitespace run.",
    },
];

pub fn show(id: &str) -> Option<String> {
    RULES.iter().find(|rule| rule.id == id).map(|rule| {
        format!("{}\n{}\n\nSeverity and confidence depend on scan evidence. Scan-specific paths and triggers appear in the report.\n", rule.id, rule.description)
    })
}

pub fn list() -> String {
    RULES
        .iter()
        .map(|rule| format!("{}  {}\n", rule.id, rule.description))
        .collect()
}
