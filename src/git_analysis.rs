use crate::model::Finding;
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

const MAX_ADMIN_ENTRIES: usize = 200_000;
const MAX_ADMIN_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_OBJECT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CHANGED_BLOBS: usize = 20_000;
const MAX_CHANGED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 250_000;
const MAX_HISTORY_COMMITS: usize = 100;
const MAX_HISTORY_ENTRIES: usize = 1_000_000;

pub(crate) struct Analysis {
    pub findings: Vec<Finding>,
    pub incomplete_reasons: Vec<String>,
}

pub(crate) struct DiffReport {
    pub output: String,
    pub incomplete: bool,
}

#[derive(Clone)]
struct TreeEntry {
    id: gix::ObjectId,
    executable: bool,
    symlink: bool,
}

struct TreeBudget {
    entries: usize,
    maximum: usize,
}

struct ChangeSet {
    findings: Vec<(String, Finding)>,
    incomplete_reasons: Vec<String>,
    changed_blobs: usize,
}

pub(crate) fn diff(root: &Path, range: &str) -> Result<DiffReport, String> {
    let (base, head) = parse_range(range)?;
    let repo = open_repository(root)?;
    let base_id = repo
        .rev_parse_single(base)
        .map_err(|error| format!("cannot resolve base commit {base}: {error}"))?;
    let base_commit = base_id
        .object()
        .map_err(|error| format!("cannot read base commit {base}: {error}"))?
        .peel_to_commit()
        .map_err(|error| format!("base object {base} is not a commit: {error}"))?;
    let head_id = repo
        .rev_parse_single(head)
        .map_err(|error| format!("cannot resolve head commit {head}: {error}"))?;
    let head_commit = head_id
        .object()
        .map_err(|error| format!("cannot read head commit {head}: {error}"))?
        .peel_to_commit()
        .map_err(|error| format!("head object {head} is not a commit: {error}"))?;
    let changes = compare(&repo, &base_commit, &head_commit, MAX_TREE_ENTRIES)?;
    let mut output = format!(
        "Git diff {}..{}\nChanged blobs: {}\n",
        base, head, changes.changed_blobs
    );
    for (path, finding) in &changes.findings {
        output.push_str(&format!("+ {}  {path}\n", finding.id));
    }
    if changes.findings.is_empty() {
        output.push_str("No new scanner findings were identified in changed blobs.\n");
    }
    let incomplete = !changes.incomplete_reasons.is_empty();
    if incomplete {
        output.push_str("Coverage: INCOMPLETE\n");
        for reason in &changes.incomplete_reasons {
            output.push_str(&format!("- {reason}\n"));
        }
    }
    Ok(DiffReport { output, incomplete })
}

pub(crate) fn history(root: &Path, quick: bool) -> Result<Analysis, String> {
    let repo = open_repository(root)?;
    let mut pending = vec![
        repo.head_commit()
            .map_err(|error| format!("cannot resolve repository HEAD: {error}"))?
            .id,
    ];
    let mut seen = HashSet::new();
    let mut findings = Vec::new();
    let mut incomplete_reasons = Vec::new();
    let mut tree_budget = TreeBudget {
        entries: 0,
        maximum: if quick {
            MAX_HISTORY_ENTRIES / 10
        } else {
            MAX_HISTORY_ENTRIES
        },
    };
    let maximum_commits = if quick { 10 } else { MAX_HISTORY_COMMITS };
    let mut commits = 0;
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        if commits >= maximum_commits {
            incomplete_reasons.push(format!(
                "Git history commit limit of {maximum_commits} reached"
            ));
            break;
        }
        commits += 1;
        let commit = repo
            .find_object(id)
            .map_err(|error| format!("cannot read commit {id}: {error}"))?
            .peel_to_commit()
            .map_err(|error| format!("object {id} is not a commit: {error}"))?;
        let parents = commit.parent_ids().take(65).collect::<Vec<_>>();
        if parents.len() > 64 {
            incomplete_reasons.push(format!("commit parent limit of 64 reached at {id}"));
        }
        pending.extend(parents.iter().take(64).map(|parent| parent.detach()));
        let Some(parent_id) = parents.first() else {
            let changes = compare_with_parent(&repo, None, &commit, &mut tree_budget)?;
            append_history_findings(
                &mut findings,
                &mut incomplete_reasons,
                id.to_string(),
                changes,
            );
            continue;
        };
        let parent = repo
            .find_object(parent_id.detach())
            .map_err(|error| format!("cannot read parent commit {parent_id}: {error}"))?
            .peel_to_commit()
            .map_err(|error| format!("parent object {parent_id} is not a commit: {error}"))?;
        let changes = compare_with_parent(&repo, Some(&parent), &commit, &mut tree_budget)?;
        append_history_findings(
            &mut findings,
            &mut incomplete_reasons,
            id.to_string(),
            changes,
        );
        if tree_budget.entries >= tree_budget.maximum {
            incomplete_reasons.push(format!(
                "Git history tree-entry limit of {} reached",
                tree_budget.maximum
            ));
            break;
        }
    }
    Ok(Analysis {
        findings,
        incomplete_reasons,
    })
}

fn append_history_findings(
    findings: &mut Vec<Finding>,
    incomplete: &mut Vec<String>,
    commit: String,
    changes: ChangeSet,
) {
    incomplete.extend(changes.incomplete_reasons);
    for (_, mut finding) in changes.findings {
        finding.title = format!("Historical commit introduced: {}", finding.title);
        finding.message = format!(
            "A scanner finding first appeared in this historical blob. Current worktree contents may differ. {}",
            finding.message
        );
        finding.evidence.push(format!("commit: {commit}"));
        findings.push(finding);
        if findings.len() >= 2_000 {
            incomplete.push("Git history finding limit of 2000 reached".to_owned());
            break;
        }
    }
}

fn compare(
    repo: &gix::Repository,
    base: &gix::Commit<'_>,
    head: &gix::Commit<'_>,
    maximum_entries: usize,
) -> Result<ChangeSet, String> {
    let mut budget = TreeBudget {
        entries: 0,
        maximum: maximum_entries,
    };
    compare_with_parent(repo, Some(base), head, &mut budget)
}

fn compare_with_parent(
    repo: &gix::Repository,
    base: Option<&gix::Commit<'_>>,
    head: &gix::Commit<'_>,
    budget: &mut TreeBudget,
) -> Result<ChangeSet, String> {
    let mut old_entries = BTreeMap::new();
    if let Some(base) = base {
        collect_tree(
            &base.tree().map_err(|error| error.to_string())?,
            "",
            0,
            &mut old_entries,
            budget,
        )?;
    }
    let mut new_entries = BTreeMap::new();
    collect_tree(
        &head.tree().map_err(|error| error.to_string())?,
        "",
        0,
        &mut new_entries,
        budget,
    )?;

    let mut result = ChangeSet {
        findings: Vec::new(),
        incomplete_reasons: Vec::new(),
        changed_blobs: 0,
    };
    let mut changed_bytes = 0_u64;
    for (path, current) in &new_entries {
        let previous = old_entries.get(path);
        if previous.is_some_and(|previous| {
            previous.id == current.id
                && previous.executable == current.executable
                && previous.symlink == current.symlink
        }) {
            continue;
        }
        result.changed_blobs += 1;
        if result.changed_blobs > MAX_CHANGED_BLOBS {
            result
                .incomplete_reasons
                .push(format!("changed blob limit of {MAX_CHANGED_BLOBS} reached"));
            break;
        }
        let object = match repo.find_object(current.id) {
            Ok(object) => object,
            Err(error) => {
                result
                    .incomplete_reasons
                    .push(format!("cannot read changed blob {path}: {error}"));
                continue;
            }
        };
        let blob = match object.try_into_blob() {
            Ok(blob) => blob,
            Err(_) => {
                result
                    .incomplete_reasons
                    .push(format!("changed Git entry is not a blob: {path}"));
                continue;
            }
        };
        if blob.data.len() as u64 > MAX_OBJECT_BYTES
            || changed_bytes.saturating_add(blob.data.len() as u64) > MAX_CHANGED_BYTES
        {
            result
                .incomplete_reasons
                .push(format!("changed Git blob byte limit reached at {path}"));
            continue;
        }
        changed_bytes += blob.data.len() as u64;
        let (current_findings, reasons) = crate::scanner::analyze_git_blob(path, &blob.data);
        result.incomplete_reasons.extend(reasons);
        let current_findings = current_findings
            .into_iter()
            .map(|finding| (finding_key(&finding), finding))
            .collect::<BTreeMap<_, _>>();
        let previous_ids = if let Some(previous) = previous {
            let object = match repo.find_object(previous.id) {
                Ok(object) => object,
                Err(error) => {
                    result
                        .incomplete_reasons
                        .push(format!("cannot read prior Git blob {path}: {error}"));
                    continue;
                }
            };
            let blob = match object.try_into_blob() {
                Ok(blob) => blob,
                Err(_) => {
                    result
                        .incomplete_reasons
                        .push(format!("prior Git entry is not a blob: {path}"));
                    continue;
                }
            };
            if blob.data.len() as u64 > MAX_OBJECT_BYTES
                || changed_bytes.saturating_add(blob.data.len() as u64) > MAX_CHANGED_BYTES
            {
                result
                    .incomplete_reasons
                    .push(format!("prior Git blob byte limit reached at {path}"));
                continue;
            }
            changed_bytes += blob.data.len() as u64;
            let (findings, reasons) = crate::scanner::analyze_git_blob(path, &blob.data);
            result.incomplete_reasons.extend(reasons);
            findings
                .into_iter()
                .map(|finding| finding_key(&finding))
                .collect()
        } else {
            std::collections::BTreeSet::new()
        };
        result.findings.extend(
            current_findings
                .iter()
                .filter(|(key, _)| !previous_ids.contains(*key))
                .map(|(_, finding)| (path.clone(), finding.clone())),
        );
    }
    Ok(result)
}

fn finding_key(finding: &Finding) -> String {
    format!(
        "{}|{}|{}",
        finding.id,
        finding.line.unwrap_or_default(),
        finding.evidence.join("|")
    )
}

fn collect_tree(
    tree: &gix::Tree<'_>,
    prefix: &str,
    depth: usize,
    entries: &mut BTreeMap<String, TreeEntry>,
    budget: &mut TreeBudget,
) -> Result<(), String> {
    if depth > 64 {
        return Err("Git tree depth limit of 64 reached".to_owned());
    }
    for entry in tree.iter() {
        let entry = entry.map_err(|error| format!("malformed Git tree: {error}"))?;
        budget.entries += 1;
        if budget.entries > budget.maximum {
            return Err(format!(
                "Git tree-entry limit of {} reached",
                budget.maximum
            ));
        }
        let name = std::str::from_utf8(entry.filename().as_ref())
            .map_err(|_| "Git tree contains a non-UTF-8 path".to_owned())?;
        if name.is_empty()
            || name.contains('/')
            || name.chars().any(char::is_control)
            || name == "."
            || name == ".."
        {
            return Err("Git tree contains an invalid path component".to_owned());
        }
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        if entry.mode().is_tree() {
            let child = entry
                .object()
                .map_err(|error| format!("cannot read Git tree {path}: {error}"))?
                .try_into_tree()
                .map_err(|error| format!("Git entry is not a tree at {path}: {error}"))?;
            collect_tree(&child, &path, depth + 1, entries, budget)?;
        } else if entry.mode().is_commit() {
            continue;
        } else if entry.mode().is_blob_or_symlink() {
            entries.insert(
                path,
                TreeEntry {
                    id: entry.object_id(),
                    executable: entry.mode().is_executable(),
                    symlink: entry.mode().is_link(),
                },
            );
        } else {
            return Err(format!("Git tree contains unsupported mode at {path}"));
        }
    }
    Ok(())
}

fn parse_range(range: &str) -> Result<(&str, &str), String> {
    let Some((base, head)) = range.split_once("..") else {
        return Err("diff requires <good-commit>..HEAD".to_owned());
    };
    if base.is_empty()
        || head != "HEAD"
        || base.len() < 7
        || base.len() > 64
        || !base.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("diff requires a hexadecimal commit ID followed by ..HEAD".to_owned());
    }
    Ok((base, head))
}

fn open_repository(root: &Path) -> Result<gix::Repository, String> {
    let root = fs::canonicalize(root)
        .map_err(|error| format!("cannot resolve repository root: {error}"))?;
    let git_dir = root.join(".git");
    let metadata = fs::symlink_metadata(&git_dir)
        .map_err(|error| format!("repository must contain a local .git directory: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("Git worktrees and .git symlinks are not supported".to_owned());
    }
    let git_dir =
        fs::canonicalize(git_dir).map_err(|error| format!("cannot resolve .git: {error}"))?;
    if !git_dir.starts_with(&root) {
        return Err(".git directory escaped the requested repository root".to_owned());
    }
    validate_admin_directory(&git_dir)?;
    if git_dir.join("commondir").exists()
        || git_dir.join("objects/info/alternates").exists()
        || git_dir.join("objects/info/http-alternates").exists()
    {
        return Err("Git worktrees and alternate object stores are not supported".to_owned());
    }
    let config_path = git_dir.join("config");
    if config_path.exists() {
        let config =
            fs::read(&config_path).map_err(|error| format!("cannot read Git config: {error}"))?;
        if config.len() > 1024 * 1024 {
            return Err("Git config exceeds the 1 MiB limit".to_owned());
        }
        let config = String::from_utf8_lossy(&config).to_ascii_lowercase();
        if ["include", "worktree", "alternates", "gitdir"]
            .iter()
            .any(|term| config.contains(term))
        {
            return Err("Git config contains path redirection or include directives".to_owned());
        }
    }
    gix::open_opts(
        &git_dir,
        gix::open::Options::isolated()
            .open_path_as_is(true)
            .strict_config(true)
            .config_overrides(["gitoxide.objects.allocLimit=67108864"]),
    )
    .map_err(|error| format!("cannot open isolated Git repository: {error}"))
}

fn validate_admin_directory(root: &Path) -> Result<(), String> {
    let mut pending = vec![PathBuf::from(root)];
    let mut entries = 0usize;
    let mut bytes = 0u64;
    while let Some(directory) = pending.pop() {
        let children = fs::read_dir(&directory)
            .map_err(|error| format!("cannot inspect Git administrative directory: {error}"))?;
        for child in children {
            let child = child.map_err(|error| format!("cannot enumerate Git metadata: {error}"))?;
            entries += 1;
            if entries > MAX_ADMIN_ENTRIES {
                return Err(format!(
                    "Git metadata entry limit of {MAX_ADMIN_ENTRIES} reached"
                ));
            }
            let metadata = fs::symlink_metadata(child.path())
                .map_err(|error| format!("cannot inspect Git metadata entry: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err("Git administrative directory contains a symlink".to_owned());
            }
            if metadata.is_dir() {
                pending.push(child.path());
            } else if metadata.is_file() {
                bytes = bytes.saturating_add(metadata.len());
                if bytes > MAX_ADMIN_BYTES {
                    return Err(format!(
                        "Git metadata byte limit of {MAX_ADMIN_BYTES} reached"
                    ));
                }
            } else {
                return Err("Git administrative directory contains a special file".to_owned());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{diff, history, open_repository, parse_range};
    use std::{
        collections::BTreeMap,
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn accepts_only_a_commit_id_to_head_range() {
        assert_eq!(
            parse_range("0123456789abcdef..HEAD"),
            Ok(("0123456789abcdef", "HEAD"))
        );
        for value in [
            "HEAD~1..HEAD",
            "../HEAD",
            "0123456..main",
            "0123456..HEAD^",
            "ab..HEAD",
        ] {
            assert!(parse_range(value).is_err(), "accepted {value}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_git_directory_symlinks_and_alternate_object_stores() {
        use std::os::unix::fs::symlink;

        let root = temporary_directory("git-link");
        let outside = temporary_directory("git-outside");
        symlink(&outside, root.join(".git")).unwrap();
        assert!(open_repository(&root).is_err());
        fs::remove_file(root.join(".git")).unwrap();
        fs::create_dir_all(root.join(".git/objects/info")).unwrap();
        fs::write(
            root.join(".git/objects/info/alternates"),
            outside.to_string_lossy().as_bytes(),
        )
        .unwrap();
        assert!(
            open_repository(&root)
                .unwrap_err()
                .contains("alternate object stores")
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn refuses_git_config_path_includes() {
        let root = temporary_directory("git-include");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git/config"), b"[include]\npath = /outside\n").unwrap();
        assert!(
            open_repository(&root)
                .unwrap_err()
                .contains("include directives")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn history_and_diff_read_local_objects_without_hooks_or_target_writes() {
        let root = temporary_directory("git-history");
        let repo = gix::init(&root).unwrap();
        let first_tree = tree_with_file(&repo, "setup.py", b"print('ordinary setup')\n");
        let first = commit(&repo, first_tree, "base", std::iter::empty());
        let second_tree = tree_with_file(&repo, "setup.py", b"requests.get(url)\nexec(payload)\n");
        commit(&repo, second_tree, "introduced capability", [first]);

        let hook_marker = root.join("hook-fired");
        let hook = repo.git_dir().join("hooks/post-checkout");
        fs::create_dir_all(hook.parent().unwrap()).unwrap();
        fs::write(
            &hook,
            format!("#!/bin/sh\nprintf hook-ran > '{}'\n", hook_marker.display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let before = snapshot(&root);
        let historic = history(&root, false).unwrap();
        let changes = diff(&root, &format!("{}..HEAD", first)).unwrap();

        assert!(historic.incomplete_reasons.is_empty());
        assert!(historic.findings.iter().any(|finding| {
            finding.id == "LANG-REMOTE-DATA-EXECUTION-CAPABILITY"
                && finding.evidence.iter().any(|item| item.contains("commit:"))
        }));
        assert!(
            changes
                .output
                .contains("LANG-REMOTE-DATA-EXECUTION-CAPABILITY")
        );
        assert!(!changes.incomplete);
        assert!(
            !hook_marker.exists(),
            "Git hook was executed by history analysis"
        );
        assert_eq!(
            snapshot(&root),
            before,
            "history analysis wrote into the repository"
        );

        drop(repo);
        fs::remove_dir_all(root).unwrap();
    }

    fn tree_with_file(repo: &gix::Repository, path: &str, bytes: &[u8]) -> gix::ObjectId {
        let blob = repo.write_blob(bytes).unwrap().detach();
        let tree = gix::objs::Tree {
            entries: vec![gix::objs::tree::Entry {
                mode: gix::objs::tree::EntryMode::from_bytes(b"100644").unwrap(),
                filename: path.into(),
                oid: blob,
            }],
        };
        repo.write_object(tree).unwrap().detach()
    }

    fn commit(
        repo: &gix::Repository,
        tree: gix::ObjectId,
        message: &str,
        parents: impl IntoIterator<Item = gix::ObjectId>,
    ) -> gix::ObjectId {
        let signature = gix::actor::SignatureRef::from_bytes(
            b"PreflightX Test <test@example.invalid> 1727200000 +0000",
        )
        .unwrap();
        repo.commit_as(signature, signature, "HEAD", message, tree, parents)
            .unwrap()
            .detach()
    }

    fn snapshot(root: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
        let mut snapshot = BTreeMap::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                assert!(!metadata.file_type().is_symlink());
                if metadata.is_dir() {
                    pending.push(path);
                } else {
                    assert!(metadata.is_file());
                    let relative = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    snapshot.insert(relative, fs::read(path).unwrap());
                }
            }
        }
        snapshot
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "preflightx-git-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }
}
