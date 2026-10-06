// Freedom modification (AGPL-3.0-or-later §5(a) prominent notice).
// Added 2026-10-06. Managed-mode guard for the 自由工坊 neo client.
// Not part of upstream BrowserOS.

//! The patch inventory must equal the paths that differ from the adopted base.
//! No network. Git reads only the local repository.

use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::Command,
};

const ADOPTED_BASE: &str = "671b9a956eb4aaba42760b7eda754b9ba56191cd";

fn repo_root() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    root.canonicalize()
        .unwrap_or_else(|error| panic!("repo root: {error}"))
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| format!("git {args:?}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

fn changed_paths(root: &Path) -> Result<BTreeSet<String>, String> {
    let diff = git(
        root,
        &["diff", "--name-only", "--diff-filter=ACMRT", ADOPTED_BASE],
    )?;
    let untracked = git(root, &["ls-files", "--others", "--exclude-standard"])?;
    let mut paths = BTreeSet::new();
    for line in diff.lines().chain(untracked.lines()) {
        if !line.is_empty() {
            paths.insert(line.to_string());
        }
    }
    let deleted = git(
        root,
        &["diff", "--name-only", "--diff-filter=D", ADOPTED_BASE],
    )?;
    if deleted.lines().any(|line| !line.is_empty()) {
        return Err(format!(
            "deleted paths are not in the inventory schema:\n{deleted}"
        ));
    }
    Ok(paths)
}

fn existed_at_base(root: &Path, path: &str) -> bool {
    Command::new("git")
        .args(["cat-file", "-e", &format!("{ADOPTED_BASE}:{path}")])
        .current_dir(root)
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[test]
fn patch_inventory_matches_the_diff_against_adopted_base() -> Result<(), String> {
    let root = repo_root();
    let changed = changed_paths(&root)?;
    let inventory_path = root.join("freedom/patch-inventory.json");
    let raw = std::fs::read_to_string(&inventory_path)
        .map_err(|error| format!("read {}: {error}", inventory_path.display()))?;
    let value: Value = serde_json::from_str(&raw).map_err(|error| error.to_string())?;
    let adopted = value
        .get("adopted_base")
        .and_then(Value::as_str)
        .ok_or_else(|| "inventory adopted_base missing".to_string())?;
    if adopted != ADOPTED_BASE {
        return Err(format!("adopted_base is {adopted}"));
    }
    let entries = value
        .get("paths")
        .and_then(Value::as_array)
        .ok_or_else(|| "inventory paths missing".to_string())?;
    let mut listed = BTreeMap::new();
    for entry in entries {
        let path = entry
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("path missing in {entry}"))?;
        let status = entry
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("status missing for {path}"))?;
        let purpose = entry
            .get("purpose")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("purpose missing for {path}"))?;
        if purpose.trim().is_empty() {
            return Err(format!("empty purpose for {path}"));
        }
        if status != "new" && status != "modified" {
            return Err(format!("bad status {status} for {path}"));
        }
        let expected = if existed_at_base(&root, path) {
            "modified"
        } else {
            "new"
        };
        if status != expected {
            return Err(format!(
                "{path} is {expected} at {ADOPTED_BASE}, inventory says {status}"
            ));
        }
        if listed
            .insert(path.to_string(), status.to_string())
            .is_some()
        {
            return Err(format!("duplicate inventory path {path}"));
        }
    }
    let listed_paths: BTreeSet<String> = listed.keys().cloned().collect();
    let missing: Vec<_> = changed.difference(&listed_paths).collect();
    let stale: Vec<_> = listed_paths.difference(&changed).collect();
    if !missing.is_empty() || !stale.is_empty() {
        return Err(format!(
            "inventory drift\nmissing: {missing:?}\nunchanged or extra: {stale:?}"
        ));
    }
    let markdown = std::fs::read_to_string(root.join("freedom/patch-inventory.md"))
        .map_err(|error| format!("read patch-inventory.md: {error}"))?;
    for path in &listed_paths {
        if !markdown.contains(path) {
            return Err(format!("patch-inventory.md does not mention {path}"));
        }
    }
    Ok(())
}
