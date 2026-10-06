// Freedom modification (AGPL-3.0-or-later §5(a) prominent notice).
// Added 2026-10-06. Managed-mode guard for the 自由工坊 neo client.
// Not part of upstream BrowserOS.

//! Startup mode selection and the managed-profile marker.
//!
//! Mode is resolved once, from the CLI flag and the sidecar `freedom` object.
//! It is not a settings field. A managed profile directory must be distinct
//! from the standalone default, including parent and child paths.

use std::{
    io,
    path::{Component, Path, PathBuf},
};

use serde::Deserialize;
use serde_json::Value;

pub const MARKER_FILE: &str = "freedom-managed-profile.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupRequest {
    pub managed: bool,
    pub profile: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeError {
    Unreadable(String),
    Invalid(String),
    Conflict(String),
    ProfileRequired,
    ProfileWithoutManaged,
}

impl std::fmt::Display for ModeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(message) | Self::Invalid(message) | Self::Conflict(message) => {
                formatter.write_str(message)
            }
            Self::ProfileRequired => {
                formatter.write_str("managed mode requires an explicit profile directory")
            }
            Self::ProfileWithoutManaged => {
                formatter.write_str("a freedom profile requires managed mode")
            }
        }
    }
}

impl std::error::Error for ModeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    NotDistinct,
    /// The path could not be resolved. Startup fails closed.
    Unresolvable(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDistinct => formatter.write_str("freedom_profile_not_distinct"),
            Self::Unresolvable(message) => {
                write!(formatter, "freedom_profile_unresolvable: {message}")
            }
        }
    }
}

impl std::error::Error for ProfileError {}

#[derive(Debug, Deserialize)]
struct SidecarFreedom {
    #[serde(default)]
    freedom: Option<FreedomFile>,
}

#[derive(Debug, Deserialize)]
struct FreedomFile {
    mode: Option<String>,
    profile: Option<PathBuf>,
}

/// Resolves managed vs standalone from the CLI and the sidecar file.
///
/// An absent CLI flag does not contradict a file that asks for managed mode.
/// An explicit disagreement, an unknown mode, or a profile without managed
/// mode fails closed. This function does not open a socket.
pub fn resolve_startup(
    cli_managed: bool,
    cli_profile: Option<PathBuf>,
    config_path: &Path,
) -> Result<StartupRequest, ModeError> {
    let file = read_freedom(config_path)?;
    let file_managed = match file.mode.as_deref() {
        None => None,
        Some("managed") => Some(true),
        Some("standalone") => Some(false),
        Some(other) => {
            return Err(ModeError::Invalid(format!(
                "unknown freedom mode `{other}`"
            )));
        }
    };
    if cli_managed && file_managed == Some(false) {
        return Err(ModeError::Conflict(
            "cli --freedom-managed conflicts with sidecar freedom.mode=standalone".to_string(),
        ));
    }
    let managed = cli_managed || file_managed.unwrap_or(false);
    let profile = match (cli_profile, file.profile) {
        (Some(cli), Some(from_file)) => {
            if normalize(&cli) != normalize(&from_file) {
                return Err(ModeError::Conflict(
                    "cli --freedom-profile conflicts with sidecar freedom.profile".to_string(),
                ));
            }
            Some(cli)
        }
        (Some(cli), None) => Some(cli),
        (None, Some(from_file)) => Some(from_file),
        (None, None) => None,
    };
    if managed && profile.is_none() {
        return Err(ModeError::ProfileRequired);
    }
    if !managed && profile.is_some() {
        return Err(ModeError::ProfileWithoutManaged);
    }
    Ok(StartupRequest { managed, profile })
}

/// Same path, or one directory nested inside the other, is not distinct.
///
/// This compare is lexical. Startup uses [`bind_distinct_profiles`], which
/// resolves symlinks before calling this function.
pub fn ensure_distinct(managed: &Path, standalone: &Path) -> Result<(), ProfileError> {
    let managed = normalize(managed);
    let standalone = normalize(standalone);
    if managed == standalone || managed.starts_with(&standalone) || standalone.starts_with(&managed)
    {
        Err(ProfileError::NotDistinct)
    } else {
        Ok(())
    }
}

/// Resolve both profiles the way the filesystem will, reject overlap, then
/// create the managed directory on that resolved path.
///
/// `..` is not removed lexically before resolution. A missing tail is the
/// deepest existing ancestor of the path as given, plus the remaining
/// components. A `..` that is still among those missing components fails
/// closed. The returned directory is the one startup must mark.
pub fn bind_distinct_profiles(managed: &Path, standalone: &Path) -> Result<PathBuf, ProfileError> {
    let managed = canonicalize_profile(managed)?;
    let standalone = canonicalize_profile(standalone)?;
    ensure_distinct(&managed, &standalone)?;
    std::fs::create_dir_all(&managed).map_err(|error| {
        ProfileError::Unresolvable(format!(
            "could not create the managed profile {}: {error}",
            managed.display()
        ))
    })?;
    Ok(managed)
}

pub async fn profile_is_managed(dir: &Path) -> io::Result<bool> {
    match tokio::fs::read(dir.join(MARKER_FILE)).await {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

pub async fn write_managed_marker(dir: &Path) -> io::Result<()> {
    tokio::fs::create_dir_all(dir).await?;
    tokio::fs::write(
        dir.join(MARKER_FILE),
        b"{\"mode\":\"managed\",\"version\":1}\n",
    )
    .await
}

/// Settings JSON that tries to flip mode, profile, or the guard.
#[must_use]
pub fn settings_try_to_relax(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    const KEYS: &[&str] = &[
        "mode",
        "freedomMode",
        "freedom_mode",
        "managed",
        "profile",
        "guard",
        "disableGuard",
    ];
    if object.keys().any(|key| KEYS.contains(&key.as_str())) {
        return true;
    }
    object.get("freedom").is_some_and(settings_try_to_relax)
}

fn read_freedom(config_path: &Path) -> Result<FreedomFile, ModeError> {
    let raw = std::fs::read_to_string(config_path).map_err(|error| {
        ModeError::Unreadable(format!("failed to read {}: {error}", config_path.display()))
    })?;
    let sidecar: SidecarFreedom = serde_json::from_str(&raw)
        .map_err(|error| ModeError::Invalid(format!("sidecar json is invalid: {error}")))?;
    Ok(sidecar.freedom.unwrap_or(FreedomFile {
        mode: None,
        profile: None,
    }))
}

fn canonicalize_profile(path: &Path) -> Result<PathBuf, ProfileError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let current = std::env::current_dir().map_err(|error| {
            ProfileError::Unresolvable(format!("could not read the working directory: {error}"))
        })?;
        current.join(path)
    };
    // Do not pop `..` before the filesystem resolves the path. A lexical pop
    // would treat `link/../profile` as a sibling of `link` even when `link`
    // is a symlink.
    resolve_filesystem_path(&absolute)
}

fn resolve_filesystem_path(path: &Path) -> Result<PathBuf, ProfileError> {
    match std::fs::canonicalize(path) {
        Ok(resolved) if resolved.is_dir() => Ok(resolved),
        Ok(resolved) => Err(ProfileError::Unresolvable(format!(
            "profile path is not a directory: {}",
            resolved.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => resolve_missing_tail(path),
        Err(error) => Err(ProfileError::Unresolvable(format!(
            "could not resolve profile path: {error}"
        ))),
    }
}

/// Deepest existing ancestor of `path` as given, plus the components that
/// do not exist yet. `..` in that missing tail is an error. It is not popped.
fn resolve_missing_tail(path: &Path) -> Result<PathBuf, ProfileError> {
    let mut missing = Vec::new();
    let mut cursor = path.to_path_buf();
    loop {
        let Some(parent) = cursor.parent() else {
            return Err(ProfileError::Unresolvable(
                "no existing ancestor for the profile path".to_string(),
            ));
        };
        if parent.as_os_str().is_empty() || parent == cursor {
            return Err(ProfileError::Unresolvable(
                "no existing ancestor for the profile path".to_string(),
            ));
        }
        match cursor.components().next_back() {
            Some(Component::Normal(name)) => missing.push(name.to_os_string()),
            Some(Component::CurDir) => {}
            Some(Component::ParentDir) => {
                return Err(ProfileError::Unresolvable(
                    "unresolved .. in the missing profile tail".to_string(),
                ));
            }
            _ => {
                return Err(ProfileError::Unresolvable(
                    "profile path has no final component".to_string(),
                ));
            }
        }
        match std::fs::canonicalize(parent) {
            Ok(resolved) if resolved.is_dir() => {
                missing.reverse();
                let mut out = resolved;
                for component in missing {
                    out.push(component);
                }
                return Ok(out);
            }
            Ok(resolved) => {
                return Err(ProfileError::Unresolvable(format!(
                    "profile ancestor is not a directory: {}",
                    resolved.display()
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                cursor = parent.to_path_buf();
            }
            Err(error) => {
                return Err(ProfileError::Unresolvable(format!(
                    "could not resolve profile path: {error}"
                )));
            }
        }
    }
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        ModeError, ProfileError, bind_distinct_profiles, ensure_distinct, profile_is_managed,
        resolve_startup, settings_try_to_relax, write_managed_marker,
    };
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn startup_modes_and_conflicts() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = dir.path().join("sidecar.json");
        std::fs::write(&path, r#"{"ports":{}}"#).unwrap_or_else(|error| panic!("{error}"));
        let standalone =
            resolve_startup(false, None, &path).unwrap_or_else(|error| panic!("{error}"));
        assert!(!standalone.managed);

        std::fs::write(
            &path,
            r#"{"freedom":{"mode":"managed","profile":"/var/freedom-profile"}}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let managed = resolve_startup(false, None, &path).unwrap_or_else(|error| panic!("{error}"));
        assert!(managed.managed);
        assert_eq!(managed.profile, Some(PathBuf::from("/var/freedom-profile")));

        let conflict = resolve_startup(true, Some(PathBuf::from("/other")), &path);
        assert!(matches!(conflict, Err(ModeError::Conflict(_))));

        std::fs::write(&path, r#"{"freedom":{"mode":"nope"}}"#)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            resolve_startup(false, None, &path),
            Err(ModeError::Invalid(_))
        ));

        std::fs::write(&path, r#"{"freedom":{"profile":"/var/freedom-profile"}}"#)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            resolve_startup(false, None, &path),
            Err(ModeError::ProfileWithoutManaged)
        ));

        std::fs::write(&path, r#"{"ports":{}}"#).unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            resolve_startup(true, None, &path),
            Err(ModeError::ProfileRequired)
        ));
    }

    #[test]
    fn distinct_profiles_reject_same_and_nested_paths() {
        assert!(
            ensure_distinct(
                PathBuf::from("/a/managed").as_path(),
                PathBuf::from("/a/standalone").as_path()
            )
            .is_ok()
        );
        assert_eq!(
            ensure_distinct(
                PathBuf::from("/a/same").as_path(),
                PathBuf::from("/a/same").as_path()
            ),
            Err(ProfileError::NotDistinct)
        );
        assert_eq!(
            ensure_distinct(
                PathBuf::from("/a/standalone/nested").as_path(),
                PathBuf::from("/a/standalone").as_path()
            ),
            Err(ProfileError::NotDistinct)
        );
        assert_eq!(
            ensure_distinct(
                PathBuf::from("/a/profile/../profile").as_path(),
                PathBuf::from("/a/profile").as_path()
            ),
            Err(ProfileError::NotDistinct)
        );
    }

    #[test]
    fn settings_relax_keys_are_detected() {
        assert!(!settings_try_to_relax(&json!({"consent": false})));
        assert!(settings_try_to_relax(
            &json!({"consent": false, "managed": true})
        ));
        assert!(settings_try_to_relax(&json!({"freedomMode": "standalone"})));
        assert!(settings_try_to_relax(
            &json!({"freedom": {"disableGuard": true}})
        ));
        assert!(!settings_try_to_relax(&json!("nope")));
    }

    #[tokio::test]
    async fn marker_file_exists_refuses_standalone_even_when_garbage() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let absent = profile_is_managed(dir.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!absent);
        write_managed_marker(dir.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let marked = profile_is_managed(dir.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(marked);
        for bytes in [&b"not-json"[..], br#"{"mode":"standalone"}"#, br#"{"#] {
            std::fs::write(dir.path().join(super::MARKER_FILE), bytes)
                .unwrap_or_else(|error| panic!("{error}"));
            let garbage = profile_is_managed(dir.path())
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert!(garbage, "existing marker must stay managed: {bytes:?}");
        }
    }

    #[tokio::test]
    async fn finding4_unreadable_marker_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        std::fs::create_dir(dir.path().join(super::MARKER_FILE))
            .unwrap_or_else(|error| panic!("{error}"));
        let Err(error) = profile_is_managed(dir.path()).await else {
            panic!("a directory at the marker path is not a missing file");
        };
        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn finding5_missing_standalone_tail_does_not_create_it() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let managed = dir.path().join("managed");
        let standalone = dir.path().join("missing").join("standalone");
        bind_distinct_profiles(&managed, &standalone).unwrap_or_else(|error| panic!("{error}"));
        assert!(managed.is_dir());
        assert!(!standalone.exists());
        assert!(!dir.path().join("missing").exists());
        assert!(!managed.join(super::MARKER_FILE).exists());
    }

    #[test]
    fn finding5_file_ancestor_fails_closed() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap_or_else(|error| panic!("{error}"));
        let managed = file.join("profile");
        let standalone = dir.path().join("standalone");
        let Err(error) = bind_distinct_profiles(&managed, &standalone) else {
            panic!("a file in the path must fail closed");
        };
        assert!(matches!(error, ProfileError::Unresolvable(_)));
        assert!(!managed.join(super::MARKER_FILE).exists());
    }

    #[test]
    fn finding5_managed_inside_missing_standalone_is_not_distinct() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let standalone = dir.path().join("standalone");
        let managed = standalone.join("nested");
        let Err(error) = bind_distinct_profiles(&managed, &standalone) else {
            panic!("a profile inside the standalone tree is not distinct");
        };
        assert_eq!(error, ProfileError::NotDistinct);
        assert!(!managed.join(super::MARKER_FILE).exists());
        assert!(!standalone.join(super::MARKER_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn finding5_symlink_profiles_are_not_distinct_in_either_direction() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let standalone = dir.path().join("standalone");
        let inside = standalone.join("inside");
        let third = dir.path().join("third");
        std::fs::create_dir_all(&inside).unwrap_or_else(|error| panic!("{error}"));
        std::fs::create_dir_all(&third).unwrap_or_else(|error| panic!("{error}"));

        let onto_standalone = dir.path().join("onto-standalone");
        std::os::unix::fs::symlink(&standalone, &onto_standalone)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            bind_distinct_profiles(&onto_standalone, &standalone),
            Err(ProfileError::NotDistinct)
        );
        assert!(!standalone.join(super::MARKER_FILE).exists());

        let onto_inside = dir.path().join("onto-inside");
        std::os::unix::fs::symlink(&inside, &onto_inside).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            bind_distinct_profiles(&onto_inside, &standalone),
            Err(ProfileError::NotDistinct)
        );

        let managed = dir.path().join("managed");
        std::fs::create_dir_all(&managed).unwrap_or_else(|error| panic!("{error}"));
        let standalone_into_managed = dir.path().join("standalone-into-managed");
        std::os::unix::fs::symlink(&managed, &standalone_into_managed)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            bind_distinct_profiles(&managed, &standalone_into_managed),
            Err(ProfileError::NotDistinct)
        );
        assert!(!managed.join(super::MARKER_FILE).exists());

        let onto_third = dir.path().join("onto-third");
        std::os::unix::fs::symlink(&third, &onto_third).unwrap_or_else(|error| panic!("{error}"));
        bind_distinct_profiles(&onto_third, &standalone).unwrap_or_else(|error| panic!("{error}"));
        assert!(third.is_dir());
        assert!(!third.join(super::MARKER_FILE).exists());
    }

    #[test]
    fn finding5_unresolved_dotdot_in_missing_tail_fails_closed() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let standalone = dir.path().join("standalone");
        let managed = dir
            .path()
            .join("missing")
            .join("..")
            .join("managed-profile");
        let Err(error) = bind_distinct_profiles(&managed, &standalone) else {
            panic!("a .. through a missing directory must fail closed");
        };
        assert!(matches!(error, ProfileError::Unresolvable(_)));
        assert!(!dir.path().join("managed-profile").exists());
        assert_no_marker_under(dir.path());
    }

    #[cfg(unix)]
    #[test]
    fn finding5_dotdot_through_symlink_into_standalone_is_not_distinct() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let standalone = dir.path().join("standalone");
        let inside = standalone.join("inside");
        std::fs::create_dir_all(&inside).unwrap_or_else(|error| panic!("{error}"));
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&inside, &link).unwrap_or_else(|error| panic!("{error}"));
        let managed = link.join("..").join("managed-profile");
        assert_eq!(
            bind_distinct_profiles(&managed, &standalone),
            Err(ProfileError::NotDistinct)
        );
        assert!(
            !standalone.join("managed-profile").exists(),
            "refusing must not create the directory inside standalone"
        );
        assert!(!dir.path().join("managed-profile").exists());
        assert_no_marker_under(dir.path());
    }

    #[cfg(unix)]
    #[test]
    fn finding5_symlinked_ancestor_in_the_middle_is_not_distinct() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let standalone = dir.path().join("standalone");
        let inside = standalone.join("inside");
        std::fs::create_dir_all(&inside).unwrap_or_else(|error| panic!("{error}"));
        let middle = dir.path().join("middle");
        std::fs::create_dir_all(&middle).unwrap_or_else(|error| panic!("{error}"));
        let link = middle.join("link");
        std::os::unix::fs::symlink(&inside, &link).unwrap_or_else(|error| panic!("{error}"));
        let managed = link.join("managed-profile");
        assert_eq!(
            bind_distinct_profiles(&managed, &standalone),
            Err(ProfileError::NotDistinct)
        );
        assert!(!inside.join("managed-profile").exists());
        assert_no_marker_under(dir.path());
    }

    #[cfg(unix)]
    #[test]
    fn finding5_reverse_symlink_ancestor_is_not_distinct() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let managed = dir.path().join("managed");
        let inside = managed.join("inside");
        std::fs::create_dir_all(&inside).unwrap_or_else(|error| panic!("{error}"));
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&inside, &link).unwrap_or_else(|error| panic!("{error}"));

        let standalone_dotdot = link.join("..").join("nested");
        assert_eq!(
            bind_distinct_profiles(&managed, &standalone_dotdot),
            Err(ProfileError::NotDistinct)
        );
        assert!(!managed.join("nested").exists());

        let middle = dir.path().join("middle");
        std::fs::create_dir_all(&middle).unwrap_or_else(|error| panic!("{error}"));
        let middle_link = middle.join("link");
        std::os::unix::fs::symlink(&inside, &middle_link).unwrap_or_else(|error| panic!("{error}"));
        let standalone_middle = middle_link.join("nested");
        assert_eq!(
            bind_distinct_profiles(&managed, &standalone_middle),
            Err(ProfileError::NotDistinct)
        );
        assert!(!inside.join("nested").exists());
        assert_no_marker_under(dir.path());
    }

    #[cfg(unix)]
    #[test]
    fn finding5_resolved_outside_symlink_is_not_the_lexical_parent() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(outside.join("inside")).unwrap_or_else(|error| panic!("{error}"));
        let standalone = dir.path().join("standalone");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(outside.join("inside"), &link)
            .unwrap_or_else(|error| panic!("{error}"));
        let managed = link.join("..").join("managed-profile");
        let resolved =
            bind_distinct_profiles(&managed, &standalone).unwrap_or_else(|error| panic!("{error}"));
        let expected = outside.join("managed-profile");
        assert_eq!(
            resolved,
            std::fs::canonicalize(&expected).unwrap_or_else(|error| panic!("{error}"))
        );
        assert!(expected.is_dir());
        assert!(!dir.path().join("managed-profile").exists());
        assert!(!expected.join(super::MARKER_FILE).exists());
    }

    fn assert_no_marker_under(root: &std::path::Path) {
        fn walk(dir: &std::path::Path) {
            let entries = std::fs::read_dir(dir).unwrap_or_else(|error| panic!("{error}"));
            for entry in entries {
                let entry = entry.unwrap_or_else(|error| panic!("{error}"));
                let path = entry.path();
                let kind = entry.file_type().unwrap_or_else(|error| panic!("{error}"));
                if kind.is_symlink() {
                    continue;
                }
                if kind.is_dir() {
                    walk(&path);
                } else {
                    assert_ne!(
                        path.file_name().and_then(|name| name.to_str()),
                        Some(super::MARKER_FILE),
                        "marker written at {}",
                        path.display()
                    );
                }
            }
        }
        if root.is_dir() {
            walk(root);
        }
    }
}
