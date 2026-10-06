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
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("freedom_profile_not_distinct")
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

pub async fn profile_is_managed(dir: &Path) -> io::Result<bool> {
    match tokio::fs::read(dir.join(MARKER_FILE)).await {
        Ok(bytes) => Ok(marker_bytes_are_managed(&bytes)),
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

fn marker_bytes_are_managed(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| {
            value
                .get("mode")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .is_some_and(|mode| mode == "managed")
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
        ModeError, ProfileError, ensure_distinct, profile_is_managed, resolve_startup,
        settings_try_to_relax, write_managed_marker,
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
    async fn marker_round_trip_ignores_garbage() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let managed = profile_is_managed(dir.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!managed);
        write_managed_marker(dir.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let marked = profile_is_managed(dir.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(marked);
        std::fs::write(dir.path().join(super::MARKER_FILE), b"not-json")
            .unwrap_or_else(|error| panic!("{error}"));
        let garbage = profile_is_managed(dir.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!garbage);
    }
}
