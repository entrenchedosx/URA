use std::path::{Path, PathBuf};

use crate::error::{ServiceError, ServiceResult};

#[derive(Debug, Clone)]
pub struct PathPolicy {
    roots: Vec<PathBuf>,
    allow_all: bool,
}

impl PathPolicy {
    pub fn new(roots: impl IntoIterator<Item = PathBuf>) -> ServiceResult<Self> {
        let mut resolved = Vec::new();
        for root in roots {
            let canonical = std::fs::canonicalize(&root).map_err(|error| {
                ServiceError::InvalidArgument(format!(
                    "allowed root {} could not be resolved: {error}",
                    root.display()
                ))
            })?;
            resolved.push(canonical);
        }
        if resolved.is_empty() {
            let current = std::env::current_dir().map_err(|error| {
                ServiceError::Io(format!("current directory is unavailable: {error}"))
            })?;
            resolved.push(std::fs::canonicalize(&current).map_err(|error| {
                ServiceError::Io(format!("current directory is unavailable: {error}"))
            })?);
        }
        Ok(Self {
            roots: resolved,
            allow_all: false,
        })
    }

    pub fn allow_all() -> Self {
        Self {
            roots: Vec::new(),
            allow_all: true,
        }
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    pub fn allow_read(&self, path: &Path) -> ServiceResult<PathBuf> {
        let resolved = std::fs::canonicalize(path).map_err(|error| {
            ServiceError::Io(format!("{} could not be opened: {error}", path.display()))
        })?;
        self.check(resolved)
    }

    pub fn allow_write(&self, path: &Path) -> ServiceResult<PathBuf> {
        let absolute = std::path::absolute(path).map_err(|error| {
            ServiceError::InvalidArgument(format!(
                "{} is not a valid path: {error}",
                path.display()
            ))
        })?;
        let name = absolute.file_name().ok_or_else(|| {
            ServiceError::InvalidArgument(format!("{} has no file name", path.display()))
        })?;
        #[cfg(windows)]
        if name.to_string_lossy().contains(':') {
            return Err(ServiceError::InvalidArgument(format!(
                "{} is not a valid write target: alternate data streams are not supported",
                path.display()
            )));
        }
        match std::fs::symlink_metadata(&absolute) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(ServiceError::PathDenied(display_path(&absolute)));
                }
                let resolved = std::fs::canonicalize(&absolute).map_err(|error| {
                    ServiceError::Io(format!("{} could not be resolved: {error}", path.display()))
                })?;
                self.check(resolved)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = absolute.parent().ok_or_else(|| {
                    ServiceError::InvalidArgument(format!(
                        "{} has no parent directory",
                        path.display()
                    ))
                })?;
                let parent = std::fs::canonicalize(parent).map_err(|error| {
                    ServiceError::Io(format!(
                        "parent directory of {} could not be resolved: {error}",
                        path.display()
                    ))
                })?;
                self.check(parent.join(name))
            }
            Err(error) => Err(ServiceError::Io(format!(
                "{} could not be inspected: {error}",
                path.display()
            ))),
        }
    }

    fn check(&self, resolved: PathBuf) -> ServiceResult<PathBuf> {
        if self.allow_all || self.roots.iter().any(|root| within(root, &resolved)) {
            Ok(resolved)
        } else {
            Err(ServiceError::PathDenied(display_path(&resolved)))
        }
    }
}

fn within(root: &Path, candidate: &Path) -> bool {
    let mut root_components = root.components();
    let mut candidate_components = candidate.components();
    loop {
        match (root_components.next(), candidate_components.next()) {
            (None, _) => return true,
            (Some(left), Some(right)) => {
                if !components_equal(left.as_os_str(), right.as_os_str()) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

#[cfg(windows)]
fn components_equal(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    left.eq_ignore_ascii_case(right)
}

#[cfg(not(windows))]
fn components_equal(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    left == right
}

pub fn display_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    text.strip_prefix(r"\\?\").unwrap_or(&text).to_string()
}
