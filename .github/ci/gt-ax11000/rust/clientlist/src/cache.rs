//! `/tmp/nmp_cache.js` and bounded file reads.

use crate::json::{self, Value};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum CacheError {
    Io(io::Error),
    /// Larger than the accepted bound.
    Oversized,
    /// Not a JSON object with a non-empty `maclist` array.
    Rejected,
}

impl From<io::Error> for CacheError {
    fn from(error: io::Error) -> Self {
        CacheError::Io(error)
    }
}

/// Read at most `limit` bytes; a longer file is an error rather than a
/// truncated document.
pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, CacheError> {
    // A FIFO/device must not hang the single-threaded httpd. Do not follow
    // links in world-writable /tmp, even for these read-only cache inputs.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
    }
    let mut bytes = Vec::new();
    let read = Read::by_ref(&mut file)
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if read > limit {
        return Err(CacheError::Oversized);
    }
    Ok(bytes)
}

/// The cache is served verbatim only when it is a JSON object whose
/// `maclist` is a non-empty array (`ej_get_clientlist()` as patched by
/// `local-qos-rust.patch`); otherwise the caller regenerates the list.
pub fn cache_is_servable(document: &[u8]) -> bool {
    // Legacy or tampered cache text is injected verbatim into inline ASP
    // script elements. Regenerate it through the HTML-safe serializer.
    if document.iter().any(|b| matches!(b, b'<' | b'>' | b'&')) {
        return false;
    }
    match json::parse(document) {
        Ok(Value::Object(document)) => document
            .get("maclist")
            .and_then(Value::as_array)
            .is_some_and(|maclist| !maclist.is_empty()),
        _ => false,
    }
}

pub fn read_cache(path: &Path, limit: usize) -> Result<Vec<u8>, CacheError> {
    let bytes = read_bounded(path, limit)?;
    if cache_is_servable(&bytes) {
        Ok(bytes)
    } else {
        Err(CacheError::Rejected)
    }
}

/// Atomic replacement using an exclusively created sibling. Never truncate
/// or unlink a pre-existing path (including an attacker's symlink).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    };
    let serial = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_file_name(format!("{file_name}.{}.{serial}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_data()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> std::path::PathBuf {
        let directory =
            std::env::temp_dir().join(format!("clientlist-cache-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        directory.join(name)
    }

    #[test]
    fn servable_requires_non_empty_maclist() {
        assert!(cache_is_servable(
            br#"{"maclist":["A"],"ClientAPILevel":"7"}"#
        ));
        assert!(!cache_is_servable(
            br#"{"maclist":[],"ClientAPILevel":"7"}"#
        ));
        assert!(!cache_is_servable(br#"{"maclist":"A"}"#));
        assert!(!cache_is_servable(br#"{"ClientAPILevel":"7"}"#));
        assert!(!cache_is_servable(b"[]"));
        assert!(!cache_is_servable(b"{"));
        assert!(!cache_is_servable(
            br#"{"maclist":["A"],"name":"</script>"}"#
        ));
    }

    #[test]
    fn read_rejects_symlinks_and_nonregular_files() {
        let target = scratch("read-target");
        fs::write(&target, b"secret").unwrap();
        let link = scratch("read-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_bounded(&link, 100).is_err());
        assert!(read_bounded(target.parent().unwrap(), 100).is_err());
    }

    #[test]
    fn replacement_does_not_follow_destination_symlink() {
        let target = scratch("unchanged-target");
        fs::write(&target, b"secret").unwrap();
        let link = scratch("destination-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        write_atomic(&link, b"cache").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"secret");
        assert_eq!(fs::read(&link).unwrap(), b"cache");
        assert!(!fs::symlink_metadata(&link).unwrap().is_symlink());
    }

    #[test]
    fn atomic_write_and_bounded_read() {
        let path = scratch("nmp_cache.js");
        let document = br#"{"maclist":["A"],"ClientAPILevel":"7"}"#;
        write_atomic(&path, document).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(read_cache(&path, 4096).unwrap(), document);
        assert!(matches!(read_cache(&path, 8), Err(CacheError::Oversized)));
        write_atomic(&path, br#"{"maclist":[]}"#).unwrap();
        assert!(matches!(read_cache(&path, 4096), Err(CacheError::Rejected)));
        assert!(matches!(
            read_cache(&scratch("missing"), 4096),
            Err(CacheError::Io(_))
        ));
        assert!(fs::read_dir(path.parent().unwrap())
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));
    }
}
