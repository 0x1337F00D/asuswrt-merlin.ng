//! SysV shared-memory snapshot and the vendor advisory file lock.
//!
//! This is the only module besides `ffi` that uses `unsafe`; it wraps the
//! `shmget`/`shmctl`/`shmat`/`shmdt` and POSIX record locks used by the vendor
//! consumers make. The segment is attached read-only, copied in full into an
//! owned `Vec<u8>` while the lock is held, detached, and only then parsed.

use std::collections::BTreeMap;
use std::ffi::{c_int, c_void};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

// POSIX locks are process-wide: closing ANY descriptor for the same inode
// releases an outer C caller's lock. Keep one descriptor per path until exit
// instead of leaking a new descriptor on every nested call as the vendor did.
static LOCK_FILES: Mutex<BTreeMap<PathBuf, File>> = Mutex::new(BTreeMap::new());
const MAX_LOCK_FILES: usize = 16; // Production uses only networkmap/clientlist.
const LOCK_WAIT: Duration = Duration::from_millis(100);

/// Segments larger than this are not copied (both known layouts are below
/// 200 KiB).
pub const MAX_SEGMENT: usize = 1024 * 1024;

#[derive(Debug)]
pub enum ShmError {
    /// `_file_lock()` failed or exceeded the bounded wait.
    Lock(io::Error),
    /// No segment exists for the key (`shmget` never creates one).
    NoSegment(io::Error),
    /// `IPC_STAT` failed.
    Stat(io::Error),
    /// Zero-sized or larger than [`MAX_SEGMENT`].
    Unsupported(usize),
    Attach(io::Error),
}

/// Compatible with shared/files.c's process-wide F_WRLCK and PID marker,
/// but bounded to 100 ms. A busy writer must not hang the Web UI. Rust calls
/// are serialized without waiting; nested C ownership is borrowed, not
/// unlocked. Persistent descriptors are bounded by MAX_LOCK_FILES.
pub struct FileLock {
    files: MutexGuard<'static, BTreeMap<PathBuf, File>>,
    path: PathBuf,
    owned: bool,
}

impl FileLock {
    pub fn acquire(directory: &Path, tag: &str) -> io::Result<FileLock> {
        let path = directory.join(format!("{tag}.lock"));
        let deadline = Instant::now() + LOCK_WAIT;
        let mut files = loop {
            match LOCK_FILES.try_lock() {
                Ok(files) => break files,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(io::Error::other("clientlist lock poisoned"))
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::from(io::ErrorKind::TimedOut));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        };
        if !files.contains_key(&path) {
            if files.len() >= MAX_LOCK_FILES {
                return Err(io::Error::other("clientlist lock descriptor limit"));
            }
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .mode(0o666)
                .open(&path)?;
            if !file.metadata()?.is_file() {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            files.insert(path.clone(), file);
        }
        let file = files.get_mut(&path).expect("inserted lock descriptor");
        let pid = std::process::id() as libc::pid_t;

        let mut recorded = [0_u8; mem::size_of::<libc::pid_t>()];
        file.seek(SeekFrom::Start(0))?;
        if file.read(&mut recorded)? == recorded.len()
            && libc::pid_t::from_ne_bytes(recorded) == pid
        {
            return Ok(FileLock {
                files,
                path,
                owned: false,
            });
        }

        let mut lock: libc::flock = unsafe { mem::zeroed() };
        lock.l_type = libc::F_WRLCK as libc::c_short;
        lock.l_whence = libc::SEEK_SET as libc::c_short;
        lock.l_start = 0;
        lock.l_len = 0;
        lock.l_pid = pid;
        loop {
            // SAFETY: `file` owns a valid descriptor and `lock` is a fully
            // initialised `struct flock` that outlives the call.
            let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) };
            if result == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if !matches!(
                error.raw_os_error(),
                Some(libc::EINTR | libc::EAGAIN | libc::EACCES)
            ) {
                return Err(error);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // Construct the guard before fallible writes so every failure unlocks.
        let mut guard = FileLock {
            files,
            path,
            owned: true,
        };
        let file = guard
            .files
            .get_mut(&guard.path)
            .expect("owned lock descriptor");
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&pid.to_ne_bytes())?;
        Ok(guard)
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        if self.owned {
            let file = self.files.get(&self.path).expect("owned lock descriptor");
            let _ = file.set_len(0);
            let mut lock: libc::flock = unsafe { mem::zeroed() };
            lock.l_type = libc::F_UNLCK as libc::c_short;
            lock.l_whence = libc::SEEK_SET as libc::c_short;
            // SAFETY: valid persistent descriptor and initialized flock.
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) };
        }
    }
}

/// Copy the networkmap segment for `key` while holding
/// `file_lock("networkmap")`. The segment is opened with `shmget(key, 0, 0)`
/// (never created: the vendor create-with-size call races the daemon when the
/// sizes differ), sized with `IPC_STAT` and attached with `SHM_RDONLY`.
pub fn read_segment(key: c_int, lock_directory: &Path) -> Result<Vec<u8>, ShmError> {
    let _lock = FileLock::acquire(lock_directory, "networkmap").map_err(ShmError::Lock)?;

    // SAFETY: plain system call with value arguments.
    let id = unsafe { libc::shmget(key, 0, 0) };
    if id == -1 {
        return Err(ShmError::NoSegment(io::Error::last_os_error()));
    }

    let mut info: libc::shmid_ds = unsafe { mem::zeroed() };
    // SAFETY: `info` is a writable `struct shmid_ds` for IPC_STAT.
    if unsafe { libc::shmctl(id, libc::IPC_STAT, &mut info) } == -1 {
        return Err(ShmError::Stat(io::Error::last_os_error()));
    }
    let size = info.shm_segsz;
    if size == 0 || size > MAX_SEGMENT {
        return Err(ShmError::Unsupported(size));
    }

    // SAFETY: a read-only attach of an existing segment at a kernel-chosen
    // address.
    let address = unsafe { libc::shmat(id, std::ptr::null(), libc::SHM_RDONLY) };
    if address as isize == -1 {
        return Err(ShmError::Attach(io::Error::last_os_error()));
    }
    // SAFETY: the kernel mapped exactly `shm_segsz` readable bytes at
    // `address`; they are copied before the mapping is detached below.
    let bytes = unsafe { std::slice::from_raw_parts(address as *const u8, size) }.to_vec();
    // SAFETY: `address` came from the successful `shmat` above.
    unsafe { libc::shmdt(address as *const c_void) };
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_records_pid_and_truncates_on_release() {
        let directory =
            std::env::temp_dir().join(format!("clientlist-lock-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("networkmap.lock");
        {
            let _lock = FileLock::acquire(&directory, "networkmap").unwrap();
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(bytes.len(), mem::size_of::<libc::pid_t>());
            assert_eq!(
                libc::pid_t::from_ne_bytes(bytes.try_into().unwrap()),
                std::process::id() as libc::pid_t
            );
        }
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }

    #[test]
    fn missing_segment_fails_closed() {
        let directory = std::env::temp_dir().join(format!("clientlist-shm-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        // A key nobody creates: derived from the PID to avoid collisions.
        let key = 0x5a00_0000 | (std::process::id() as c_int & 0x00ff_ffff);
        assert!(matches!(
            read_segment(key, &directory),
            Err(ShmError::NoSegment(_))
        ));
    }
}
