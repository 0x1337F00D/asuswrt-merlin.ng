//! SysV shared-memory snapshot and the vendor advisory file lock.
//!
//! This is the only module besides `ffi` that uses `unsafe`; it wraps the
//! `shmget`/`shmctl`/`shmat`/`shmdt` and `fcntl(F_SETLKW)` calls the vendor
//! consumers make. The segment is attached read-only, copied in full into an
//! owned `Vec<u8>` while the lock is held, detached, and only then parsed.

use std::ffi::{c_int, c_void};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Segments larger than this are not copied (both known layouts are below
/// 200 KiB).
pub const MAX_SEGMENT: usize = 1024 * 1024;

#[derive(Debug)]
pub enum ShmError {
    /// `_file_lock()` failed (open or `F_SETLKW`).
    Lock(io::Error),
    /// No segment exists for the key (`shmget` never creates one).
    NoSegment(io::Error),
    /// `IPC_STAT` failed.
    Stat(io::Error),
    /// Zero-sized or larger than [`MAX_SEGMENT`].
    Unsupported(usize),
    Attach(io::Error),
}

/// `shared/files.c:_file_lock()` (`6be5bc84b50`, lines 323-417) with
/// `LET_FD_LEAK`: open `<dir>/<tag>.lock` with `O_CREAT|O_RDWR` (0666), skip
/// locking when the file already records this process' PID (the descriptor
/// is then deliberately leaked so the outer lock survives), otherwise take a
/// whole-file `F_WRLCK` with `F_SETLKW` (retrying on `EINTR`) and record the
/// PID. `file_unlock()` truncates and closes.
pub struct FileLock {
    file: Option<File>,
}

impl FileLock {
    pub fn acquire(directory: &Path, tag: &str) -> io::Result<FileLock> {
        let path = directory.join(format!("{tag}.lock"));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o666)
            .open(path)?;
        let pid = std::process::id() as libc::pid_t;

        let mut recorded = [0_u8; mem::size_of::<libc::pid_t>()];
        if file.read(&mut recorded)? == recorded.len()
            && libc::pid_t::from_ne_bytes(recorded) == pid
        {
            // Already locked by this process: do not close the descriptor,
            // closing would release the lock held by the outer caller.
            mem::forget(file);
            return Ok(FileLock { file: None });
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
            let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLKW, &lock) };
            if result == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error);
            }
        }
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&pid.to_ne_bytes())?;
        Ok(FileLock { file: Some(file) })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = file.set_len(0);
            drop(file);
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
            // Re-entry by the same process is a no-op, like the vendor lock.
            let nested = FileLock::acquire(&directory, "networkmap").unwrap();
            assert!(nested.file.is_none());
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
