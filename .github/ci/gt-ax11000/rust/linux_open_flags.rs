//! Values from the *target* libc headers, not the build host. ARM EABI uses
//! different O_NOFOLLOW/O_DIRECTORY bits than x86-64. Pinned vendor sysroot:
//! usr/include/bits/fcntl.h (__O_NOFOLLOW=0100000), fcntl-linux.h (O_NONBLOCK=04000).
#[cfg(all(target_os = "linux", target_arch = "arm"))]
pub const O_NOFOLLOW: i32 = 0o100000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const O_NOFOLLOW: i32 = 0o400000;
#[cfg(not(all(target_os = "linux", any(target_arch = "arm", target_arch = "x86_64"))))]
compile_error!("Validate open flags against target headers before supporting this architecture");
pub const O_NONBLOCK: i32 = 0o4000;
