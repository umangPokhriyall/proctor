//! `sys` — the **only** unsafe-bearing module in `crypto` (phase2-spec.md §2).
//!
//! It confines the libc FFI that the rest of the crate needs but cannot express
//! in safe Rust: `mlock`/`munlock` (pin secret pages so they never reach swap,
//! which is a disk surface), `memfd_create` (an anonymous RAM file, never in the
//! filesystem namespace), and the child fd hand-off (clear `CLOEXEC` in the forked
//! child so ffmpeg inherits the memfd and can open it as `/proc/self/fd/N`). Every
//! `unsafe` block carries a `// SAFETY:` justifying the invariant it upholds. The
//! crate root is `#![deny(unsafe_code)]`; this file is the single
//! `#![allow(unsafe_code)]` exception, and all I/O on the resulting fds is done in
//! safe Rust (`std::fs::File`) by the caller.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::CryptoError;

/// Pin `len` bytes starting at `ptr` into RAM so the kernel cannot page them to
/// swap. Returns `Err(MlockFailed)` if the kernel refuses (e.g. `RLIMIT_MEMLOCK`):
/// a secret that could swap is never silently accepted (phase2-spec.md §3).
pub(crate) fn mlock(ptr: *const u8, len: usize) -> Result<(), CryptoError> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: `ptr..ptr+len` is a single live allocation the caller owns for the
    // whole lifetime of the lock — the caller holds the backing `Box`/`Vec` and
    // releases exactly this range via `munlock` before the allocation is freed.
    // `mlock` neither reads nor writes the bytes, it only pins their pages; a
    // non-zero return means the kernel declined and we surface that as an error.
    let rc = unsafe { libc::mlock(ptr.cast(), len) };
    if rc == 0 {
        Ok(())
    } else {
        Err(CryptoError::MlockFailed)
    }
}

/// Release a pin previously taken by [`mlock`] over the *same* `ptr`/`len`. Called
/// from `Drop` after the bytes are zeroized, so the return value is not actionable
/// and is deliberately ignored.
pub(crate) fn munlock(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: `ptr..ptr+len` is the same range a prior `mlock` pinned and is still
    // owned and live at this point (drop runs before the allocation is released).
    // `munlock` only unpins pages; it cannot corrupt memory, so ignoring its return
    // at drop time is sound.
    unsafe {
        let _ = libc::munlock(ptr.cast(), len);
    }
}

/// Create an anonymous, RAM-backed file via `memfd_create`. It is seekable (so any
/// container works), never present in the filesystem namespace, and reachable only
/// through the owning process's fd table (or `/proc/self/fd/N`). The fd is created
/// `CLOEXEC` so it does not leak into unrelated spawns; [`set_fds_inheritable`]
/// clears that flag for the one ffmpeg child that must inherit it (phase2-spec.md §5).
pub(crate) fn memfd_create(name: &str) -> Result<OwnedFd, CryptoError> {
    let cname = CString::new(name).map_err(|_| CryptoError::Memfd)?;
    // SAFETY: `cname` is a valid NUL-terminated C string that outlives the call.
    // `memfd_create` only reads the name and the flags; it returns a fresh fd or -1.
    let fd = unsafe { libc::memfd_create(cname.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(CryptoError::Memfd);
    }
    // SAFETY: `fd` is a fresh, valid, exclusively-owned file descriptor just
    // returned by `memfd_create`; nothing else holds it, so wrapping it in an
    // `OwnedFd` (which will close it on drop) transfers sole ownership correctly.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Arrange for the given `fds` to survive `exec` in the child `cmd` spawns, so
/// ffmpeg inherits the memfds and can open them as `/proc/self/fd/N`. The closure
/// runs in the forked child *before* exec and only clears the `CLOEXEC` flag.
pub(crate) fn set_fds_inheritable(cmd: &mut Command, fds: Vec<RawFd>) {
    // SAFETY: the `pre_exec` closure runs in the child after `fork`, before `exec`,
    // where only async-signal-safe operations are permitted. It performs only
    // `fcntl(F_SETFD, 0)` (async-signal-safe) on caller-owned fds and allocates
    // nothing (the `fds` Vec is moved in already-allocated; iteration does not
    // allocate). It touches no shared state and returns the kernel error verbatim.
    unsafe {
        cmd.pre_exec(move || {
            for &fd in &fds {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}
