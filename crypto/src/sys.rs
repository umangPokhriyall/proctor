//! `sys` — the **only** unsafe-bearing module in `crypto` (phase2-spec.md §2).
//!
//! It confines the libc FFI that the rest of the crate needs but cannot express
//! in safe Rust. This session supplies `mlock`/`munlock` (pin secret pages so they
//! never reach swap, which is a disk surface); Session 2 adds `memfd_create` and
//! the child fd hand-off. Every `unsafe` block carries a `// SAFETY:` justifying
//! the invariant it upholds. The crate root is `#![deny(unsafe_code)]`; this file
//! is the single `#![allow(unsafe_code)]` exception.

#![allow(unsafe_code)]

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
