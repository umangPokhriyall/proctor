#!/usr/bin/env bash
# Regenerate the tier-2 no-plaintext-on-disk strace evidence (phase2-spec.md §7.2).
#
# This drives the `no_disk_cycle` example under strace and prints the syscalls that
# matter (memfd_create + writable opens). The curated summary committed alongside
# this script (`no-disk-audit.txt`) is hand-distilled from this output; rerun this
# to confirm the property still holds. If `strace` is absent, it skips LOUDLY and
# writes nothing — the trace is never fabricated (same honesty discipline as the
# Phase 0 corpus gating).
set -euo pipefail

cd "$(dirname "$0")/../../.."   # repo root

if ! command -v strace >/dev/null 2>&1; then
  echo "SKIP: strace not installed — tier-2 audit not regenerated (tier-1 test still proves the property)." >&2
  exit 0
fi

cargo build --example no_disk_cycle
BIN=target/debug/examples/no_disk_cycle
TRACE="$(mktemp)"
trap 'rm -f "$TRACE"' EXIT

strace -f -e trace=openat,open,creat,memfd_create -o "$TRACE" "$BIN"

echo
echo "=== memfd_create (plaintext lives only here) ==="
grep "memfd_create" "$TRACE" || true
echo
echo "=== writable opens of real files (must be ciphertext .enc only) ==="
grep -E "open|creat" "$TRACE" | grep -E "O_WRONLY|O_RDWR|O_CREAT|creat\(" | grep -vE "/dev/null|/proc/self/fd" || true
echo
echo "=== ffmpeg child plaintext I/O via /proc/self/fd -> memfd ==="
grep "/proc/self/fd/" "$TRACE" || true
