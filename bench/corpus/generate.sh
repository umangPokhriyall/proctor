#!/usr/bin/env bash
#
# proctor — deterministic synthetic corpus generator (Phase 0).
#
# Every clip is generated from ffmpeg's `lavfi` synthetic sources: copyright-clean,
# regenerable byte-for-byte, no external video ever enters the repo. The clip set is
# varied on purpose — SSIM needs real spatial/temporal detail to separate an honest
# transcode from a cheap-downscale or frame-substitution attack, so a flat source alone
# would not exercise the comparator. That choice is itself part of the verification signal.
#
# Determinism: fixed duration/resolution/frame-rate per clip, GOP pinned (-g/-keyint_min/
# -sc_threshold 0) so segmentation is reproducible, and pinned encoder flags. Record the
# ffmpeg version this was run with in README.md (the script prints it below).
#
# Phase 0 commits the seed set (kept to a few MB). The full set is generated on the bench
# host by raising SIZE/DUR via the environment, e.g. SIZE=1280x720 DUR=10 ./generate.sh

set -euo pipefail

OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DUR="${DUR:-4}"          # seconds per clip
FPS="${FPS:-30}"         # frames per second
SIZE="${SIZE:-320x240}"  # seed set kept tiny; on-host runs scale up via this env var
GOP="${FPS}"             # one keyframe per second -> GOP-aligned segmentation

# Pinned encoder flags shared by every clip. yuv420p + libx264, GOP forced, scene-cut off.
ENC=(-pix_fmt yuv420p -c:v libx264 -preset veryslow -crf 18
     -g "${GOP}" -keyint_min "${GOP}" -sc_threshold 0)

echo "== ffmpeg version (record this in README.md) =="
ffmpeg -version | head -1

# 1) Clean gradient — low-entropy baseline (testsrc2).
ffmpeg -y -f lavfi -i "testsrc2=size=${SIZE}:rate=${FPS}:duration=${DUR}" \
  "${ENC[@]}" "${OUT_DIR}/gradient.mp4"

# 2) High-entropy / high-detail — exercises SSIM against cheap-downscale (mandelbrot).
ffmpeg -y -f lavfi -i "mandelbrot=size=${SIZE}:rate=${FPS}" -t "${DUR}" \
  "${ENC[@]}" "${OUT_DIR}/detail.mp4"

# 3) High-motion — exercises temporal fidelity / frame-substitution detection.
ffmpeg -y -f lavfi -i "testsrc2=size=${SIZE}:rate=${FPS}:duration=${DUR}" \
  -vf "rotate=PI*t:c=black,noise=alls=20:allf=t+u" \
  "${ENC[@]}" "${OUT_DIR}/motion.mp4"

echo "== wrote: gradient.mp4 detail.mp4 motion.mp4 to ${OUT_DIR} =="
