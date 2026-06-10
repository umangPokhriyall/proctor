# proctor — synthetic benchmark corpus

A reproducible benchmark needs a deterministic, copyright-clean event source. Every clip
here is generated from ffmpeg's `lavfi` synthetic sources — no external or copyrighted
video ever enters the repository — and is regenerable byte-for-byte from `generate.sh`.

## Regenerate

```sh
./generate.sh
```

Scale up for the on-host full set via environment variables (the committed seed set is
kept tiny — a few MB total):

```sh
SIZE=1280x720 DUR=10 FPS=30 ./generate.sh
```

## Clips (varied on purpose)

| File           | lavfi source                    | Why it's here                                                             |
| -------------- | ------------------------------- | ------------------------------------------------------------------------- |
| `gradient.mp4` | `testsrc2`                      | Clean, low-entropy baseline.                                              |
| `detail.mp4`   | `mandelbrot`                    | High-entropy/high-detail — exercises SSIM against cheap-downscale.        |
| `motion.mp4`   | `testsrc2` + `rotate` + `noise` | High motion — exercises temporal fidelity / frame-substitution detection. |

SSIM needs real spatial/temporal detail to separate an honest transcode from a
cheap-downscale or frame-substitution attack; a flat source alone would not exercise the
comparator. This clip choice is itself part of the verification signal.

## Determinism

Fixed duration, resolution, and frame rate per clip; GOP pinned
(`-g`/`-keyint_min`/`-sc_threshold 0`) so segmentation is reproducible; pinned encoder
flags (`libx264 -preset veryslow -crf 18 -pix_fmt yuv420p`). Determinism is only
guaranteed against a recorded encoder build, so the ffmpeg version is pinned below.

## ffmpeg version

```
ffmpeg version: ffmpeg version 8.0.1-3ubuntu2 Copyright (c) 2000-2025 the FFmpeg developers

```
