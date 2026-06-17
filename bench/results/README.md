# `bench/results/` — platform-keyed measurement tree (phase7-spec.md §3)

Results are **keyed by platform** so every number is attributable to the box it ran on and the
honest dev baseline is preserved rather than overwritten.

| Path | Platform | Status |
|---|---|---|
| `laptop-i5-1135g7/` | Intel i5-1135G7, 4c/8t, 8 GB, 1 NUMA node (dev laptop) | **Dev baseline** (Phase 6). Correctness/security/crypto numbers stand; scaling/throughput above N≈8 is laptop oversubscription, superseded by the bare-metal run. |
| `metal-<instance>/` | Citable bare-metal x86 (≥~64 physical cores, 2 NUMA, AES-NI) | **Cited baseline** once the Phase 7 re-run lands (Session 2). The true disjoint-core scaling curve, jitter-free latency tails, server-CPU crypto. |
| `verify/` | *(platform-independent)* | The Phase 3 ROC calibration + detection study and the committed `roc-threshold.json`. Hardware-independent (SSIM geometry), so it is **not** platform-keyed — it is the shared input both runs load. |

## How results are written

`bench` writes each result set to `results/<platform>/<subdir>/`. The platform tag comes from
`--platform <tag>` (default `laptop-i5-1135g7`, the dev baseline). The bare-metal re-run passes
`--platform metal-<instance>`; an explicit `--out DIR` still overrides the full path verbatim.

The worker-count grid is configurable (`--n-grid 1,4,16,64,...`) and capped at the host's
physical-core count with a loud caveat above it — disjoint-physical-core pinning is the only way
to get a clean scaling curve (the laptop cannot pin past 4 physical cores). NUMA-aware pinning
dedicates a core each to `sched`/Redis/verifier and one disjoint physical core per worker; the
chosen socket placement is logged at spawn and recorded in the run's `METHODOLOGY.md`.

The supersede / confirm / new reconciliation between the two platforms lands in
`PLATFORM-RECONCILIATION.md` (Phase 7 Session 3).
