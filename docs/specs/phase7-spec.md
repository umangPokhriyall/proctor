# proctor — Phase 7 Specification: Hardware Validation & Bare-Metal Re-run

**Companion to:** `kickoff-brief.md`, `kickoff-amendment-1.md`, `phase0–6-spec.md`. Read the amendment first — this phase puts its claims on a citable platform.
**This is the complete, authoritative Phase 7 spec.** Phase 6's numbers are honest but came from a 4c/8t / 8 GB laptop, which **cannot** legitimately produce a scaling curve above N ≈ 8 (`taskset` cannot pin 64 worker processes to disjoint cores on 8 threads — that curve is oversubscription, not scheduler capacity). This phase re-runs the full Phase 6 suite on a **citable bare-metal platform** with true disjoint-core pinning, then **reconciles**: superseding the hardware-confounded scaling/throughput numbers, confirming the hardware-independent correctness/security/crypto numbers, and making the bare-metal run the cited baseline. No new product code; the closeout (README, x-thread, SELF-AUDIT, distribution) is **Phase 8**.
**Scope:** additive harness portability in `bench` (NUMA-aware pinning, a larger N grid, dedicated cores), the bare-metal re-run, the reconciliation writeup, and an **optional** placement-RTT optimization in `sched` motivated by the validation. The laptop results are **preserved** (the honest dev baseline), not deleted.
**Audience:** the operator provisions the bare-metal box; **Claude Code runs on that box** (as it built Redis from source and ran the suite in Phase 6) and commits. Split called out in §0.
**Frozen:** `proctor_core` is FROZEN (`v0.1.0-core-frozen`); `git diff v0.1.0-core-frozen -- core/` stays empty. `bench`/`sched` extend additively; all prior-phase suites stay green. No `core` change — if one seems needed, STOP and escalate.

---

## 0. Why this phase exists, and the human/Claude split

The single objective is to make pedigree irrelevant through numbers a senior reader cannot dismiss. Phase 6 delivered that for the **correctness and security** thesis — fencing (zero double-outputs), the verifiable-compute detection math with CIs, crypto-sub-percent — all of which are **hardware-independent** and already stand. But the **scaling/throughput** numbers were produced where they cannot be valid: 64 worker processes pinned on 8 threads is context-switch thrash, and "throughput 5451 → 557 as N 1→64" measures the laptop running out of cores, not the scheduler. A Principal reviewer dismisses that on sight. This phase de-confounds those numbers on a platform anyone can rent and re-run — rigor, not vanity — and reconciles honestly, which is itself the senior signal.

**The split (mirrors Phase 0 genesis):**
- **Operator:** provision a bare-metal instance meeting §2's requirements; point Claude Code at it (run Claude Code on the box, or SSH).
- **Claude Code (on the box):** the additive harness prep (§3), the full re-run via the committed regen commands (§4), the reconciliation (§5), the optional optimization (§6), and the commits.

---

## 1. Phase 7 in one paragraph

Make `bench`'s orchestrator **NUMA-aware** and **larger-N-capable** (dedicated cores for `sched`/Redis/verifier, workers pinned to disjoint physical cores up to the box's count, generous `RLIMIT_MEMLOCK`), keep all suites green, and key results by platform so the laptop run is preserved. On a citable **bare-metal** x86 box (≥ ~64 physical cores, 2 NUMA, AES-NI; bare-metal so the CO-corrected tail is jitter-free), re-run every Phase 6 result set via the committed regen commands and re-confirm the correctness suites (`contract.rs` both tiers, `live_smoke`, the adversary suite) live. Then write `PLATFORM-RECONCILIATION.md`: per measurement, **superseded** (hardware-confounded → bare-metal authoritative) vs **confirmed** (hardware-independent → laptop already valid, bare-metal agrees) vs **new** (what the box enables — the true scaling ceiling, NUMA effects, high-concurrency no-disk validation), each with laptop and bare-metal side by side and any divergence investigated honestly. Update `BENCHMARKS.md`/`METHODOLOGY.md` to cite the bare-metal platform as the baseline. Optionally implement the placement-RTT remedy (fold the 2N+4 round trips into O(1)) and show a measured before/after.

### 1.1 The supersede / confirm / new split (the spine of the reconciliation)

| Phase 6 result | Class | Why |
|---|---|---|
| `throughput_vs_n` (5451→557) | **SUPERSEDE** | laptop oversubscription above N≈8; bare-metal gives the true curve with disjoint-core pinning |
| `dispatch_latency` at N=16/64 | **SUPERSEDE** | p99 inflated by core contention on 8 threads |
| reclaim latency (p50 158 µs) | **SUPERSEDE** | platform-specific; re-measure jitter-free |
| crypto GB/s (1.55/0.99) | **SUPERSEDE** | server CPU differs; the **%-of-transcode** is robust → also confirm |
| verification cost (1.66×) | **SUPERSEDE + decompose** | 1.66× was short-clip ffmpeg-startup-inflated; re-measure on faster CPU (and longer segments) to separate fixed startup from the fundamental re-encode |
| Redis RTT absolute (~10–11 µs) | **SUPERSEDE** | platform-specific; the **2N+4 count** is algorithmic → confirm |
| fencing: zero double-outputs (1000/1000) | **CONFIRM** | safety property, hardware-independent |
| per-class detection + CIs; hypergeometric × (1−FAR) match | **CONFIRM** | algorithmic / SSIM-geometry; identical ffmpeg version → same separation |
| decomposition insight (Redis dominates, decision µs, 2N+4) | **CONFIRM** | qualitative dominance + RTT count are hardware-independent |
| AES-NI engaged; crypto sub-percent | **CONFIRM** | the % is hardware-robust |
| adaptive escalation + `P_MIN` floor | **CONFIRM** | reputation logic, hardware-independent |
| true N up to physical cores; NUMA effects; high-conc no-disk | **NEW** | the box enables what 8 threads / 8 GB could not |

If any **CONFIRM** row diverges on bare-metal, that is a finding to investigate and state honestly (e.g., at true N=64 a new Redis-contention regime) — never paper over it.

---

## 2. Platform requirements (operator selects; record the exact instance in `METHODOLOGY.md`)

- **Bare-metal**, not a virtualized instance — the CO-corrected p99/p99.9 tail must be free of hypervisor jitter (the whole point of the open-loop methodology is an honest tail).
- **≥ ~64 physical cores** so workers pin to **disjoint physical cores** up to the N-grid max, with separate dedicated cores for `sched`, Redis, and the verifier(s). If N=64 disjoint-physical pinning exceeds the box, either size up or cap the authoritative pinned-N grid at what fits physical cores and document where hyperthread-sharing/oversubscription begins (even N≈48–56 clean is a vast improvement over 8).
- **2 NUMA nodes** to exercise NUMA-aware pinning and surface (or rule out) NUMA effects on the loopback Redis RTT — relevant to the flagship's host-placement analogue.
- **AES-NI** (x86) so the crypto claim is on the same instruction path as Phase 2/6.
- **Ample RAM** (≥ 64 GB) and a generous `RLIMIT_MEMLOCK` so the mlock'd-key / memfd no-disk path runs at high concurrency without swap pressure (8 GB was a constraint).
- **Citable & reproducible:** a published instance type (established AWS bare-metal families such as `c6i.metal` / `c7i.metal`-class / `x2idn.metal` are illustrative — **operator confirms the current best fit** and records exact instance type, region, AMI, kernel, microcode in `METHODOLOGY.md`).
- **Pinned environment:** the same ffmpeg version as Phase 6 (8.0.1 — identical encoder for the detection results to remain comparable), Redis built from source at a pinned version, pinned `rustc`, and the corpus SHA-256s matching Phase 6 (re-verify the hashes before trusting any number).
- *(Optional bonus, cuttable: a second run on an ARM bare-metal box (e.g., Graviton `c7g.metal`) — AES via ARMv8 crypto extensions, the no-disk path on ARM — as a cross-architecture portability confirmation. Strengthens "real systems work, ISA-portable" but adds a variable; primary is x86 to match the AES-NI claim.)*

---

## 3. Harness portability prep (additive `bench`; runnable/verified on the laptop first)

- **NUMA-aware pinning:** assign worker cores with socket awareness; dedicate cores for `sched`, Redis, and verifier(s); document which socket Redis sits on (so the loopback RTT is representative and NUMA effects are attributable). Keep `taskset` (external command; `bench` stays `#![forbid(unsafe_code)]`).
- **Configurable, larger N grid** up to the box's physical core count; the grid is a parameter, not a constant.
- **Generous `RLIMIT_MEMLOCK`** set/raised for the worker/verifier processes so the mlock path doesn't fail under high concurrency; documented.
- **Platform-keyed results:** results go under `bench/results/<platform-tag>/...` (e.g., `laptop-i5-1135g7/` retroactively for the Phase 6 set, `metal-<instance>/` for the new run) so both are preserved and comparable. Do **not** overwrite or delete the laptop results — they are the honest dev baseline (same ethos as keeping the frozen legacy `Stream-hive` snapshot).
- Regression: all Phase 4/5/6 suites + `contract.rs` (both tiers) + `live_smoke` stay green; `core` 0-byte diff.

---

## 4. The bare-metal re-run (on the box)

- Re-verify the corpus SHA-256s and tool versions against `METHODOLOGY.md`.
- Execute **every** committed regen command for the Phase 6 result sets (`sched/`, `pipeline/`, `saturation/`, `adversary/`, profiling) into the `metal-<instance>/` tree, with the larger N grid and NUMA-aware pinning.
- Re-confirm the **correctness suites live** on the box: `contract.rs` both store tiers, `live_smoke` (no skip), and the adversary suite — including **fencing zero-double-outputs at scale** and the **per-class detection + CIs**.
- For verification cost, re-measure and, if feasible, add a longer-segment variant to **decompose** the 1.66× into fixed ffmpeg-startup vs fundamental re-encode (the honest follow-up to Phase 6's stated divergence).
- All numbers from the real Redis + ffmpeg on the documented box; nothing fabricated; if anything cannot run, loud-skip and mark pending.

---

## 5. The reconciliation (`PLATFORM-RECONCILIATION.md`) — the elite artifact

A document structured by the §1.1 table: for each measurement, state **superseded / confirmed / new**, show the **laptop and bare-metal numbers side by side**, and explain. Specifically:
- **Superseded:** the true scaling curve up to physical-core N (the headline fix — what the laptop could not produce), jitter-free dispatch/reclaim latency, server-CPU crypto throughput (with the robust %-of-transcode confirmed), and the verification-cost re-measure/decomposition.
- **Confirmed:** fencing zero-double-outputs, per-class detection within CIs, the Redis-dominates decomposition and the 2N+4 RTT count, AES-NI + crypto sub-percent, adaptive escalation + floor — each shown to agree across platforms (and any divergence investigated).
- **New:** NUMA effects on RTT (if any), the real scheduler ceiling, the high-concurrency no-disk path validated without swap.
- Update `BENCHMARKS.md` and `METHODOLOGY.md` to make the bare-metal run the **cited baseline**, with the laptop run retained and labeled the dev baseline. Every figure cites its CSV under the platform-keyed path. Writing Standard: declarative, units + conditions, honest negatives; public framing stays a systems artifact (flagship/AI-infra synergy internal).

This reconciliation — knowing exactly which numbers hardware moves and which it does not — is the senior judgment the whole project is built to demonstrate.

---

## 6. OPTIONAL stretch: the placement-RTT remedy (additive `sched`; cuttable)

Phase 6 surfaced that `dispatch_one_live` issues **2N+4** round trips (the 2N per-candidate `worker_load` reads are the scaling variable). On a 64-core box this dominates the scaling curve. The telemetry now justifies the remedy (NORTH-STAR: "don't add complexity the telemetry doesn't justify" — here it does):
- Fold placement + lease + push into **one Lua script** (or maintain worker-load in a Redis sorted structure the scheduler reads in O(1)), cutting per-dispatch round trips from 2N+4 toward O(1).
- **Mandatory if attempted:** a measured **before/after** on the box (re-run the dispatch decomposition), reported predicted-then-confirmed ("folding 2N+4 → O(1) moved dispatch p99 from X to Y; the placement reads are no longer the scaling variable"). Keep the old path or a flag so the before-number is reproducible.
- Additive to `sched`; `core` untouched; all prior suites green. **Cuttable** under the clock — the validation + reconciliation (§3–§5) are the load-bearing deliverable; this is the high-leverage bonus.

---

## 7. Correctness, reproducibility & purity (verify before commit)
- `bench`/`sched` stay `#![forbid(unsafe_code)]`, no async; pinning via `taskset`, profiling via `perf` (external).
- `core` 0-byte diff; all Phase 4/5/6 suites + `contract.rs` (both tiers) + `live_smoke` + adversary green **on the box**, against the real Redis.
- Laptop results preserved; results platform-keyed; corpus SHA-256s + tool versions re-verified and recorded.
- The reconciliation reports laptop vs bare-metal side by side; every figure cites its CSV; honest divergences stated.
- Allowlist: §6, if done, adds no new `sched` dep; `bench` allowlist unchanged.
- `cargo build --all-targets && cargo clippy --all-targets -- -D warnings && cargo test` clean on the box.

---

## 8. Commit discipline (carried forward)
- Conventional Commits `<type>(bench|sched|docs): <imperative>`, ≤72 chars; body cites the spec/amendment section and the rejected alternative where relevant.
- Atomic, one logical change per commit, each on a green tree. Never commit red. No `--no-verify`, no force-push, no `core/` edits. Commit CSVs/JSON/text, never media/large binaries. The optional optimization (§6) lands as its own commit with the before/after.

---

## 9. Phase 7 Definition of Done
1. `bench` orchestrator made NUMA-aware, larger-N-capable, dedicated-core, generous `RLIMIT_MEMLOCK`; results platform-keyed; laptop results preserved; all suites green (`core` 0-byte diff).
2. Operator-provisioned bare-metal box meeting §2 (≥~64 physical cores, 2 NUMA, AES-NI, bare-metal, ample RAM), exact instance + kernel/microcode + tool versions + corpus hashes recorded in `METHODOLOGY.md`.
3. Full Phase 6 suite re-run on the box into `bench/results/metal-<instance>/`; correctness suites (`contract.rs` both tiers, `live_smoke`, adversary incl. fencing zero-double-output + per-class detection CIs) re-confirmed **live**.
4. **The true scaling curve** (throughput + dispatch latency vs N up to physical-core N, disjoint-pinned) committed — superseding the confounded laptop curve.
5. Verification cost re-measured (and decomposed into startup vs fundamental if the longer-segment variant is run); crypto re-measured (server GB/s + confirmed sub-percent); reclaim latency re-measured jitter-free.
6. `PLATFORM-RECONCILIATION.md` committed (§5): per-measurement supersede/confirm/new with laptop vs bare-metal side by side and divergences explained; `BENCHMARKS.md`/`METHODOLOGY.md` updated to cite the bare-metal baseline (laptop retained, labeled).
7. (Optional §6) placement-RTT remedy with a measured before/after, predicted-then-confirmed; or explicitly deferred to Phase 8/post-distribution with a one-line note.
8. `core` unchanged since freeze; purity/allowlist respected; full gate green on the box; commits per §8.

Next: `phase8-spec.md` — Closeout & Distribution: the 60-second `README` and the `x-thread` built **only** from the bare-metal committed numbers; the `SELF-AUDIT` re-deriving the hardest mechanisms from memory (fencing/epoch CAS, the confidentiality boundary, the hypergeometric × (1−FAR) detection composition) — the comprehension gate; final `ARCHITECTURE` polish; and the proof-first distribution doctrine (NORTH-STAR §7). The artifact made undeniable, then seen.

---

# Appendix A — `CLAUDE.md` update for Phase 7

```markdown
## Authoritative specs
- docs/specs/kickoff-brief.md + kickoff-amendment-1.md
- docs/specs/phase0–6-spec.md  — core (FROZEN), crypto, verify, sched, worker+verifier, bench
- docs/specs/phase7-spec.md    — CURRENT: hardware validation & bare-metal re-run

## Frozen
- proctor_core FROZEN @ v0.1.0-core-frozen. git diff v0.1.0-core-frozen -- core/ MUST be empty.
- bench/sched extend ADDITIVELY; ALL prior-phase suites + contract.rs (both tiers) + live_smoke + adversary green.

## Hard rules (Phase 7)
1. bench/sched stay #![forbid(unsafe_code)], no async. Pinning = taskset; profiling = perf (external).
2. Real numbers only, from a documented BARE-METAL box (not a VM — jitter-free tail). Record exact instance,
   kernel/microcode, ffmpeg/Redis/rustc versions, corpus SHA-256s in METHODOLOGY.md. No fabrication; loud-skip if absent.
3. Same ffmpeg version as Phase 6 (8.0.1) so detection results stay comparable.
4. PRESERVE the laptop results (the honest dev baseline). Results are platform-keyed; never overwrite/delete.
5. Reconcile, don't replace silently: per measurement state SUPERSEDE (hardware-confounded) / CONFIRM
   (hardware-independent) / NEW; laptop vs bare-metal side by side; explain any CONFIRM-row divergence.
6. The true scaling curve uses DISJOINT physical-core pinning up to the box's core count; document where
   hyperthread/oversubscription begins. NUMA-aware pinning; dedicated cores for sched/Redis/verifier.
7. CO-correct (intended-issue time, hdrhistogram), distributions (p50/p99/p99.9), every figure cites its CSV.
8. Optional §6 placement-RTT remedy: MANDATORY measured before/after if attempted; additive sched; cuttable.

## Commit discipline
Conventional Commits, atomic, GREEN tree (incl. prior suites on the box), body cites spec/amendment.
Commit CSVs/JSON/text, NEVER media/large binaries. No --no-verify, no force-push, no core/ edits.

## Scope discipline
Harness prep + bare-metal re-run + reconciliation (+ optional optimization) only. NO README/x-thread/
SELF-AUDIT/distribution (Phase 8). End with build+clippy+test, commit(s), change list, STOP.
```

---

# Appendix B — Claude Code execution plan

| # | Session | Where | Deliverable | Done when |
|---|---|---|---|---|
| 0 (operator) | provision | — | bare-metal box per §2; point Claude Code at it | instance up; specs recorded |
| 1 | harness prep | laptop or box | NUMA-aware + larger-N + dedicated-core + memlock; platform-keyed results; laptop set relabeled | all suites green; commit |
| 2 | re-run | box | full Phase 6 suite into `metal-<instance>/`; correctness suites live | regen complete; fencing + detection re-confirmed; commit |
| 3 | reconcile | box | `PLATFORM-RECONCILIATION.md`; BENCHMARKS/METHODOLOGY cite bare-metal | side-by-side, supersede/confirm/new; commit |
| 4 (optional) | optimize | box | single-Lua placement remedy + before/after | dispatch p99 before/after committed; commit — or defer with a note |
| 5 | DoD verify | box | item-by-item | DoD §9 reported with evidence; commit |

### Exact prompts (one per session; verify + commit before the next)

**Session 1**
> Read `phase7-spec.md` (§1–§3, §7–§9) and `CLAUDE.md`; update `CLAUDE.md` per Appendix A. Execute **Session 1 only**: additively make `bench`'s orchestrator NUMA-aware (dedicated cores for `sched`/Redis/verifier; workers pinned to disjoint physical cores; documented socket placement), the N grid a configurable parameter up to physical-core count, and `RLIMIT_MEMLOCK` raised for worker/verifier processes; key results by platform (`bench/results/<platform-tag>/`) and relabel the existing Phase 6 set as the laptop dev baseline (do not delete it). Keep `#![forbid(unsafe_code)]`, no async, `taskset`-based pinning. All Phase 4/5/6 suites + `contract.rs` (both tiers) + `live_smoke` stay green; `core` 0-byte diff. Build+clippy `-D warnings`+test; commit `feat(bench): NUMA-aware pinning, configurable N grid, platform-keyed results`; STOP.

**Session 2** *(on the bare-metal box)*
> Read `CLAUDE.md` and `phase7-spec.md` §2, §4. Execute **Session 2 only**: re-verify the corpus SHA-256s and tool versions against `METHODOLOGY.md`; provision Redis (build from source, pinned) and confirm ffmpeg 8.0.1; run **every** committed Phase 6 regen command into `bench/results/metal-<instance>/` with the larger N grid and NUMA-aware pinning; re-confirm the correctness suites **live** (`contract.rs` both tiers, `live_smoke` no-skip, adversary suite — fencing zero-double-output at scale + per-class detection with CIs). Re-measure verification cost (add a longer-segment variant to decompose startup vs fundamental if feasible) and crypto. Record the exact instance, kernel/microcode, and versions in `METHODOLOGY.md`. Commit `docs(bench): bare-metal re-run results`; STOP.

**Session 3** *(on the box)*
> Read `CLAUDE.md` and `phase7-spec.md` §5, §1.1. Execute **Session 3 only**: write `bench/results/PLATFORM-RECONCILIATION.md` structured by the §1.1 supersede/confirm/new table — laptop vs bare-metal side by side per measurement, with the true scaling curve as the headline supersession and every CONFIRM-row agreement (or divergence, investigated) stated; update `BENCHMARKS.md` and `METHODOLOGY.md` to cite the bare-metal run as the baseline (laptop retained and labeled). Every figure cites its CSV; Writing Standard; systems framing. Commit `docs(bench): platform reconciliation, bare-metal baseline`; STOP.

**Session 4 (optional)** *(on the box)*
> Read `CLAUDE.md` and `phase7-spec.md` §6. Execute **Session 4 only** *if pursuing the optimization*: fold the placement reads + lease + push into one Lua script (or O(1) worker-load structure), keeping a flag/path for the old behavior so the before-number reproduces; re-run the dispatch decomposition and commit the measured **before/after** (dispatch p99 X→Y; round trips 2N+4→O(1)) predicted-then-confirmed. Additive `sched`, `core` untouched, all suites green. Commit `perf(sched): O(1) placement round trips with measured before/after`; STOP. *(If deferring, skip and note it in the DoD.)*

**Session 5** *(on the box)*
> Read `CLAUDE.md` and `phase7-spec.md` §9. Execute **Session 5 only**: verify the Phase 7 DoD §9 item by item with evidence; confirm `git diff v0.1.0-core-frozen -- core/` is empty and all suites green on the box against the real Redis; confirm the laptop results are preserved and the bare-metal baseline is cited. Commit `docs: phase 7 DoD verification`; STOP.
```
