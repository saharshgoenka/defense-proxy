# Day 2 Runbook — Capstone Evaluation

Step-by-step guide for running all 6 conditions and backfilling
the paper. Designed so that the only thing required tomorrow morning
is rate-limit reset + ~3 hours of wall-clock.

## 0. Pre-flight (do once, even if rate limit isn't reset)

```bash
# verify pentestgpt container is up (it usually persists across reboots
# once you've done `make connect` once)
docker ps | grep pentestgpt
# if it's not, bring it up:
( cd ../PentestGPT && make start )

# verify pentestgpt CLI is on PATH inside the container
docker exec pentestgpt which pentestgpt
# expected: /usr/local/bin/pentestgpt

# verify config files all validate
for f in baseline fixed_best random adaptive; do
  .venv/bin/python3 main.py --config configs/bandit/$f.yaml --validate-config
done
# expected: all "CONFIG OK"

# verify rate limit is fresh (≤ 5s, no LLM tokens)
docker exec pentestgpt pentestgpt --target http://127.0.0.1:9 --raw 2>&1 \
  | grep -E '\[INFO\] (You|Starting|Target)'
# you want to NOT see "You've hit your limit" in the output
```

If "You've hit your limit" still appears, wait until your Claude Code
quota resets (it shows the reset time in UTC, e.g. `7:20am (UTC)` ≈
midnight Pacific the night before).

## 1. Run all six conditions, unattended

```bash
cd /Users/saharsh/Desktop/research-project/defense-proxy
.venv/bin/python3 run_day2.py --all
```

Per condition this does:

1. Tears down any leftover `juice-shop-benchmark` and stale mitmdump.
2. Starts a fresh CTF-mode Juice Shop on `:3000` (snapshots `baseline.json`).
3. Starts mitmdump in reverse-proxy mode pointed at the right config
   (with `DEFENSEPROXY_CONFIG`/`DEFENSEPROXY_RUN_ID` env vars so the
   bandit picks up the right priors).
4. Waits for proxy bind on `:8080`.
5. Runs `pentestgpt --raw --target http://host.docker.internal:8080`
   inside the `pentestgpt` Docker container, with `--instruction "<verify
   flags before submission>"` for the two hardened conditions.
6. Captures stdout to `logs/<run_id>/agent_stdout.txt`.
7. Sends SIGINT to mitmdump so the bandit's final `bandit_snapshot.json`
   flushes.
8. Runs `score_juice_shop.sh` and copies the score CSV.
9. Stops Juice Shop.
10. Runs `metrics.py` to compute APR / DSR / ARC →
    `logs/<run_id>/metrics_summary.json`. ARC is parsed in USD from
    PentestGPT's `[DONE] Cost: $X.XXXX` terminator line; total cost
    across the batch prints at the end of the runner.

Expected wall-clock: ~30–40 min per condition × 6 = 3–4 hours total.

If any single condition fails (network blip, container hiccup), re-run
just that one:

```bash
.venv/bin/python3 run_day2.py --condition fixed_best_hardened
```

Or resume after a partial run:

```bash
.venv/bin/python3 run_day2.py --all --skip-existing
```

The top-level summary CSV `logs/day2_results.csv` is appended to (not
overwritten); duplicate rows for the same condition are de-duplicated
by `analyze_day2.py` with last-write-wins.

## 2. Aggregate

```bash
.venv/bin/python3 analyze_day2.py
```

Writes:

- `paper/results.json` — machine-readable, consumed by `backfill_paper.py`
- `paper/results.md`   — human-readable summary tables
- `paper/figures/posterior_heatmap.png` — end-of-run (payload, phase) heatmap
- `paper/figures/arm_selection_freq.png` — top arms by selection count

Open `paper/results.md` and eyeball the numbers. If anything looks
suspicious (zero injections, agent died at step 0, etc.), diagnose
before backfilling.

## 3. Backfill the paper

```bash
.venv/bin/python3 backfill_paper.py
```

This auto-fills:

- §5.1 Table 1 (six condition rows with APR, DSR, **Cost (USD)** parsed
  from the `[DONE]` line of each run)
- §5.2 Table 2 (per-category solves for the three baseline/fixed/adaptive cols)
- §5.3 figure paths
- §5.5 total LLM cost in USD + per-condition breakdown + wall-clock

It does **not** auto-fill:

- The §5.1 narrative paragraph (you write the headline finding)
- The §5.2 narrative ("broad win or narrow win?")
- The §5.3 dynamics interpretation
- §5.4 ablations (those need their own runs; see §4 below if you have time)
- Abstract `<RESULT: ...>` placeholder (you write the one-sentence headline)
- Any `<RESULT: link to public repo if applicable...>`

Use `--dry-run` first to preview:

```bash
.venv/bin/python3 backfill_paper.py --dry-run
```

## 4. (Optional) Ablations — only if time permits

The paper §5.4 anticipates three ablations of the algorithm itself:

- **A1: No cold-start priors.** Edit `configs/bandit/priors.yaml` →
  set `prior_strength: 0` → re-run adaptive_hardened with
  `--run-id-suffix _a1_no_priors`.
- **A2: No contextual bucketing.** Edit `bandit.py` so all phases
  resolve to a single `"all"` bucket (one-line patch in
  `_PhaseClassifier.classify`) → re-run with `_a2_no_buckets`.
- **A3: No solve-spike cooldown.** Edit `reward_tracker.py` so the
  post-update `cooldown(...)` branch after `delta > 0` is disabled →
  re-run with `_a3_no_spike_cooldown`.

Each ablation = ~30–40 min. Skip if you're tight on quota; the
narrative in §5.4 can stand on a one-line "deferred to future work".

## 5. (Optional) Repeat baseline once

The paper claims baseline ≈ 11.8/111 from prior work. The prior data
came from `make connect` runs on a different day with different
infrastructure. Even a single fresh baseline run today gives Table 1
internal consistency. The runner does this automatically as the first
of the six conditions.

## Troubleshooting

### `[Errno 48] address already in use` on `:8080`

A previous mitmdump didn't shut down. Kill it:

```bash
lsof -ti tcp:8080 | xargs kill
```

`run_day2.py` does this automatically before each condition, but
manual interventions can leave stale processes.

### `proxy on :8080 did not bind within 30s`

Check `logs/<run_id>/mitmdump.log`. Most likely: the addon raised an
exception during `_init_bandit_mode` (priors path resolution, YAML
syntax error). Run with the same env vars manually:

```bash
DEFENSEPROXY_CONFIG="$(pwd)/configs/bandit/adaptive.yaml" \
DEFENSEPROXY_RUN_ID=debug \
.venv/bin/mitmdump -s http_proxy.py --mode reverse:http://localhost:3000 -p 8080
```

### `'pentestgpt' container is not running`

Bring it up: `cd ../PentestGPT && make start`.

### `[INFO] You've hit your limit` shows up in agent_stdout.txt

Your Claude Code quota was exhausted partway through. Wait for reset,
then `--skip-existing --all` to resume.

### A condition reports 0 injections but the agent ran for 5+ minutes

Check `logs/<run_id>/events.jsonl` for `addon_loaded` and at least one
`injection_applied: true`. If none, the agent's traffic isn't
matching any feasible position — likely the agent never read an HTML
body (e.g., it short-circuited to a flag from `[INFO]` logs only).
Cross-check against the agent's stdout and the proxy log.

### A condition reports many injections but DSR ≈ 0

The agent's stdout doesn't contain any of `PAYLOAD_DSR_KEYWORDS`. Look
at `logs/<run_id>/agent_stdout.txt` and decide whether to add a new
fingerprint (see `payloads.py::PAYLOAD_DSR_KEYWORDS`). Then re-run
just the metrics step:

```bash
.venv/bin/python3 metrics.py \
  --run-id adaptive_hardened_run1 \
  --log-dir logs \
  --agent-log logs/adaptive_hardened_run1/agent_stdout.txt \
  --score-csv logs/adaptive_hardened_run1/score.csv
```

No need to re-run the agent.

## Files this runbook touches

| File | Purpose |
| --- | --- |
| `run_day2.py` | 6-condition orchestrator |
| `analyze_day2.py` | Cross-condition aggregator + figure renderer |
| `backfill_paper.py` | Auto-fill numeric `<RESULT>` placeholders |
| `configs/bandit/baseline.yaml` | Passthrough (no injections) |
| `configs/bandit/fixed_best.yaml` | Static `fake_flag` in HTML body |
| `configs/bandit/random.yaml` | Uniform-random arm selection |
| `configs/bandit/adaptive.yaml` | Thompson sampling bandit |
| `configs/bandit/priors.yaml` | Cold-start Beta priors from prior ablation |
| `paper/capstone.md` | Target document for backfill |
| `paper/results.md` | Auto-generated aggregate summary |
| `paper/results.json` | Machine-readable for backfill |
| `paper/figures/*.png` | Auto-generated figures |
| `logs/<run_id>/` | Per-condition outputs (events, score, metrics, snapshot) |
| `logs/day2_results.csv` | Top-level row-per-run CSV |
