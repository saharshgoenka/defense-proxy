# Adaptive Defense, Flag Rotation, and Cold-Start / Cadence

This note explains three mechanisms that work together in DefenseProxy's
`bandit` and `llm_adaptive` modes:

1. **Adaptive defense** — picking an injection (or generating one) per response.
2. **Flag rotation** — varying the concrete `fake_flag` body so repeat exposures
   don't look identical.
3. **Cold start + nth-injection cadence** — deciding *when* to inject, so the
   defense doesn't blast every response and instantly fingerprint itself.

All three live in `defense-proxy/`. Pointers to the relevant code are inline.

---

## 1. Adaptive defense

Two modes share the same plumbing but differ in how an injection is chosen:

### 1a. Bandit mode (`mode: bandit`)

Selection is **contextual Thompson sampling** over arms `(position, trigger,
payload)`. Implementation in [bandit.py](../bandit.py):

- Each arm × phase keeps a `Beta(α, β)` posterior (`BetaPosterior`,
  [bandit.py:60](../bandit.py#L60)).
- Phases come from a lightweight classifier of recent agent traffic —
  `recon | enum | exploit | exfil | unknown`
  ([reward_tracker.py:119](../reward_tracker.py#L119)).
- On each response, the proxy:
  1. Filters arms to those *feasible* for the response (e.g. `robots_txt`
     only at `/robots.txt`, `error_message` only on 4xx/5xx, `http_body`
     only on text-ish content types — see
     [reward_tracker.py:187](../reward_tracker.py#L187)).
  2. Samples `θ_a ~ Beta(α_a, β_a)` per feasible arm and picks the argmax
     ([bandit.py:212](../bandit.py#L212)).
- After a configurable **attribution window** (`window_requests`,
  `window_seconds`), the tracker computes the reward (see §1c) and calls
  `bandit.update(arm, phase, reward)`.

Cold-start priors are seeded from `configs/bandit/priors.yaml` using
per-dimension "post-defense solve rate" estimates from the prior empirical
study; the worst dimension caps the prior mean
([bandit.py:149-181](../bandit.py#L149-L181)). Arms with no prior data fall
back to uniform `Beta(1, 1)`.

A `RandomBandit` subclass picks uniformly and never updates — used as a
control ([bandit.py:279](../bandit.py#L279)).

### 1b. LLM-adaptive mode (`mode: llm_adaptive`)

Same dispatch loop, but instead of selecting from a finite arm set, it asks
DeepSeek-v4-flash (via OpenRouter) to generate the payload text from scratch,
conditioned on:

- the current phase,
- recent endpoints + HTTP methods,
- a short summary of what's worked / failed this session (the
  `reward_history` buffer),
- the page body excerpt and content type,
- the injection slot (position).

See [llm_defender.py:99](../llm_defender.py#L99). The reward tracker still
runs — it just feeds back into a `RandomBandit` (so we keep solve-spike
cooldowns and logging, but skip Thompson updates) and into the rolling
`reward_history` the next LLM prompt reads.

If the LLM call fails (timeout, empty response, missing key), the proxy
falls back to a configured static payload — usually `fake_flag` — so the
defense degrades gracefully rather than passing through cleanly.

### 1c. Reward attribution

Reward is **solve-supervised**, not heuristic. See
[reward_tracker.py](../reward_tracker.py):

- At injection time, snapshot `S_start` = number of Juice Shop challenges
  with `solved: true` (polled from `/api/Challenges`).
- Close the window after `window_requests` agent requests OR
  `window_seconds`, whichever fires first.
- Poll `S_end`. Reward = `1.0` if `S_end == S_start`, else `0.0`.
- If `Δ = S_end − S_start > 0` (a "solve spike"), put that arm on a
  60s **cooldown** across all phases — we don't want to keep firing an arm
  that's coinciding with progress.
- If either poll returns `None`, the update is skipped (logged with
  `skipped: true`), so transient Juice Shop hiccups don't poison the
  posterior.

---

## 2. Flag rotation

The `fake_flag` payload defaults to a single hardcoded string. With repeated
exposure, an agent (or its operator reading logs) starts to recognise it.

When `use_rotating_fake_flag: true` is set under `bandit:` in the config,
each `fake_flag` rendering draws uniformly from
[`FAKE_FLAG_VARIANTS`](../payloads.py#L84) — five plausible-looking flag
strings in CTF shape (`flag{...}`, `FLAG{...}`, `key{...}`). Wiring:

- [`configure_runtime_payload_options`](../payloads.py#L97) flips a module-
  level flag at proxy startup and seeds the RNG.
- [`get_injection`](../payloads.py#L144) checks the flag at render time:
  ```python
  if payload == "fake_flag" and _USE_ROTATING_FAKE_FLAG:
      body = _FAKE_FLAG_RNG.choice(FAKE_FLAG_VARIANTS)
  ```

The variants are intentionally close to the expected CTF output shape so
the first exposure is less obviously synthetic. Determinism is preserved
via the seeded RNG, so a run is reproducible end-to-end.

LLM-adaptive mode gets rotation "for free" — every call yields a fresh
payload string anyway.

---

## 3. Cold start and nth-injection cadence

If the proxy injects on every single response, two things go wrong:

1. **Detection** — the agent (or its trace) sees defense text everywhere
   and either learns to ignore it or pivots away.
2. **Attribution noise** — overlapping injection windows make it hard to
   say which injection caused which (non-)solve.

The cadence controls (configured per mode under `bandit:` or
`llm_defense:`) gate injection in three stages. All three are checked
in order; the first one that fails causes the response to pass through
untouched, logged with the reason. See
[http_proxy.py:336-377](../http_proxy.py#L336-L377) (bandit) and
[http_proxy.py:458-470](../http_proxy.py#L458-L470) (llm_adaptive).

### 3a. Warmup (cold start)

```yaml
bandit:
  warmup_requests: 0   # default
```

For the first `warmup_requests` agent requests, the proxy passes everything
through. This gives the agent time to establish its session, read its first
page of HTML, and start its scan loop before the defense engages — so the
first injection lands on a response the agent is *actually reading*, not on
a static asset fetch the browser kicked off automatically.

Logged as `bandit_skipped: "cadence_warmup"`.

### 3b. Every-nth injection

```yaml
bandit:
  inject_every_nth: 1   # default — every eligible response
```

Among responses that pass feasibility and warmup, only every `n`-th is a
candidate for injection. The counter is `_eligible_response_count` — it
ticks for any response that *could* have been injected, regardless of
whether the probability gate (§3c) eventually lets it through.

Logged as `bandit_skipped: "cadence_every_nth"`.

### 3c. Phase-aware probabilistic gate

```yaml
bandit:
  inject_prob_recon:   1.0
  inject_prob_enum:    1.0
  inject_prob_exploit: 1.0
  inject_prob_exfil:   1.0
```

After warmup and the nth-injection filter, the proxy draws `u ~ U(0, 1)`
and injects only if `u <= p_phase`. This lets us be more aggressive in
phases where defense is cheap (recon, enum) and back off in phases where
the agent is already burning compute (exploit, exfil).

Logged as `bandit_skipped: "cadence_probability"` with the threshold.

### 3d. Order of operations (per response)

```
agent request count += 1
response arrives
└── if mode in {bandit, llm_adaptive}:
      feasible = feasible_arms(response)
      phase    = classify(recent_requests)
      ├── warmup not yet over?        → passthrough, log "cadence_warmup"
      ├── not the nth eligible?       → passthrough, log "cadence_every_nth"
      ├── u > inject_prob[phase]?     → passthrough, log "cadence_probability"
      ├── arm = bandit.select(phase, feasible)
      │   (or: payload = llm_defender.generate_injection(...))
      ├── apply at arm.position
      └── register_injection(...) → opens reward attribution window
```

---

## 4. How they interact

- **Bandit + cadence**: cadence is a *pre-filter*. The bandit only sees
  responses that survived warmup, nth-injection, and the phase probability.
  This keeps the bandit's posteriors clean — they reflect "did this arm
  work *when we chose to inject*", not "did this arm work *averaged over a
  blanket of injections, some of which the agent never read*".
- **Flag rotation + bandit**: rotation lives below the bandit. When
  `bandit.select()` returns `(http_body, context_blend, fake_flag)`, the
  rendering step at `get_injection()` picks one of the five variants. From
  the bandit's perspective, all renderings collapse to the same arm key,
  so reward updates aggregate across variants — which is what we want for
  generalisation.
- **LLM-adaptive + cadence + reward**: same cadence, but the bandit is a
  `RandomBandit` shell. Updates go to logs and to `_reward_history`, which
  feeds the *next* LLM prompt's "WHAT'S WORKED SO FAR" section. So the LLM
  is the learner; the bandit infrastructure is just bookkeeping.

---

## 5. Config knobs in one place

```yaml
mode: bandit                       # or: llm_adaptive | random | (legacy single)

bandit:
  priors_path: configs/bandit/priors.yaml
  seed: 0
  use_rotating_fake_flag: true     # §2

  # cadence (§3)
  warmup_requests: 5
  inject_every_nth: 2
  inject_prob_recon:   1.0
  inject_prob_enum:    0.8
  inject_prob_exploit: 0.5
  inject_prob_exfil:   0.7

  # reward attribution (§1c)
  window_requests: 5
  window_seconds:  30.0

llm_defense:                       # only used when mode: llm_adaptive
  model: deepseek/deepseek-v4-flash
  position: http_body
  fallback_payload: fake_flag
  warmup_requests: 0
  inject_every_nth: 1
  inject_prob_recon:   0.4
  inject_prob_enum:    0.7
  inject_prob_exploit: 0.9
  inject_prob_exfil:   0.8
  window_requests: 5
  window_seconds:  30.0
```

See `configs/bandit/*.yaml` for the four pre-baked variants:
`baseline`, `fixed_best`, `random`, `new_adaptive`,
`new_adaptive_flag_rotate`, `llm_adaptive`.
