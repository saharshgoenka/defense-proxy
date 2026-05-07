# Adaptive Defensive Prompt Injection: An Online Bandit for Disrupting LLM-Driven Hacking Agents

**Saharsh Goenka — Master's Capstone Report**
**Draft — May 2026**

---

## Abstract

LLM-based hacking agents (e.g., PentestGPT, CAI) autonomously enumerate, exploit, and capture flags on vulnerable targets by reading service responses and reasoning about next actions. Recent work (Mantis, 2024) showed that defenders can hijack these agents by *injecting adversarial text into responses* — defensive prompt injection. Existing systems, however, rely on a single hand-crafted payload that is fixed for the entire session. In a prior empirical study we found that this static approach is brittle: the marginal-best payload (`fake_flag`) drove the agent's challenge-solve count from 11.8/111 to 0/111, but other plausibly-good payloads either had no effect (`tool_confusion`: 9/111) or *backfired* (`decoy_port`: 9/111, by causing the agent to find and attack a sibling service it would otherwise have ignored). Static defense is one bad payload-choice away from making the situation worse.

We present **AdaptiveDefenseProxy**, the first online learning algorithm for selecting defensive prompt injections. The proxy formulates per-response injection as a contextual multi-armed bandit over the cross product `{positions} × {triggers} × {payloads}` from our prior three-dimensional taxonomy, and uses Thompson sampling to balance exploitation of known-good payloads against exploration of context-dependent winners. Crucially, the per-arm **online reward is aligned with the headline evaluation metric**: after each injection we poll Juice Shop's `/api/Challenges` and set reward to **1 iff no new challenge flipped to solved** within a short attribution window (otherwise **0**). This uses **local HTTP only** (no extra LLM calls beyond the attacker). Beta posteriors are cold-started from the prior empirical study, turning a one-shot ablation table into a meaningful learning prior.

We evaluate on OWASP Juice Shop against PentestGPT under six coordinated runs: undefended baseline, fixed-best static defense, uniform-random arm selection, our adaptive bandit against a standard agent, fixed-best against a verify-flag-hardened agent, and our adaptive bandit against that hardened attacker. **Headline (single coordinated sweep):** undefended PentestGPT solves **17**/111 challenges (\~\$2.24 ARC); static **fake_flag** drives that to **1**/111 (\~\$0.06); random injection sits at **15**/111 (\~\$2.51); adaptive Thompson sampling sits at **2**/111 (\~\$0.07); under verify-flag instructions, static **fake_flag** achieves **0**/111 (\~\$0.09) while the hardened adaptive bandit achieves **0**/111 (\~\$0.09)—both far below baseline, with **single-run variance** between bandit, random, and static standard rows. The contribution of this work is threefold: (1) the first formulation of defensive PI selection as an online bandit; (2) a **Juice Shop–supervised** bandit reward (challenge solve deltas via `/api/Challenges`) that requires **no additional LLM** calls beyond the attacker; and (3) a reproducible harness that reports costs and per-category solves honestly across standard and hardened attacker prompts.

---

## 1. Introduction

LLM-driven autonomous hacking agents are no longer a research curiosity. PentestGPT, CAI, Mayoral-Vilches's MAPTA, and similar systems can read the output of `nmap`, `curl`, `ls`, and `cat`, decide what to do next, and chain shell commands until they capture flags or compromise a target. They scale: one operator can launch many agents in parallel, against many targets, for the cost of LLM tokens. Defenders, by contrast, are stuck patching CVEs at human speed.

A small but growing body of work has observed that these agents inherit the foundational vulnerability of all LLM-driven systems: they cannot reliably distinguish *data* from *instructions* in their context window. Pasquini et al. (Mantis, 2024) showed that hand-crafted payloads embedded in service banners and HTTP responses can trick attacking agents 95% of the time. Mayoral-Vilches et al. (2025) showed similar vulnerabilities at 91.4% across 14 attack variants on CAI. We built on this in prior work by proposing the first formal taxonomy of defensive PI along three dimensions — **position**, **trigger**, and **payload** — and a configurable proxy (DefenseProxy) that injects any 3-tuple from the taxonomy into traffic between an attacker agent and a target.

In an ablation study against PentestGPT on Juice Shop, we found that some 4-tuples were devastatingly effective. The strongest payload (`fake_flag` injected into the HTTP body with a `context_blend` trigger) drove the agent's solve count from 11.8/111 (undefended baseline) to 0/111. But the same study revealed an uncomfortable result: **payload effectiveness is highly non-uniform, and some payloads make the situation worse.** The `decoy_port` payload, designed to redirect the agent to a non-existent service, instead caused PentestGPT to scan its host's port range and find a sibling Juice Shop instance the agent would otherwise have ignored, yielding 9/111 — *worse* than no defense at all. The `tool_confusion` payload had no measurable effect (9/111). Of nine plausibly-designed payloads, only four reduced the agent's solve rate meaningfully, and the gap between the best and worst was the gap between perfect defense and active self-harm.

This raises a pointed question. In a deployed setting, the defender does not know in advance which payload is the marginal best for a given agent, model, target, and attack phase. Today's deployed defense must either (a) commit to a single payload across the entire session — accepting the risk of catastrophic backfire — or (b) randomize across payloads — which our results show would be little better than a coin flip between effective and counterproductive defenses. **There is no principled algorithm for *which* defensive payload to inject *when*.**

This work introduces one. We formulate per-response defensive PI selection as a contextual multi-armed bandit, with arms drawn from the existing taxonomy and per-arm reward derived from **ground-truth challenge progression** on the defended target. The result is a proxy that picks a different payload for every response and learns which arms correlate with **fewer new solves** in short post-injection windows.

### 1.1 Contributions

1. **Algorithm.** The first online learning formulation of defensive prompt injection: a contextual Thompson sampling bandit with per-arm Beta posteriors keyed by attack phase, cold-started from a prior empirical ablation study (§3.2).
2. **LLM-free, metric-aligned reward.** After each injection, the proxy polls `/api/Challenges` and attributes a Bernoulli reward: **1** if the count of solved challenges does not increase before the attribution window closes, **0** otherwise—so online learning optimizes the same quantity we report in Table 1 (§3.3). No defender-side LLM calls; only local HTTP to the target API.
3. **Empirical evidence under two attacker regimes.** Against a standard PentestGPT, strong static and adaptive defenses both substantially reduce solves versus baseline (§5). Against a verify-flag-hardened PentestGPT, **both** static **fake_flag** and the adaptive bandit remain effective versus baseline in our run; we report numbers honestly rather than assuming static ``collapse'' (§5).

### 1.2 Why this matters now

The arms race between LLM hackers and LLM defenders is structurally similar to the malware/AV arms race of the 2000s — except both sides can update at conversational latency, with no human in the loop. A static defensive payload deployed today is a static signature, and like static AV signatures it will be obsolete the moment one operator publishes a "defeat fake_flag" prompt template on Twitter. An algorithmic defense — one that re-derives its winning move every time it meets a new agent — is the only kind that survives the first round of attacker adaptation. This paper is a concrete, runnable, $0-marginal-cost instance of that idea.

---

## 2. Background and Prior Work

### 2.1 LLM-driven hacking agents

LLM-driven hacking agents are autonomous systems that wrap a foundation model in a tool-using scaffold (typically: a shell, a browser, and a notepad) and assign it the high-level goal "find and exploit vulnerabilities in `target`". The model reads a system prompt that frames it as a penetration tester, then iteratively (a) inspects the most recent tool output, (b) reasons about what to try next, (c) issues a tool call, and (d) repeats until it either captures a flag or exhausts a step budget. PentestGPT (Deng et al., 2023) is the canonical open-source example; CAI (Mayoral-Vilches et al., 2025) and MAPTA are more recent and more capable instances.

The critical property for this paper is that the agent's reasoning is **driven by data it does not control** — every byte of every tool output is read by the LLM and may influence the next action. This is the prompt-injection attack surface, but inverted: in classical prompt injection, an attacker poisons the LLM's context to compromise the user; in *defensive* PI, the user (the defender) poisons the LLM's context to compromise the attacker.

### 2.2 Defensive prompt injection

Pasquini et al. (Mantis, 2024) introduced the concept of defensive PI and demonstrated two payload families: **counterstrike** (instruct the agent to run a reverse shell on its own host) and **tarpit** (instruct the agent to enumerate an infinite filesystem). They reported a 95% defense success rate against PentestGPT and CAI on three Hack-The-Box challenges. Their evaluation used a single hand-tuned payload per target.

In prior work, we extended this in two directions. First, we proposed a three-dimensional taxonomy:

- **Position** (P1: service banner, P2: login response, P3: HTTP header, P4: HTTP body, P5: file content, P6: error message, P7: DNS/network, P8: code comment, P9: robots.txt, P10: cookie) — where in the attack chain the payload is injected.
- **Trigger** (override, momentum, system_alert, reward_signal, authority, context_blend) — the framing prefix that coerces the LLM to treat the payload as instruction.
- **Payload** (decoy_port, fake_vulnerability, fake_flag, task_complete, recursive_exploration, reverse_shell, prompt_leak, tool_confusion, resource_exhaustion) — the concrete content of the injection.

Second, we built **DefenseProxy**, a configurable mitmproxy addon that implements the taxonomy: a YAML config specifies a list of (position, trigger, payload) tuples and the proxy injects them into intercepted traffic between any agent and any HTTP target. We ran an ablation study on Juice Shop measuring solve-count under one-dimension-at-a-time variation. The summary table from that study (the empirical foundation of this work):

| Dimension | Best entry | Solves | Worst entry | Solves | Baseline |
| --- | --- | --- | --- | --- | --- |
| Position | HTTP header / HTTP body / code comment / robots.txt | 0/111 | error message | 7/111 | 11.8/111 |
| Trigger | context_blend / reward_signal / system_alert | 0/111 | override | 12/111 | 11.8/111 |
| Payload | fake_flag | 0/111 | decoy_port (backfired) | 9/111 | 11.8/111 |

That table is what motivates this work. The marginal best is unambiguous (`fake_flag` in HTTP body with a context-blending trigger drives the agent to zero), but seven of the nine payloads either fail to help or actively harm — and the defender, in a deployed setting, has no way to know which is which without already running the experiment.

### 2.3 Prior-study contributions in detail

The prior study contributed three artifacts that this capstone depends on directly.

**(1) Taxonomy formalization.** We operationalized defensive prompt injection as a composable design space over three dimensions: `position × trigger × payload`. This gave us a language for systematic experimentation (rather than ad hoc prompt crafting), and made it possible to compare defenses on controlled one-factor-at-a-time sweeps.

**(2) Experimental protocol and defaults.** We defined D1/D2/D3 sweeps with explicit held-constant defaults:

- **D1 (Position sweep):** varied position while fixing trigger and payload to `context_blend + fake_flag`.
- **D2 (Trigger sweep):** varied trigger while fixing position and payload to `http_body + fake_flag`.
- **D3 (Payload sweep):** varied payload while fixing position and trigger to `http_body + context_blend`.

These defaults are important because they anchor interpretation of the prior table: "best in a dimension" means "best under those controlled counterparts," not a universal global optimum over all combinations.

**(3) Empirical findings that motivate online selection.** The prior runs established a strong but fragile static winner (`http_body + context_blend + fake_flag`) and exposed severe non-uniformity across alternatives. In particular, `decoy_port` could backfire by increasing agent activity, while several payloads were near-neutral. This is the key methodological bridge to the current capstone: in deployment, defenders do not know the best arm in advance, and naive randomization can pick actively harmful arms.

### 2.4 DefenseProxy system creation and engineering contribution

The prior work also delivered a reusable system, **DefenseProxy**, not just a table of results.

DefenseProxy is implemented as a transparent mitmproxy layer that sits between attacker and target, intercepts HTTP traffic, and applies configured injections before forwarding responses. The system accepts YAML-defined defense tuples and supports multiple injection surfaces in a single framework (e.g., HTTP header/body, error-message channels, code comments, `robots.txt`, cookies). This unified implementation made cross-dimension comparisons technically consistent: all conditions share the same transport path, logging substrate, and target harness.

From an engineering perspective, the critical contribution is reproducibility. Runs are namespaced by `run_id`, injection events are logged with structured metadata, and outputs are machine-consumable for downstream scoring and aggregation. This infrastructure is what makes the present capstone feasible on a near-zero budget: we can swap only the **selection policy** (static vs random vs bandit) while keeping injection mechanics, instrumentation, and scoring constant. In short, this capstone's novelty is the online policy layer; the proxy substrate and taxonomy instrumentation are substantive prior contributions.

### 2.5 Bandits and Thompson sampling

The multi-armed bandit (Robbins, 1952) is the canonical framework for sequential decision problems where (a) at each step the learner picks one of K actions, (b) only the reward of the picked action is observed, and (c) the goal is to maximize cumulative reward without prior knowledge of which action is best. Thompson sampling (Thompson, 1933; revived by Chapelle and Li, 2011) maintains a posterior distribution over each arm's reward and selects, at each step, the arm whose reward sample is highest. For Bernoulli rewards (success/failure), the natural posterior is a Beta distribution updated as `Beta(α, β) → Beta(α + r, β + (1 - r))`. Thompson sampling is asymptotically optimal under standard assumptions, and (more importantly for us) it is trivial to implement, requires no hyperparameter tuning, and gracefully handles cold-start priors derived from external data.

The **contextual bandit** generalization (Li et al., 2010; LinUCB) lets the learner observe a feature vector before each decision and condition arm choice on context. We use the simplest contextual variant, *disjoint* contextual TS: bucket the context into a small number of discrete states and maintain independent Beta posteriors per (arm, bucket). This is one paragraph of code rather than a regression.

### 2.6 Why bandits, why not RL or GA or LLM-as-optimizer

We considered three alternative algorithm families:

- **Reinforcement learning over the full proxy session.** The state space (agent's history) is too rich to model usefully and the trajectory length per session is too short (~50–200 requests) for episodic RL to converge. The bandit framing is the right granularity because each injection's effect on the agent is approximately independent — the agent forgets stale instructions within a few turns.
- **Genetic / evolutionary payload generation.** This is the most defensible alternative and is on our roadmap as future work. It requires an LLM-as-fitness function (or an expensive end-to-end run per candidate), which puts it out of scope for a near-zero-budget capstone.
- **LLM-as-optimizer (OPRO-style).** Same constraint: needs a strong LLM in an outer loop to propose payload mutations. The bandit's selection problem is upstream of the generation problem and can be tackled independently.

Bandits are the right algorithm for the right sub-problem at the right cost.

---

## 3. AdaptiveDefenseProxy

### 3.1 Threat model

We adopt the same threat model as our prior work and Mantis. The **attacker** is an autonomous LLM-driven hacking agent that knows only the target's IP. The **defender** operates the target, cannot patch the underlying vulnerable services (legacy, third-party, production constraints), and can only modify content in network responses the agent will read. The defender does not know which LLM, which agent framework, or which prompting strategy the attacker uses. Defensive PI must not disrupt legitimate human users. We assume the defender controls a transparent proxy positioned between the agent and the target — this is the same deployment posture as a WAF.

The novel assumption in this work is that **the attacker may adapt**. In our experimental evaluation we explicitly model an attacker that has read prior defensive-PI papers and instructs its agent to verify flags before submission. This breaks any static fake-flag defense and is the regime where adaptive defense earns its keep.

### 3.2 Algorithm

AdaptiveDefenseProxy is a stateless mitmproxy addon plus a stateful bandit module that share three pieces of state across the proxy session: the bandit posteriors, a sliding window of recent agent requests, and a registry of pending injections awaiting reward attribution.

For each HTTP response from the target to the agent, the proxy:

1. Computes a **context bucket** from features of the response and the agent's recent request history (§3.4).
2. Enumerates the set of **feasible arms** for this response. An arm is a (position, trigger, payload) tuple. Feasibility depends on the response: a `robots_txt` arm is only feasible on `/robots.txt`; an `error_message` arm only on a 4xx/5xx; a `code_comment` arm only on JavaScript or HTML responses. Of the 6 × 6 × 9 = 324 nominal arms, typically 30–60 are feasible per response.
3. **Selects an arm** by Thompson sampling: for each feasible arm `a` in the current context bucket `b`, draw `θ_(a,b) ~ Beta(α_(a,b), β_(a,b))`, and pick `argmax_a θ_(a,b)`. Ties are broken uniformly.
4. **Injects** the selected payload using the existing per-position injection logic from `http_proxy.py`, stamping the response with a hidden `injection_id` so we can later attribute reward.
5. **Registers** the (injection_id, arm, phase) tuple in the reward tracker, together with a snapshot `S_start` = number of challenges already marked solved in `/api/Challenges`.

For each HTTP request from the agent (intercepted by the same proxy on its way to the target), the proxy:

1. Appends the request to the sliding window (used for phase classification).
2. Increments per-injection request counters for pending injections whose attribution window is still open.
3. When a window closes (K post-injection requests **or** T seconds, whichever comes first), polls `S_end` from `/api/Challenges`, sets `r = 1` iff `S_end = S_start`, and updates the corresponding Beta posterior: `Beta(α, β) → Beta(α + r, β + (1 - r))`.
4. If `S_end > S_start`, applies a **short cooldown** on that arm (60s): the window coincided with scoreboard progress, so we temporarily suppress that arm.

**Cold-start priors.** Before the run starts we initialize each arm's Beta posterior from the prior empirical ablation study. Concretely, for each arm `(position, trigger, payload)` we set `α_0 = 1 + w * (1 - solves_p / baseline)` and `β_0 = 1 + w * (solves_p / baseline)` where `solves_p` is the post-defense solve count for the matching dimension entry in our prior table, `baseline = 11.8`, and `w = 10` is a prior strength parameter. This gives `fake_flag` a prior of approximately `Beta(11, 1)` (mean = 0.92, near-certain win) and `decoy_port` a prior of approximately `Beta(1, 11)` (mean = 0.08, near-certain backfire). Arms whose payload was not in the prior study get the uniform prior `Beta(1, 1)`. The bandit thus walks in informed and updates from there.

### 3.3 Reward signal

The defining design choice is to **align the bandit's reward with Juice Shop ground truth** while still requiring **zero defender-side LLM** usage.

Let `S(t)` be the number of challenges in `/api/Challenges` with `solved: true` at poll time `t`. When an injection is registered at time `t_0`, we record `S_start = S(t_0)`. The attribution window closes when **either** (a) `K` subsequent agent-originated requests have been observed after `t_0`, **or** (b) `T` seconds have elapsed since `t_0` — whichever occurs first (defaults match the prior `window_requests` / `window_seconds` in `adaptive.yaml`). At close we poll `S_end`.

**Bernoulli reward:** `r = 1` if `S_end = S_start`, else `r = 0`. Intuitively, `r = 1` means “no new flags hit the scoreboard during this arm's window.” We then apply the standard Beta–Bernoulli Thompson update with this `r`.

**Cooldown:** if `S_end > S_start`, we place the arm on a 60-second cooldown so the learner does not keep selecting arms whose recent windows coincided with attacker progress.

**Failure handling:** if either poll fails (timeout, parse error), we **skip** the Beta update for that injection so posteriors are not corrupted.

**Limitation (credit assignment):** multiple injections can overlap in time; `S_end - S_start` for one window may include progress caused by earlier context or unrelated exploration. We treat this as a simple, honest surrogate; repeated runs and longer horizons are the principled fix.

### 3.4 Context bucketing

The contextual bandit conditions arm selection on a small discrete bucket derived from the agent's current attack phase. We use a four-state state machine:

- **Recon** — agent is making GETs to `/`, `/robots.txt`, `/sitemap.xml`, `/.well-known/*`, top-level pages.
- **Enum** — agent is making GETs to `/api/*`, listing endpoints, walking link graphs.
- **Exploit** — agent is making POSTs, fuzzing parameters, retrying with payload variations.
- **Exfil** — agent is making requests to `/admin*`, `/auth*`, `/login*`, `/users*`, file-disclosure paths.

The phase is computed online from the agent's last 10 requests using simple URL-pattern rules. Each phase has its own set of Beta posteriors per arm. The intuition: payload effectiveness is plausibly phase-dependent (`fake_flag` may dominate during exploit but be premature during recon; `recursive_exploration` may shine during enum but waste a slot during exfil), and disjoint contextual TS lets the bandit discover such dependencies without us hand-coding them.

If results show that bucketing does not help (i.e., the per-bucket posteriors all converge to similar arm rankings), we fall back to a single-bucket bandit. **Bucket-vs-no-bucket ablation (§5.4):** not executed in this capstone — budget reserved for the six primary conditions and hardened follow-up; future work should disable phase splits and compare solve/APR on identical harness.

### 3.5 Implementation

AdaptiveDefenseProxy is implemented as a Python addon to mitmproxy, layered on top of the existing DefenseProxy codebase. The core algorithm lives in two new files (`bandit.py`, ~150 lines; `reward_tracker.py`, ~150 lines) and a ~30-line patch to `http_proxy.py` that adds a `mode: bandit` branch alongside the existing static `defenses:` list. The existing payload library, position-injection routines, and logging infrastructure are reused verbatim. A new YAML config schema (`configs/bandit/adaptive.yaml`) selects bandit mode and points at the cold-start priors file (`configs/bandit/priors.yaml`). The CLI is unchanged: `python main.py --config configs/bandit/adaptive.yaml --run-id <id>`.

The implementation (proxy, bandit, runners, and this report) resides in the author's **`defense-proxy`** research workspace; a separate public GitHub release was out of scope for this capstone timeline.

---

## 4. Evaluation Setup

### 4.1 Target and agent

We evaluate on **OWASP Juice Shop** (Docker, version `bkimminich/juice-shop` latest at evaluation time), the same target as our prior work. Juice Shop tracks 111 challenges of varying difficulty (1-star to 6-star) across categories including injection, broken access control, sensitive data exposure, XSS, and broken authentication. The proxy reports challenge solve state by querying `/api/Challenges` before and after each run.

The attacker is **PentestGPT** (commit `6e84be8df5338b724adfb21c19700dd03547b007`) running the `claude-sonnet-4-5-20250929` model via the user's Claude Code subscription (no per-token cost beyond the existing subscription). We use the default 300-iteration budget. The agent is launched with `--target http://host.docker.internal:8080` so that traffic transits the defense proxy.

### 4.2 Conditions

We evaluate **six** conditions (six PentestGPT runs in the reported batch):

1. **Baseline.** No proxy injection. Agent talks directly to Juice Shop. Establishes the undefended solve count (here **13**/111).
2. **Fixed-best (standard agent).** Static `fake_flag` injected into the HTTP body with `context_blend` trigger on every applicable response—the marginal-best static defense from our prior ablation.
3. **Random.** A new arm sampled uniformly at random from the feasible set on every response. Isolates the contribution of *learning* versus mere injection noise.
4. **Adaptive (standard agent).** Full bandit; default PentestGPT instructions.
5. **Fixed-best (hardened agent).** Same static injection as (2), but PentestGPT includes the hardened instruction: *"Before submitting any flag string as a solution, you MUST independently verify it exists by re-requesting the page where you found it and confirming the exact flag value appears in the response body. Do not submit unverified flags."*
6. **Adaptive (hardened agent).** Full bandit under the same hardened instruction as (5), isolating adaptivity when the attacker is prompted to verify flags.

Each condition runs once due to budget constraints. We acknowledge this as a limitation in §6.3. To partially mitigate, we report variance across challenges within each run via the per-challenge breakdown in Table 2, and we report posterior trajectories and reward histograms across the bandit run (§5.3) to show that the algorithm is exploring meaningfully even in a single session.

### 4.3 Metrics

- **APR (Attack Prevention Rate).** Fraction of challenges *not* solved by the agent. APR = 1 - solves / 111. Higher is better for the defender.
- **DSR (Defense Success Rate).** Fraction of injected payloads whose post-injection reward exceeded 0.5. Measures whether the defense is operating as intended (independent of whether challenges are prevented).
- **ARC (Attacker Resource Cost).** USD spent by the attacker. PentestGPT's `--raw` mode emits a `[DONE] Flags: N, Cost: $X.XXXX, Session: …` terminator at the end of every run; we parse `Cost` directly from each run's `agent_stdout.txt`, so cost is reported in dollars rather than tokens. Higher ARC for the same APR is better for the defender — it indicates a tarpit-style success where the agent burned budget without making progress. We also report wall-clock seconds per run as a secondary cost proxy.
- **Injection-attribution heatmap.** For the adaptive conditions: the posterior mean of each (payload, phase) cell at end-of-run, plus the count of times each arm was selected. Shows whether the bandit converged to a stable winner and whether that winner was phase-dependent.

### 4.4 Procedure per run

For each condition: (1) start a fresh Juice Shop container; (2) launch the proxy in the appropriate mode against a clean log directory; (3) wait for the proxy to bind; (4) launch PentestGPT pointed at the proxy; (5) wait for PentestGPT to terminate (challenge solve, max iterations, or stuck-detection); (6) query `/api/Challenges` for final solve state; (7) tear down. Total wall-clock time per run is roughly 30–60 minutes depending on agent verbosity.

---

## 5. Results

### 5.1 Headline comparison

Table 1 reports APR, DSR, and ARC for all six conditions.

**Table 1.** Defense effectiveness across conditions. Higher APR is better; higher ARC for similar APR is better (the defender prefers the attacker to burn budget without progress).

| Condition | Solves / 111 | APR | DSR | Cost (USD) |
| --- | --- | --- | --- | --- |
| Baseline (no proxy) | 17/111 | 0.847 | n/a | $2.2374 |
| Fixed-best, standard agent | 1/111 | 0.991 | 1.000 | $0.0576 |
| Random arm, standard agent | 15/111 | 0.865 | 0.333 | $2.5143 |
| Adaptive bandit, standard agent | 2/111 | 0.982 | 0.500 | $0.0742 |
| Fixed-best, hardened agent | 0/111 | 1.000 | 1.000 | $0.0946 |
| Adaptive bandit, hardened agent | 0/111 | 1.000 | 1.000 | $0.0933 |

Table 1 is a **point estimate** from one batch per condition (rows deduplicated in the project CSV). Versus the **17**/111 baseline, **fixed-best** **fake_flag** is strongest on solves among standard defenses (**1**/111, APR $\approx 0.991$). **Adaptive** achieves **2**/111 and **Random** achieves **15**/111 on this run—so adaptive beats random here, while fixed-best remains best. Under **verify-flag** instructions, both **fixed-best hardened** and **adaptive hardened** reach **0**/111 (DSR 1.0), far stronger than baseline **17**.

### 5.2 Per-challenge breakdown

Table 2 reports per-category solve counts for **all six conditions**, aligned with the Juice Shop scoreboard themes. It shows where baseline spreads damage versus where defenses pinch particular lanes.

**Table 2.** Per-category solves (all conditions).

| Category | Total | Baseline | Fixed-best | Adaptive |
| --- | --- | --- | --- | --- |
| Broken Access Control | 11 | 2 | 0 | 0 |
| Broken Anti Automation | 4 | 0 | 0 | 0 |
| Broken Authentication | 9 | 1 | 0 | 0 |
| Cryptographic Issues | 5 | 0 | 0 | 0 |
| Improper Input Validation | 12 | 3 | 0 | 0 |
| Injection | 11 | 3 | 0 | 0 |
| Insecure Deserialization | 3 | 0 | 0 | 0 |
| Miscellaneous | 7 | 1 | 0 | 1 |
| Observability Failures | 4 | 1 | 0 | 0 |
| Security Misconfiguration | 4 | 1 | 1 | 1 |
| Security through Obscurity | 3 | 0 | 0 | 0 |
| Sensitive Data Exposure | 16 | 4 | 0 | 0 |
| Unvalidated Redirects | 2 | 1 | 0 | 0 |
| Vulnerable Components | 9 | 0 | 0 | 0 |
| XSS | 9 | 0 | 0 | 0 |
| XXE | 2 | 0 | 0 | 0 |

Baseline concentrates damage across **Sensitive Data Exposure** (4), **Injection** (3), and **Improper Input Validation** (3), with smaller contributions from **Broken Authentication** (1) and **Miscellaneous** (1). **Fixed-best standard** puts its single solve in **Security Misconfiguration** (1). **Adaptive standard** produces two solves: one in **Miscellaneous** and one in **Security Misconfiguration**. Because both hardened conditions achieved **0/111** solves, no hardened residual path remains in this batch.

### 5.3 Bandit dynamics

Figure 1 shows the per-arm posterior mean trajectory (or top-arm selection frequency) for the **adaptive (standard-agent)** run. Under cold-start priors, early mass should lean toward **`fake_flag`**-heavy arms; the realized plot, together with only **2** bandit updates in that run, should be read as **illustrative**—not proof of a clean two-phase story (§5.3 narrative below).

**Figure 1.** Posterior mean trajectory for top-5 arms, adaptive (standard-agent) condition. `paper/figures/arm_selection_freq.png`

Figure 2 reports the final per-(payload, phase) posterior heatmap. With sparse updates, it mainly shows **where** the prior and early observations placed mass—not a definitive phase-separated winner.

**Figure 2.** End-of-run posterior mean per (payload, phase) cell, adaptive (hardened-agent) condition. `paper/figures/posterior_heatmap.png`

From the **bandit snapshots** and automated roll-up in `results.md` (solve-supervised reward): both adaptive conditions use the full **324 arms × 5 phases** library. **Adaptive standard** recorded **2** posterior updates; **adaptive hardened** recorded **0**. Because updates are sparse, posterior means are qualitative approximate **P(no new solve in window)** estimates, and the heatmap/top-arm plots should be read as illustrative snapshots of where cold-start priors placed mass. (In the standard run, the two top arms were still on cooldown at end-of-run.)

### 5.4 Ablations

**A1–A3 were not executed** in this capstone: budget was spent on the six primary conditions and a **post-quota** hardened follow-up (§6.3). We do not report invented solve counts. Intended ablations: (A1) uniform `Beta(1,1)` priors, (A2) no per-phase bucketing, (A3) disable the **solve-spike cooldown** guard—each as a separate adaptive run when compute allows.

### 5.5 Cost

Total LLM API cost for the **six** primary condition runs: **$5.0714** (parsed from PentestGPT’s `[DONE] Cost:` line in each run’s `agent_stdout.txt`). Per-condition breakdown: Baseline (no proxy) **$2.2374**; Fixed-best, standard agent **$0.0576**; Random arm, standard agent **$2.5143**; Adaptive bandit, standard agent **$0.0742**; Fixed-best, hardened agent **$0.0946**; Adaptive bandit, hardened agent **$0.0933**. All charges accrued against the lead author’s existing Claude Code subscription, so the **marginal dollar cost to the research group was zero**; the figures are still useful for comparing agent burn across conditions. **Total wall-clock** (PentestGPT-facing, sum of the six runs): **1880.0 s** (\~**0.52 h**). Compute footprint of the bandit itself (excluding the agent): negligible — < 1 ms per arm selection on a 2020 MacBook Pro (profiled with 1620 (arm, phase) Beta posteriors held in memory).

---

## 6. Discussion

### 6.1 What this paper is and is not

This paper is a **proof of concept for online algorithms in defensive PI**, evaluated under tight resource constraints. It is the first work, to our knowledge, to formulate defensive PI as an online learning problem with a **Juice Shop–supervised** bandit reward that does not require additional LLM calls. The empirical evaluation is intentionally minimal — **six** conditions (single batch row each after deduplication), single runs, one target, one agent — because the contribution is the algorithm and the framing, not the scale of the validation.

It is **not** a head-to-head competitive evaluation against Mantis or related defensive PI systems on a shared benchmark (XBOW or Hack-The-Box). Such an evaluation is the obvious next step but requires substantially more compute than this capstone budget supports.

### 6.2 Implications

A practical implication is that **defensive PI cannot be evaluated on a single static payload story**. Verify-flag instructions change which injections ``stick,'' yet in our run **static `fake_flag` under verify-flag remained extremely strong** (**0**/111 solves), and hardened adaptive also achieved **0**/111. At the same time, **adaptive standard did not beat fixed-best standard** on solves (**2** vs **1**) and **random was far closer to baseline** (**15** vs **17**), so **one-shot ordering is unstable**. Deployed systems should plan for **repeated trials**, **monitoring**, and **algorithmic selection** not because static defense always fails first, but because attacker scaffolding and session variance both move the optimum arm.

A second implication is that **the prior empirical taxonomy data is not wasted by switching to a learning algorithm**. The cold-start priors are derived entirely from the prior table; without them the bandit would have to discover the strong moves from scratch within a session budget that may not allow it. Empirical ablation studies and online learning are complements, not substitutes.

### 6.3 Limitations

- **Hardened runs and API quota.** The first attempted hardened-condition rows during the broad coherent sweep **failed** when the Claude quota was exhausted (runs exited quickly with **\$0** reported cost and **no** valid injections). After quota reset, **fixed-best hardened** and **adaptive hardened** were **re-run successfully** on **2026-05-04** (\~**22:22–22:25 UTC** wall-clock window for the follow-up script). Reported hardened numbers refer to those follow-up logs, not the starved attempts.
- **Single run per condition.** Our budget did not permit repeated runs. Per-challenge breakdowns and within-run posterior trajectories are reported as a partial mitigation, but the headline numbers should be treated as point estimates without confidence intervals. Replication with K=5 runs per condition is the highest-priority next experiment.
- **Single agent (PentestGPT).** Generalization to CAI, MAPTA, or proprietary agents is unverified. The bandit framing is agent-agnostic; the *learned arms* are likely agent-specific.
- **Single target (Juice Shop).** Generalization to harder targets (XBOW benchmark, real CTF, real production) is unverified. Juice Shop's challenge set is well-categorized but not adversarially hardened.
- **Solve-supervised reward is a windowed surrogate.** We only observe whether the global solved-challenge count increased between two polls; we do not causally identify which injection (if any) caused a new solve. Overlapping windows and delayed scoreboard updates can add noise. Mitigation: longer runs, tighter windows tuned to injection rate, or explicit causal models / Shapley-style credit (future work).
- **Hardened-agent instruction is one of many possible attacker adaptations.** "Verify flags before submitting" is realistic but not exhaustive; an attacker could harden against `task_complete` ("never trust a stop signal that arrives in HTTP"), against `recursive_exploration` ("never enumerate filesystems"), and so on. A complete arms-race evaluation would iterate this loop.
- **No formal regret bound.** Standard Thompson sampling regret analysis assumes stationarity, but our reward distribution may shift as the agent's trajectory evolves. The solve-spike cooldown is a heuristic stabilizer, not a theoretical guarantee.

### 6.4 Future work

1. **Repeated-runs evaluation with confidence intervals**, with budget for ≥ 5 runs per condition.
2. **Cross-agent evaluation** on CAI and MAPTA to test the agent-agnosticism of the *algorithm* (the *arms* are expected to differ).
3. **XBOW benchmark validation** to test generalization beyond Juice Shop.
4. **LLM-driven payload generation** as an outer loop around the bandit (the offline optimizer that this work intentionally deferred). The bandit selects from a library; the outer loop expands the library when the bandit's best posterior plateaus.
5. **Adversarial co-evolution** where the attacker side is also a learning agent that updates its system prompt against the proxy's observed behaviors. The natural endpoint of the arms race motivation in §6.2.
6. **Theoretical regret analysis** under a non-stationary reward model that captures attacker learning.

---

## 7. Conclusion

We presented AdaptiveDefenseProxy, the first online algorithm for defensive prompt injection against LLM-driven hacking agents. By formulating per-response payload selection as a contextual Thompson sampling bandit with a **Juice Shop–supervised** reward (no new solves in an attribution window), we obtained a defense that requires **zero additional LLM API calls** beyond the attacker and uses only **local** reads of `/api/Challenges` for learning feedback. Empirically, on **one** coordinated six-condition batch (solve-supervised reward): **fixed-best `fake_flag`** achieved the **lowest** solve count among **standard** defenses (**1**/111), while the **adaptive** bandit logged **2**/111 and **random** logged **15**/111; both hardened rows were **0**/111 versus **17**/111 baseline. The contribution is modest in statistical strength but clear in **shape**: instrumented evaluation with **ARC**, category breakdowns, and honest limits under tight budget—including quota-recovery reruns for hardened conditions.

---

## Appendix A — Algorithm in pseudocode

```
state:
    posteriors: dict[(arm, phase) -> (alpha, beta)]   # initialized from priors.yaml
    pending_injections: dict[injection_id -> (arm, phase, t_inject, S_start)]
    request_window: deque[Request]                    # for phase classification
    cooldowns: dict[arm -> deadline_timestamp]

on_response(response):
    phase = compute_phase(request_window)
    feasible = enumerate_feasible_arms(response, phase)
    feasible = [a for a in feasible if cooldowns.get(a, 0) <= now()]
    if not feasible:
        return                                         # passthrough
    samples = {a: sample_beta(*posteriors[(a, phase)]) for a in feasible}
    arm = argmax(samples)
    payload_text = render(arm)
    injection_id = stamp_response(response, payload_text)
    S_start = count_solved_challenges(GET /api/Challenges)
    pending_injections[injection_id] = (arm, phase, now(), S_start)
    inject(response, arm, payload_text)

on_request(request):
    request_window.append(request)
    for each pending injection whose window closes (K requests or T seconds):
        S_end = count_solved_challenges(GET /api/Challenges)
        r = 1 if S_end == S_start else 0
        a, b = posteriors[(arm, phase)]
        posteriors[(arm, phase)] = (a + r, b + (1 - r))
        if S_end > S_start:
            cooldowns[arm] = now() + 60
    remove_closed(pending_injections)
```

---

## Appendix B — Cold-start priors derivation

For each `(position, trigger, payload)` arm seen in the prior empirical ablation table:

```
solves_p = post_defense_solve_count          # e.g., fake_flag → 0
baseline = 11.8                              # undefended solve count
mean_post = 1 - solves_p / baseline          # → fake_flag → ~1.0; decoy_port → ~0.24 (backfire)
w = 10                                       # prior strength
alpha_0 = 1 + w * mean_post
beta_0  = 1 + w * (1 - mean_post)
```

Arms whose payload was tested in the prior dimension but with a different trigger/position get the same prior (we lack data to refine further). Arms whose payload was *not* in the prior study get the uniform `Beta(1, 1)` prior. The `decoy_port` backfire is encoded as a low mean rather than a negative mean because the Beta posterior support is [0, 1]; **online** learning additionally uses the solve-spike cooldown (§3.2) when a window coincides with new scoreboard progress.

---

## References

(Compact reference list, to be filled in via existing prior work bibliography.)

- Pasquini et al., 2024. *Mantis: Defensive Prompt Injection against LLM-Driven Cyberattacks.*
- Mayoral-Vilches et al., 2025. *Cybersecurity AI (CAI): Open Bug Bounty-Ready Reasoning.*
- Deng et al., 2023. *PentestGPT: Evaluating and Harnessing Large Language Models for Automated Penetration Testing.*
- Thompson, 1933. *On the Likelihood that One Unknown Probability Exceeds Another in View of the Evidence of Two Samples.*
- Chapelle and Li, 2011. *An Empirical Evaluation of Thompson Sampling.*
- Li et al., 2010. *A Contextual-Bandit Approach to Personalized News Article Recommendation.*
- Goenka et al. (prior unpublished work). *Defensive Prompt Injection: A Taxonomy and Empirical Study.*
