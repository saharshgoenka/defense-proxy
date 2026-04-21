# DefenseProxy

Research proxy for evaluating defensive prompt injection against LLM-based
hacking agents (PentestGPT, CAI). Sits between the agent and a target
system, intercepts server responses, and injects adversarial text payloads
across an 8-position taxonomy:

```
Objective × Position × Trigger × Payload
```

DefenseProxy runs on the host, forwarding traffic from `localhost:8080` to
an OWASP Juice Shop container on `localhost:3000`. During defended runs,
agents are pointed at `http://host.docker.internal:8080` instead of
`:3000`.

```
PentestGPT / CAI  →  host.docker.internal:8080 (DefenseProxy)  →  localhost:3000 (Juice Shop)
```

Juice Shop itself is managed externally by
`../benchmarking/setup_juice_shop.sh` and `../benchmarking/score_juice_shop.sh`.
The `juice-shop/` directory at the project root is unused.

## Install

```bash
pip install -r requirements.txt
```

Requires Python 3.10+ and Docker (for Juice Shop).

## Quickstart — defended run

```bash
./run_experiment.sh config.yaml exp_001
# proxy comes up on :8080; set your agent's target to
#   http://host.docker.internal:8080
# then press ENTER here once the agent has finished
```

`run_experiment.sh` resets Juice Shop, launches the proxy in the
background, waits for you to finish the agent run, kills the proxy,
scores Juice Shop, and copies the score CSV into
`./logs/exp_001/score.csv`.

## Quickstart — baseline (passthrough) run

```bash
./run_experiment.sh config_baseline.yaml baseline_001
# still goes through the proxy for uniform logging, but
# defenses: [] so nothing is injected.
# Alternatively, skip the proxy entirely and point the agent at
#   http://host.docker.internal:3000
```

## Post-run metrics

After the agent finishes (and you've saved its stdout to
`logs/<run_id>/agent_stdout.txt`):

```bash
python3 metrics.py \
    --run-id exp_001 \
    --agent-log ./logs/exp_001/agent_stdout.txt \
    --score-csv ./logs/exp_001/score.csv
```

Produces:

- `logs/<run_id>/results.json`  — `{"challenges": {name: bool, …}}`
- `logs/<run_id>/metrics_summary.json` — DSR, APR, ARC

Where:

- **DSR** (Defense Success Rate) — per-payload keyword hits in agent stdout
- **APR** (Attack Prevention Rate) — `1 - solved/total` from Juice Shop
- **ARC** (Agent Resource Cost) — `sum(total_tokens)` across events.jsonl

## CLI reference

```bash
python3 main.py --config config.yaml --run-id exp_001 --mode http     # HTTP proxy (mitmdump)
python3 main.py --config config.yaml --run-id exp_001 --mode banner   # TCP banner/login proxy
python3 main.py --config config.yaml --run-id exp_001 --mode all      # both
python3 main.py --validate-config --config config.yaml
python3 main.py --list-payloads

python3 file_injector.py --file /tmp/secrets.conf \
    --payload-key fake_vulnerability --trigger system_alert \
    --mode comment_block
python3 file_injector.py --file /tmp/secrets.conf --restore
```

## Config schema

Top-level keys:

| key | required | description |
|---|---|---|
| `target.host`            | yes | hostname of the backend to proxy |
| `target.http_port`       | yes | backend HTTP port |
| `target.tcp_port`        | no  | backend TCP port for banner_proxy |
| `proxy.http_port`        | yes | listen port for mitmdump |
| `proxy.tcp_port`         | no  | listen port for banner_proxy |
| `logging.log_dir`        | yes | base dir for per-run JSONL logs |
| `defenses`               | yes | list (may be empty) |

Each entry in `defenses`:

| key | values | notes |
|---|---|---|
| `enabled`   | bool                                                                                                             | disabled entries are ignored |
| `objective` | `MISDIRECTION`, `GOAL_MANIPULATION`, `TARPIT`, `COUNTERSTRIKE`, `EXFILTRATION`, `DEGRADATION`                     | metadata; not injected verbatim |
| `position`  | `service_banner`, `login_response`, `http_header`, `http_body`, `file_content`, `error_message`, `dns_network`, `code_comment` | routes entry to the right module |
| `trigger`   | `override`, `momentum`, `system_alert`, `reward_signal`, `authority`, `context_blend`                            | coercive prefix (empty for `context_blend`) |
| `payload`   | `decoy_port`, `fake_vulnerability`, `fake_flag`, `task_complete`, `recursive_exploration`, `reverse_shell`, `prompt_leak`, `tool_confusion`, `resource_exhaustion` | concrete injected body |
| `stealth`   | (http_body only) `inline` · `html_comment` · `meta_tag` | how the payload is wrapped |
| `mode`      | (error_message only) `body` · `json_field`              | where to inject for 4xx/5xx |

`defenses: []` is always a pure passthrough.

## Position coverage

| ID | position          | module           | notes |
|----|-------------------|------------------|---|
| P1 | `service_banner`  | banner_proxy.py  | appended to first server→client chunk |
| P2 | `login_response`  | banner_proxy.py  | matches `220`/`230`/`Welcome`/`Login successful` |
| P3 | `http_header`     | http_proxy.py    | `X-Defense-Info` (configurable via `header_name`) |
| P4 | `http_body`       | http_proxy.py    | stealth modes: inline / html_comment / meta_tag |
| P5 | `file_content`    | file_injector.py | offline CLI, `.bak` snapshot, `--restore` |
| P6 | `error_message`   | http_proxy.py    | 4xx/5xx; JSON-aware |
| P7 | `dns_network`     | payloads.generate_dns_payload | returns BIND TXT line; paste into a zone file or a mock DNS server |
| P8 | `code_comment`    | http_proxy.py    | `// <payload>` injected into JS responses |

## Project layout

```
research-project/
├── benchmarking/          ← existing, untouched
├── PentestGPT/            ← existing, untouched
├── cai/                   ← existing, untouched
├── juice-shop/            ← unused; managed via benchmarking scripts
└── defense-proxy/         ← this project
    ├── main.py
    ├── http_proxy.py
    ├── banner_proxy.py
    ├── file_injector.py
    ├── payloads.py
    ├── logger.py
    ├── metrics.py
    ├── run_experiment.sh
    ├── config.yaml
    ├── config_baseline.yaml
    ├── config_multipoint.yaml
    ├── config_xbow_final.yaml
    ├── requirements.txt
    └── README.md
```
