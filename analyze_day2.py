"""Aggregate Day-2 per-condition runs into the artefacts the paper needs.

Reads:
    logs/<run_id>/metrics_summary.json    (from metrics.py)
    logs/<run_id>/score.csv               (from benchmarking/score_juice_shop.sh)
    logs/<run_id>/bandit_snapshot.json    (from http_proxy.py, adaptive runs)
    logs/<run_id>/agent_stdout.txt        (raw pentestgpt --raw transcript)
    logs/day2_results.csv                 (single-row-per-run from run_day2.py)

Writes:
    paper/results.json                    (machine-readable; consumed by
                                           backfill_paper.py)
    paper/results.md                      (human-readable summary tables)
    paper/figures/posterior_heatmap.png   (mean per (payload, phase) cell)
    paper/figures/arm_selection_freq.png  (top-10 arms by selection count)

Usage:
    python analyze_day2.py
    python analyze_day2.py --include-only adaptive,adaptive_hardened
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
LOGS_DIR = HERE / "logs"
PAPER_DIR = HERE / "paper"
FIG_DIR = PAPER_DIR / "figures"

# Display order matches paper §4.2.
CONDITION_ORDER: list[str] = [
    "baseline",
    "fixed_best",
    "random",
    "adaptive",
    "fixed_best_hardened",
    "adaptive_hardened",
]

CONDITION_LABEL: dict[str, str] = {
    "baseline":            "Baseline (no proxy)",
    "fixed_best":          "Fixed-best, standard agent",
    "random":              "Random arm, standard agent",
    "adaptive":            "Adaptive bandit, standard agent",
    "fixed_best_hardened": "Fixed-best, hardened agent",
    "adaptive_hardened":   "Adaptive bandit, hardened agent",
}


# --------------------------------------------------------------------- #
# loaders                                                               #
# --------------------------------------------------------------------- #

def load_run(condition: str) -> dict[str, Any]:
    run_id = f"{condition}_run1"
    rd = LOGS_DIR / run_id
    out: dict[str, Any] = {
        "condition": condition,
        "run_id": run_id,
        "log_dir": str(rd),
        "exists": rd.exists(),
    }
    if not rd.exists():
        return out

    summary_path = rd / "metrics_summary.json"
    if summary_path.exists():
        out["metrics"] = json.loads(summary_path.read_text())

    snap_path = rd / "bandit_snapshot.json"
    if snap_path.exists():
        out["bandit_snapshot"] = json.loads(snap_path.read_text())

    score_path = rd / "score.csv"
    if score_path.exists():
        out["score_rows"] = list(csv.DictReader(open(score_path)))

    agent_log = rd / "agent_stdout.txt"
    if agent_log.exists():
        out["agent_log_size"] = agent_log.stat().st_size
        out["agent_log_path"] = str(agent_log)

    return out


def load_results_csv() -> dict[str, dict[str, str]]:
    path = LOGS_DIR / "day2_results.csv"
    if not path.exists():
        return {}
    rows = list(csv.DictReader(open(path)))
    # Last write wins per condition (so re-runs supersede stale rows).
    out: dict[str, dict[str, str]] = {}
    for r in rows:
        out[r["condition"]] = r
    return out


# --------------------------------------------------------------------- #
# aggregations                                                          #
# --------------------------------------------------------------------- #

def per_category_solves(score_rows: list[dict[str, str]]) -> dict[str, dict[str, int]]:
    by_cat: dict[str, dict[str, int]] = defaultdict(
        lambda: {"solved": 0, "total": 0})
    for r in score_rows:
        cat = (r.get("category") or "Other").strip()
        by_cat[cat]["total"] += 1
        if (r.get("solved_by_agent") or "").upper() == "YES":
            by_cat[cat]["solved"] += 1
    return dict(by_cat)


def headline_table(runs: dict[str, dict]) -> list[dict[str, Any]]:
    """Build the row-list that becomes Table 1 (paper §5.1)."""
    out: list[dict[str, Any]] = []
    for cond in CONDITION_ORDER:
        run = runs.get(cond, {})
        m = run.get("metrics") or {}
        apr_block = m.get("apr") or {}
        dsr_block = m.get("dsr") or {}
        arc_block = m.get("arc") or {}
        out.append({
            "condition": cond,
            "label": CONDITION_LABEL[cond],
            "solved": apr_block.get("solved_by_agent"),
            "total": apr_block.get("total_challenges"),
            "apr": apr_block.get("apr"),
            "dsr": dsr_block.get("dsr"),
            "successful_payloads": dsr_block.get("successful_payloads"),
            "total_payloads": dsr_block.get("total_payloads"),
            "cost_usd": arc_block.get("cost_usd"),
            "flags_reported": arc_block.get("flags_reported"),
            "agent_session": arc_block.get("session_id"),
            "done_line_matched": arc_block.get("done_line_matched"),
            "total_tokens": arc_block.get("total_tokens"),
            "injection_events": m.get("injection_events"),
        })
    return out


def category_table(runs: dict[str, dict],
                   conds: list[str]) -> list[dict[str, Any]]:
    """For Table 2 — per-category solves across the chosen conditions."""
    cats: dict[str, dict[str, dict[str, int]]] = {}
    for cond in conds:
        run = runs.get(cond) or {}
        rows = run.get("score_rows") or []
        cats[cond] = per_category_solves(rows)

    all_cat_names: set[str] = set()
    for d in cats.values():
        all_cat_names.update(d.keys())

    out: list[dict[str, Any]] = []
    for cat in sorted(all_cat_names):
        row: dict[str, Any] = {"category": cat}
        # total is taken from any condition that ran — they should all
        # see the same Juice Shop challenge inventory.
        total = next(
            (d[cat]["total"] for d in cats.values()
             if cat in d and d[cat]["total"]),
            0,
        )
        row["total"] = total
        for cond in conds:
            d = cats.get(cond) or {}
            row[cond] = (d[cat]["solved"]
                         if cat in d else None)
        out.append(row)
    return out


# --------------------------------------------------------------------- #
# figure rendering                                                      #
# --------------------------------------------------------------------- #

def render_posterior_heatmap(runs: dict[str, dict], out_path: Path) -> bool:
    """Posterior mean per (payload, phase) cell for the adaptive_hardened run.

    Returns True if a figure was written, False if the data was missing.
    """
    snap = (runs.get("adaptive_hardened") or {}).get("bandit_snapshot")
    if not snap:
        snap = (runs.get("adaptive") or {}).get("bandit_snapshot")
    if not snap or not snap.get("posteriors"):
        return False

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    by_pp: dict[tuple[str, str], list[float]] = defaultdict(list)
    by_pp_n: dict[tuple[str, str], int] = defaultdict(int)
    for entry in snap["posteriors"]:
        # arm key is "position|trigger|payload"
        try:
            position, trigger, payload = entry["arm"].split("|")
        except ValueError:
            continue
        phase = entry.get("phase", "unknown")
        by_pp[(payload, phase)].append(float(entry.get("mean", 0.0)))
        by_pp_n[(payload, phase)] += int(entry.get("n_updates", 0))

    payloads = sorted({p for (p, _) in by_pp})
    phases = ["recon", "enum", "exploit", "exfil", "unknown"]

    grid_mean = np.full((len(payloads), len(phases)), np.nan)
    grid_n = np.zeros_like(grid_mean)
    for i, pl in enumerate(payloads):
        for j, ph in enumerate(phases):
            vals = by_pp.get((pl, ph)) or []
            if vals:
                # average over triggers/positions to get a payload-level cell
                grid_mean[i, j] = float(np.mean(vals))
                grid_n[i, j] = by_pp_n.get((pl, ph), 0)

    fig, ax = plt.subplots(figsize=(7, 0.5 * len(payloads) + 1.5))
    im = ax.imshow(grid_mean, aspect="auto", cmap="RdYlGn",
                   vmin=0.0, vmax=1.0)
    ax.set_xticks(range(len(phases)))
    ax.set_xticklabels(phases)
    ax.set_yticks(range(len(payloads)))
    ax.set_yticklabels(payloads)
    for i in range(len(payloads)):
        for j in range(len(phases)):
            v = grid_mean[i, j]
            n = int(grid_n[i, j])
            if np.isnan(v):
                continue
            ax.text(j, i, f"{v:.2f}\n(n={n})", ha="center", va="center",
                    fontsize=8,
                    color="black" if v > 0.4 else "white")
    fig.colorbar(im, ax=ax, label="posterior mean reward")
    ax.set_title("End-of-run posterior mean per (payload, phase)\n"
                 "adaptive_hardened condition")
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return True


def render_arm_selection_freq(runs: dict[str, dict], out_path: Path) -> bool:
    # Prefer plotting adaptive_hardened, but fall back to adaptive if hardened
    # has no posterior updates (which can happen with sparse attributions).
    for cond in ("adaptive_hardened", "adaptive"):
        snap = (runs.get(cond) or {}).get("bandit_snapshot")
        if not snap or not snap.get("posteriors"):
            continue

        by_arm = [
            (p["arm"], int(p.get("n_updates", 0)), float(p.get("mean", 0.0)))
            for p in snap["posteriors"]
        ]
        by_arm.sort(key=lambda t: -t[1])
        top = [t for t in by_arm if t[1] > 0][:10]
        if not top:
            continue

        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(8, 0.4 * len(top) + 1.5))
        labels = [a for (a, _, _) in top]
        counts = [n for (_, n, _) in top]
        means = [m for (_, _, m) in top]
        ypos = list(range(len(top)))
        ax.barh(
            ypos,
            counts,
            color=[(1 - m, m, 0.3) for m in means],
        )
        ax.set_yticks(ypos)
        ax.set_yticklabels(labels, fontsize=8)
        ax.invert_yaxis()
        for y, (n, m) in enumerate(zip(counts, means)):
            ax.text(n + 0.1, y, f"  n={n}  μ={m:.2f}",
                    va="center", fontsize=8)
        ax.set_xlabel("times this arm was updated (≈ selected & rewarded)")
        ax.set_title(f"Top arms by selection count — {cond}")
        fig.tight_layout()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(out_path, dpi=150)
        plt.close(fig)
        return True

    return False


# --------------------------------------------------------------------- #
# markdown rendering                                                    #
# --------------------------------------------------------------------- #

def fmt_apr(apr: float | None) -> str:
    return f"{apr:.3f}" if isinstance(apr, (int, float)) else "—"


def fmt_dsr(d: float | None) -> str:
    return f"{d:.3f}" if isinstance(d, (int, float)) else "—"


def fmt_solves(s: int | None, t: int | None) -> str:
    if s is None or t is None:
        return "—"
    return f"{s}/{t}"


def fmt_tokens(n: int | None) -> str:
    if not n:
        return "—"
    return f"{n / 1000:.1f}"


def fmt_cost(c: float | None) -> str:
    if not isinstance(c, (int, float)):
        return "—"
    return f"${c:.4f}"


def render_markdown(headline: list[dict],
                    cat_table: list[dict],
                    cat_conds: list[str],
                    runs: dict[str, dict]) -> str:
    md: list[str] = []
    md.append("# Day 2 — Aggregated Results\n")
    md.append("Auto-generated by `analyze_day2.py`. Numbers here can be "
              "spliced into `paper/capstone.md` via `backfill_paper.py`.\n")

    # ---- Table 1 ----
    md.append("## Table 1 — Defense effectiveness across conditions\n")
    md.append("| Condition | Solves / 111 | APR | DSR | "
              "ARC (cost USD) |")
    md.append("| --- | --- | --- | --- | --- |")
    total_cost = 0.0
    for r in headline:
        c = r.get("cost_usd")
        if isinstance(c, (int, float)):
            total_cost += c
        md.append(
            f"| {r['label']} | {fmt_solves(r['solved'], r['total'])} "
            f"| {fmt_apr(r['apr'])} | {fmt_dsr(r['dsr'])} "
            f"| {fmt_cost(c)} |")
    md.append(f"| **Total** | | | | **${total_cost:.4f}** |")
    md.append("")
    md.append(f"_Cost is parsed from PentestGPT's `[DONE]` line in each run's "
              f"`agent_stdout.txt`. PentestGPT reports cost on every "
              f"`--raw` termination._\n")

    # ---- wall-clock + injection counts ----
    md.append("### Per-run wall-clock and injection volume\n")
    res_csv = load_results_csv()
    md.append("| Condition | Wall-clock (s) | Cost (USD) | Flags reported | "
              "Agent exit | Injections |")
    md.append("| --- | --- | --- | --- | --- | --- |")
    for cond in CONDITION_ORDER:
        r = res_csv.get(cond) or {}
        cost_str = (f"${float(r['cost_usd']):.4f}"
                    if r.get("cost_usd") not in (None, "", "None")
                    else "—")
        md.append(
            f"| {CONDITION_LABEL[cond]} | "
            f"{r.get('wall_seconds', '—')} | "
            f"{cost_str} | "
            f"{r.get('flags_reported', '—')} | "
            f"{r.get('agent_exit_code', '—')} | "
            f"{r.get('injection_events', '—')} |")
    md.append("")

    # ---- Table 2 ----
    md.append("## Table 2 — Per-category solves\n")
    header = ["Category", "Total"] + [CONDITION_LABEL[c] for c in cat_conds]
    md.append("| " + " | ".join(header) + " |")
    md.append("| " + " | ".join("---" for _ in header) + " |")
    for r in cat_table:
        cells = [r["category"], str(r.get("total", "—"))]
        for cond in cat_conds:
            v = r.get(cond)
            cells.append(str(v) if v is not None else "—")
        md.append("| " + " | ".join(cells) + " |")
    md.append("")

    # ---- bandit dynamics summary ----
    md.append("## §5.3 — Bandit dynamics summary\n")
    for cond in ("adaptive", "adaptive_hardened"):
        snap = (runs.get(cond) or {}).get("bandit_snapshot")
        if not snap or not snap.get("posteriors"):
            md.append(f"- **{CONDITION_LABEL[cond]}**: no snapshot found.")
            continue
        post = snap["posteriors"]
        n_arms = len({p["arm"] for p in post})
        n_phases = len({p["phase"] for p in post})
        n_updates = sum(p.get("n_updates", 0) for p in post)
        cooled = [p["arm"] for p in post if p.get("on_cooldown")]
        with_data = [p for p in post if p.get("n_updates", 0) > 0]
        with_data.sort(key=lambda p: -p.get("n_updates", 0))
        top3 = [(p["arm"], p["n_updates"], p["mean"]) for p in with_data[:3]]
        top3_str = "; ".join(
            f"{a} (n={n}, μ={m:.2f})" for (a, n, m) in top3) or "(none)"
        md.append(f"- **{CONDITION_LABEL[cond]}**: "
                  f"{n_arms} arms × {n_phases} phases, "
                  f"{n_updates} total updates, "
                  f"top by selection: {top3_str}")
        if cooled:
            md.append(f"  - Arms still on cooldown at end-of-run: "
                      f"`{', '.join(sorted(set(cooled)))}`")
    md.append("")

    md.append("## Figures\n")
    md.append("- `paper/figures/posterior_heatmap.png` — "
              "end-of-run posterior mean heatmap.")
    md.append("- `paper/figures/arm_selection_freq.png` — "
              "top arms by update count.")
    md.append("")
    return "\n".join(md)


# --------------------------------------------------------------------- #
# main                                                                  #
# --------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--include-only", default="",
                    help="comma-separated subset of condition names")
    args = ap.parse_args()

    chosen = (args.include_only.split(",")
              if args.include_only else CONDITION_ORDER)
    chosen = [c.strip() for c in chosen if c.strip()]

    runs: dict[str, dict] = {c: load_run(c) for c in CONDITION_ORDER}
    headline = headline_table(runs)

    # Per-category breakdown is most interesting on the hardened conditions.
    available_cat_conds = [c for c in CONDITION_ORDER
                           if (runs.get(c) or {}).get("score_rows")]
    cat_table = category_table(runs, available_cat_conds) if available_cat_conds else []

    # ---- write JSON sidecar for backfill_paper.py ----
    PAPER_DIR.mkdir(parents=True, exist_ok=True)
    res_csv = load_results_csv()
    total_cost = sum((r.get("cost_usd") or 0.0) for r in headline
                     if isinstance(r.get("cost_usd"), (int, float)))
    results_json = {
        "headline": headline,
        "category_table": cat_table,
        "category_conditions": available_cat_conds,
        "wall_seconds": {c: res_csv.get(c, {}).get("wall_seconds")
                         for c in CONDITION_ORDER},
        "total_cost_usd": total_cost,
    }
    json_path = PAPER_DIR / "results.json"
    json_path.write_text(json.dumps(results_json, indent=2, default=str))
    print(f"wrote {json_path}")

    md = render_markdown(headline, cat_table, available_cat_conds, runs)
    md_path = PAPER_DIR / "results.md"
    md_path.write_text(md)
    print(f"wrote {md_path}")

    FIG_DIR.mkdir(parents=True, exist_ok=True)
    if render_posterior_heatmap(runs, FIG_DIR / "posterior_heatmap.png"):
        print(f"wrote {FIG_DIR / 'posterior_heatmap.png'}")
    if render_arm_selection_freq(runs, FIG_DIR / "arm_selection_freq.png"):
        print(f"wrote {FIG_DIR / 'arm_selection_freq.png'}")

    print()
    print("Quick-look summary:")
    print(f"  {'CONDITION':<36} {'SOLVES':>10} {'APR':>7} {'DSR':>7} "
          f"{'COST':>9}")
    for r in headline:
        print(f"  {r['label']:<36} "
              f"{fmt_solves(r['solved'], r['total']):>10} "
              f"{fmt_apr(r['apr']):>7} "
              f"{fmt_dsr(r['dsr']):>7} "
              f"{fmt_cost(r.get('cost_usd')):>9}")
    print(f"  {'-'*36} {'-'*10} {'-'*7} {'-'*7} {'-'*9}")
    print(f"  {'TOTAL':<36} {'':>10} {'':>7} {'':>7} "
          f"{fmt_cost(total_cost):>9}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
