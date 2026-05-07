"""Contextual Thompson sampling bandit for adaptive defensive PI selection.

Each "arm" is a (position, trigger, payload) tuple. We maintain a Beta(alpha,
beta) posterior per (arm, context_bucket) and pick, at each response,
argmax over feasible arms of theta_a ~ Beta(alpha_a, beta_a).

Cold-start priors are loaded from a YAML file derived from the prior
empirical ablation study (see priors.yaml). Solve-spike cooldowns after
reward attribution are enforced in ``reward_tracker.py`` — this module is
the pure decision core; reward computation is upstream.

Public surface:
    DefenseBandit.from_yaml(path) -> DefenseBandit
    DefenseBandit.select(context_bucket, feasible_arms) -> Arm | None
    DefenseBandit.update(arm, context_bucket, reward) -> None
    DefenseBandit.cooldown(arm, until_ts) -> None
    DefenseBandit.snapshot() -> dict
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from payloads import PAYLOADS, Position, TRIGGERS


# ---- arm representation ----------------------------------------------------

@dataclass(frozen=True)
class Arm:
    """A defensive-PI selection: where to inject, with what framing, and what content."""
    position: str
    trigger: str
    payload: str

    def key(self) -> str:
        return f"{self.position}|{self.trigger}|{self.payload}"

    @classmethod
    def from_key(cls, key: str) -> "Arm":
        position, trigger, payload = key.split("|")
        return cls(position=position, trigger=trigger, payload=payload)


# Phase buckets for the contextual bandit. The proxy classifies each
# response/request stream into one of these states (see _PhaseClassifier
# in reward_tracker.py); we keep a separate Beta posterior per (arm, phase).
PHASES: tuple[str, ...] = ("recon", "enum", "exploit", "exfil", "unknown")


# ---- per-arm posterior -----------------------------------------------------

@dataclass
class BetaPosterior:
    """Beta(alpha, beta) with online updates and backfire-cooldown bookkeeping."""
    alpha: float = 1.0
    beta: float = 1.0
    n_updates: int = 0
    last_reward: float = 0.0
    cooldown_until: float = 0.0  # epoch seconds; 0 means not on cooldown

    def sample(self, rng: random.Random) -> float:
        return rng.betavariate(self.alpha, self.beta)

    def mean(self) -> float:
        s = self.alpha + self.beta
        return self.alpha / s if s > 0 else 0.0

    def update(self, reward: float) -> None:
        r = max(0.0, min(1.0, reward))
        self.alpha += r
        self.beta += 1.0 - r
        self.n_updates += 1
        self.last_reward = r

    def is_on_cooldown(self, now: float | None = None) -> bool:
        return (now or time.time()) < self.cooldown_until


# ---- the bandit -----------------------------------------------------------

@dataclass
class DefenseBandit:
    """Disjoint contextual Thompson sampling over defensive-PI arms."""

    posteriors: dict[tuple[str, str], BetaPosterior] = field(default_factory=dict)
    seed: int | None = None
    rng: random.Random = field(default_factory=random.Random)
    prior_strength: float = 10.0
    baseline_solves: float = 11.8

    def __post_init__(self) -> None:
        if self.seed is not None:
            self.rng = random.Random(self.seed)

    # ---- factory --------------------------------------------------------

    @classmethod
    def from_yaml(cls, priors_path: str | Path,
                  seed: int | None = None) -> "DefenseBandit":
        """Build a bandit and seed Beta posteriors from a priors YAML file.

        The YAML schema is intentionally small — see configs/bandit/priors.yaml:

            prior_strength: 10
            baseline_solves: 11.8
            payload_solves:
                fake_flag: 0
                decoy_port: 9
                ...
            position_solves:
                http_body: 0
                error_message: 7
                ...
            trigger_solves:
                context_blend: 0
                override: 12
                ...

        For each arm (position, trigger, payload), we derive a "mean post-defense
        reward" from the lowest-known-effective component (using the *minimum*
        of the three is a defensible aggregation: the dimension that hurt the
        defense the most caps how confident we should be the arm wins). Arms
        without any prior data get the uniform Beta(1, 1).
        """
        with open(priors_path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}

        bandit = cls(
            seed=seed,
            prior_strength=float(cfg.get("prior_strength", 10.0)),
            baseline_solves=float(cfg.get("baseline_solves", 11.8)),
        )

        payload_solves: dict[str, float] = cfg.get("payload_solves", {}) or {}
        position_solves: dict[str, float] = cfg.get("position_solves", {}) or {}
        trigger_solves: dict[str, float] = cfg.get("trigger_solves", {}) or {}

        baseline = bandit.baseline_solves
        w = bandit.prior_strength

        for arm in bandit.enumerate_all_arms():
            # Per-dimension "post-defense success rate" estimate, in [0, 1].
            # Missing data falls back to baseline (i.e., zero confidence the arm
            # works above chance), which leaves the dimension neutral.
            def mean_for(d: dict[str, float], k: str) -> float:
                if k not in d:
                    return 0.0  # neutral: no evidence
                return max(0.0, min(1.0, 1.0 - float(d[k]) / baseline))

            ms = [
                mean_for(position_solves, arm.position),
                mean_for(trigger_solves, arm.trigger),
                mean_for(payload_solves, arm.payload),
            ]
            # Conservative aggregation: prior mean = minimum of available
            # per-dimension means (the worst dimension caps the arm's expected
            # reward). If all dims are unknown, ms == [0, 0, 0] and we get
            # mean = 0, which is then dampened by the uniform fallback below.
            knowns = [m for m, k, d in zip(ms,
                                           [arm.position, arm.trigger, arm.payload],
                                           [position_solves, trigger_solves,
                                            payload_solves]) if k in d]
            if knowns:
                mean_post = min(knowns)
                alpha0 = 1.0 + w * mean_post
                beta0 = 1.0 + w * (1.0 - mean_post)
            else:
                alpha0, beta0 = 1.0, 1.0  # uniform

            for phase in PHASES:
                bandit.posteriors[(arm.key(), phase)] = BetaPosterior(
                    alpha=alpha0, beta=beta0
                )

        return bandit

    # ---- arm enumeration ------------------------------------------------

    @staticmethod
    def enumerate_all_arms() -> list[Arm]:
        """All (position, trigger, payload) tuples for HTTP-mode positions.

        We only enumerate the positions the HTTP proxy actually implements
        today (see _HTTP_POSITIONS in http_proxy.py); banner/file/dns
        positions live elsewhere and are handled by separate code paths.
        """
        http_positions = [
            Position.HTTP_HEADER.value,
            Position.HTTP_BODY.value,
            Position.ERROR_MESSAGE.value,
            Position.CODE_COMMENT.value,
            Position.ROBOTS_TXT.value,
            Position.COOKIE.value,
        ]
        arms: list[Arm] = []
        for pos in http_positions:
            for trig in TRIGGERS.keys():
                for pld in PAYLOADS.keys():
                    arms.append(Arm(position=pos, trigger=trig, payload=pld))
        return arms

    # ---- decision core --------------------------------------------------

    def select(
        self,
        context_bucket: str,
        feasible_arms: Iterable[Arm],
        now: float | None = None,
    ) -> Arm | None:
        """Sample a θ_a per feasible arm and return argmax. None if nothing feasible."""
        bucket = context_bucket if context_bucket in PHASES else "unknown"
        ts = now if now is not None else time.time()

        scored: list[tuple[float, Arm]] = []
        for arm in feasible_arms:
            post = self._posterior(arm, bucket)
            if post.is_on_cooldown(ts):
                continue
            theta = post.sample(self.rng)
            scored.append((theta, arm))
        if not scored:
            return None
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[0][1]

    def update(self, arm: Arm, context_bucket: str, reward: float) -> None:
        bucket = context_bucket if context_bucket in PHASES else "unknown"
        self._posterior(arm, bucket).update(reward)

    def cooldown(self, arm: Arm, until_ts: float,
                 context_bucket: str | None = None) -> None:
        """Place an arm on cooldown across all phases (or just one if specified)."""
        if context_bucket is not None:
            self._posterior(arm, context_bucket).cooldown_until = until_ts
            return
        for phase in PHASES:
            self._posterior(arm, phase).cooldown_until = until_ts

    # ---- introspection / persistence -----------------------------------

    def _posterior(self, arm: Arm, bucket: str) -> BetaPosterior:
        key = (arm.key(), bucket)
        if key not in self.posteriors:
            self.posteriors[key] = BetaPosterior()
        return self.posteriors[key]

    def snapshot(self) -> dict[str, Any]:
        """Serialisable snapshot of all posteriors. Useful for logging/plots."""
        out: dict[str, Any] = {"posteriors": []}
        for (arm_key, bucket), p in sorted(self.posteriors.items()):
            out["posteriors"].append({
                "arm": arm_key,
                "phase": bucket,
                "alpha": p.alpha,
                "beta": p.beta,
                "mean": p.mean(),
                "n_updates": p.n_updates,
                "last_reward": p.last_reward,
                "on_cooldown": p.is_on_cooldown(),
            })
        return out

    def write_snapshot(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.snapshot(), fh, indent=2)


# ---- random-baseline bandit (control condition) ---------------------------

class RandomBandit(DefenseBandit):
    """Uniform-random arm selection. Does not learn. Used as a control."""

    def select(self, context_bucket: str, feasible_arms: Iterable[Arm],
               now: float | None = None) -> Arm | None:
        arms = list(feasible_arms)
        if not arms:
            return None
        return self.rng.choice(arms)

    def update(self, arm: Arm, context_bucket: str, reward: float) -> None:
        pass


# ---- self-test ------------------------------------------------------------

def _selftest() -> None:
    """Unit smoke test on synthetic rewards. Run as: python bandit.py."""
    here = Path(__file__).resolve().parent
    priors_path = here / "configs" / "bandit" / "priors.yaml"
    if not priors_path.exists():
        print(f"[selftest] priors not found at {priors_path}; using uniform Beta(1,1)")
        bandit = DefenseBandit(seed=0)
        for arm in DefenseBandit.enumerate_all_arms():
            for phase in PHASES:
                bandit.posteriors[(arm.key(), phase)] = BetaPosterior()
    else:
        bandit = DefenseBandit.from_yaml(priors_path, seed=0)

    feasible = DefenseBandit.enumerate_all_arms()
    # Fix one arm as the "true winner". Reward it whenever the bandit picks it;
    # punish everything else. After 200 trials we should mostly select the winner.
    winner = Arm(position="http_body", trigger="context_blend", payload="fake_flag")
    counts: dict[str, int] = {}
    for _ in range(200):
        arm = bandit.select("exploit", feasible)
        assert arm is not None
        counts[arm.key()] = counts.get(arm.key(), 0) + 1
        r = 1.0 if arm == winner else 0.0
        bandit.update(arm, "exploit", r)

    top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]
    print("[selftest] top-5 selected arms after 200 trials:")
    for k, n in top:
        print(f"  {n:3d}  {k}")
    assert counts.get(winner.key(), 0) > 50, \
        f"winner under-selected: {counts.get(winner.key(), 0)}/200"
    print(f"[selftest] OK — winner selected {counts[winner.key()]}/200 times")

    # Cooldown smoke test: cool the winner and confirm it's excluded.
    bandit.cooldown(winner, until_ts=time.time() + 60)
    excluded = bandit.select("exploit", [winner])
    assert excluded is None, "cooldown failed: winner still selectable when only feasible"
    print("[selftest] OK — cooldown excludes the only feasible arm")

    # Snapshot smoke test.
    snap = bandit.snapshot()
    assert "posteriors" in snap and len(snap["posteriors"]) > 0
    print(f"[selftest] OK — snapshot has {len(snap['posteriors'])} (arm, phase) entries")

    # Random baseline.
    rb = RandomBandit(seed=0)
    counts2: dict[str, int] = {}
    for _ in range(200):
        a = rb.select("exploit", feasible)
        assert a is not None
        counts2[a.key()] = counts2.get(a.key(), 0) + 1
    n_unique = len(counts2)
    print(f"[selftest] OK — RandomBandit hit {n_unique} unique arms across 200 trials")


if __name__ == "__main__":
    _selftest()
