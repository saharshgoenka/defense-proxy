"""Solve-supervised online reward for AdaptiveDefenseProxy.

Each injection opens an attribution window (``window_requests`` agent requests
after the stamp, or ``window_seconds`` — whichever comes first). At registration
we snapshot ``S_start``, the count of Juice Shop challenges with ``solved``
true (``GET {target_base_url}/api/Challenges``). When the window closes we poll
``S_end``.

    reward = 1.0 if S_end == S_start else 0.0

So the bandit prefers arms that do not coincide with new solves during the
horizon. If ``Δ = S_end - S_start > 0`` (solve spike), the arm is placed on
cooldown for ``SOLVE_SPIKE_COOLDOWN_SECONDS`` (default 60).

If a solve-count poll returns ``None``, ``bandit.update`` is skipped and
``on_update`` is called with ``skipped=True``.

Optional ``solve_count_fn(base_url) -> int | None`` overrides HTTP polling for
tests. Production uses :func:`fetch_juice_shop_solved_count`.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from bandit import Arm, DefenseBandit

DEFAULT_WINDOW_REQUESTS = 5
DEFAULT_WINDOW_SECONDS = 30.0
SOLVE_SPIKE_COOLDOWN_SECONDS = 60.0


def fetch_juice_shop_solved_count(
    base_url: str,
    *,
    timeout: float = 10.0,
) -> int | None:
    """GET ``{base_url}/api/Challenges`` and count challenges with ``solved`` true."""
    url = base_url.rstrip("/") + "/api/Challenges"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        obj = json.loads(raw)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, OSError, ValueError):
        return None

    challenges = _challenges_list(obj)
    n = 0
    for c in challenges:
        if isinstance(c, dict) and c.get("solved"):
            n += 1
    return n


def _challenges_list(obj: Any) -> list[Any]:
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        data = obj.get("data")
        if isinstance(data, list):
            return data
    return []


# ---- request abstraction --------------------------------------------------


@dataclass
class RequestSummary:
    """Minimal request snapshot for phase classification."""
    timestamp: float
    method: str
    url: str
    path: str
    headers_text: str = ""
    body_text: str = ""


# ---- per-injection bookkeeping --------------------------------------------


@dataclass
class PendingInjection:
    injection_id: str
    arm: Arm
    phase: str
    t_inject: float
    s_start: int | None
    requests_seen: int = 0
    closed: bool = False

    def maybe_close(
        self,
        now: float,
        window_requests: int,
        window_seconds: float,
    ) -> bool:
        if self.closed:
            return True
        if self.requests_seen >= window_requests:
            return True
        if now - self.t_inject >= window_seconds:
            return True
        return False


# ---- phase classifier -----------------------------------------------------


class PhaseClassifier:
    """Classify the agent's current attack phase from its recent requests."""

    EXFIL_PREFIXES = ("/admin", "/auth", "/login", "/users", "/rest/user",
                      "/profile", "/me", "/api/users", "/api/admin",
                      "/secret", "/.env", "/.git")
    RECON_PATHS = ("/", "/robots.txt", "/sitemap.xml", "/favicon.ico",
                   "/.well-known")
    ENUM_PREFIXES = ("/api", "/rest", "/graphql", "/v1", "/v2")

    @classmethod
    def classify(cls, recent: Iterable[RequestSummary]) -> str:
        rs = list(recent)[-10:]
        if not rs:
            return "recon"

        for r in reversed(rs):
            if r.method.upper() == "POST":
                return "exploit"
            if any(r.path.startswith(p) for p in cls.EXFIL_PREFIXES):
                return "exfil"

        if all(r.path in cls.RECON_PATHS or r.path == "/" for r in rs):
            return "recon"

        if any(r.path.startswith(p) for p in cls.ENUM_PREFIXES for r in rs):
            return "enum"

        return "recon"


# ---- the tracker ----------------------------------------------------------


class RewardTracker:
    """Solve-supervised reward attribution for a :class:`DefenseBandit`."""

    def __init__(
        self,
        bandit: DefenseBandit,
        *,
        target_base_url: str,
        window_requests: int = DEFAULT_WINDOW_REQUESTS,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        on_update: Callable[[dict[str, Any]], None] | None = None,
        solve_count_fn: Callable[[str], int | None] | None = None,
    ) -> None:
        self.bandit = bandit
        self.target_base_url = target_base_url.rstrip("/")
        self.window_requests = window_requests
        self.window_seconds = window_seconds
        self.on_update = on_update
        self._solve_count_fn = (
            solve_count_fn if solve_count_fn is not None
            else fetch_juice_shop_solved_count
        )
        self._lock = threading.Lock()
        self._requests: deque[RequestSummary] = deque(maxlen=2048)
        self._pending: dict[str, PendingInjection] = {}

    def _solve_count(self) -> int | None:
        return self._solve_count_fn(self.target_base_url)

    def current_phase(self) -> str:
        with self._lock:
            recent = list(self._requests)[-10:]
        return PhaseClassifier.classify(recent)

    def feasible_arms(self, response_features: dict[str, Any],
                      all_arms: Iterable[Arm]) -> list[Arm]:
        """Filter arms to those compatible with this response."""
        path = (response_features.get("path") or "").split("?")[0]
        ctype = (response_features.get("content_type") or "").lower()
        status = int(response_features.get("status") or 200)

        out: list[Arm] = []
        for arm in all_arms:
            if arm.position == "robots_txt" and path != "/robots.txt":
                continue
            if arm.position == "error_message" and not (400 <= status < 600):
                continue
            if arm.position == "code_comment" and not (
                "javascript" in ctype or "ecmascript" in ctype or "html" in ctype
            ):
                continue
            if arm.position == "http_body" and ctype and not (
                ctype.startswith("text/") or "html" in ctype
                or "xml" in ctype or "json" in ctype
            ):
                continue
            out.append(arm)
        return out

    def register_injection(
        self,
        injection_id: str,
        arm: Arm,
        phase: str,
        t_inject: float | None = None,
    ) -> None:
        ts = t_inject if t_inject is not None else time.time()
        s_start = self._solve_count()
        with self._lock:
            self._pending[injection_id] = PendingInjection(
                injection_id=injection_id,
                arm=arm,
                phase=phase,
                t_inject=ts,
                s_start=s_start,
            )

    def observe_request(self, req: RequestSummary) -> None:
        """Record agent traffic and advance / close attribution windows."""
        with self._lock:
            self._requests.append(req)
            ids_to_close: list[str] = []
            for inj_id, pi in self._pending.items():
                if req.timestamp < pi.t_inject:
                    continue
                pi.requests_seen += 1
                if pi.maybe_close(req.timestamp, self.window_requests,
                                   self.window_seconds):
                    ids_to_close.append(inj_id)

            now = req.timestamp
            for inj_id, pi in self._pending.items():
                if inj_id in ids_to_close or pi.closed:
                    continue
                if now - pi.t_inject >= self.window_seconds:
                    ids_to_close.append(inj_id)

        for inj_id in ids_to_close:
            self._close_and_update(inj_id)

    def flush_expired(self, now: float | None = None) -> None:
        ts = now if now is not None else time.time()
        with self._lock:
            ids = [
                inj_id for inj_id, pi in self._pending.items()
                if (not pi.closed) and (ts - pi.t_inject >= self.window_seconds)
            ]
        for inj_id in ids:
            self._close_and_update(inj_id)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "n_requests": len(self._requests),
                "n_pending": sum(1 for p in self._pending.values()
                                 if not p.closed),
                "n_closed": sum(1 for p in self._pending.values() if p.closed),
            }

    def _close_and_update(self, injection_id: str) -> None:
        with self._lock:
            pi = self._pending.get(injection_id)
            if pi is None or pi.closed:
                return
            pi.closed = True
            arm = pi.arm
            phase = pi.phase
            inj_id = pi.injection_id
            s_start = pi.s_start

        now = time.time()
        s_end = self._solve_count()

        skipped = s_start is None or s_end is None
        if skipped:
            if self.on_update is not None:
                self.on_update({
                    "skipped": True,
                    "injection_id": inj_id,
                    "arm": arm.key(),
                    "phase": phase,
                    "s_start": s_start,
                    "s_end": s_end,
                })
            return

        delta = s_end - s_start
        reward = 1.0 if s_end == s_start else 0.0
        self.bandit.update(arm, phase, reward)
        if delta > 0:
            self.bandit.cooldown(arm, until_ts=now + SOLVE_SPIKE_COOLDOWN_SECONDS)

        if self.on_update is not None:
            self.on_update({
                "skipped": False,
                "injection_id": inj_id,
                "arm": arm.key(),
                "phase": phase,
                "s_start": s_start,
                "s_end": s_end,
                "delta": delta,
                "reward": reward,
                "solve_spike_cooldown": delta > 0,
            })


# ---- self-test ------------------------------------------------------------


def _selftest() -> None:
    """Smoke test with a fake solve-count fetcher (no live Juice Shop)."""
    from pathlib import Path

    here = Path(__file__).resolve().parent
    priors = here / "configs" / "bandit" / "priors.yaml"

    def make_seq_fetch(seq: list[int | None]) -> Callable[[str], int | None]:
        idx = [0]

        def fn(_base: str) -> int | None:
            i = idx[0]
            idx[0] += 1
            return seq[i] if i < len(seq) else seq[-1]

        return fn

    bandit = DefenseBandit.from_yaml(priors, seed=0)
    updates: list[dict[str, Any]] = []
    rt = RewardTracker(
        bandit,
        target_base_url="http://127.0.0.1:3000",
        window_requests=3,
        window_seconds=30.0,
        on_update=updates.append,
        solve_count_fn=make_seq_fetch([5, 5]),
    )

    t = time.time()
    for i in range(5):
        rt.observe_request(RequestSummary(
            timestamp=t - 10 + i * 2, method="GET",
            url="http://target/api/foo", path="/api/foo"))

    arm = Arm("http_body", "context_blend", "fake_flag")
    rt.register_injection("inj1", arm, "exploit", t_inject=t + 0.1)
    assert rt._pending["inj1"].s_start == 5

    for i in range(3):
        rt.observe_request(RequestSummary(
            timestamp=t + 1 + i * 0.1, method="GET",
            url="http://target/api/bar", path="/api/bar"))

    u_no_spike = [x for x in updates if x.get("injection_id") == "inj1"]
    assert len(u_no_spike) == 1 and not u_no_spike[0].get("skipped")
    assert u_no_spike[0]["reward"] == 1.0 and u_no_spike[0]["delta"] == 0
    print(f"[selftest] OK — stable solves reward=1: {u_no_spike[0]}")

    updates.clear()
    bandit2 = DefenseBandit.from_yaml(priors, seed=1)
    rt2 = RewardTracker(
        bandit2,
        target_base_url="http://127.0.0.1:3000",
        window_requests=2,
        window_seconds=30.0,
        on_update=updates.append,
        solve_count_fn=make_seq_fetch([5, 7]),
    )
    rt2.observe_request(RequestSummary(
        timestamp=t + 100, method="GET",
        url="http://target/", path="/"))
    arm_spike = Arm("http_body", "override", "decoy_port")
    rt2.register_injection("inj2", arm_spike, "exploit", t_inject=t + 100.1)
    rt2.observe_request(RequestSummary(
        timestamp=t + 100.2, method="GET",
        url="http://target/a", path="/a"))
    rt2.observe_request(RequestSummary(
        timestamp=t + 100.3, method="GET",
        url="http://target/b", path="/b"))

    u_spike = updates[-1]
    assert not u_spike.get("skipped")
    assert u_spike["reward"] == 0.0 and u_spike["delta"] == 2
    assert u_spike.get("solve_spike_cooldown") is True
    assert bandit2._posterior(arm_spike, "exploit").is_on_cooldown(
        now=time.time())
    assert bandit2.select("exploit", [arm_spike], now=time.time()) is None
    print(f"[selftest] OK — solve spike reward=0 + cooldown: {u_spike}")

    updates.clear()

    def failing_fetch(_base: str) -> int | None:
        return None

    rt3 = RewardTracker(
        bandit,
        target_base_url="http://127.0.0.1:3000",
        window_requests=1,
        window_seconds=30.0,
        on_update=updates.append,
        solve_count_fn=failing_fetch,
    )
    pre_updates = bandit._posterior(arm, "exploit").n_updates
    rt3.register_injection("inj3", arm, "exploit", t_inject=t + 200)
    rt3.observe_request(RequestSummary(
        timestamp=t + 200.5, method="GET",
        url="http://target/z", path="/z"))

    u_skip = updates[-1]
    assert u_skip.get("skipped") is True
    assert bandit._posterior(arm, "exploit").n_updates == pre_updates
    print(f"[selftest] OK — poll failure skips update: {u_skip}")

    b4 = DefenseBandit.from_yaml(priors, seed=2)
    arm_b = Arm("http_body", "context_blend", "decoy_port")
    pre_n = b4._posterior(arm_b, "exploit").n_updates
    rt4 = RewardTracker(
        b4,
        target_base_url="http://127.0.0.1:3000",
        window_requests=1,
        window_seconds=30.0,
        solve_count_fn=lambda _: None,
    )
    rt4.register_injection("injB", arm_b, "exploit", t_inject=t + 300)
    rt4.observe_request(RequestSummary(
        timestamp=t + 300.5, method="GET",
        url="http://target/q", path="/q"))
    assert rt4._pending["injB"].closed
    assert b4._posterior(arm_b, "exploit").n_updates == pre_n
    print("[selftest] OK — all-None fetch skips posterior update")

    print("[selftest] all checks passed")


if __name__ == "__main__":
    _selftest()
