"""Structured JSON logger for DefenseProxy.

Each intercepted request/response produces a single JSON line in
`<log_dir>/<run_id>/events.jsonl`. Downstream tooling (metrics.py) consumes
these lines directly.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class RunLogger:
    """Append-only JSONL logger for a single run_id.

    Thread/greenlet-safe for mitmproxy and asyncio writers.
    """

    def __init__(self, log_dir: str | os.PathLike, run_id: str):
        self.run_id = run_id
        self.root = Path(log_dir).expanduser().resolve() / run_id
        self.root.mkdir(parents=True, exist_ok=True)
        self.events_path = self.root / "events.jsonl"
        self._lock = threading.Lock()

    # ---- core ---------------------------------------------------------

    def log(self, **fields: Any) -> None:
        """Emit one JSON event. Common fields are populated automatically."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "position": fields.pop("position", None),
            "injection_applied": fields.pop("injection_applied", False),
            "target_url": fields.pop("target_url", None),
            "response_status": fields.pop("response_status", None),
            "response_size_bytes": fields.pop("response_size_bytes", None),
            # Taxonomy dimensions (nullable until set by the proxy layer).
            "objective": fields.pop("objective", None),
            "trigger": fields.pop("trigger", None),
            "payload": fields.pop("payload", None),
        }
        record.update(fields)

        line = json.dumps(record, default=str, ensure_ascii=False)
        with self._lock:
            with open(self.events_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    # ---- convenience --------------------------------------------------

    def log_passthrough(self, *, position: str, target_url: str,
                        response_status: int | None,
                        response_size_bytes: int | None, **extra: Any) -> None:
        self.log(
            position=position,
            injection_applied=False,
            target_url=target_url,
            response_status=response_status,
            response_size_bytes=response_size_bytes,
            **extra,
        )

    def log_injection(self, *, position: str, target_url: str,
                      response_status: int | None,
                      response_size_bytes: int | None,
                      objective: str | None, trigger: str | None,
                      payload: str | None, injected_text: str,
                      **extra: Any) -> None:
        self.log(
            position=position,
            injection_applied=True,
            target_url=target_url,
            response_status=response_status,
            response_size_bytes=response_size_bytes,
            objective=objective,
            trigger=trigger,
            payload=payload,
            injected_text=injected_text,
            injected_bytes=len(injected_text.encode("utf-8")),
            **extra,
        )


# Module-level singleton, initialised by the proxy entrypoints. mitmproxy
# instantiates addons via class, so we share one logger across addon calls.
_ACTIVE: RunLogger | None = None


def init(log_dir: str, run_id: str) -> RunLogger:
    global _ACTIVE
    _ACTIVE = RunLogger(log_dir, run_id)
    _ACTIVE.log(event="run_start", startup_ts=time.time())
    return _ACTIVE


def get() -> RunLogger:
    if _ACTIVE is None:
        raise RuntimeError("RunLogger not initialised — call logger.init() first")
    return _ACTIVE
