"""DefenseProxy entrypoint.

Usage:
    python main.py --config config.yaml --run-id exp_001 --mode http
    python main.py --config config.yaml --run-id exp_001 --mode banner
    python main.py --config config.yaml --run-id exp_001 --mode all
    python main.py --config config.yaml --validate-config
    python main.py --list-payloads
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from payloads import (
    PAYLOADS,
    Objective,
    Position,
    TRIGGERS,
    list_payloads_table,
)


HERE = Path(__file__).resolve().parent


# ---------- config validation -------------------------------------------

VALID_OBJECTIVES = {o.value for o in Objective}
VALID_POSITIONS = {p.value for p in Position}
VALID_TRIGGERS = set(TRIGGERS.keys())
VALID_PAYLOADS = set(PAYLOADS.keys())
VALID_STEALTH = {"inline", "html_comment", "meta_tag"}
VALID_ERROR_MODES = {"body", "json_field"}


def validate_config(cfg: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    target = cfg.get("target") or {}
    if not target.get("host"):
        errors.append("target.host missing")
    if not target.get("http_port"):
        errors.append("target.http_port missing")

    proxy = cfg.get("proxy") or {}
    if not proxy.get("http_port"):
        errors.append("proxy.http_port missing")

    log_dir = (cfg.get("logging") or {}).get("log_dir")
    if not log_dir:
        errors.append("logging.log_dir missing")

    defenses = cfg.get("defenses")
    if defenses is None:
        errors.append("defenses key missing (use `defenses: []` for passthrough)")
    else:
        seen: set[tuple[str, str]] = set()
        for i, d in enumerate(defenses or []):
            prefix = f"defenses[{i}]"
            if not isinstance(d, dict):
                errors.append(f"{prefix} must be a mapping")
                continue
            if "enabled" not in d:
                errors.append(f"{prefix}.enabled missing")
            obj = d.get("objective")
            if obj and obj not in VALID_OBJECTIVES:
                errors.append(f"{prefix}.objective={obj!r} not in {sorted(VALID_OBJECTIVES)}")
            pos = d.get("position")
            if not pos:
                errors.append(f"{prefix}.position missing")
            elif pos not in VALID_POSITIONS:
                errors.append(f"{prefix}.position={pos!r} not in {sorted(VALID_POSITIONS)}")
            trig = d.get("trigger")
            if trig and trig not in VALID_TRIGGERS:
                errors.append(f"{prefix}.trigger={trig!r} not in {sorted(VALID_TRIGGERS)}")
            payload = d.get("payload")
            if payload and payload not in VALID_PAYLOADS:
                errors.append(f"{prefix}.payload={payload!r} not in {sorted(VALID_PAYLOADS)}")
            if pos == Position.HTTP_BODY.value:
                stealth = d.get("stealth", "inline")
                if stealth not in VALID_STEALTH:
                    errors.append(f"{prefix}.stealth={stealth!r} not in {sorted(VALID_STEALTH)}")
            if pos == Position.ERROR_MESSAGE.value:
                mode = d.get("mode", "body")
                if mode not in VALID_ERROR_MODES:
                    errors.append(f"{prefix}.mode={mode!r} not in {sorted(VALID_ERROR_MODES)}")
            # Duplicate (position, payload) detection — warning only.
            key = (pos or "", payload or obj or "")
            if d.get("enabled") and key in seen:
                errors.append(f"{prefix} duplicate (position, payload) = {key}")
            else:
                seen.add(key)
    return errors


def load_config(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# ---------- HTTP proxy launch ------------------------------------------

def launch_http_proxy(config_path: str, run_id: str, cfg: dict[str, Any]
                      ) -> subprocess.Popen:
    target = cfg["target"]
    proxy = cfg["proxy"]
    target_url = f"http://{target['host']}:{int(target['http_port'])}"
    listen_port = int(proxy["http_port"])

    env = os.environ.copy()
    env["DEFENSEPROXY_CONFIG"] = str(Path(config_path).resolve())
    env["DEFENSEPROXY_RUN_ID"] = run_id

    # Keep mitmproxy's CA/cert store inside the project so we don't rely on
    # $HOME being writable (sandboxed environments, CI, etc.).
    confdir = HERE / ".mitmproxy"
    confdir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "mitmdump",
        "-s", str(HERE / "http_proxy.py"),
        "--mode", f"reverse:{target_url}",
        "-p", str(listen_port),
        "--set", "connection_strategy=lazy",
        "--set", f"confdir={confdir}",
    ]
    print(f"[main] launching: {' '.join(cmd)}")
    return subprocess.Popen(cmd, env=env, cwd=str(HERE))


# ---------- orchestration ----------------------------------------------

async def run_banner(cfg: dict[str, Any], run_id: str) -> None:
    from banner_proxy import run_banner_proxy
    await run_banner_proxy(cfg, run_id)


def _install_signal_handlers(procs: list[subprocess.Popen]) -> None:
    def _graceful(signum, _frame):
        print(f"\n[main] signal {signum} — shutting down subprocesses")
        for p in procs:
            if p.poll() is None:
                try:
                    p.terminate()
                except Exception:
                    pass
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _graceful)
        except ValueError:
            pass


def main() -> int:
    ap = argparse.ArgumentParser(prog="defenseproxy")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--run-id", default="run_default")
    ap.add_argument("--mode", choices=["http", "banner", "all"], default="http")
    ap.add_argument("--validate-config", action="store_true")
    ap.add_argument("--list-payloads", action="store_true")
    args = ap.parse_args()

    if args.list_payloads:
        print(list_payloads_table())
        return 0

    cfg = load_config(args.config)
    errs = validate_config(cfg)
    if args.validate_config:
        if errs:
            print("CONFIG INVALID:")
            for e in errs:
                print(f"  - {e}")
            return 1
        print(f"CONFIG OK: {args.config}")
        return 0
    if errs:
        print("CONFIG INVALID — refusing to start:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1

    log_dir = Path((cfg.get("logging") or {}).get("log_dir", "./logs"))
    (log_dir / args.run_id).mkdir(parents=True, exist_ok=True)

    procs: list[subprocess.Popen] = []
    try:
        if args.mode in ("http", "all"):
            procs.append(launch_http_proxy(args.config, args.run_id, cfg))
        _install_signal_handlers(procs)

        if args.mode == "banner":
            asyncio.run(run_banner(cfg, args.run_id))
        elif args.mode == "all":
            # Banner proxy in the main thread; HTTP proxy is already a
            # subprocess. Press Ctrl-C to stop both.
            try:
                asyncio.run(run_banner(cfg, args.run_id))
            except KeyboardInterrupt:
                pass
        else:  # http only — just wait on the subprocess
            try:
                procs[0].wait()
            except KeyboardInterrupt:
                pass
    finally:
        for p in procs:
            if p.poll() is None:
                try:
                    p.terminate()
                    p.wait(timeout=5)
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
