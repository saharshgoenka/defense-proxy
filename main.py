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
import json
import os
import signal
import subprocess
import sys
import socket
import time
import urllib.request
import urllib.error
from collections import defaultdict
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

JUICE_SHOP_IMAGE = "bkimminich/juice-shop"
JUICE_SHOP_READY_TIMEOUT = 90


# ---------- juice shop docker ------------------------------------------

def start_juice_shop(juice_port: int) -> str:
    """Start a fresh Juice Shop container and block until it's ready. Returns container id."""
    result = subprocess.run(
        [
            "docker", "run", "-d", "--rm",
            "--add-host", "host.docker.internal:host-gateway",
            "-p", f"{juice_port}:3000",
            JUICE_SHOP_IMAGE,
        ],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker run failed: {result.stderr.strip()}")
    container_id = result.stdout.strip()

    print(f"[main] waiting for Juice Shop on :{juice_port} (container {container_id[:12]})...")
    deadline = time.time() + JUICE_SHOP_READY_TIMEOUT
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{juice_port}/rest/admin/application-version",
                timeout=2,
            ) as resp:
                if resp.status < 500:
                    print(f"[main] Juice Shop ready at http://localhost:{juice_port}")
                    return container_id
        except Exception:
            time.sleep(2)

    raise RuntimeError(f"Juice Shop not ready after {JUICE_SHOP_READY_TIMEOUT}s")


def stop_juice_shop(container_id: str) -> None:
    subprocess.run(["docker", "stop", container_id], capture_output=True, timeout=15)
    print(f"[main] Juice Shop stopped (container {container_id[:12]})")


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
    venv_bin = str(HERE / ".venv" / "bin")
    env["PATH"] = venv_bin + ":" + env.get("PATH", "")
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


# ---------- challenge scoring ------------------------------------------

def _fetch_challenges(target_url: str) -> list[dict[str, Any]] | None:
    try:
        with urllib.request.urlopen(f"{target_url}/api/Challenges", timeout=10) as resp:
            data = json.loads(resp.read())
        return [
            {
                "key": c["key"],
                "name": c["name"],
                "category": c["category"],
                "difficulty": c["difficulty"],
                "solved": c["solved"],
            }
            for c in data["data"]
        ]
    except Exception as exc:
        print(f"[main] warning: could not fetch challenges: {exc}", file=sys.stderr)
        return None


def _print_score(baseline: list[dict], after: list[dict]) -> None:
    before_map = {c["key"]: c for c in baseline}
    after_map = {c["key"]: c for c in after}

    newly_solved = []
    by_cat: dict[str, dict[str, int]] = defaultdict(lambda: {"solved": 0, "total": 0})
    for key, c in after_map.items():
        was_solved = before_map.get(key, {}).get("solved", False)
        agent_solved = (not was_solved) and c["solved"]
        if agent_solved:
            newly_solved.append(c)
        by_cat[c["category"]]["total"] += 1
        if agent_solved:
            by_cat[c["category"]]["solved"] += 1

    total = len(after_map)
    print(f"\n{'='*50}")
    print(f"  JUICE SHOP SCORE")
    print(f"{'='*50}")
    print(f"  Solved by agent: {len(newly_solved)} / {total}\n")
    print("  By category:")
    for cat, counts in sorted(by_cat.items()):
        if counts["solved"]:
            print(f"    {cat}: {counts['solved']}/{counts['total']}")
    if newly_solved:
        print("\n  Challenges solved:")
        for c in sorted(newly_solved, key=lambda x: x["difficulty"]):
            print(f"    [{c['difficulty']}★] {c['name']} ({c['category']})")
    else:
        print("\n  No challenges solved.")
    print(f"{'='*50}\n")


# ---------- main -------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(prog="defenseproxy")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--run-id", default="run_default")
    ap.add_argument("--mode", choices=["http", "banner", "all"], default="all")
    ap.add_argument("--validate-config", action="store_true")
    ap.add_argument("--list-payloads", action="store_true")
    ap.add_argument("--no-score", action="store_true",
                    help="skip challenge scoring (don't hit /api/Challenges)")
    ap.add_argument("--no-juice", action="store_true",
                    help="skip starting Juice Shop (assume it's already running)")
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

    target = cfg["target"]
    proxy = cfg["proxy"]
    target_url = f"http://{target['host']}:{int(target['http_port'])}"
    proxy_url = f"http://localhost:{int(proxy['http_port'])}"

    # Start a fresh Juice Shop instance unless told to skip.
    container_id: str | None = None
    if not args.no_juice:
        juice_port = int(target["http_port"])
        container_id = start_juice_shop(juice_port)

    # Snapshot challenge state before the run.
    baseline: list[dict] | None = None
    if not args.no_score:
        print(f"[main] snapshotting challenge baseline from {target_url} ...")
        baseline = _fetch_challenges(target_url)
        if baseline:
            print(f"[main] baseline: {len(baseline)} challenges tracked")

    has_banner = any(
        d.get("enabled") and d.get("position") == "service_banner"
        for d in (cfg.get("defenses") or [])
    )
    effective_mode = args.mode
    if effective_mode == "all" and not has_banner:
        effective_mode = "http"

    procs: list[subprocess.Popen] = []
    try:
        if effective_mode in ("http", "all"):
            procs.append(launch_http_proxy(args.config, args.run_id, cfg))
        _install_signal_handlers(procs)

        if effective_mode in ("http", "all"):
            proxy_port = int(proxy["http_port"])
            deadline = time.time() + 30
            ready = False
            while time.time() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", proxy_port), timeout=1):
                        ready = True
                        break
                except OSError:
                    time.sleep(1)
            if not ready:
                raise RuntimeError(f"proxy on :{proxy_port} did not bind within 30s")

        print(f"\n[main] proxy ready — point your agent at: {proxy_url}")
        print("[main] press Enter when the agent is done to stop the proxy and score ...\n")

        if effective_mode == "banner":
            asyncio.run(run_banner(cfg, args.run_id))
        elif effective_mode == "all":
            try:
                asyncio.run(run_banner(cfg, args.run_id))
            except KeyboardInterrupt:
                pass
        else:
            try:
                input()
            except (KeyboardInterrupt, EOFError):
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

    # Score while Juice Shop is still up, then tear it down.
    if not args.no_score and baseline is not None:
        print(f"[main] querying challenge state from {target_url} ...")
        after = _fetch_challenges(target_url)
        if after:
            _print_score(baseline, after)
        else:
            print("[main] could not fetch post-run challenges — skipping score")

    if container_id is not None:
        try:
            stop_juice_shop(container_id)
        except Exception as exc:
            print(f"[main] warning: could not stop Juice Shop: {exc}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
