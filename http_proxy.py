"""mitmproxy addon implementing DefenseProxy's HTTP injection positions.

Launched by main.py as a subprocess:

    mitmdump -s http_proxy.py \
        --mode reverse:http://<target_host>:<target_port> \
        -p <proxy_port>

Configuration is read from the environment:

    DEFENSEPROXY_CONFIG    path to config.yaml
    DEFENSEPROXY_RUN_ID    run identifier (used for log dir)

Supports these positions:
    P3  http_header    — append payload to X-Defense-Info response header
    P4  http_body      — append payload to HTML body (modes: inline |
                          html_comment | meta_tag)
    P6  error_message  — inject into 4xx/5xx responses (body or JSON field)
    P8  code_comment   — inject as `// <payload>` into JS responses
    P9  robots_txt     — append payload as a comment in /robots.txt
    P10 cookie         — set payload as a cookie value via Set-Cookie header

All other positions are handled by banner_proxy.py / file_injector.py.
"""

from __future__ import annotations

import json
import os
import random
import re
import time
import uuid
from pathlib import Path
from typing import Any

import yaml
from mitmproxy import http

import logger as dp_logger
from bandit import Arm, DefenseBandit, RandomBandit
from payloads import Position, get_injection
from reward_tracker import RequestSummary, RewardTracker


# ---------- config loading -----------------------------------------------

def _load_config() -> dict[str, Any]:
    cfg_path = os.environ.get("DEFENSEPROXY_CONFIG")
    if not cfg_path:
        raise RuntimeError("DEFENSEPROXY_CONFIG env var must be set")
    with open(cfg_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _target_base_url(cfg: dict[str, Any]) -> str:
    """HTTP origin for Juice Shop API polls from the proxy host (bandit rewards)."""
    t = cfg.get("target") or {}
    host = str(t.get("host", "localhost"))
    if host.lower() == "localhost":
        host = "127.0.0.1"
    port = int(t.get("http_port", 3000))
    return f"http://{host}:{port}"


# Positions implemented in *this* module. Entries with other positions are
# silently ignored here (they are handled by banner_proxy.py / file_injector.py).
_HTTP_POSITIONS = {
    Position.HTTP_HEADER.value,
    Position.HTTP_BODY.value,
    Position.ERROR_MESSAGE.value,
    Position.CODE_COMMENT.value,
    Position.ROBOTS_TXT.value,
    Position.COOKIE.value,
}


class DefenseProxyAddon:
    def __init__(self) -> None:
        self.config = _load_config()
        log_dir = self.config.get("logging", {}).get("log_dir", "./logs")
        run_id = os.environ.get("DEFENSEPROXY_RUN_ID", "unnamed_run")
        self.log = dp_logger.init(log_dir, run_id)
        self._run_id = run_id
        self._log_dir = Path(log_dir)

        self.defenses: list[dict[str, Any]] = [
            d for d in (self.config.get("defenses") or [])
            if d.get("enabled") and d.get("position") in _HTTP_POSITIONS
        ]
        self._warn_duplicates()

        # ---- bandit mode (optional, additive) ---------------------------
        self.mode: str = (self.config.get("mode") or "static").lower()
        self.bandit: DefenseBandit | None = None
        self.tracker: RewardTracker | None = None
        if self.mode in ("bandit", "random"):
            self._init_bandit_mode()

        self.log.log(event="addon_loaded",
                     mode=self.mode,
                     active_http_defenses=len(self.defenses),
                     positions=[d.get("position") for d in self.defenses])

    def _init_bandit_mode(self) -> None:
        bandit_cfg = self.config.get("bandit") or {}
        priors_path = self._resolve_priors_path(
            bandit_cfg.get("priors_path", "configs/bandit/priors.yaml"))
        seed = bandit_cfg.get("seed")
        cls = RandomBandit if self.mode == "random" else DefenseBandit
        self.bandit = cls.from_yaml(priors_path, seed=seed)
        # Adaptive anti-detection cadence controls (bandit mode only).
        self._agent_request_count = 0
        self._eligible_response_count = 0
        self._cadence_warmup_requests = int(bandit_cfg.get("warmup_requests", 4))
        self._cadence_every_nth = max(1, int(bandit_cfg.get("inject_every_nth", 2)))
        self._phase_inject_prob: dict[str, float] = {
            "recon": float(bandit_cfg.get("inject_prob_recon", 0.35)),
            "enum": float(bandit_cfg.get("inject_prob_enum", 0.50)),
            "exploit": float(bandit_cfg.get("inject_prob_exploit", 0.85)),
            "exfil": float(bandit_cfg.get("inject_prob_exfil", 0.80)),
        }
        self._cadence_rng = random.Random(seed if seed is not None else 0)
        self.tracker = RewardTracker(
            self.bandit,
            target_base_url=_target_base_url(self.config),
            window_requests=int(bandit_cfg.get("window_requests", 5)),
            window_seconds=float(bandit_cfg.get("window_seconds", 30.0)),
            on_update=self._log_bandit_update,
        )
        self._all_arms = DefenseBandit.enumerate_all_arms()
        self.log.log(event="bandit_initialized",
                     mode=self.mode, n_arms=len(self._all_arms),
                     priors_path=str(priors_path))

    @staticmethod
    def _resolve_priors_path(p: str) -> Path:
        """Try (a) absolute, (b) cwd-relative, (c) project-root-relative,
        (d) config-file-dir-relative. First existing wins; raise if none."""
        candidates: list[Path] = []
        path = Path(p)
        if path.is_absolute():
            candidates.append(path)
        else:
            candidates.append(Path.cwd() / path)
            here = Path(__file__).resolve().parent
            candidates.append(here / path)
            cfg_env = os.environ.get("DEFENSEPROXY_CONFIG")
            if cfg_env:
                candidates.append(Path(cfg_env).resolve().parent / path.name)
        for c in candidates:
            if c.exists():
                return c
        raise FileNotFoundError(
            f"priors file not found; tried: {[str(c) for c in candidates]}"
        )

    def _log_bandit_update(self, info: dict[str, Any]) -> None:
        self.log.log(event="bandit_update", **info)
        # Persist a posterior snapshot every 5 updates (cheap; tiny file).
        if self.bandit is not None:
            n = sum(p.n_updates for p in self.bandit.posteriors.values())
            if n % 5 == 0 or n <= 5:
                snap_path = self._log_dir / self._run_id / "bandit_snapshot.json"
                self.bandit.write_snapshot(snap_path)

    def done(self) -> None:  # noqa: D401 — mitm shutdown hook
        """Persist a final posterior snapshot when the proxy stops."""
        if self.bandit is not None:
            snap_path = self._log_dir / self._run_id / "bandit_snapshot.json"
            self.bandit.write_snapshot(snap_path)
            self.log.log(event="bandit_final_snapshot",
                         path=str(snap_path),
                         n_posterior_cells=len(self.bandit.posteriors))

    # ---- dedup ---------------------------------------------------------

    def _warn_duplicates(self) -> None:
        seen: set[tuple[str, str]] = set()
        kept: list[dict[str, Any]] = []
        for d in self.defenses:
            key = (d.get("position"), d.get("payload"))
            if key in seen:
                print(f"[DefenseProxy] WARN: duplicate (position, payload) "
                      f"{key} — skipping entry")
                continue
            seen.add(key)
            kept.append(d)
        self.defenses = kept

    # ---- mitmproxy hooks -----------------------------------------------

    def request(self, flow: http.HTTPFlow) -> None:  # noqa: D401 — mitm hook
        """Feed every agent-originated request into the reward tracker."""
        if self.tracker is None:
            return
        self._agent_request_count += 1
        try:
            body = flow.request.get_text() or ""
        except Exception:
            body = ""
        headers_text = "\n".join(f"{k}: {v}" for k, v in flow.request.headers.items())
        self.tracker.observe_request(RequestSummary(
            timestamp=time.time(),
            method=flow.request.method,
            url=flow.request.pretty_url,
            path=flow.request.path.split("?")[0] if flow.request.path else "/",
            headers_text=headers_text,
            body_text=body,
        ))
        # Opportunistically expire any pending injections whose window
        # has elapsed.
        self.tracker.flush_expired()

    def response(self, flow: http.HTTPFlow) -> None:  # noqa: D401 — mitm hook
        """Process every response from the upstream target."""
        url = flow.request.pretty_url
        status = flow.response.status_code
        orig_size = len(flow.response.raw_content or b"")

        if self.mode in ("bandit", "random") and self.bandit is not None:
            self._apply_bandit(flow)
            return

        any_injection = False

        for entry in self.defenses:
            pos = entry.get("position")
            if pos == Position.HTTP_HEADER.value:
                if self._apply_header(flow, entry):
                    any_injection = True
            elif pos == Position.HTTP_BODY.value:
                if self._apply_body(flow, entry):
                    any_injection = True
            elif pos == Position.ERROR_MESSAGE.value:
                if self._apply_error(flow, entry):
                    any_injection = True
            elif pos == Position.CODE_COMMENT.value:
                if self._apply_code_comment(flow, entry):
                    any_injection = True
            elif pos == Position.ROBOTS_TXT.value:
                if self._apply_robots_txt(flow, entry):
                    any_injection = True
            elif pos == Position.COOKIE.value:
                if self._apply_cookie(flow, entry):
                    any_injection = True

        if not any_injection:
            self.log.log_passthrough(
                position="http",
                target_url=url,
                response_status=status,
                response_size_bytes=orig_size,
            )

    # ---- bandit-mode dispatch ------------------------------------------

    def _apply_bandit(self, flow: http.HTTPFlow) -> None:
        """Per-response: pick an arm via Thompson sampling, inject, register."""
        assert self.bandit is not None and self.tracker is not None
        self._eligible_response_count += 1
        path = flow.request.path.split("?")[0] if flow.request.path else "/"
        ctype = flow.response.headers.get("Content-Type", "")
        status = flow.response.status_code

        feasible = self.tracker.feasible_arms(
            {"path": path, "content_type": ctype, "status": status},
            self._all_arms,
        )
        phase = self.tracker.current_phase()
        # Avoid immediately revealing the defense: warmup + sparse cadence +
        # phase-aware probabilistic gating.
        if self.mode == "bandit":
            if self._agent_request_count < self._cadence_warmup_requests:
                self.log.log_passthrough(
                    position="http",
                    target_url=flow.request.pretty_url,
                    response_status=status,
                    response_size_bytes=len(flow.response.raw_content or b""),
                    bandit_phase=phase,
                    feasible=len(feasible),
                    bandit_skipped="cadence_warmup",
                    cadence_requests_seen=self._agent_request_count,
                )
                return
            if self._cadence_every_nth > 1 and (
                self._eligible_response_count % self._cadence_every_nth != 0
            ):
                self.log.log_passthrough(
                    position="http",
                    target_url=flow.request.pretty_url,
                    response_status=status,
                    response_size_bytes=len(flow.response.raw_content or b""),
                    bandit_phase=phase,
                    feasible=len(feasible),
                    bandit_skipped="cadence_every_nth",
                    cadence_nth=self._cadence_every_nth,
                )
                return
            p = max(0.0, min(1.0, self._phase_inject_prob.get(phase, 0.6)))
            if self._cadence_rng.random() > p:
                self.log.log_passthrough(
                    position="http",
                    target_url=flow.request.pretty_url,
                    response_status=status,
                    response_size_bytes=len(flow.response.raw_content or b""),
                    bandit_phase=phase,
                    feasible=len(feasible),
                    bandit_skipped="cadence_probability",
                    cadence_probability=p,
                )
                return
        arm = self.bandit.select(phase, feasible)
        if arm is None:
            self.log.log_passthrough(
                position="http",
                target_url=flow.request.pretty_url,
                response_status=status,
                response_size_bytes=len(flow.response.raw_content or b""),
                bandit_phase=phase,
                feasible=len(feasible),
            )
            return

        # Synthesize a one-shot entry that the existing _apply_* methods
        # consume verbatim.
        entry: dict[str, Any] = {
            "position": arm.position,
            "trigger": arm.trigger,
            "payload": arm.payload,
        }
        injected = False
        if arm.position == Position.HTTP_HEADER.value:
            injected = self._apply_header(flow, entry)
        elif arm.position == Position.HTTP_BODY.value:
            injected = self._apply_body(flow, entry)
        elif arm.position == Position.ERROR_MESSAGE.value:
            injected = self._apply_error(flow, entry)
        elif arm.position == Position.CODE_COMMENT.value:
            injected = self._apply_code_comment(flow, entry)
        elif arm.position == Position.ROBOTS_TXT.value:
            injected = self._apply_robots_txt(flow, entry)
        elif arm.position == Position.COOKIE.value:
            injected = self._apply_cookie(flow, entry)

        if injected:
            inj_id = uuid.uuid4().hex[:12]
            self.tracker.register_injection(inj_id, arm, phase)
            self.log.log(event="bandit_select",
                         injection_id=inj_id,
                         arm=arm.key(),
                         phase=phase,
                         n_feasible=len(feasible),
                         target_url=flow.request.pretty_url,
                         response_status=status)
        else:
            self.log.log_passthrough(
                position="http",
                target_url=flow.request.pretty_url,
                response_status=status,
                response_size_bytes=len(flow.response.raw_content or b""),
                bandit_phase=phase,
                bandit_arm_attempted=arm.key(),
                bandit_skipped="apply_returned_false",
            )

    # ---- position P3: http_header -------------------------------------

    def _apply_header(self, flow: http.HTTPFlow, entry: dict[str, Any]) -> bool:
        text = get_injection(entry.get("trigger"), entry.get("payload"))
        if not text:
            return False
        header_name = entry.get("header_name", "X-Defense-Info")
        existing = flow.response.headers.get(header_name, "")
        new_val = (existing + " " + text).strip() if existing else text
        # HTTP headers forbid CR/LF; collapse any multi-line payloads.
        new_val = re.sub(r"[\r\n]+", " ", new_val)
        flow.response.headers[header_name] = new_val
        self._log_injection(flow, entry, text, position=Position.HTTP_HEADER.value)
        return True

    # ---- position P4: http_body ---------------------------------------

    def _apply_body(self, flow: http.HTTPFlow, entry: dict[str, Any]) -> bool:
        ctype = flow.response.headers.get("Content-Type", "")
        # Only inject into textual bodies (HTML, text/*). Avoid binary blobs.
        if ctype and not (ctype.startswith("text/") or "html" in ctype
                          or "xml" in ctype or "json" in ctype):
            return False

        text = get_injection(entry.get("trigger"), entry.get("payload"))
        if not text:
            return False

        stealth = entry.get("stealth", "inline")
        if stealth == "html_comment":
            fragment = f"\n<!-- {text} -->\n"
        elif stealth == "meta_tag":
            # Meta tags must appear inside <head> to be well-formed, but
            # browsers / parsers accept them anywhere; agents scraping raw
            # HTML will still see them. Escape quotes in content.
            safe = text.replace('"', "&quot;")
            fragment = f'\n<meta name="generator" content="{safe}">\n'
        else:  # inline
            fragment = "\n" + text + "\n"

        try:
            body = flow.response.get_text() or ""
        except Exception:
            body = flow.response.raw_content.decode("utf-8", errors="replace") \
                if flow.response.raw_content else ""

        if not body:
            return False

        # Try to find a logical insertion point in HTML. Prioritize </footer>,
        # then </body>, then </html>. Fall back to appending.
        lower_body = body.lower()
        insertion_point = -1
        for tag in ["</footer>", "</body>", "</html>"]:
            idx = lower_body.rfind(tag)
            if idx != -1:
                insertion_point = idx
                break

        if insertion_point != -1:
            flow.response.set_text(body[:insertion_point] + fragment + body[insertion_point:])
        else:
            flow.response.set_text(body + fragment)

        # Let mitmproxy recompute Content-Length — per project rules, remove it.
        flow.response.headers.pop("Content-Length", None)
        # Strip conflicting content encodings since set_text re-serialises plain text.
        flow.response.headers.pop("Content-Encoding", None)

        self._log_injection(flow, entry, text, position=Position.HTTP_BODY.value,
                            stealth=stealth)
        return True

    # ---- position P6: error_message -----------------------------------

    def _apply_error(self, flow: http.HTTPFlow, entry: dict[str, Any]) -> bool:
        status = flow.response.status_code
        if not (400 <= status < 600):
            return False

        text = get_injection(entry.get("trigger"), entry.get("payload"))
        if not text:
            return False

        mode = entry.get("mode", "body")
        ctype = flow.response.headers.get("Content-Type", "")

        # Explicit JSON-field mode, or auto-detect JSON and inject into
        # the first `error`/`message` field found.
        if mode == "json_field" or "application/json" in ctype:
            try:
                doc = json.loads(flow.response.get_text() or "null")
            except Exception:
                doc = None
            if isinstance(doc, dict):
                injected = False
                for key in ("error", "message"):
                    if key in doc and isinstance(doc[key], str):
                        doc[key] = doc[key] + " " + text
                        injected = True
                        break
                    if key in doc and isinstance(doc[key], dict):
                        for k2 in ("message", "name"):
                            if k2 in doc[key] and isinstance(doc[key][k2], str):
                                doc[key][k2] = doc[key][k2] + " " + text
                                injected = True
                                break
                        if injected:
                            break
                if injected:
                    flow.response.set_text(json.dumps(doc))
                    flow.response.headers.pop("Content-Length", None)
                    flow.response.headers.pop("Content-Encoding", None)
                    self._log_injection(flow, entry, text,
                                        position=Position.ERROR_MESSAGE.value,
                                        mode="json_field")
                    return True
            # Fall through to body-append if JSON injection didn't apply.

        body = flow.response.get_text() or ""
        flow.response.set_text(body + "\n" + text + "\n")
        flow.response.headers.pop("Content-Length", None)
        flow.response.headers.pop("Content-Encoding", None)
        self._log_injection(flow, entry, text,
                            position=Position.ERROR_MESSAGE.value, mode="body")
        return True

    # ---- position P8: code_comment ------------------------------------

    def _apply_code_comment(self, flow: http.HTTPFlow, entry: dict[str, Any]) -> bool:
        ctype = flow.response.headers.get("Content-Type", "")
        is_js = "javascript" in ctype or "ecmascript" in ctype
        is_html = "html" in ctype

        if not (is_js or is_html):
            return False

        text = get_injection(entry.get("trigger"), entry.get("payload"))
        if not text:
            return False

        single_line = re.sub(r"[\r\n]+", " ", text)
        body = flow.response.get_text() or ""
        
        if is_js:
            flow.response.set_text(f"// {single_line}\n" + body)
        elif is_html:
            # Inject right after <body> or at the top
            fragment = f'\n<script>// {single_line}</script>\n'
            lower_body = body.lower()
            idx = lower_body.find("<body")
            if idx != -1:
                # Find the end of the opening body tag
                end_idx = body.find(">", idx)
                if end_idx != -1:
                    flow.response.set_text(body[:end_idx + 1] + fragment + body[end_idx + 1:])
                else:
                    flow.response.set_text(fragment + body)
            else:
                flow.response.set_text(fragment + body)

        flow.response.headers.pop("Content-Length", None)
        flow.response.headers.pop("Content-Encoding", None)
        self._log_injection(flow, entry, text,
                            position=Position.CODE_COMMENT.value)
        return True

    # ---- position P9: robots_txt --------------------------------------

    def _apply_robots_txt(self, flow: http.HTTPFlow, entry: dict[str, Any]) -> bool:
        if flow.request.path.split("?")[0] != "/robots.txt":
            return False

        text = get_injection(entry.get("trigger"), entry.get("payload"))
        if not text:
            return False

        body = flow.response.get_text() or ""
        flow.response.set_text(body + "\n# " + text + "\n")
        flow.response.headers.pop("Content-Length", None)
        flow.response.headers.pop("Content-Encoding", None)
        self._log_injection(flow, entry, text, position=Position.ROBOTS_TXT.value)
        return True

    # ---- position P10: cookie -----------------------------------------

    def _apply_cookie(self, flow: http.HTTPFlow, entry: dict[str, Any]) -> bool:
        text = get_injection(entry.get("trigger"), entry.get("payload"))
        if not text:
            return False

        cookie_name = entry.get("cookie_name", "hint")
        safe_val = text.replace(";", "").replace("\n", " ").replace("\r", "")
        flow.response.headers.add("Set-Cookie", f"{cookie_name}={safe_val}; Path=/")
        self._log_injection(flow, entry, text, position=Position.COOKIE.value,
                            cookie_name=cookie_name)
        return True

    # ---- helpers ------------------------------------------------------

    def _log_injection(self, flow: http.HTTPFlow, entry: dict[str, Any],
                       text: str, *, position: str, **extra: Any) -> None:
        self.log.log_injection(
            position=position,
            target_url=flow.request.pretty_url,
            response_status=flow.response.status_code,
            response_size_bytes=len(flow.response.raw_content or b""),
            trigger=entry.get("trigger"),
            payload=entry.get("payload"),
            injected_text=text,
            **extra,
        )


# mitmproxy discovers addons by looking for module-level `addons` list.
addons = [DefenseProxyAddon()]
