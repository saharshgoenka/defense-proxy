"""mitmproxy addon implementing DefenseProxy's HTTP injection positions.

Launched by main.py as a subprocess:

    mitmdump -s http_proxy.py \
        --mode reverse:http://<target_host>:<target_port> \
        -p <proxy_port>

Configuration is read from the environment:

    DEFENSEPROXY_CONFIG    path to config.yaml
    DEFENSEPROXY_RUN_ID    run identifier (used for log dir)

Supports these positions:
    P3 http_header    — append payload to X-Defense-Info response header
    P4 http_body      — append payload to HTML body (modes: inline |
                         html_comment | meta_tag)
    P6 error_message  — inject into 4xx/5xx responses (body or JSON field)
    P8 code_comment   — inject as `// <payload>` into JS responses

All other positions are handled by banner_proxy.py / file_injector.py.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import yaml
from mitmproxy import http

import logger as dp_logger
from payloads import Position, get_injection


# ---------- config loading -----------------------------------------------

def _load_config() -> dict[str, Any]:
    cfg_path = os.environ.get("DEFENSEPROXY_CONFIG")
    if not cfg_path:
        raise RuntimeError("DEFENSEPROXY_CONFIG env var must be set")
    with open(cfg_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# Positions implemented in *this* module. Entries with other positions are
# silently ignored here (they are handled by banner_proxy.py / file_injector.py).
_HTTP_POSITIONS = {
    Position.HTTP_HEADER.value,
    Position.HTTP_BODY.value,
    Position.ERROR_MESSAGE.value,
    Position.CODE_COMMENT.value,
}


class DefenseProxyAddon:
    def __init__(self) -> None:
        self.config = _load_config()
        log_dir = self.config.get("logging", {}).get("log_dir", "./logs")
        run_id = os.environ.get("DEFENSEPROXY_RUN_ID", "unnamed_run")
        self.log = dp_logger.init(log_dir, run_id)

        self.defenses: list[dict[str, Any]] = [
            d for d in (self.config.get("defenses") or [])
            if d.get("enabled") and d.get("position") in _HTTP_POSITIONS
        ]
        self._warn_duplicates()

        self.log.log(event="addon_loaded",
                     active_http_defenses=len(self.defenses),
                     positions=[d.get("position") for d in self.defenses])

    # ---- dedup ---------------------------------------------------------

    def _warn_duplicates(self) -> None:
        seen: set[tuple[str, str]] = set()
        kept: list[dict[str, Any]] = []
        for d in self.defenses:
            key = (d.get("position"), d.get("payload") or d.get("objective"))
            if key in seen:
                print(f"[DefenseProxy] WARN: duplicate (position, payload) "
                      f"{key} — skipping entry")
                continue
            seen.add(key)
            kept.append(d)
        self.defenses = kept

    # ---- mitmproxy hook -----------------------------------------------

    def response(self, flow: http.HTTPFlow) -> None:  # noqa: D401 — mitm hook
        """Process every response from the upstream target."""
        url = flow.request.pretty_url
        status = flow.response.status_code
        orig_size = len(flow.response.raw_content or b"")

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

        if not any_injection:
            self.log.log_passthrough(
                position="http",
                target_url=url,
                response_status=status,
                response_size_bytes=orig_size,
            )

    # ---- position P3: http_header -------------------------------------

    def _apply_header(self, flow: http.HTTPFlow, entry: dict[str, Any]) -> bool:
        text = get_injection(entry.get("objective"), entry.get("trigger"),
                             entry.get("payload"))
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

        text = get_injection(entry.get("objective"), entry.get("trigger"),
                             entry.get("payload"))
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

        text = get_injection(entry.get("objective"), entry.get("trigger"),
                             entry.get("payload"))
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
        if "javascript" not in ctype and "ecmascript" not in ctype:
            return False

        text = get_injection(entry.get("objective"), entry.get("trigger"),
                             entry.get("payload"))
        if not text:
            return False

        single_line = re.sub(r"[\r\n]+", " ", text)
        body = flow.response.get_text() or ""
        flow.response.set_text(f"// {single_line}\n" + body)
        flow.response.headers.pop("Content-Length", None)
        flow.response.headers.pop("Content-Encoding", None)
        self._log_injection(flow, entry, text,
                            position=Position.CODE_COMMENT.value)
        return True

    # ---- helpers ------------------------------------------------------

    def _log_injection(self, flow: http.HTTPFlow, entry: dict[str, Any],
                       text: str, *, position: str, **extra: Any) -> None:
        self.log.log_injection(
            position=position,
            target_url=flow.request.pretty_url,
            response_status=flow.response.status_code,
            response_size_bytes=len(flow.response.raw_content or b""),
            objective=entry.get("objective"),
            trigger=entry.get("trigger"),
            payload=entry.get("payload"),
            injected_text=text,
            **extra,
        )


# mitmproxy discovers addons by looking for module-level `addons` list.
addons = [DefenseProxyAddon()]
