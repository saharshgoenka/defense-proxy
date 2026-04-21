"""asyncio TCP MITM for DefenseProxy — P1 (service_banner) and P2 (login_response).

Invoked via:

    python banner_proxy.py --config config.yaml --run-id <id>

or from main.py. Forwards raw TCP bytes between a client and the target
and, where configured, injects a payload into specific server-to-client
packets.

By default this is passthrough — if no defenses with position
`service_banner` / `login_response` are enabled the proxy just shuttles
bytes unchanged.
"""

from __future__ import annotations

import argparse
import asyncio
import re
from typing import Any

import yaml

import logger as dp_logger
from payloads import Position, get_injection


LOGIN_MARKERS: list[re.Pattern[bytes]] = [
    re.compile(rb"^220[\s\-].*", re.MULTILINE),
    re.compile(rb"^230[\s\-].*", re.MULTILINE),
    re.compile(rb"(?i)^.*welcome.*$", re.MULTILINE),
    re.compile(rb"(?i)^.*login successful.*$", re.MULTILINE),
]


class BannerInjector:
    def __init__(self, defenses: list[dict[str, Any]]):
        self.banner_entries = [d for d in defenses
                               if d.get("position") == Position.SERVICE_BANNER.value]
        self.login_entries = [d for d in defenses
                              if d.get("position") == Position.LOGIN_RESPONSE.value]

    def build_banner_suffix(self) -> bytes:
        parts: list[str] = []
        for e in self.banner_entries:
            t = get_injection(e.get("objective"), e.get("trigger"),
                              e.get("payload"))
            if t:
                parts.append(t)
        if not parts:
            return b""
        return ("\r\n" + " ".join(parts) + "\r\n").encode("utf-8", errors="replace")

    def apply_login_injection(self, data: bytes) -> tuple[bytes, list[str]]:
        if not self.login_entries:
            return data, []
        injected_texts: list[str] = []
        mutated = data
        for e in self.login_entries:
            t = get_injection(e.get("objective"), e.get("trigger"),
                              e.get("payload"))
            if not t:
                continue
            suffix = (" " + t).encode("utf-8", errors="replace")
            for pat in LOGIN_MARKERS:
                m = pat.search(mutated)
                if m:
                    end = m.end()
                    mutated = mutated[:end] + suffix + mutated[end:]
                    injected_texts.append(t)
                    break
        return mutated, injected_texts


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                on_chunk=None, label: str = "") -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            if on_chunk is not None:
                chunk = on_chunk(chunk) or chunk
            writer.write(chunk)
            await writer.drain()
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _handle_client(client_reader: asyncio.StreamReader,
                         client_writer: asyncio.StreamWriter,
                         *, target_host: str, target_port: int,
                         injector: BannerInjector,
                         log: dp_logger.RunLogger) -> None:
    peer = client_writer.get_extra_info("peername")
    try:
        server_reader, server_writer = await asyncio.open_connection(
            target_host, target_port)
    except OSError as exc:
        log.log(event="tcp_connect_failed", target=f"{target_host}:{target_port}",
                error=str(exc))
        client_writer.close()
        return

    log.log(event="tcp_connection_open", peer=str(peer),
            target=f"{target_host}:{target_port}")

    # --- Server → Client: banner is the first chunk; subsequent chunks
    # may match login markers.
    banner_suffix = injector.build_banner_suffix()
    state = {"first_chunk": True}

    def s2c(chunk: bytes) -> bytes:
        out = chunk
        if state["first_chunk"] and banner_suffix:
            out = out + banner_suffix
            for e in injector.banner_entries:
                log.log_injection(
                    position=Position.SERVICE_BANNER.value,
                    target_url=f"tcp://{target_host}:{target_port}",
                    response_status=None,
                    response_size_bytes=len(out),
                    objective=e.get("objective"),
                    trigger=e.get("trigger"),
                    payload=e.get("payload"),
                    injected_text=get_injection(e.get("objective"),
                                                e.get("trigger"),
                                                e.get("payload")),
                )
            state["first_chunk"] = False
        out, injected_texts = injector.apply_login_injection(out)
        for i, text in enumerate(injected_texts):
            entry = injector.login_entries[i] if i < len(injector.login_entries) else {}
            log.log_injection(
                position=Position.LOGIN_RESPONSE.value,
                target_url=f"tcp://{target_host}:{target_port}",
                response_status=None,
                response_size_bytes=len(out),
                objective=entry.get("objective"),
                trigger=entry.get("trigger"),
                payload=entry.get("payload"),
                injected_text=text,
            )
        state["first_chunk"] = False
        return out

    await asyncio.gather(
        _pipe(server_reader, client_writer, on_chunk=s2c, label="s2c"),
        _pipe(client_reader, server_writer, on_chunk=None, label="c2s"),
        return_exceptions=True,
    )
    log.log(event="tcp_connection_close", peer=str(peer))


async def run_banner_proxy(config: dict[str, Any], run_id: str) -> None:
    target = config.get("target", {})
    proxy = config.get("proxy", {})
    target_host = target.get("host", "localhost")
    target_port = int(target.get("tcp_port") or target.get("http_port", 3000))
    listen_port = int(proxy.get("tcp_port", 2121))

    log_dir = config.get("logging", {}).get("log_dir", "./logs")
    log = dp_logger.init(log_dir, run_id)

    defenses = [d for d in (config.get("defenses") or []) if d.get("enabled")]
    injector = BannerInjector(defenses)

    server = await asyncio.start_server(
        lambda r, w: _handle_client(r, w, target_host=target_host,
                                    target_port=target_port,
                                    injector=injector, log=log),
        host="0.0.0.0", port=listen_port,
    )
    log.log(event="banner_proxy_listening", listen_port=listen_port,
            target=f"{target_host}:{target_port}",
            service_banner_entries=len(injector.banner_entries),
            login_response_entries=len(injector.login_entries))
    print(f"[banner_proxy] listening on 0.0.0.0:{listen_port} -> "
          f"{target_host}:{target_port}")
    async with server:
        await server.serve_forever()


def _main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--run-id", required=True)
    args = ap.parse_args()

    with open(args.config, "r", encoding="utf-8") as fh:
        config = yaml.safe_load(fh) or {}

    try:
        asyncio.run(run_banner_proxy(config, args.run_id))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    _main()
