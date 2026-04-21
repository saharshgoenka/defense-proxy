"""P5 (file_content) injector — CLI-driven, not part of the live proxy.

Supports:
    --file PATH     target file
    --payload TEXT  raw text to inject (if --payload-key omitted)
    --payload-key K key from payloads.PAYLOADS
    --trigger T     optional trigger prefix from payloads.TRIGGERS
    --mode MODE     prepend | append | comment_block
    --restore       restore from the sibling .bak saved on first mutate

Saves a `.bak` snapshot before modifying. `--restore` copies `.bak` back
over the working file.

Example:
    python file_injector.py --file /tmp/notes.txt \
        --payload-key fake_flag --trigger system_alert --mode comment_block
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from payloads import PAYLOADS, TRIGGERS


def _bak_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".bak")


def _comment_wrap(text: str, suffix: str) -> str:
    """Pick a plausible comment syntax from the file extension."""
    ext = suffix.lower()
    if ext in {".py", ".rb", ".sh", ".yaml", ".yml", ".toml", ".conf", ".ini"}:
        lines = text.splitlines() or [""]
        return "\n".join(f"# {ln}" for ln in lines) + "\n"
    if ext in {".js", ".ts", ".c", ".cc", ".cpp", ".java", ".go", ".rs",
               ".h", ".hpp", ".css", ".scss"}:
        return f"/* {text} */\n"
    if ext in {".html", ".htm", ".xml", ".svg"}:
        return f"<!-- {text} -->\n"
    return f"# {text}\n"


def inject(path: Path, payload_text: str, mode: str) -> None:
    if not path.exists():
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        sys.exit(2)

    bak = _bak_path(path)
    if not bak.exists():
        shutil.copy2(path, bak)

    original = path.read_text(encoding="utf-8", errors="replace")

    if mode == "prepend":
        new = payload_text + "\n" + original
    elif mode == "append":
        new = original + "\n" + payload_text + "\n"
    elif mode == "comment_block":
        new = _comment_wrap(payload_text, path.suffix) + original
    else:
        print(f"ERROR: unknown --mode: {mode}", file=sys.stderr)
        sys.exit(2)

    path.write_text(new, encoding="utf-8")
    print(f"[file_injector] wrote {len(payload_text)} chars to {path} "
          f"(mode={mode}; backup at {bak})")


def restore(path: Path) -> None:
    bak = _bak_path(path)
    if not bak.exists():
        print(f"ERROR: no backup at {bak}", file=sys.stderr)
        sys.exit(2)
    shutil.copy2(bak, path)
    print(f"[file_injector] restored {path} from {bak}")


def _main() -> None:
    ap = argparse.ArgumentParser(description="P5 file-content injector")
    ap.add_argument("--file", required=True, type=Path)
    ap.add_argument("--payload", default=None,
                    help="Raw payload text (overrides --payload-key)")
    ap.add_argument("--payload-key", default=None,
                    help=f"One of: {', '.join(PAYLOADS.keys())}")
    ap.add_argument("--trigger", default="context_blend",
                    help=f"One of: {', '.join(TRIGGERS.keys())}")
    ap.add_argument("--mode", default="append",
                    choices=["prepend", "append", "comment_block"])
    ap.add_argument("--restore", action="store_true")
    args = ap.parse_args()

    if args.restore:
        restore(args.file)
        return

    if args.payload:
        text = args.payload
    elif args.payload_key:
        if args.payload_key not in PAYLOADS:
            print(f"ERROR: unknown payload-key: {args.payload_key}", file=sys.stderr)
            sys.exit(2)
        prefix = TRIGGERS.get(args.trigger, "")
        text = prefix + PAYLOADS[args.payload_key]
    else:
        print("ERROR: provide --payload or --payload-key (or --restore)",
              file=sys.stderr)
        sys.exit(2)

    inject(args.file, text, args.mode)


if __name__ == "__main__":
    _main()
