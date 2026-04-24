#!/bin/bash
.venv/bin/python -c "
import subprocess, sys, importlib.util
from pathlib import Path
HERE = Path('.')
checks = [
    ('Docker running',        subprocess.run(['docker','info'], capture_output=True).returncode == 0),
    ('mitmproxy installed',   importlib.util.find_spec('mitmproxy') is not None),
    ('PyYAML installed',      importlib.util.find_spec('yaml') is not None),
    ('CAI binary',            (HERE.parent / 'cai_env/bin/cai').exists()),
    ('pentestgpt image',      subprocess.run(['docker','image','inspect','pentestgpt:latest'], capture_output=True).returncode == 0),
    ('.env.auth',             (HERE.parent / 'PentestGPT/.env.auth').exists()),
    ('config.yaml',           (HERE / 'config.yaml').exists()),
]
all_ok = True
for name, ok in checks:
    print(f\"[{'OK  ' if ok else 'FAIL'}] {name}\")
    if not ok: all_ok = False
sys.exit(0 if all_ok else 1)
" && .venv/bin/python run_experiments.py . \
    --agent pentestgpt --replicas 1 --workers 1 \
    --proxy-port-base 8081 --juice-port-base 3001 \
    --results-dir /tmp/smoke_test
