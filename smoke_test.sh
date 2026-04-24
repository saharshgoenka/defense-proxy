#!/bin/bash
.venv/bin/python -c "
import subprocess, sys, importlib.util, shutil
from pathlib import Path
HERE = Path('.').resolve()

def check_cai():
    # Try the expected venv location first, then fall back to PATH
    venv_path = HERE.parent / 'cai_env/bin/cai'
    if venv_path.exists():
        return True, str(venv_path)
    found = shutil.which('cai')
    return bool(found), found or 'not found'

def check_env_auth():
    p = HERE.parent / 'PentestGPT/.env.auth'
    return p.exists(), str(p)

cai_ok, cai_path = check_cai()
env_ok, env_path = check_env_auth()

checks = [
    ('Docker running',       subprocess.run(['docker','info'], capture_output=True).returncode == 0, ''),
    ('mitmproxy installed',  importlib.util.find_spec('mitmproxy') is not None, ''),
    ('PyYAML installed',     importlib.util.find_spec('yaml') is not None, ''),
    ('CAI binary',           cai_ok,  cai_path),
    ('pentestgpt image',     subprocess.run(['docker','image','inspect','pentestgpt:latest'], capture_output=True).returncode == 0, ''),
    ('.env.auth',            env_ok,  env_path),
    ('config.yaml',          (HERE / 'config.yaml').exists(), ''),
]
all_ok = True
for name, ok, detail in checks:
    tag = 'OK  ' if ok else 'FAIL'
    suffix = f'  ({detail})' if detail and not ok else ''
    print(f\"[{tag}] {name}{suffix}\")
    if not ok: all_ok = False
sys.exit(0 if all_ok else 1)
" && .venv/bin/python run_experiments.py . \
    --agent pentestgpt --replicas 1 --workers 1 \
    --proxy-port-base 8081 --juice-port-base 3001 \
    --results-dir /tmp/smoke_test
