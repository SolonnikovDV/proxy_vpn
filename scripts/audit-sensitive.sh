#!/usr/bin/env bash
# Scan repository for potentially sensitive data accidentally committed.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(".").resolve()
ignore_dirs = {".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache"}
ignore_suffixes = {".pyc", ".pyo", ".db"}
ignore_files = {"scripts/audit-sensitive.sh"}

patterns = [
    re.compile(r"BEGIN (RSA|OPENSSH|EC) PRIVATE KEY"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-"),
    re.compile(r"-----BEGIN"),
]

violations = []

for p in root.rglob("*"):
    if not p.is_file():
        continue
    parts = set(p.relative_to(root).parts)
    rel = str(p.relative_to(root))
    if parts & ignore_dirs:
        continue
    if rel in ignore_files:
        continue
    if p.suffix.lower() in ignore_suffixes:
        continue
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    for pat in patterns:
        m = pat.search(text)
        if m:
            violations.append(f"{p.relative_to(root)}: pattern={pat.pattern}")
            break

env_prod = root / ".env.prod.example"
if env_prod.exists():
    txt = env_prod.read_text(encoding="utf-8", errors="ignore")
    if re.search(r"^APP_SECRET_KEY=", txt, flags=re.M) or re.search(r"^ADMIN_PASSWORD=", txt, flags=re.M):
        violations.append(".env.prod.example: inline APP_SECRET_KEY/ADMIN_PASSWORD is not allowed")

if violations:
    print("Potential sensitive content found:")
    for v in violations:
        print(f"- {v}")
    sys.exit(1)

print("Sensitive data audit passed.")
PY
