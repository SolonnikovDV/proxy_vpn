#!/usr/bin/env bash
# Scan repository for potentially sensitive data accidentally committed.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(".").resolve()
ignore_suffixes = {".pyc", ".pyo", ".db", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf"}
ignore_files = {"scripts/audit-sensitive.sh"}

patterns = [
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key ID
    re.compile(r"ASIA[0-9A-Z]{16}"),  # AWS STS Access Key ID
    re.compile(r"(?i)aws(.{0,20})?(secret|access).{0,20}?['\"][A-Za-z0-9/+]{30,}={0,2}['\"]"),
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),  # Google API key
    re.compile(r"sk_(live|test)_[0-9a-zA-Z]{20,}"),  # Stripe-like
]

violations = []
tracked = []

try:
    out = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    tracked = [p for p in out.decode("utf-8", errors="ignore").split("\x00") if p]
except Exception as e:
    print(f"Failed to enumerate tracked files: {e}")
    sys.exit(2)

for rel in tracked:
    p = root / rel
    if not p.is_file():
        continue
    if rel in ignore_files:
        continue
    if p.suffix.lower() in ignore_suffixes:
        continue
    if p.stat().st_size > 1_000_000:
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

env_prod = root / ".env.production.example"
if env_prod.exists():
    txt = env_prod.read_text(encoding="utf-8", errors="ignore")
    # Production template must not contain inline long-lived secrets.
    if re.search(r"^APP_SECRET_KEY=", txt, flags=re.M) or re.search(r"^ADMIN_PASSWORD=", txt, flags=re.M):
        violations.append(".env.production.example: inline APP_SECRET_KEY/ADMIN_PASSWORD is not allowed")

if violations:
    print("Potential sensitive content found:")
    for v in violations:
        print(f"- {v}")
    sys.exit(1)

print("Sensitive data audit passed.")
PY
