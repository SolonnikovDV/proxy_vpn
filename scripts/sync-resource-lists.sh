#!/usr/bin/env bash
# Scheduled sync for proxy bypass whitelist and RKN blacklist from remote feeds.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }

python3 - <<'PY'
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def split_sources(raw: str) -> list[str]:
    text = str(raw or "").replace(",", "\n").replace(";", "\n")
    out: list[str] = []
    seen: set[str] = set()
    for part in text.splitlines():
        item = part.strip()
        if not item or item.startswith("#") or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def normalize_resource(raw: str) -> str:
    value = str(raw or "").strip().lower()
    if not value:
        return ""
    value = re.sub(r"^https?://", "", value)
    value = re.sub(r"^www\.", "", value)
    value = value.split("/", 1)[0].strip()
    value = value.split(":", 1)[0].strip()
    value = re.sub(r"\s+", "", value)
    if not value:
        return ""
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", value):
        return value
    if not re.match(r"^[a-z0-9][a-z0-9._-]*[a-z0-9]$", value):
        return ""
    return value[:255]


def extract_resources_from_json(value, out: set[str]) -> None:
    if isinstance(value, str):
        token = normalize_resource(value)
        if token:
            out.add(token)
        return
    if isinstance(value, dict):
        for v in value.values():
            extract_resources_from_json(v, out)
        return
    if isinstance(value, list):
        for v in value:
            extract_resources_from_json(v, out)


def parse_resources(text: str) -> list[str]:
    items: set[str] = set()
    raw = str(text or "")
    stripped = raw.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            obj = json.loads(stripped)
            extract_resources_from_json(obj, items)
        except Exception:
            pass
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        first = re.split(r"[\s,\t;]+", s, maxsplit=1)[0]
        token = normalize_resource(first)
        if token:
            items.add(token)
    return sorted(items)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def parse_whitelist_map(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in str(text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = [p.strip() for p in re.split(r"[,\t;]+", s) if p.strip()]
        if not parts:
            continue
        resource = normalize_resource(parts[0])
        if not resource:
            continue
        flag = "false"
        if len(parts) > 1 and str(parts[1]).strip().lower() in {"1", "true", "yes", "on"}:
            flag = "true"
        out[resource] = flag
    return out


def serialize_whitelist_map(items: dict[str, str]) -> str:
    rows = []
    for resource in sorted(items.keys()):
        flag = "true" if str(items[resource]).lower() == "true" else "false"
        rows.append(f"{resource},{flag}")
    return "\n".join(rows)


def serialize_resource_list(items: set[str]) -> str:
    return "\n".join(sorted(items))


def fetch_source(url: str, timeout: int, user_agent: str) -> str:
    if url.startswith("file://"):
        return read_text(Path(url[len("file://") :]))
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    return data.decode("utf-8", errors="replace")


repo_root = Path(".")
whitelist_path = Path(os.getenv("PROXY_BYPASS_RULES_PATH", "config/proxy-bypass-rules.txt"))
blacklist_path = Path(os.getenv("RKN_BLACKLIST_RULES_PATH", "config/rkn-blacklist-rules.txt"))
status_path = Path(os.getenv("LIST_SYNC_STATUS_PATH", "logs/list-sync-status.json"))
audit_path = Path(os.getenv("LIST_SYNC_AUDIT_PATH", "logs/list-sync-audit.jsonl"))
whitelist_sources = split_sources(os.getenv("PROXY_BYPASS_FEED_URLS", ""))
blacklist_sources = split_sources(os.getenv("RKN_BLACKLIST_FEED_URLS", ""))
whitelist_enabled = os.getenv("PROXY_BYPASS_SYNC_ENABLED", "1").strip() in {"1", "true", "yes", "on"}
blacklist_enabled = os.getenv("RKN_BLACKLIST_SYNC_ENABLED", "1").strip() in {"1", "true", "yes", "on"}
whitelist_mode = os.getenv("PROXY_BYPASS_SYNC_MODE", "merge").strip().lower()
blacklist_mode = os.getenv("RKN_BLACKLIST_SYNC_MODE", "merge").strip().lower()
preserve_force_vpn = os.getenv("PROXY_BYPASS_PRESERVE_FORCE_VPN_ON_REPLACE", "1").strip() in {"1", "true", "yes", "on"}
strict_mode = os.getenv("LIST_SYNC_STRICT", "0").strip() in {"1", "true", "yes", "on"}
http_timeout = max(3, int(float(os.getenv("LIST_SYNC_HTTP_TIMEOUT_SECONDS", "20"))))
max_items = max(100, int(float(os.getenv("LIST_SYNC_MAX_ITEMS", "15000"))))
user_agent = os.getenv("LIST_SYNC_USER_AGENT", "proxy-vpn-list-sync/1.0")

errors: list[str] = []
changed_whitelist = False
changed_blacklist = False
fetched_whitelist: set[str] = set()
fetched_blacklist: set[str] = set()

for src in whitelist_sources:
    try:
        for item in parse_resources(fetch_source(src, http_timeout, user_agent)):
            fetched_whitelist.add(item)
            if len(fetched_whitelist) >= max_items:
                break
    except Exception as e:
        errors.append(f"whitelist source error [{src}]: {e}")

for src in blacklist_sources:
    try:
        for item in parse_resources(fetch_source(src, http_timeout, user_agent)):
            fetched_blacklist.add(item)
            if len(fetched_blacklist) >= max_items:
                break
    except Exception as e:
        errors.append(f"blacklist source error [{src}]: {e}")

whitelist_before = parse_whitelist_map(read_text(whitelist_path))
blacklist_before = set(parse_resources(read_text(blacklist_path)))

whitelist_after = dict(whitelist_before)
if whitelist_enabled and whitelist_sources:
    if whitelist_mode == "replace":
        whitelist_after = {k: "false" for k in fetched_whitelist}
        if preserve_force_vpn:
            for k, v in whitelist_before.items():
                if str(v).lower() == "true":
                    whitelist_after[k] = "true"
    else:
        for k in fetched_whitelist:
            whitelist_after.setdefault(k, "false")

blacklist_after = set(blacklist_before)
if blacklist_enabled and blacklist_sources:
    if blacklist_mode == "replace":
        blacklist_after = set(fetched_blacklist)
    else:
        blacklist_after.update(fetched_blacklist)

whitelist_text_after = serialize_whitelist_map(whitelist_after)
blacklist_text_after = serialize_resource_list(blacklist_after)
whitelist_text_before = serialize_whitelist_map(whitelist_before)
blacklist_text_before = serialize_resource_list(blacklist_before)

if whitelist_text_after != whitelist_text_before:
    whitelist_path.parent.mkdir(parents=True, exist_ok=True)
    whitelist_path.write_text(whitelist_text_after + ("\n" if whitelist_text_after else ""), encoding="utf-8")
    changed_whitelist = True

if blacklist_text_after != blacklist_text_before:
    blacklist_path.parent.mkdir(parents=True, exist_ok=True)
    blacklist_path.write_text(blacklist_text_after + ("\n" if blacklist_text_after else ""), encoding="utf-8")
    changed_blacklist = True

status = {
    "status": "ok" if not errors else ("degraded" if not strict_mode else "error"),
    "updated_at": now_iso(),
    "whitelist": {
        "enabled": whitelist_enabled,
        "mode": whitelist_mode,
        "sources": whitelist_sources,
        "fetched_count": len(fetched_whitelist),
        "before_count": len(whitelist_before),
        "after_count": len(whitelist_after),
        "changed": changed_whitelist,
    },
    "blacklist": {
        "enabled": blacklist_enabled,
        "mode": blacklist_mode,
        "sources": blacklist_sources,
        "fetched_count": len(fetched_blacklist),
        "before_count": len(blacklist_before),
        "after_count": len(blacklist_after),
        "changed": changed_blacklist,
    },
    "errors": errors,
}

status_path.parent.mkdir(parents=True, exist_ok=True)
status_path.write_text(json.dumps(status, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

audit_path.parent.mkdir(parents=True, exist_ok=True)
with audit_path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(status, ensure_ascii=True) + "\n")

print("List sync status:", status["status"])
print(
    "Whitelist:",
    f"{status['whitelist']['before_count']} -> {status['whitelist']['after_count']}",
    "(changed)" if changed_whitelist else "(no changes)",
)
print(
    "Blacklist:",
    f"{status['blacklist']['before_count']} -> {status['blacklist']['after_count']}",
    "(changed)" if changed_blacklist else "(no changes)",
)
if errors:
    print("Warnings:")
    for e in errors[:20]:
        print("-", e)

if strict_mode and errors:
    sys.exit(2)
PY

