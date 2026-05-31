import json
import hashlib
import os
from datetime import datetime, timezone, timedelta

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".depcheck", "cache")
CACHE_TTL_HOURS = 24


def _cache_path(key: str) -> str:
    os.makedirs(CACHE_DIR, exist_ok=True)
    hashed = hashlib.sha256(key.encode()).hexdigest()[:16]
    return os.path.join(CACHE_DIR, f"{hashed}.json")


def cache_get(key: str) -> dict | None:
    path = _cache_path(key)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            entry = json.load(f)
        cached_at = datetime.fromisoformat(entry["cached_at"])
        if datetime.now(timezone.utc) - cached_at > timedelta(hours=CACHE_TTL_HOURS):
            os.remove(path)
            return None
        return entry["data"]
    except Exception:
        return None


def cache_set(key: str, data) -> None:
    path = _cache_path(key)
    try:
        with open(path, "w") as f:
            json.dump({"cached_at": datetime.now(timezone.utc).isoformat(), "data": data}, f)
    except Exception:
        pass


def cache_clear() -> int:
    if not os.path.exists(CACHE_DIR):
        return 0
    count = 0
    for f in os.listdir(CACHE_DIR):
        if f.endswith(".json"):
            os.remove(os.path.join(CACHE_DIR, f))
            count += 1
    return count


def cache_stats() -> dict:
    if not os.path.exists(CACHE_DIR):
        return {"entries": 0, "size_kb": 0}
    files = [f for f in os.listdir(CACHE_DIR) if f.endswith(".json")]
    size = sum(os.path.getsize(os.path.join(CACHE_DIR, f)) for f in files)
    return {"entries": len(files), "size_kb": round(size / 1024, 1)}