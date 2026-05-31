import json
import os
import subprocess
import requests

OSV_API = "https://api.osv.dev/v1/query"


def get_npm_packages(project_path: str = ".") -> list[tuple[str, str]]:
    """
    Read packages from package-lock.json or package.json.
    Returns list of (name, version) tuples.
    """
    lockfile = os.path.join(project_path, "package-lock.json")
    pkgfile = os.path.join(project_path, "package.json")

    # Prefer lockfile — has exact resolved versions
    if os.path.exists(lockfile):
        return _parse_lockfile(lockfile)
    elif os.path.exists(pkgfile):
        return _parse_packagejson(pkgfile)
    return []


def _parse_lockfile(path: str) -> list[tuple[str, str]]:
    packages = []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        # npm lockfile v2/v3 format
        pkgs = data.get("packages", {})
        for key, info in pkgs.items():
            if not key or key == "":
                continue
            name = key.replace("node_modules/", "").split("node_modules/")[-1]
            version = info.get("version", "unknown")
            if name and version:
                packages.append((name, version))

        # Fallback: lockfile v1 format
        if not packages:
            deps = data.get("dependencies", {})
            for name, info in deps.items():
                version = info.get("version", "unknown")
                packages.append((name, version))

    except Exception:
        pass
    return packages


def _parse_packagejson(path: str) -> list[tuple[str, str]]:
    packages = []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for section in ("dependencies", "devDependencies"):
            for name, version_spec in data.get(section, {}).items():
                # Strip semver operators
                version = version_spec.lstrip("^~>=<").split(" ")[0]
                packages.append((name, version))
    except Exception:
        pass
    return packages


def query_osv_npm(name: str, version: str) -> list[dict]:
    """Query OSV for an npm package."""
    from .cache import cache_get, cache_set
    cache_key = f"osv:npm:{name}:{version}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    payload = {
        "package": {"name": name, "ecosystem": "npm"},
        "version": version,
    }
    try:
        resp = requests.post(OSV_API, json=payload, timeout=5)
        if resp.status_code == 200:
            result = resp.json().get("vulns", [])
            cache_set(cache_key, result)
            return result
    except Exception:
        pass
    return []


def scan_npm_packages(packages: list[tuple[str, str]]) -> list[dict]:
    """Scan npm packages for vulnerabilities. Same output format as PyPI scanner."""
    from .scanner import classify_severity
    results = []
    for name, version in packages:
        vulns = query_osv_npm(name, version)
        for vuln in vulns:
            ids = vuln.get("aliases", []) or [vuln.get("id", "")]
            summary = vuln.get("summary", "No description.")
            severity = classify_severity(vuln)
            fix_version = None
            for affected in vuln.get("affected", []):
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fix_version = event["fixed"]
                            break
            results.append({
                "name": name,
                "version": version,
                "ecosystem": "npm",
                "severity": severity,
                "ids": ids,
                "summary": summary,
                "fix_version": fix_version,
            })
    return results