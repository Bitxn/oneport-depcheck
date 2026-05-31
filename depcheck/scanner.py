import json
import subprocess
import sys
import importlib.metadata
import requests
from packaging.version import Version


OSV_API = "https://api.osv.dev/v1/query"


def get_installed_packages():
    """Return list of (name, version) tuples for all installed packages."""
    packages = []
    for dist in importlib.metadata.distributions():
        name = dist.metadata["Name"]
        version = dist.metadata["Version"]
        if name and version:
            packages.append((name, version))
    return packages


def get_packages_from_requirements(req_file):
    """Parse a requirements.txt and return (name, version) tuples."""
    packages = []
    with open(req_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Handle name==version, name>=version etc.
            for sep in ["==", ">=", "<=", "~=", "!="]:
                if sep in line:
                    name, version = line.split(sep, 1)
                    packages.append((name.strip(), version.strip()))
                    break
            else:
                packages.append((line, "unknown"))
    return packages


# Add this import at the top of scanner.py
from .cache import cache_get, cache_set

def query_osv(name: str, version: str) -> list:
    cache_key = f"osv:{name}:{version}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    payload = {
        "package": {"name": name, "ecosystem": "PyPI"},
        "version": version,
    }
    try:
        resp = requests.post(OSV_API, json=payload, timeout=5)
        if resp.status_code == 200:
            result = resp.json().get("vulns", [])
            cache_set(cache_key, result)
            return result
    except requests.RequestException:
        pass
    return []

def classify_severity(vuln):
    """Return CRITICAL / HIGH / MEDIUM / LOW from a vuln dict."""
    for severity in vuln.get("severity", []):
        score_str = severity.get("score", "")
        if score_str.startswith("CVSS"):
            # Extract numeric score from e.g. "CVSS:3.1/AV:N/AC:L/..."
            try:
                parts = score_str.split("/")
                for p in parts:
                    if p.startswith("CVSS:"):
                        continue
                    # Rough fallback
                pass
            except Exception:
                pass
        rating = severity.get("type", "")
        if rating == "CVSS_V3":
            try:
                score = float(severity.get("score", 0))
                if score >= 9.0:
                    return "CRITICAL"
                elif score >= 7.0:
                    return "HIGH"
                elif score >= 4.0:
                    return "MEDIUM"
                else:
                    return "LOW"
            except (ValueError, TypeError):
                pass

    # Fallback: check database_specific
    db = vuln.get("database_specific", {})
    sev = db.get("severity", "").upper()
    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return sev

    return "UNKNOWN"


def scan_packages(packages):
    """
    Given a list of (name, version) tuples, query OSV and return results.
    Returns a list of dicts with keys: name, version, severity, ids, summary, fix.
    """
    results = []
    for name, version in packages:
        vulns = query_osv(name, version)
        for vuln in vulns:
            ids = vuln.get("aliases", []) or [vuln.get("id", "")]
            summary = vuln.get("summary", "No description available.")
            severity = classify_severity(vuln)

            # Try to extract a fix version
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
                "severity": severity,
                "ids": ids,
                "summary": summary,
                "fix_version": fix_version,
            })

    return results