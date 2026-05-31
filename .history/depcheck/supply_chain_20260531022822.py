import re
import requests
from datetime import datetime, timezone
from packaging.version import Version, InvalidVersion


PYPI_API = "https://pypi.org/pypi/{name}/json"

KNOWN_TYPOSQUATS = [
    ("requests", ["request", "requets", "requestss", "reqests"]),
    ("numpy", ["nummpy", "nupy", "numppy", "numpy-python"]),
    ("pandas", ["panda", "pandass", "pndas"]),
    ("flask", ["falsk", "flaskk", "flaask"]),
    ("django", ["dajngo", "djang0", "djanggo"]),
    ("boto3", ["botto3", "boto-3", "botto"]),
    ("setuptools", ["setuptool", "setup-tools", "setuptoolz"]),
    ("urllib3", ["urlib3", "urllib-3", "urllib2"]),
    ("cryptography", ["cryptograpy", "cyrptography", "cryptographyy"]),
    ("pillow", ["pillow-python", "pillo", "pilllow"]),
]

INFLATED_VERSION_PATTERN = re.compile(
    r"^(\d{3,})\.\d+\.\d+$|^\d+\.(\d{3,})\.\d+$|^\d+\.\d+\.(\d{3,})$"
)

SUSPICIOUS_INSTALL_SCRIPTS = ["preinstall", "postinstall", "install"]


def check_version_inflation(name: str, version: str) -> dict | None:
    """Flag versions like 100.0.0, 99.99.99 — classic dependency confusion pattern."""
    if INFLATED_VERSION_PATTERN.match(version):
        return {
            "type": "VERSION_INFLATION",
            "severity": "HIGH",
            "package": name,
            "version": version,
            "detail": f"Version {version} looks inflated — matches dependency confusion attack pattern.",
            "action": "Block installation immediately. Verify on PyPI.",
        }
    return None


def check_typosquatting(name: str) -> dict | None:
    """Check if the package name looks like a typosquat of a popular library."""
    name_lower = name.lower().replace("-", "").replace("_", "")
    for legit, squats in KNOWN_TYPOSQUATS:
        legit_clean = legit.replace("-", "").replace("_", "")
        squats_clean = [s.replace("-", "").replace("_", "") for s in squats]
        if name_lower in squats_clean:
            return {
                "type": "TYPOSQUATTING",
                "severity": "CRITICAL",
                "package": name,
                "version": None,
                "detail": f"'{name}' closely resembles the legitimate package '{legit}'.",
                "action": f"Remove immediately. Install '{legit}' instead.",
            }
    return None


def check_recently_published(name: str, version: str) -> dict | None:
    """
    Query PyPI to see if this specific version was published very recently (within 48 hours).
    A brand-new version of a stable package warrants extra scrutiny.
    """
    url = PYPI_API.format(name=name)
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return None
        data = resp.json()
        releases = data.get("releases", {})
        if version not in releases:
            return None
        release_files = releases[version]
        if not release_files:
            return None

        upload_time_str = release_files[0].get("upload_time_iso_8601") or release_files[0].get("upload_time")
        if not upload_time_str:
            return None

        upload_time = datetime.fromisoformat(upload_time_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        hours_since = (now - upload_time).total_seconds() / 3600

        if hours_since < 48:
            return {
                "type": "RECENTLY_PUBLISHED",
                "severity": "MEDIUM",
                "package": name,
                "version": version,
                "detail": f"Version {version} was published {hours_since:.1f} hours ago.",
                "action": "Review carefully before using. Wait 48–72 hours unless urgent.",
            }
    except Exception:
        pass
    return None


def check_package_exists_on_pypi(name: str) -> dict | None:
    """
    Check if the package even exists on PyPI. If not, it may be an internal
    package name that an attacker has registered publicly (dependency confusion).
    """
    url = PYPI_API.format(name=name)
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 404:
            return {
                "type": "NOT_ON_PYPI",
                "severity": "HIGH",
                "package": name,
                "version": None,
                "detail": f"'{name}' is not found on PyPI. Could be an internal package name exposed to dependency confusion.",
                "action": "Ensure this package is only sourced from your private registry.",
            }
    except Exception:
        pass
    return None


def run_supply_chain_checks(packages: list[tuple[str, str]]) -> list[dict]:
    """
    Run all supply chain checks on a list of (name, version) tuples.
    Returns a list of anomaly dicts.
    """
    findings = []

    for name, version in packages:
        typo = check_typosquatting(name)
        if typo:
            findings.append(typo)
            continue  # no point checking further if it's a known squat

        if version and version != "unknown":
            inflation = check_version_inflation(name, version)
            if inflation:
                findings.append(inflation)
                continue

            recent = check_recently_published(name, version)
            if recent:
                findings.append(recent)

    return findings