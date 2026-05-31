import requests


PYPI_API = "https://pypi.org/pypi/{name}/json"

# Risk levels for license types
LICENSE_RISK = {
    # BLOCKED — copyleft, forces open-sourcing your entire codebase
    "GPL-2.0": "BLOCKED",
    "GPL-3.0": "BLOCKED",
    "GNU General Public License v2 (GPLv2)": "BLOCKED",
    "GNU General Public License v3 (GPLv3)": "BLOCKED",
    "GPLv2": "BLOCKED",
    "GPLv3": "BLOCKED",
    "GPL v2": "BLOCKED",
    "GPL v3": "BLOCKED",
    "AGPL-3.0": "BLOCKED",
    "GNU Affero General Public License v3": "BLOCKED",
    "AGPLv3": "BLOCKED",

    # REVIEW — weak copyleft, may be okay but legal review required
    "LGPL-2.0": "REVIEW",
    "LGPL-2.1": "REVIEW",
    "LGPL-3.0": "REVIEW",
    "GNU Lesser General Public License v2 (LGPLv2)": "REVIEW",
    "GNU Lesser General Public License v3 (LGPLv3)": "REVIEW",
    "LGPLv2": "REVIEW",
    "LGPLv3": "REVIEW",
    "MPL-2.0": "REVIEW",
    "Mozilla Public License 2.0 (MPL 2.0)": "REVIEW",
    "EUPL-1.1": "REVIEW",
    "EUPL-1.2": "REVIEW",
    "OSL-3.0": "REVIEW",
    "CDDL-1.0": "REVIEW",
    "EPL-1.0": "REVIEW",
    "EPL-2.0": "REVIEW",

    # ALLOWED — permissive, commercial-friendly
    "MIT": "ALLOWED",
    "MIT License": "ALLOWED",
    "Apache-2.0": "ALLOWED",
    "Apache Software License": "ALLOWED",
    "Apache 2.0": "ALLOWED",
    "BSD-2-Clause": "ALLOWED",
    "BSD-3-Clause": "ALLOWED",
    "BSD License": "ALLOWED",
    "ISC": "ALLOWED",
    "ISC License (ISCL)": "ALLOWED",
    "Python Software Foundation License": "ALLOWED",
    "PSF": "ALLOWED",
    "Unlicense": "ALLOWED",
    "CC0-1.0": "ALLOWED",
    "Public Domain": "ALLOWED",
    "WTFPL": "ALLOWED",
    "Zlib": "ALLOWED",
    "Boost Software License 1.0 (BSL-1.0)": "ALLOWED",
}

RISK_DESCRIPTIONS = {
    "BLOCKED": "Copyleft — forces open-sourcing your commercial code. Do not use.",
    "REVIEW":  "Weak copyleft — may be usable, but requires legal sign-off first.",
    "ALLOWED": "Permissive — safe for commercial use.",
    "UNKNOWN": "License not found or not recognised. Manual review required.",
}


def _normalise_license(raw: str) -> str:
    """Strip common suffixes and extra whitespace for better matching."""
    return raw.strip().rstrip(";").strip()


def get_license_from_pypi(name: str) -> str:
    """Fetch the license string for a package from PyPI metadata."""
    url = PYPI_API.format(name=name)
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return "UNKNOWN"
        data = resp.json()
        info = data.get("info", {})

        # Primary field
        license_field = info.get("license") or ""
        if license_field and license_field.lower() not in ("unknown", ""):
            return _normalise_license(license_field)

        # Fallback: classifiers
        classifiers = info.get("classifiers", [])
        for c in classifiers:
            if c.startswith("License ::"):
                parts = c.split(" :: ")
                if len(parts) >= 3:
                    return _normalise_license(parts[-1])

        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def classify_license(license_str: str) -> str:
    """Return BLOCKED / REVIEW / ALLOWED / UNKNOWN for a license string."""
    if not license_str or license_str.upper() == "UNKNOWN":
        return "UNKNOWN"

    # Exact match first
    if license_str in LICENSE_RISK:
        return LICENSE_RISK[license_str]

    # Partial match — handles things like "MIT License" vs "MIT"
    upper = license_str.upper()
    if "AGPL" in upper:
        return "BLOCKED"
    if "GPL" in upper:
        # Distinguish LGPL from GPL
        if "LESSER" in upper or "LGPL" in upper:
            return "REVIEW"
        return "BLOCKED"
    if "LGPL" in upper:
        return "REVIEW"
    if "MPL" in upper or "MOZILLA" in upper:
        return "REVIEW"
    if "MIT" in upper:
        return "ALLOWED"
    if "APACHE" in upper:
        return "ALLOWED"
    if "BSD" in upper:
        return "ALLOWED"
    if "ISC" in upper:
        return "ALLOWED"
    if "PSF" in upper or "PYTHON SOFTWARE" in upper:
        return "ALLOWED"

    return "UNKNOWN"


def run_license_checks(packages: list[tuple[str, str]]) -> list[dict]:
    """
    Check licenses for all packages.
    Returns findings for BLOCKED, REVIEW, and UNKNOWN only.
    ALLOWED packages are silently passed — no noise.
    """
    findings = []

    for name, version in packages:
        license_str = get_license_from_pypi(name)
        risk = classify_license(license_str)

        if risk == "ALLOWED":
            continue  # no issue, skip

        findings.append({
            "package": name,
            "version": version,
            "license": license_str,
            "risk": risk,
            "detail": RISK_DESCRIPTIONS.get(risk, ""),
            "action": _suggest_action(risk, name),
        })

    return findings


def _suggest_action(risk: str, name: str) -> str:
    if risk == "BLOCKED":
        return f"Remove '{name}' or replace with a permissively licensed alternative."
    if risk == "REVIEW":
        return f"Escalate '{name}' to legal review before shipping to production."
    return f"Identify the license for '{name}' manually and confirm it is commercial-safe."