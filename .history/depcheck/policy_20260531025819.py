import json
import os
from pathlib import Path


DEFAULT_POLICY = {
    "block_licenses": ["GPL-2.0", "GPL-3.0", "AGPL-3.0"],
    "review_licenses": ["LGPL-2.1", "LGPL-3.0", "MPL-2.0"],
    "fail_on_severity": ["CRITICAL"],
    "allowlist_packages": [],
    "blocklist_packages": [],
    "max_age_days": None,
    "require_fix_available": False,
}

POLICY_FILENAMES = [".depcheck-policy.json", "depcheck-policy.json"]


def load_policy(path: str = None) -> dict:
    """
    Load policy from a JSON file. Searches current dir then home dir.
    Returns merged dict (user policy overrides defaults).
    """
    policy = dict(DEFAULT_POLICY)

    search_paths = []
    if path:
        search_paths.append(path)
    for name in POLICY_FILENAMES:
        search_paths.append(name)
        search_paths.append(os.path.join(os.path.expanduser("~"), ".depcheck", name))

    for p in search_paths:
        if os.path.exists(p):
            try:
                with open(p) as f:
                    user_policy = json.load(f)
                policy.update(user_policy)
                policy["_loaded_from"] = p
                break
            except Exception:
                pass

    return policy


def apply_policy(results: list[dict], license_findings: list[dict], policy: dict) -> list[dict]:
    """
    Apply policy rules to scan results and license findings.
    Returns a list of policy violation dicts.
    """
    violations = []
    allowlist = {p.lower() for p in policy.get("allowlist_packages", [])}
    blocklist = {p.lower() for p in policy.get("blocklist_packages", [])}
    fail_severities = set(policy.get("fail_on_severity", []))
    block_licenses = set(policy.get("block_licenses", []))
    require_fix = policy.get("require_fix_available", False)

    for result in results:
        name = result["name"]
        if name.lower() in allowlist:
            continue

        if name.lower() in blocklist:
            violations.append({
                "type": "BLOCKLISTED",
                "severity": "CRITICAL",
                "package": name,
                "version": result["version"],
                "detail": f"'{name}' is explicitly blocked by your org policy.",
                "rule": "blocklist_packages",
            })
            continue

        if result.get("severity") in fail_severities:
            violations.append({
                "type": "SEVERITY_THRESHOLD",
                "severity": result["severity"],
                "package": name,
                "version": result["version"],
                "detail": f"{result['severity']} vulnerability found: {', '.join(result.get('ids', [])[:2])}",
                "rule": "fail_on_severity",
            })

        if require_fix and not result.get("fix_version"):
            violations.append({
                "type": "NO_FIX_AVAILABLE",
                "severity": result.get("severity", "UNKNOWN"),
                "package": name,
                "version": result["version"],
                "detail": "Vulnerable with no fix available — policy requires a fix to exist.",
                "rule": "require_fix_available",
            })

    for lic in license_findings:
        name = lic["package"]
        if name.lower() in allowlist:
            continue
        license_str = lic.get("license", "")
        if any(bl.upper() in license_str.upper() for bl in block_licenses):
            violations.append({
                "type": "LICENSE_BLOCKED",
                "severity": "CRITICAL",
                "package": name,
                "version": lic.get("version", ""),
                "detail": f"License '{license_str}' is blocked by org policy.",
                "rule": "block_licenses",
            })

    return violations


def generate_policy_template(output_path: str = ".depcheck-policy.json") -> str:
    """Write a starter policy file the team can customise."""
    template = {
        "_comment": "oneport-depcheck org policy — edit and commit to your repo root",
        "fail_on_severity": ["CRITICAL", "HIGH"],
        "block_licenses": ["GPL-2.0", "GPL-3.0", "AGPL-3.0"],
        "review_licenses": ["LGPL-2.1", "LGPL-3.0", "MPL-2.0"],
        "allowlist_packages": [],
        "blocklist_packages": [],
        "require_fix_available": False,
        "max_age_days": None,
    }
    with open(output_path, "w") as f:
        json.dump(template, f, indent=2)
    return output_path