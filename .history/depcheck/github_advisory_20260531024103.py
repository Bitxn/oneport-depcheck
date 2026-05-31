import requests

GHSA_API = "https://api.github.com/advisories"
GHSA_PACKAGE_URL = "https://api.github.com/advisories?affects={name}&ecosystem=pip&per_page=10"


def query_github_advisories(name: str, version: str) -> list[dict]:
    """
    Query GitHub Advisory Database for a PyPI package.
    Returns list of advisory dicts with severity, CVE IDs, summary, and patched versions.
    """
    url = GHSA_PACKAGE_URL.format(name=name)
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

    try:
        resp = requests.get(url, headers=headers, timeout=6)
        if resp.status_code != 200:
            return []
        advisories = resp.json()
    except Exception:
        return []

    results = []
    for adv in advisories:
        # Check if this advisory affects the specific version we have
        affected_versions = []
        patched_versions = []

        for vuln in adv.get("vulnerabilities", []):
            pkg = vuln.get("package", {})
            if pkg.get("ecosystem", "").lower() != "pip":
                continue
            if pkg.get("name", "").lower() != name.lower():
                continue

            affected_versions.extend(vuln.get("vulnerable_version_range", []) or [])
            patched_versions.extend(vuln.get("patched_versions", []) or [])

        if not affected_versions and not patched_versions:
            continue

        severity = adv.get("severity", "UNKNOWN").upper()
        if severity == "MODERATE":
            severity = "MEDIUM"

        cve_ids = [c["value"] for c in adv.get("cve_id", []) or []
                   if isinstance(c, dict)] if adv.get("cve_id") else []
        if isinstance(adv.get("cve_id"), str) and adv["cve_id"]:
            cve_ids = [adv["cve_id"]]

        results.append({
            "source": "GitHub Advisory",
            "ghsa_id": adv.get("ghsa_id", ""),
            "cve_ids": cve_ids,
            "severity": severity,
            "summary": adv.get("summary", "No description."),
            "description": adv.get("description", ""),
            "published_at": adv.get("published_at", ""),
            "patched_versions": patched_versions,
            "affected_versions": affected_versions,
            "references": [r.get("url", "") for r in adv.get("references", [])],
        })

    return results


def enrich_with_github(scan_results: list[dict]) -> list[dict]:
    """
    Take existing scan results and add GHSA data where available.
    Merges into existing entries or adds new ones.
    """
    enriched = list(scan_results)
    existing_packages = {r["name"].lower() for r in scan_results}

    # For packages already found by OSV, add GHSA references
    for result in enriched:
        ghsa_findings = query_github_advisories(result["name"], result["version"])
        if ghsa_findings:
            existing_ids = set(result.get("ids", []))
            for finding in ghsa_findings:
                new_ids = [finding["ghsa_id"]] + finding["cve_ids"]
                for nid in new_ids:
                    if nid and nid not in existing_ids:
                        result["ids"].append(nid)
                        existing_ids.add(nid)
                # Upgrade severity if GHSA says worse
                sev_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
                current_idx = sev_order.index(result.get("severity", "UNKNOWN"))
                new_idx = sev_order.index(finding.get("severity", "UNKNOWN"))
                if new_idx > current_idx and finding["severity"] != "UNKNOWN":
                    result["severity"] = finding["severity"]
                if not result.get("references"):
                    result["references"] = finding["references"]

    return enriched