import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_cvss_from_nvd(cve_id: str) -> dict | None:
    """
    Fetch CVSS v3 score, vector, and description from NVD for a given CVE ID.
    Returns dict with score, severity, vector, description or None on failure.
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return None

    try:
        resp = requests.get(
            NVD_API,
            params={"cveId": cve_id},
            headers={"Accept": "application/json"},
            timeout=8,
        )
        if resp.status_code != 200:
            return None

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        cve_data = vulns[0].get("cve", {})
        metrics = cve_data.get("metrics", {})

        # Try CVSS v3.1 first, then v3.0, then v2
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                vector = cvss_data.get("vectorString", "")
                severity = entries[0].get("baseSeverity") or cvss_data.get("baseSeverity", "")

                if score is not None:
                    return {
                        "cve_id": cve_id,
                        "score": float(score),
                        "severity": severity.upper() if severity else _score_to_severity(float(score)),
                        "vector": vector,
                        "version": "3.1" if key == "cvssMetricV31" else ("3.0" if key == "cvssMetricV30" else "2.0"),
                        "description": _get_description(cve_data),
                        "published": cve_data.get("published", ""),
                        "last_modified": cve_data.get("lastModified", ""),
                        "references": [
                            r.get("url", "") for r in cve_data.get("references", [])[:5]
                        ],
                    }
    except Exception:
        pass

    return None


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "UNKNOWN"


def _get_description(cve_data: dict) -> str:
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def enrich_with_nvd(scan_results: list[dict]) -> list[dict]:
    """
    For each finding that has a CVE ID, fetch the full NVD record and
    attach the CVSS score, vector, and detailed description.
    NVD rate-limits to 5 req/sec without an API key — we sleep between calls.
    """
    import time

    for result in scan_results:
        cve_ids = [i for i in result.get("ids", []) if i.startswith("CVE-")]
        if not cve_ids:
            continue

        # Use the first CVE ID for enrichment
        nvd_data = get_cvss_from_nvd(cve_ids[0])
        if nvd_data:
            result["cvss_score"] = nvd_data["score"]
            result["cvss_vector"] = nvd_data["vector"]
            result["cvss_version"] = nvd_data["version"]
            result["nvd_description"] = nvd_data["description"]
            result["nvd_published"] = nvd_data["published"]
            result["nvd_references"] = nvd_data["references"]
            # Override severity with NVD's authoritative score
            result["severity"] = nvd_data["severity"]

        time.sleep(0.2)  # stay under NVD rate limit

    return scan_results