import requests
from .cache import cache_get, cache_set

EPSS_API = "https://api.first.org/data/v1/epss"


def get_epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    """
    Fetch EPSS scores for a list of CVE IDs.
    Returns dict: { "CVE-2021-23337": { "epss": 0.042, "percentile": 0.91 } }
    EPSS score = probability of exploitation in next 30 days (0.0 to 1.0)
    """
    if not cve_ids:
        return {}

    results = {}
    uncached = []

    for cve in cve_ids:
        cached = cache_get(f"epss:{cve}")
        if cached is not None:
            results[cve] = cached
        else:
            uncached.append(cve)

    if not uncached:
        return results

    # EPSS API accepts comma-separated CVE IDs, max 100 per call
    for i in range(0, len(uncached), 100):
        batch = uncached[i:i+100]
        try:
            resp = requests.get(
                EPSS_API,
                params={"cve": ",".join(batch)},
                timeout=8,
            )
            if resp.status_code != 200:
                continue
            data = resp.json().get("data", [])
            for entry in data:
                cve_id = entry.get("cve", "")
                score_data = {
                    "epss": float(entry.get("epss", 0)),
                    "percentile": float(entry.get("percentile", 0)),
                }
                results[cve_id] = score_data
                cache_set(f"epss:{cve_id}", score_data)
        except Exception:
            pass

    return results


def epss_label(score: float) -> str:
    """Human-readable label for EPSS score."""
    if score >= 0.5:
        return "actively exploited"
    elif score >= 0.1:
        return "high exploit probability"
    elif score >= 0.01:
        return "some exploit activity"
    else:
        return "low exploit probability"