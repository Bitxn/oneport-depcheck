import json
import os
from datetime import datetime, timezone

AUDIT_LOG_PATH = os.path.join(os.path.expanduser("~"), ".depcheck", "audit.jsonl")


def _ensure_dir():
    os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)


def log_scan(
    packages_scanned: int,
    findings: list[dict],
    supply_chain: list[dict],
    license_issues: list[dict],
    policy_violations: list[dict],
    scan_target: str = "unknown",
    extra: dict = None,
) -> str:
    """Append one scan record to the audit log. Returns the log path."""
    _ensure_dir()

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_target": scan_target,
        "packages_scanned": packages_scanned,
        "findings_count": len(findings),
        "severity_breakdown": severity_counts,
        "supply_chain_count": len(supply_chain),
        "license_issues_count": len(license_issues),
        "policy_violations_count": len(policy_violations),
        "cve_ids": [
            cve for f in findings
            for cve in f.get("ids", [])
            if cve.startswith("CVE-")
        ][:20],
        "extra": extra or {},
    }

    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    return AUDIT_LOG_PATH


def read_audit_log(last_n: int = 20) -> list[dict]:
    """Read the last N scan records from the audit log."""
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    records = []
    try:
        with open(AUDIT_LOG_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except Exception:
        pass
    return records[-last_n:]


def export_audit_log_pdf(output_path: str = "depcheck-audit.json") -> str:
    """Export full audit log as JSON for compliance teams."""
    records = read_audit_log(last_n=9999)
    with open(output_path, "w") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(),
                   "total_scans": len(records),
                   "scans": records}, f, indent=2)
    return output_path