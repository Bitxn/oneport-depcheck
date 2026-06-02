from .epss import get_epss_scores, epss_label


SEVERITY_BASE = {
    "CRITICAL": 40,
    "HIGH": 30,
    "MEDIUM": 15,
    "LOW": 5,
    "UNKNOWN": 8,
}


def compute_risk_scores(findings: list[dict]) -> list[dict]:
    """
    Compute a 0–100 composite risk score for each finding.

    Formula:
      base        = severity base score (CRITICAL=40, HIGH=30 ...)
      cvss_bonus  = (cvss_score / 10) * 25        → max 25
      epss_bonus  = epss_score * 25                → max 25
      reachable   = +10 if imported in codebase
      ─────────────────────────────────────────────────────
      total       = min(base + cvss + epss + reach, 100)

    Then sort descending — index 0 = fix first.
    """
    all_cves = [
        cve for f in findings
        for cve in f.get("ids", [])
        if cve.startswith("CVE-")
    ]
    epss_data = get_epss_scores(all_cves)

    for finding in findings:
        base = SEVERITY_BASE.get(finding.get("severity", "UNKNOWN"), 8)

        cvss_score = finding.get("cvss_score")
        cvss_bonus = (float(cvss_score) / 10.0) * 25 if cvss_score else 0

        cve_ids = [i for i in finding.get("ids", []) if i.startswith("CVE-")]
        epss_score = 0.0
        epss_pct = 0.0
        for cve in cve_ids:
            entry = epss_data.get(cve, {})
            epss_score = max(epss_score, entry.get("epss", 0.0))
            epss_pct = max(epss_pct, entry.get("percentile", 0.0))

        epss_bonus = epss_score * 25
        reachable_bonus = 10 if finding.get("reachable", True) else 0

        total = min(round(base + cvss_bonus + epss_bonus + reachable_bonus), 100)

        finding["risk_score"] = total
        finding["epss_score"] = round(epss_score, 4)
        finding["epss_percentile"] = round(epss_pct, 4)
        finding["epss_label"] = epss_label(epss_score)
        finding["risk_label"] = _risk_label(total)
        finding["fix_priority"] = None  # set after sorting

    findings.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    for i, f in enumerate(findings):
        f["fix_priority"] = i + 1

    return findings


def _risk_label(score: int) -> str:
    if score >= 80:
        return "URGENT"
    elif score >= 60:
        return "HIGH RISK"
    elif score >= 35:
        return "MODERATE"
    else:
        return "LOW RISK"


def print_risk_table(findings: list[dict], console) -> None:
    """Print a ranked fix-this-first table using Rich."""
    from rich.table import Table
    from rich import box
    from rich.text import Text

    if not findings:
        console.print("[green]  No findings to rank.[/green]\n")
        return

    table = Table(box=box.ROUNDED, show_header=True,
                  header_style="bold white", title="Fix priority ranking")
    table.add_column("#", width=4)
    table.add_column("Risk", width=11)
    table.add_column("Score", width=7)
    table.add_column("Package", width=20)
    table.add_column("CVE", width=20)
    table.add_column("CVSS", width=6)
    table.add_column("EPSS", width=18)
    table.add_column("Reachable", width=10)
    table.add_column("Fix", width=14)

    risk_colors = {
        "URGENT": "bold red",
        "HIGH RISK": "red",
        "MODERATE": "yellow",
        "LOW RISK": "cyan",
    }

    for f in findings:
        color = risk_colors.get(f.get("risk_label", ""), "white")
        cve = next((i for i in f.get("ids", []) if i.startswith("CVE-")), "")
        cvss = f"{f['cvss_score']:.1f}" if f.get("cvss_score") else "—"
        epss_str = f"{f['epss_score']*100:.1f}% ({f['epss_label']})" if f.get("epss_score") else "—"
        reachable = (Text("yes", style="bold red") if f.get("reachable")
                     else Text("no", style="dim"))
        fix = f.get("fix_version") or "—"

        table.add_row(
            str(f.get("fix_priority", "")),
            Text(f.get("risk_label", ""), style=color),
            Text(str(f.get("risk_score", "")), style=color),
            f"{f['name']} {f['version']}",
            cve[:20],
            cvss,
            epss_str,
            reachable,
            fix,
        )

    console.print(table)
    console.print()