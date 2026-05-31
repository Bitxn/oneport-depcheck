import json
import os
import requests

SLACK_WEBHOOK_ENV = "DEPCHECK_SLACK_WEBHOOK"
SEVERITY_EMOJI = {
    "CRITICAL": ":red_circle:",
    "HIGH": ":orange_circle:",
    "MEDIUM": ":yellow_circle:",
    "LOW": ":white_circle:",
}


def _get_webhook(webhook_url: str = None) -> str | None:
    return webhook_url or os.environ.get(SLACK_WEBHOOK_ENV)


def send_slack_alert(
    findings: list[dict],
    supply_chain: list[dict],
    policy_violations: list[dict],
    scan_target: str = "unknown",
    webhook_url: str = None,
    min_severity: str = "HIGH",
) -> bool:
    """
    Send a Slack message summarising critical findings.
    Returns True if message was sent successfully.
    Set DEPCHECK_SLACK_WEBHOOK env var or pass webhook_url directly.
    """
    webhook = _get_webhook(webhook_url)
    if not webhook:
        return False

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    min_idx = severity_order.index(min_severity) if min_severity in severity_order else 1
    important = [f for f in findings
                 if severity_order.index(f.get("severity", "UNKNOWN")) <= min_idx]

    if not important and not supply_chain and not policy_violations:
        return False

    counts = {}
    for f in findings:
        s = f.get("severity", "UNKNOWN")
        counts[s] = counts.get(s, 0) + 1

    summary_parts = [f"{SEVERITY_EMOJI.get(s, '')} *{c} {s}*"
                     for s, c in counts.items() if c > 0]

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "oneport-depcheck — Vulnerability Alert"}
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Scan target:* `{scan_target}`\n" +
                        ("  ".join(summary_parts) if summary_parts else "No CVEs found")
            }
        },
    ]

    # Top critical/high findings
    top = sorted(important, key=lambda x: severity_order.index(x.get("severity", "UNKNOWN")))[:5]
    if top:
        finding_lines = []
        for f in top:
            emoji = SEVERITY_EMOJI.get(f["severity"], "")
            ids = ", ".join(f.get("ids", [])[:2])
            fix = f"→ fix: `{f['name']}=={f['fix_version']}`" if f.get("fix_version") else "→ no fix available"
            finding_lines.append(f"{emoji} *{f['name']}* `{f['version']}` — {ids}\n   {fix}")
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "\n".join(finding_lines)}
        })

    # Supply chain alerts
    if supply_chain:
        sc_lines = [f":warning: *{s['type']}* — `{s['package']}`: {s['detail']}"
                    for s in supply_chain[:3]]
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": "*Supply chain anomalies:*\n" + "\n".join(sc_lines)}
        })

    # Policy violations
    if policy_violations:
        pv_lines = [f":no_entry: *{v['type']}* — `{v['package']}`: {v['detail']}"
                    for v in policy_violations[:3]]
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": "*Policy violations:*\n" + "\n".join(pv_lines)}
        })

    blocks.append({"type": "divider"})
    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn",
                      "text": "Run `depcheck scan --fix` to see upgrade commands"}]
    })

    try:
        resp = requests.post(webhook, json={"blocks": blocks}, timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


def send_generic_webhook(
    findings: list[dict],
    supply_chain: list[dict],
    webhook_url: str,
    scan_target: str = "unknown",
) -> bool:
    """Send a plain JSON payload to any webhook (Teams, Discord, custom)."""
    payload = {
        "tool": "oneport-depcheck",
        "scan_target": scan_target,
        "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
        "high": sum(1 for f in findings if f.get("severity") == "HIGH"),
        "supply_chain_alerts": len(supply_chain),
        "top_findings": [
            {"package": f["name"], "version": f["version"],
             "severity": f["severity"], "ids": f.get("ids", [])[:2]}
            for f in findings[:10]
        ],
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=5)
        return resp.status_code < 400
    except Exception:
        return False