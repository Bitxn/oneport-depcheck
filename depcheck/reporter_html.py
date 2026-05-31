from datetime import datetime, timezone


def generate_html_report(
    findings: list[dict],
    supply_chain: list[dict],
    license_issues: list[dict],
    policy_violations: list[dict],
    packages_scanned: int,
    scan_target: str = "unknown",
    output_path: str = "depcheck-report.html",
) -> str:

    def sev_color(sev):
        return {"CRITICAL": "#E24B4A", "HIGH": "#EF9F27",
                "MEDIUM": "#BA7517", "LOW": "#1D9E75"}.get(sev, "#888780")

    def sev_bg(sev):
        return {"CRITICAL": "#FCEBEB", "HIGH": "#FAEEDA",
                "MEDIUM": "#FAEEDA", "LOW": "#E1F5EE"}.get(sev, "#F1EFE8")

    rows = ""
    for f in sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"].index(x.get("severity","UNKNOWN"))):
        ids = ", ".join(f.get("ids", [])[:3])
        fix = f.get("fix_version") or "—"
        cvss = f"{f['cvss_score']:.1f}" if f.get("cvss_score") else "—"
        sev = f.get("severity", "UNKNOWN")
        rows += f"""
        <tr>
          <td><span style="background:{sev_bg(sev)};color:{sev_color(sev)};
              padding:2px 8px;border-radius:4px;font-weight:600;font-size:12px">{sev}</span></td>
          <td><strong>{f['name']}</strong></td>
          <td>{f['version']}</td>
          <td style="font-size:12px">{ids}</td>
          <td style="font-size:12px">{f.get('summary','')[:80]}</td>
          <td>{cvss}</td>
          <td style="font-family:monospace;font-size:12px">{fix}</td>
        </tr>"""

    sc_rows = ""
    for s in supply_chain:
        sc_rows += f"""
        <tr>
          <td><span style="background:#FCEBEB;color:#E24B4A;
              padding:2px 8px;border-radius:4px;font-weight:600;font-size:12px">{s['severity']}</span></td>
          <td>{s['type']}</td>
          <td><strong>{s['package']}</strong></td>
          <td>{s['detail']}</td>
          <td>{s['action']}</td>
        </tr>"""

    lic_rows = ""
    for l in license_issues:
        risk_color = {"BLOCKED": "#E24B4A", "REVIEW": "#BA7517"}.get(l["risk"], "#888780")
        lic_rows += f"""
        <tr>
          <td><span style="color:{risk_color};font-weight:600">{l['risk']}</span></td>
          <td><strong>{l['package']}</strong></td>
          <td>{l['license']}</td>
          <td>{l['action']}</td>
        </tr>"""

    pv_rows = ""
    for v in policy_violations:
        pv_rows += f"""
        <tr>
          <td><strong>{v['package']}</strong></td>
          <td>{v['type']}</td>
          <td>{v['detail']}</td>
          <td style="font-size:11px;color:#888">{v.get('rule','')}</td>
        </tr>"""

    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>depcheck security report — {now}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         font-size: 14px; color: #1a1a1a; background: #f5f5f0; padding: 32px; }}
  .header {{ background: #26215C; color: white; padding: 24px 32px;
             border-radius: 12px; margin-bottom: 24px; }}
  .header h1 {{ font-size: 22px; font-weight: 600; margin-bottom: 4px; }}
  .header p {{ font-size: 13px; opacity: 0.7; }}
  .stats {{ display: flex; gap: 16px; margin-bottom: 24px; }}
  .stat {{ background: white; border-radius: 10px; padding: 16px 24px;
           border: 1px solid #e0ddd4; flex: 1; }}
  .stat .num {{ font-size: 28px; font-weight: 700; }}
  .stat .label {{ font-size: 12px; color: #666; margin-top: 2px; }}
  .section {{ background: white; border-radius: 10px; border: 1px solid #e0ddd4;
              margin-bottom: 20px; overflow: hidden; }}
  .section-header {{ padding: 14px 20px; background: #fafaf7;
                     border-bottom: 1px solid #e0ddd4; font-weight: 600; font-size: 14px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ padding: 10px 12px; text-align: left; font-size: 11px; font-weight: 600;
        color: #666; text-transform: uppercase; letter-spacing: 0.5px;
        border-bottom: 1px solid #e0ddd4; background: #fafaf7; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #f0ede6; font-size: 13px;
        vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #fafaf7; }}
  .empty {{ padding: 20px; color: #888; font-style: italic; text-align: center; }}
  .footer {{ text-align: center; font-size: 12px; color: #999; margin-top: 24px; }}
</style>
</head>
<body>

<div class="header">
  <h1>oneport-depcheck — Security Report</h1>
  <p>Scan target: {scan_target} &nbsp;|&nbsp; Generated: {now} &nbsp;|&nbsp;
     {packages_scanned} packages scanned</p>
</div>

<div class="stats">
  <div class="stat">
    <div class="num" style="color:#E24B4A">{critical_count}</div>
    <div class="label">Critical vulnerabilities</div>
  </div>
  <div class="stat">
    <div class="num" style="color:#EF9F27">{high_count}</div>
    <div class="label">High vulnerabilities</div>
  </div>
  <div class="stat">
    <div class="num" style="color:#534AB7">{len(supply_chain)}</div>
    <div class="label">Supply chain alerts</div>
  </div>
  <div class="stat">
    <div class="num" style="color:#D85A30">{len(license_issues)}</div>
    <div class="label">License issues</div>
  </div>
  <div class="stat">
    <div class="num" style="color:#1D9E75">{len(policy_violations)}</div>
    <div class="label">Policy violations</div>
  </div>
</div>

<div class="section">
  <div class="section-header">Vulnerabilities ({len(findings)})</div>
  {"<table><thead><tr><th>Severity</th><th>Package</th><th>Version</th>"
   "<th>CVE / ID</th><th>Summary</th><th>CVSS</th><th>Fix</th></tr></thead>"
   f"<tbody>{rows}</tbody></table>" if findings else '<div class="empty">No vulnerabilities found</div>'}
</div>

<div class="section">
  <div class="section-header">Supply chain alerts ({len(supply_chain)})</div>
  {"<table><thead><tr><th>Severity</th><th>Type</th><th>Package</th>"
   "<th>Detail</th><th>Action</th></tr></thead>"
   f"<tbody>{sc_rows}</tbody></table>" if supply_chain else '<div class="empty">No anomalies detected</div>'}
</div>

<div class="section">
  <div class="section-header">License issues ({len(license_issues)})</div>
  {"<table><thead><tr><th>Risk</th><th>Package</th><th>License</th>"
   "<th>Action</th></tr></thead>"
   f"<tbody>{lic_rows}</tbody></table>" if license_issues else '<div class="empty">No license issues found</div>'}
</div>

<div class="section">
  <div class="section-header">Policy violations ({len(policy_violations)})</div>
  {"<table><thead><tr><th>Package</th><th>Type</th><th>Detail</th>"
   "<th>Rule</th></tr></thead>"
   f"<tbody>{pv_rows}</tbody></table>" if policy_violations else '<div class="empty">No policy violations</div>'}
</div>

<div class="footer">Generated by oneport-depcheck &nbsp;|&nbsp; oneport.co.in</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path