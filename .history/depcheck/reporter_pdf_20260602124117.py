from datetime import datetime, timezone

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, HRFlowable, PageBreak)
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


BRAND_PURPLE = colors.HexColor("#26215C")
BRAND_CYAN   = colors.HexColor("#0F6E56")
RED          = colors.HexColor("#E24B4A")
AMBER        = colors.HexColor("#BA7517")
YELLOW_BG    = colors.HexColor("#FAEEDA")
RED_BG       = colors.HexColor("#FCEBEB")
GREEN_BG     = colors.HexColor("#E1F5EE")
GRAY_BG      = colors.HexColor("#F1EFE8")
LIGHT_GRAY   = colors.HexColor("#D3D1C7")

SEV_COLORS = {
    "CRITICAL": RED,
    "HIGH":     colors.HexColor("#EF9F27"),
    "MEDIUM":   colors.HexColor("#BA7517"),
    "LOW":      colors.HexColor("#1D9E75"),
    "UNKNOWN":  colors.HexColor("#888780"),
}


def generate_pdf_report(
    findings: list[dict],
    supply_chain: list[dict],
    license_issues: list[dict],
    policy_violations: list[dict],
    packages_scanned: int,
    scan_target: str = "unknown",
    output_path: str = "depcheck-report.pdf",
) -> str:
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "reportlab is required for PDF reports.\n"
            "Install with: pip install reportlab"
        )

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    style_h1 = ParagraphStyle("h1", fontSize=20, textColor=BRAND_PURPLE,
                               spaceAfter=6, fontName="Helvetica-Bold")
    style_h2 = ParagraphStyle("h2", fontSize=13, textColor=BRAND_PURPLE,
                               spaceBefore=14, spaceAfter=4, fontName="Helvetica-Bold")
    style_body = ParagraphStyle("body", fontSize=9, spaceAfter=3,
                                 textColor=colors.HexColor("#2C2C2A"))
    style_small = ParagraphStyle("small", fontSize=8,
                                  textColor=colors.HexColor("#5F5E5A"))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    critical_n = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_n = sum(1 for f in findings if f.get("severity") == "HIGH")

    story = []

    # Header
    story.append(Paragraph("oneport-depcheck", style_h1))
    story.append(Paragraph("Dependency Security Report", ParagraphStyle(
        "sub", fontSize=14, textColor=BRAND_CYAN, spaceAfter=4,
        fontName="Helvetica")))
    story.append(Paragraph(f"Target: {scan_target}  |  Generated: {now}", style_small))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=BRAND_PURPLE, spaceAfter=12))

    # Executive summary table
    summary_data = [
        ["Packages scanned", "Critical", "High", "Supply chain", "License", "Policy"],
        [str(packages_scanned), str(critical_n), str(high_n),
         str(len(supply_chain)), str(len(license_issues)), str(len(policy_violations))],
    ]
    summary_table = Table(summary_data, colWidths=[2.8*cm]*6)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_PURPLE),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (1, 1), (1, 1), RED_BG),
        ("BACKGROUND", (2, 1), (2, 1), YELLOW_BG),
        ("GRID",       (0, 0), (-1, -1), 0.25, LIGHT_GRAY),
        ("ROWBACKGROUNDS", (0, 1), (-1, 1), [GRAY_BG]),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.4*cm))

    # Vulnerabilities
    story.append(Paragraph(f"Vulnerabilities ({len(findings)})", style_h2))
    if findings:
        vdata = [["#", "Severity", "Package", "Version", "CVE", "CVSS", "EPSS", "Fix"]]
        for f in findings:
            cve = next((i for i in f.get("ids", []) if i.startswith("CVE-")), "")
            cvss = f"{f['cvss_score']:.1f}" if f.get("cvss_score") else "—"
            epss = f"{f['epss_score']*100:.1f}%" if f.get("epss_score") else "—"
            fix = f.get("fix_version") or "—"
            priority = str(f.get("fix_priority", ""))
            vdata.append([priority, f.get("severity",""), f["name"],
                          f["version"], cve[:18], cvss, epss, fix])

        vtable = Table(vdata, colWidths=[0.6*cm, 1.6*cm, 3*cm, 1.5*cm,
                                          3.2*cm, 1*cm, 1.2*cm, 2*cm])
        vstyle = [
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_PURPLE),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("GRID",       (0, 0), (-1, -1), 0.25, LIGHT_GRAY),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GRAY_BG]),
        ]
        for i, f in enumerate(findings, start=1):
            sev = f.get("severity", "")
            if sev in SEV_COLORS:
                vstyle.append(("TEXTCOLOR", (1, i), (1, i), SEV_COLORS[sev]))
                vstyle.append(("FONTNAME",  (1, i), (1, i), "Helvetica-Bold"))
        vtable.setStyle(TableStyle(vstyle))
        story.append(vtable)
    else:
        story.append(Paragraph("No vulnerabilities found.", style_body))

    story.append(Spacer(1, 0.3*cm))

    # Supply chain
    story.append(Paragraph(f"Supply chain alerts ({len(supply_chain)})", style_h2))
    if supply_chain:
        scdata = [["Severity", "Type", "Package", "Detail"]]
        for s in supply_chain:
            scdata.append([s["severity"], s["type"], s["package"], s["detail"][:60]])
        sctable = Table(scdata, colWidths=[1.6*cm, 3*cm, 3*cm, 9*cm])
        sctable.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_PURPLE),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("GRID",       (0, 0), (-1, -1), 0.25, LIGHT_GRAY),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GRAY_BG]),
        ]))
        story.append(sctable)
    else:
        story.append(Paragraph("No supply chain anomalies detected.", style_body))

    # License issues
    story.append(Paragraph(f"License issues ({len(license_issues)})", style_h2))
    if license_issues:
        ldata = [["Risk", "Package", "License", "Action"]]
        for l in license_issues:
            ldata.append([l["risk"], l["package"], l["license"], l["action"][:60]])
        ltable = Table(ldata, colWidths=[1.6*cm, 3*cm, 3.5*cm, 8.5*cm])
        ltable.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_PURPLE),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("GRID",       (0, 0), (-1, -1), 0.25, LIGHT_GRAY),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GRAY_BG]),
        ]))
        story.append(ltable)
    else:
        story.append(Paragraph("No license issues found.", style_body))

    # Footer
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY))
    story.append(Paragraph(
        f"Generated by oneport-depcheck v0.4.0 | oneport.co.in | {now}",
        style_small))

    doc.build(story)
    return output_path