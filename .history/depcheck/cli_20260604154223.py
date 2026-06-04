import click
import os
from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text
from rich.panel import Panel

from .scanner import get_installed_packages, get_packages_from_requirements, scan_packages
from .reporter import print_results
from .supply_chain import run_supply_chain_checks
from .license_checker import run_license_checks
from .transitive import build_full_tree, flatten_to_packages
from .github_advisory import enrich_with_github
from .nvd import enrich_with_nvd
from .sbom import generate_spdx, generate_cyclonedx
from .cicd import generate_github_actions, generate_gitlab_ci
from .cache import cache_clear, cache_stats
from .policy import load_policy, apply_policy, generate_policy_template
from .audit_log import log_scan, read_audit_log, export_audit_log_pdf
from .slack_notify import send_slack_alert
from .reporter_html import generate_html_report
from .npm_scanner import get_npm_packages, scan_npm_packages

console = Console()
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_COLORS = {
    "CRITICAL": "bold red", "HIGH": "red",
    "MEDIUM": "yellow", "LOW": "cyan", "UNKNOWN": "dim",
}


@click.group()
def main():
    """oneport-depcheck v0.3.0 — Dependency Vulnerability Scanner"""
    pass


@main.command()
@click.argument("target", default=".", required=False)
@click.option("--requirements", "-r", default=None, help="requirements.txt path")
@click.option("--npm", is_flag=True, default=False, help="Scan package-lock.json instead")
@click.option("--fix", is_flag=True, default=False, help="Show fix commands")
@click.option("--transitive", "-t", is_flag=True, default=False)
@click.option("--depth", default=3, help="Transitive depth (max 5)")
@click.option("--no-supply-chain", is_flag=True, default=False)
@click.option("--no-license", is_flag=True, default=False)
@click.option("--no-nvd", is_flag=True, default=False)
@click.option("--no-github", is_flag=True, default=False)
@click.option("--no-cache", is_flag=True, default=False, help="Bypass cache")
@click.option("--policy", "policy_path", default=None, help="Policy file path")
@click.option("--output", "-o", default=None, help="Save HTML report to file")
@click.option("--format", "fmt", default="terminal",
              type=click.Choice(["terminal", "json", "html"]))
@click.option("--slack-webhook", default=None, help="Slack webhook URL")
@click.option("--fail-on", default=None, help="Exit 1 on severity e.g. CRITICAL,HIGH")
def scan(target, requirements, npm, fix, transitive, depth,
         no_supply_chain, no_license, no_nvd, no_github, no_cache,
         policy_path, output, fmt, slack_webhook, fail_on):
    """Scan for vulnerabilities, supply chain risks, license issues, and policy violations."""
    import json as _json

    console.print()
    console.print(Panel.fit(
        "[bold cyan]oneport-depcheck[/bold cyan]  v0.3.0\n[dim]MNC-grade dependency security[/dim]",
        border_style="cyan"
    ))
    console.print()

    policy = load_policy(policy_path)
    if "_loaded_from" in policy:
        console.print(f"[dim]Policy loaded from {policy['_loaded_from']}[/dim]")

    # Load packages
    if npm:
        console.print(f"[dim]Reading npm packages from {target}[/dim]")
        packages = get_npm_packages(target)
        ecosystem = "npm"
    elif requirements:
        console.print(f"[dim]Reading from {requirements}[/dim]")
        packages = get_packages_from_requirements(requirements)
        ecosystem = "pypi"
    else:
        console.print("[dim]Scanning installed Python environment[/dim]")
        packages = get_installed_packages()
        ecosystem = "pypi"

    direct_count = len(packages)

    if transitive and ecosystem == "pypi":
        console.print(f"[dim]Building transitive tree (depth={min(depth,5)})...[/dim]")
        tree = build_full_tree(packages, max_depth=min(depth, 5))
        all_packages = flatten_to_packages(tree)
        console.print(f"[dim]{direct_count} direct + {len(all_packages)-direct_count} transitive = {len(all_packages)} total[/dim]")
    else:
        all_packages = packages

    console.print()

    # CVE scan
    console.print("[bold]Scanning for CVEs...[/bold]")
    if ecosystem == "npm":
        results = scan_npm_packages(all_packages)
    else:
        results = scan_packages(all_packages)

    if not no_nvd and results:
        cve_count = sum(1 for r in results if any(i.startswith("CVE-") for i in r.get("ids", [])))
        if cve_count:
            console.print(f"[dim]Enriching {cve_count} CVEs with NVD...[/dim]")
            results = enrich_with_nvd(results)

    if not no_github and results:
        console.print(f"[dim]Cross-referencing with GitHub Advisory DB...[/dim]")
        results = enrich_with_github(results)

    print_results(results, len(all_packages))

    if fix and results:
        console.print("[bold]Fix commands:[/bold]")
        for r in sorted(results, key=lambda x: SEVERITY_ORDER.index(x.get("severity", "UNKNOWN"))):
            if r.get("fix_version"):
                color = SEVERITY_COLORS.get(r["severity"], "white")
                console.print(f"  [{color}]{r['severity']:8}[/{color}]  pip install {r['name']}=={r['fix_version']}")
        console.print()

    # Supply chain
    sc_findings = []
    if not no_supply_chain:
        console.print("[bold]Checking supply chain...[/bold]")
        sc_findings = run_supply_chain_checks(all_packages)
        _print_supply_chain(sc_findings)

    # License
    lic_findings = []
    if not no_license:
        console.print("[bold]Auditing licenses...[/bold]")
        lic_findings = run_license_checks(all_packages)
        _print_license(lic_findings)

    # Policy
    console.print("[bold]Applying org policy...[/bold]")
    violations = apply_policy(results, lic_findings, policy)
    _print_policy_violations(violations)

    # Audit log
    scan_target = requirements or ("npm:" + target if npm else "env")
    log_scan(len(all_packages), results, sc_findings, lic_findings, violations, scan_target)

    # HTML report
    html_path = output or ("depcheck-report.html" if fmt == "html" else None)
    if html_path:
        path = generate_html_report(results, sc_findings, lic_findings, violations,
                                    len(all_packages), scan_target, html_path)
        console.print(f"\n[green]HTML report saved → {path}[/green]")

    # JSON output
    if fmt == "json":
        out = {
            "scan_target": scan_target,
            "packages_scanned": len(all_packages),
            "findings": results,
            "supply_chain": sc_findings,
            "license_issues": lic_findings,
            "policy_violations": violations,
        }
        console.print_json(_json.dumps(out))

    # Slack
    webhook = slack_webhook or os.environ.get("DEPCHECK_SLACK_WEBHOOK")
    if webhook:
        sent = send_slack_alert(results, sc_findings, violations, scan_target, webhook)
        console.print(f"[dim]Slack alert {'sent' if sent else 'failed'}[/dim]")

    _print_summary(results, sc_findings, lic_findings, violations, all_packages)

    # Fail-on
    effective_fail = fail_on or ",".join(policy.get("fail_on_severity", []))
    if effective_fail:
        fail_sevs = [s.strip().upper() for s in effective_fail.split(",")]
        if any(r.get("severity") in fail_sevs for r in results) or violations:
            console.print(f"[bold red]Failing build: findings at {effective_fail} level detected.[/bold red]")
            raise SystemExit(1)


@main.command()
@click.option("--requirements", "-r", default=None)
@click.option("--format", "fmt", default="both",
              type=click.Choice(["spdx", "cyclonedx", "both"]))
def sbom(requirements, fmt):
    """Generate SBOM in SPDX and/or CycloneDX format."""
    packages = (get_packages_from_requirements(requirements)
                if requirements else get_installed_packages())
    console.print(f"\n[bold]Generating SBOM for {len(packages)} packages...[/bold]\n")
    if fmt in ("spdx", "both"):
        console.print(f"[green]SPDX 2.3   → {generate_spdx(packages)}[/green]")
    if fmt in ("cyclonedx", "both"):
        console.print(f"[green]CycloneDX  → {generate_cyclonedx(packages)}[/green]")
    console.print()


@main.command("ci-config")
@click.option("--platform", default="github", type=click.Choice(["github", "gitlab"]))
def ci_config(platform):
    """Generate CI/CD pipeline integration config."""
    if platform == "github":
        console.print(f"\n[green]Written → {generate_github_actions()}[/green]\n")
    else:
        console.print(f"\n[green]Written → {generate_gitlab_ci()}[/green]\n")


@main.command()
@click.option("--last", default=10, help="Show last N scans")
@click.option("--export", is_flag=True, default=False, help="Export full log to JSON")
def audit(last, export):
    """View scan audit history."""
    if export:
        path = export_audit_log_pdf()
        console.print(f"\n[green]Audit log exported → {path}[/green]\n")
        return
    records = read_audit_log(last_n=last)
    if not records:
        console.print("\n[dim]No audit records found.[/dim]\n")
        return
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("Timestamp", width=22)
    table.add_column("Target", width=24)
    table.add_column("Pkgs", width=6)
    table.add_column("CRIT", width=6)
    table.add_column("HIGH", width=6)
    table.add_column("SC", width=4)
    table.add_column("Policy", width=6)
    console.print()
    for r in records:
        sev = r.get("severity_breakdown", {})
        table.add_row(
            r["timestamp"][:19],
            r.get("scan_target", "")[:24],
            str(r.get("packages_scanned", "")),
            Text(str(sev.get("CRITICAL", 0)), style="bold red" if sev.get("CRITICAL") else "dim"),
            Text(str(sev.get("HIGH", 0)), style="red" if sev.get("HIGH") else "dim"),
            str(r.get("supply_chain_count", 0)),
            str(r.get("policy_violations_count", 0)),
        )
    console.print(table)
    console.print()


@main.command()
@click.option("--clear", is_flag=True, default=False)
def cache(clear):
    """Manage the local scan cache."""
    if clear:
        n = cache_clear()
        console.print(f"\n[green]Cleared {n} cache entries.[/green]\n")
    else:
        stats = cache_stats()
        console.print(f"\nCache: [bold]{stats['entries']}[/bold] entries, "
                      f"[bold]{stats['size_kb']}[/bold] KB\n"
                      f"Location: ~/.depcheck/cache\n")


@main.command("init-policy")
def init_policy():
    """Generate a starter .depcheck-policy.json for your team."""
    path = generate_policy_template()
    console.print(f"\n[green]Policy template written → {path}[/green]")
    console.print("[dim]Edit it, then commit it to your repo root.[/dim]\n")


@main.command()
def version():
    """Show version."""
    console.print("oneport-depcheck v0.3.0")


def _print_supply_chain(findings):
    if not findings:
        console.print("[green]  No supply chain anomalies.[/green]\n")
        return
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("Severity", width=10)
    table.add_column("Type", width=22)
    table.add_column("Package", width=24)
    table.add_column("Detail", width=52)
    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "white")
        table.add_row(Text(f["severity"], style=color), f["type"], f["package"], f["detail"])
    console.print(table)
    console.print()


def _print_license(findings):
    if not findings:
        console.print("[green]  No license issues.[/green]\n")
        return
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("Risk", width=10)
    table.add_column("Package", width=24)
    table.add_column("License", width=28)
    table.add_column("Action", width=50)
    risk_colors = {"BLOCKED": "bold red", "REVIEW": "yellow", "UNKNOWN": "dim"}
    for f in findings:
        table.add_row(Text(f["risk"], style=risk_colors.get(f["risk"], "white")),
                      f["package"], f["license"], f["action"])
    console.print(table)
    console.print()


def _print_policy_violations(violations):
    if not violations:
        console.print("[green]  No policy violations.[/green]\n")
        return
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("Severity", width=10)
    table.add_column("Type", width=20)
    table.add_column("Package", width=24)
    table.add_column("Detail", width=52)
    for v in violations:
        color = SEVERITY_COLORS.get(v.get("severity", "UNKNOWN"), "white")
        table.add_row(Text(v.get("severity",""), style=color),
                      v["type"], v["package"], v["detail"])
    console.print(table)
    console.print()


def _print_summary(results, sc, lic, pv, all_packages):
    counts = {s: sum(1 for r in results if r.get("severity") == s) for s in SEVERITY_ORDER}
    lines = [f"[dim]Packages scanned:[/dim] {len(all_packages)}"]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[sev]:
            lines.append(f"[{SEVERITY_COLORS[sev]}]{sev}: {counts[sev]}[/{SEVERITY_COLORS[sev]}]")
    if sc:
        lines.append(f"[yellow]Supply chain alerts: {len(sc)}[/yellow]")
    if lic:
        lines.append(f"[yellow]License issues: {len(lic)}[/yellow]")
    if pv:
        lines.append(f"[bold red]Policy violations: {len(pv)}[/bold red]")
    if not any([results, sc, lic, pv]):
        lines.append("[green]Clean — no issues found.[/green]")
    lines += ["",
              "[dim]depcheck scan --fix          fix commands[/dim]",
              "[dim]depcheck scan -t             transitive tree[/dim]",
              "[dim]depcheck scan --npm          scan Node.js project[/dim]",
              "[dim]depcheck scan -o report.html HTML report[/dim]",
              "[dim]depcheck scan --format json  JSON output[/dim]",
              "[dim]depcheck audit               scan history[/dim]",
              "[dim]depcheck cache               cache stats[/dim]",
              "[dim]depcheck init-policy         create org policy file[/dim]"]
    console.print(Panel("\n".join(lines), title="Summary", border_style="dim"))
    console.print()

# Add these imports at the top of cli.py
from .risk_scorer import compute_risk_scores, print_risk_table
from .reachability import check_reachability
from .reporter_pdf import generate_pdf_report
from .sbom_diff import diff_sboms, print_diff
from .scheduler import install_cron_job, remove_cron_job, show_schedule_status
from .hooks import install_pre_commit_hook, install_vscode_config, uninstall_hook

# In the scan() command, after enrich_with_nvd/github, add:
#   results = check_reachability(results, target)
#   results = compute_risk_scores(results)
#   print_risk_table(results, console)
#
# And add --pdf flag to the scan command:
#   @click.option("--pdf", default=None, help="Save PDF report")
#   if pdf: generate_pdf_report(results, sc_findings, lic_findings,
#                               violations, len(all_packages), scan_target, pdf)


@main.command()
@click.option("--install", is_flag=True, default=False, help="Install weekly cron job")
@click.option("--remove", is_flag=True, default=False, help="Remove scheduled scan")
@click.option("--requirements", "-r", default=None)
@click.option("--slack-webhook", default=None)
@click.option("--cron", default="0 9 * * 1", help="Cron schedule (default: Mondays 9am)")
def schedule(install, remove, requirements, slack_webhook, cron):
    """Install or manage automated weekly scan schedule."""
    if remove:
        remove_cron_job()
        console.print("\n[green]Scheduled scan removed.[/green]\n")
        return
    if install:
        entry = install_cron_job(requirements, slack_webhook, cron)
        console.print(f"\n[green]Scheduled scan installed:[/green]\n  [dim]{entry}[/dim]\n")
        return
    show_schedule_status(console)


@main.command("install-hook")
@click.option("--path", default=".", help="Project root path")
@click.option("--vscode", is_flag=True, default=False, help="Also install VS Code config")
@click.option("--uninstall", is_flag=True, default=False)
def install_hook(path, vscode, uninstall):
    """Install pre-commit git hook to block commits with critical vulnerabilities."""
    if uninstall:
        result = uninstall_hook(path)
        console.print(f"\n[green]Hook removed from {result}[/green]\n")
        return
    hook_path = install_pre_commit_hook(path)
    console.print(f"\n[green]Pre-commit hook installed → {hook_path}[/green]")
    console.print("[dim]depcheck will now run on every git commit.[/dim]")
    if vscode:
        written = install_vscode_config(path)
        for p in written:
            console.print(f"[green]VS Code config written → {p}[/green]1")
    console.print()


@main.command("diff-sbom")
@click.argument("old_sbom")
@click.argument("new_sbom")
@click.option("--json", "as_json", is_flag=True, default=False)
def diff_sbom(old_sbom, new_sbom, as_json):
    """Compare two SBOMs and show what changed between releases."""
    import json as _json
    diff = diff_sboms(old_sbom, new_sbom)
    if as_json:
        console.print_json(_json.dumps(diff))
    else:
        print_diff(diff, console)