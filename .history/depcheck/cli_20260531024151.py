import click
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

console = Console()

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "UNKNOWN": "dim",
}


@click.group()
def main():
    """oneport-depcheck — Dependency Vulnerability Scanner"""
    pass


@main.command()
@click.argument("target", default=".", required=False)
@click.option("--requirements", "-r", default=None, help="Path to requirements.txt")
@click.option("--fix", is_flag=True, default=False, help="Show fix commands")
@click.option("--transitive", "-t", is_flag=True, default=False, help="Scan full transitive tree (slower)")
@click.option("--depth", default=3, help="Max transitive depth (default 3, max 5)")
@click.option("--no-supply-chain", is_flag=True, default=False)
@click.option("--no-license", is_flag=True, default=False)
@click.option("--no-nvd", is_flag=True, default=False, help="Skip NVD enrichment (faster)")
@click.option("--no-github", is_flag=True, default=False, help="Skip GitHub Advisory enrichment")
@click.option("--fail-on", default=None, help="Exit code 1 if severities found e.g. CRITICAL,HIGH")
def scan(target, requirements, fix, transitive, depth, no_supply_chain,
         no_license, no_nvd, no_github, fail_on):
    """Scan dependencies for vulnerabilities, supply chain risks, and license issues."""
    console.print()
    console.print(Panel.fit(
        "[bold cyan]oneport-depcheck[/bold cyan]  v0.2.0\n"
        "[dim]Dependency Vulnerability Scanner[/dim]",
        border_style="cyan"
    ))
    console.print()

    # --- Load packages ---
    if requirements:
        console.print(f"[dim]Reading from {requirements}[/dim]")
        packages = get_packages_from_requirements(requirements)
    else:
        console.print("[dim]Scanning installed packages in current environment[/dim]")
        packages = get_installed_packages()

    direct_count = len(packages)

    # --- Transitive tree ---
    if transitive:
        console.print(f"[dim]Building transitive dependency tree (depth={min(depth,5)})...[/dim]")
        tree = build_full_tree(packages, max_depth=min(depth, 5))
        all_packages = flatten_to_packages(tree)
        transitive_count = len(all_packages) - direct_count
        console.print(f"[dim]Found {direct_count} direct + {transitive_count} transitive = {len(all_packages)} total packages[/dim]")
    else:
        all_packages = packages
        console.print(f"[dim]{direct_count} packages to scan (use --transitive for full tree)[/dim]")

    console.print()

    # --- CVE scan via OSV ---
    console.print("[bold]Scanning for CVEs via OSV...[/bold]")
    results = scan_packages(all_packages)

    # --- NVD enrichment ---
    if not no_nvd and results:
        cve_count = sum(1 for r in results if any(i.startswith("CVE-") for i in r.get("ids", [])))
        if cve_count:
            console.print(f"[dim]Enriching {cve_count} CVEs with NVD CVSS scores...[/dim]")
            results = enrich_with_nvd(results)

    # --- GitHub Advisory enrichment ---
    if not no_github and results:
        console.print(f"[dim]Cross-referencing {len(results)} findings with GitHub Advisory DB...[/dim]")
        results = enrich_with_github(results)

    print_results(results, len(all_packages))

    if fix and results:
        console.print("[bold]Fix commands:[/bold]")
        for r in sorted(results, key=lambda x: SEVERITY_ORDER.index(x.get("severity", "UNKNOWN"))):
            if r.get("fix_version"):
                color = SEVERITY_COLORS.get(r["severity"], "white")
                console.print(
                    f"  [{color}]{r['severity']:8}[/{color}]  "
                    f"pip install {r['name']}=={r['fix_version']}"
                )
        console.print()

    # --- Supply chain ---
    if not no_supply_chain:
        console.print("[bold]Checking for supply chain anomalies...[/bold]")
        sc_findings = run_supply_chain_checks(all_packages)
        _print_supply_chain(sc_findings)

    # --- License ---
    if not no_license:
        console.print("[bold]Auditing licenses...[/bold]")
        lic_findings = run_license_checks(all_packages)
        _print_license(lic_findings)

    # --- Summary panel ---
    _print_summary(results, all_packages)

    # --- Fail-on exit code ---
    if fail_on:
        fail_severities = [s.strip().upper() for s in fail_on.split(",")]
        found = [r for r in results if r.get("severity") in fail_severities]
        if found:
            console.print(f"[bold red]Failing: {len(found)} findings at {fail_on} level.[/bold red]")
            raise SystemExit(1)


@main.command()
@click.option("--requirements", "-r", default=None, help="Path to requirements.txt")
@click.option("--format", "fmt", default="both", type=click.Choice(["spdx", "cyclonedx", "both"]))
def sbom(requirements, fmt):
    """Generate SBOM in SPDX and/or CycloneDX format."""
    if requirements:
        from .scanner import get_packages_from_requirements
        packages = get_packages_from_requirements(requirements)
    else:
        from .scanner import get_installed_packages
        packages = get_installed_packages()

    console.print(f"\n[bold]Generating SBOM for {len(packages)} packages...[/bold]\n")

    if fmt in ("spdx", "both"):
        path = generate_spdx(packages)
        console.print(f"[green]SPDX 2.3   →  {path}[/green]")

    if fmt in ("cyclonedx", "both"):
        path = generate_cyclonedx(packages)
        console.print(f"[green]CycloneDX  →  {path}[/green]")

    console.print()


@main.command("ci-config")
@click.option("--platform", default="github", type=click.Choice(["github", "gitlab"]))
def ci_config(platform):
    """Generate CI/CD pipeline config for depcheck."""
    if platform == "github":
        path = generate_github_actions()
        console.print(f"\n[green]GitHub Actions workflow written to {path}[/green]")
        console.print("[dim]Commit this file and push — depcheck will run on every PR.[/dim]\n")
    else:
        path = generate_gitlab_ci()
        console.print(f"\n[green]GitLab CI config written to {path}[/green]")
        console.print("[dim]Add this to your .gitlab-ci.yml[/dim]\n")


@main.command()
def version():
    """Show version."""
    console.print("oneport-depcheck v0.2.0")


def _print_supply_chain(findings):
    if not findings:
        console.print("[green]  No supply chain anomalies detected.[/green]\n")
        return
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("Type", width=22)
    table.add_column("Severity", width=10)
    table.add_column("Package", width=24)
    table.add_column("Detail", width=50)
    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "white")
        table.add_row(f["type"], Text(f["severity"], style=color), f["package"], f["detail"])
    console.print(table)
    console.print()


def _print_license(findings):
    if not findings:
        console.print("[green]  No license issues found.[/green]\n")
        return
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("Risk", width=10)
    table.add_column("Package", width=24)
    table.add_column("License", width=28)
    table.add_column("Action", width=50)
    risk_colors = {"BLOCKED": "bold red", "REVIEW": "yellow", "UNKNOWN": "dim"}
    for f in findings:
        color = risk_colors.get(f["risk"], "white")
        table.add_row(Text(f["risk"], style=color), f["package"], f["license"], f["action"])
    console.print(table)
    console.print()


def _print_summary(results, all_packages):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        counts[r.get("severity", "UNKNOWN")] = counts.get(r.get("severity", "UNKNOWN"), 0) + 1

    lines = [f"[dim]Packages scanned:[/dim] {len(all_packages)}"]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[sev]:
            color = SEVERITY_COLORS[sev]
            lines.append(f"[{color}]{sev}: {counts[sev]}[/{color}]")

    if not any(counts[s] for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
        lines.append("[green]No vulnerabilities found.[/green]")

    lines.append("")
    lines.append("[dim]depcheck sbom          → generate SBOM[/dim]")
    lines.append("[dim]depcheck ci-config     → add to GitHub Actions[/dim]")
    lines.append("[dim]depcheck scan --fix    → show upgrade commands[/dim]")
    lines.append("[dim]depcheck scan -t       → include transitive deps[/dim]")

    console.print(Panel("\n".join(lines), title="Summary", border_style="dim"))
    console.print()


if __name__ == "__main__":
    main()