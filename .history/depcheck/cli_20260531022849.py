import click
from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

from .scanner import get_installed_packages, get_packages_from_requirements, scan_packages
from .reporter import print_results
from .supply_chain import run_supply_chain_checks
from .license_checker import run_license_checks

console = Console()


@click.group()
def main():
    """oneport-depcheck — Dependency Vulnerability Scanner"""
    pass


@main.command()
@click.argument("target", default=".", required=False)
@click.option("--requirements", "-r", default=None, help="Path to requirements.txt")
@click.option("--fix", is_flag=True, default=False, help="Show fix commands")
@click.option("--no-supply-chain", is_flag=True, default=False, help="Skip supply chain checks")
@click.option("--no-license", is_flag=True, default=False, help="Skip license checks")
def scan(target, requirements, fix, no_supply_chain, no_license):
    """Scan dependencies for vulnerabilities, supply chain attacks, and license issues."""
    console.print()
    console.print("[bold cyan]oneport-depcheck[/bold cyan] — scanning...")
    console.print()

    if requirements:
        console.print(f"[dim]Reading from {requirements}[/dim]")
        packages = get_packages_from_requirements(requirements)
    else:
        console.print("[dim]Scanning all installed packages in current environment[/dim]")
        packages = get_installed_packages()

    # --- CVE scan ---
    console.print(f"[dim]Querying OSV for {len(packages)} packages...[/dim]")
    results = scan_packages(packages)
    print_results(results, len(packages))

    if fix and results:
        console.print("[bold]Suggested fix commands:[/bold]")
        for r in results:
            if r["fix_version"]:
                console.print(f"  pip install {r['name']}=={r['fix_version']}")
        console.print()

    # --- Supply chain scan ---
    if not no_supply_chain:
        console.print("[bold]Running supply chain checks...[/bold]")
        sc_findings = run_supply_chain_checks(packages)
        _print_supply_chain(sc_findings)

    # --- License scan ---
    if not no_license:
        console.print("[bold]Running license checks...[/bold]")
        lic_findings = run_license_checks(packages)
        _print_license(lic_findings)


def _print_supply_chain(findings: list):
    if not findings:
        console.print("[green]✓ No supply chain anomalies detected.[/green]")
        console.print()
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("Type", width=20)
    table.add_column("Severity", width=10)
    table.add_column("Package", width=22)
    table.add_column("Detail", width=44)
    table.add_column("Action", width=36)

    severity_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}

    for f in findings:
        color = severity_colors.get(f["severity"], "white")
        table.add_row(
            f["type"],
            Text(f["severity"], style=color),
            f["package"],
            f["detail"],
            f["action"],
        )

    console.print(table)
    console.print()


def _print_license(findings: list):
    if not findings:
        console.print("[green]✓ No license issues found.[/green]")
        console.print()
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("Risk", width=10)
    table.add_column("Package", width=22)
    table.add_column("License", width=28)
    table.add_column("Detail", width=40)
    table.add_column("Action", width=44)

    risk_colors = {"BLOCKED": "bold red", "REVIEW": "yellow", "UNKNOWN": "dim"}

    for f in findings:
        color = risk_colors.get(f["risk"], "white")
        table.add_row(
            Text(f["risk"], style=color),
            f["package"],
            f["license"],
            f["detail"],
            f["action"],
        )

    console.print(table)
    console.print()


@main.command()
def version():
    """Show version."""
    from depcheck import __version__
    console.print(f"oneport-depcheck v{__version__}")


if __name__ == "__main__":
    main()