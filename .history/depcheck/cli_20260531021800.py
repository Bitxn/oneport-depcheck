import click
from rich.console import Console
from .scanner import get_installed_packages, get_packages_from_requirements, scan_packages
from .reporter import print_results

console = Console()


@click.group()
def main():
    """oneport-depcheck — Dependency Vulnerability Scanner"""
    pass


@main.command()
@click.argument("target", default=".", required=False)
@click.option("--requirements", "-r", default=None, help="Path to requirements.txt")
@click.option("--fix", is_flag=True, default=False, help="Show fix commands")
def scan(target, requirements, fix):
    """Scan dependencies for known vulnerabilities."""
    console.print()
    console.print("[bold cyan]oneport-depcheck[/bold cyan] — scanning for vulnerabilities...")
    console.print()

    if requirements:
        console.print(f"[dim]Reading packages from {requirements}[/dim]")
        packages = get_packages_from_requirements(requirements)
    else:
        console.print("[dim]Scanning all installed packages in current environment[/dim]")
        packages = get_installed_packages()

    console.print(f"[dim]Querying OSV database for {len(packages)} packages...[/dim]")
    console.print()

    results = scan_packages(packages)
    print_results(results, len(packages))

    if fix and results:
        console.print("[bold]Suggested fix commands:[/bold]")
        for r in results:
            if r["fix_version"]:
                console.print(
                    f"  pip install {r['name']}=={r['fix_version']}"
                )
        console.print()


@main.command()
def version():
    """Show version."""
    from depcheck import __version__
    console.print(f"oneport-depcheck v{__version__}")


if __name__ == "__main__":
    main()