from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "UNKNOWN": "white",
}


def print_results(results, total_scanned):
    console.print()
    console.print(f"[bold]Scanned {total_scanned} packages[/bold]")
    console.print()

    if not results:
        console.print("[bold green]✓ No vulnerabilities found.[/bold green]")
        return

    # Group by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for r in results:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Package", width=22)
    table.add_column("Installed", width=12)
    table.add_column("CVE / ID", width=22)
    table.add_column("Summary", width=40)
    table.add_column("Fix", width=15)

    for r in sorted(results, key=lambda x: list(SEVERITY_COLORS.keys()).index(x["severity"])):
        color = SEVERITY_COLORS.get(r["severity"], "white")
        ids_str = ", ".join(r["ids"][:2])  # show max 2 IDs
        fix_str = r["fix_version"] or "—"
        table.add_row(
            Text(r["severity"], style=color),
            r["name"],
            r["version"],
            ids_str,
            r["summary"][:80],
            fix_str,
        )

    console.print(table)
    console.print()

    # Summary line
    summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        c = counts[sev]
        if c:
            color = SEVERITY_COLORS[sev]
            summary_parts.append(f"[{color}]{c} {sev}[/{color}]")

    console.print("Summary: " + "  |  ".join(summary_parts))
    console.print()
    console.print("[dim]Run: depcheck scan --fix to see upgrade commands[/dim]")