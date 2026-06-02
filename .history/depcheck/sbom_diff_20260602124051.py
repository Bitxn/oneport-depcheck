import json
from datetime import datetime, timezone


def load_sbom(path: str) -> dict:
    """Load a CycloneDX or SPDX JSON SBOM and return normalised package dict."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    packages = {}

    # CycloneDX
    if data.get("bomFormat") == "CycloneDX":
        for comp in data.get("components", []):
            name = comp.get("name", "")
            version = comp.get("version", "")
            if name:
                packages[name.lower()] = {"name": name, "version": version}

    # SPDX
    elif "spdxVersion" in data:
        for pkg in data.get("packages", []):
            name = pkg.get("name", "")
            version = pkg.get("versionInfo", "")
            if name:
                packages[name.lower()] = {"name": name, "version": version}

    return packages


def diff_sboms(old_path: str, new_path: str) -> dict:
    """
    Compare two SBOMs. Returns dict with:
      added:    packages in new but not old
      removed:  packages in old but not new
      upgraded: version changed (old < new)
      downgraded: version changed (old > new)
      unchanged: same name and version
    """
    old = load_sbom(old_path)
    new = load_sbom(new_path)

    old_keys = set(old.keys())
    new_keys = set(new.keys())

    added = [new[k] for k in new_keys - old_keys]
    removed = [old[k] for k in old_keys - new_keys]
    upgraded = []
    downgraded = []
    unchanged = []

    for key in old_keys & new_keys:
        ov = old[key]["version"]
        nv = new[key]["version"]
        if ov == nv:
            unchanged.append(new[key])
        else:
            entry = {
                "name": new[key]["name"],
                "old_version": ov,
                "new_version": nv,
            }
            try:
                from packaging.version import Version
                if Version(nv) > Version(ov):
                    upgraded.append(entry)
                else:
                    downgraded.append(entry)
            except Exception:
                upgraded.append(entry)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "old_sbom": old_path,
        "new_sbom": new_path,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "upgraded": len(upgraded),
            "downgraded": len(downgraded),
            "unchanged": len(unchanged),
        },
        "added": sorted(added, key=lambda x: x["name"]),
        "removed": sorted(removed, key=lambda x: x["name"]),
        "upgraded": sorted(upgraded, key=lambda x: x["name"]),
        "downgraded": sorted(downgraded, key=lambda x: x["name"]),
    }


def print_diff(diff: dict, console) -> None:
    from rich.table import Table
    from rich import box
    from rich.text import Text

    s = diff["summary"]
    console.print(f"\n[bold]SBOM diff:[/bold]  "
                  f"[green]+{s['added']} added[/green]  "
                  f"[red]-{s['removed']} removed[/red]  "
                  f"[cyan]~{s['upgraded']} upgraded[/cyan]  "
                  f"[yellow]{s['downgraded']} downgraded[/yellow]\n")

    for section, label, color in [
        ("added", "Added packages", "green"),
        ("removed", "Removed packages", "red"),
        ("upgraded", "Upgraded", "cyan"),
        ("downgraded", "Downgraded", "yellow"),
    ]:
        items = diff.get(section, [])
        if not items:
            continue
        table = Table(box=box.SIMPLE, show_header=True,
                      header_style="bold", title=label)
        table.add_column("Package", style=color)
        if section in ("upgraded", "downgraded"):
            table.add_column("From")
            table.add_column("To")
            for item in items:
                table.add_row(item["name"], item["old_version"], item["new_version"])
        else:
            table.add_column("Version")
            for item in items:
                table.add_row(item["name"], item.get("version", ""))
        console.print(table)