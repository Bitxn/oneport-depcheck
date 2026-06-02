import os
import ast
import re


def get_imported_packages(project_path: str = ".") -> set[str]:
    """
    Walk all .py files in a project and extract imported package names.
    Returns a set of top-level package names actually used.
    """
    imported = set()
    project_path = os.path.abspath(project_path)

    for root, dirs, files in os.walk(project_path):
        # Skip common non-project directories
        dirs[:] = [d for d in dirs if d not in
                   {".git", "__pycache__", ".venv", "venv", "env",
                    "node_modules", ".tox", "dist", "build", ".eggs"}]

        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    source = f.read()
                tree = ast.parse(source, filename=fpath)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            top = alias.name.split(".")[0].lower().replace("-", "_")
                            imported.add(top)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            top = node.module.split(".")[0].lower().replace("-", "_")
                            imported.add(top)
            except Exception:
                pass

    return imported


def _normalise_pkg_name(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def check_reachability(
    findings: list[dict],
    project_path: str = ".",
) -> list[dict]:
    """
    For each finding, check if the vulnerable package is actually
    imported anywhere in the codebase. Adds 'reachable' bool and
    'reachability_note' string to each finding dict.
    """
    imported = get_imported_packages(project_path)

    for finding in findings:
        pkg_norm = _normalise_pkg_name(finding["name"])
        is_reachable = pkg_norm in imported or any(
            pkg_norm in imp for imp in imported
        )
        finding["reachable"] = is_reachable
        finding["reachability_note"] = (
            "Imported in your codebase — fix urgently"
            if is_reachable
            else "Not directly imported — lower immediate risk"
        )

    return findings