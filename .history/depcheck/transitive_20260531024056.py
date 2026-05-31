import importlib.metadata
from importlib.metadata import PackageNotFoundError


def get_dependencies(package_name: str, depth: int = 0, max_depth: int = 5,
                     visited: set = None) -> list[tuple[str, str, int]]:
    """
    Recursively resolve all dependencies of a package up to max_depth.
    Returns list of (name, version, depth_level) tuples.
    """
    if visited is None:
        visited = set()

    results = []
    if depth > max_depth or package_name.lower() in visited:
        return results

    visited.add(package_name.lower())

    try:
        dist = importlib.metadata.distribution(package_name)
        version = dist.metadata["Version"] or "unknown"
        requires = dist.requires or []
    except PackageNotFoundError:
        return results

    for req_str in requires:
        # Skip environment markers like "; extra == 'dev'"
        if ";" in req_str:
            marker_part = req_str.split(";", 1)[1].strip()
            # Skip optional/extra deps unless they are unconditional
            if "extra ==" in marker_part:
                continue

        # Extract just the package name (strip version specifiers)
        dep_name = req_str.split(";")[0].strip()
        for sep in [">=", "<=", "!=", "~=", "==", ">", "<", "["]:
            dep_name = dep_name.split(sep)[0].strip()

        if not dep_name or dep_name.lower() in visited:
            continue

        try:
            dep_dist = importlib.metadata.distribution(dep_name)
            dep_version = dep_dist.metadata["Version"] or "unknown"
            results.append((dep_name, dep_version, depth + 1))
            # Recurse
            results.extend(
                get_dependencies(dep_name, depth + 1, max_depth, visited)
            )
        except PackageNotFoundError:
            results.append((dep_name, "not installed", depth + 1))

    return results


def build_full_tree(packages: list[tuple[str, str]], max_depth: int = 5) -> list[tuple[str, str, int]]:
    """
    Given top-level packages, return the full transitive tree as flat list.
    Deduplicates — each package appears only once (at its shallowest depth).
    """
    visited = set()
    full_tree = []

    for name, version in packages:
        if name.lower() in visited:
            continue
        visited.add(name.lower())
        full_tree.append((name, version, 0))
        children = get_dependencies(name, depth=0, max_depth=max_depth, visited=visited)
        full_tree.extend(children)

    # Deduplicate by name keeping first occurrence
    seen = set()
    deduped = []
    for item in full_tree:
        if item[0].lower() not in seen:
            seen.add(item[0].lower())
            deduped.append(item)

    return deduped


def flatten_to_packages(tree: list[tuple[str, str, int]]) -> list[tuple[str, str]]:
    """Strip depth info — return plain (name, version) list for scanning."""
    return [(name, version) for name, version, _ in tree
            if version != "not installed"]