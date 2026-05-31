import json
import uuid
from datetime import datetime, timezone


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_spdx(packages: list[tuple[str, str]], output_path: str = "sbom.spdx.json") -> str:
    """
    Generate an SPDX 2.3 JSON SBOM from a list of (name, version) tuples.
    Returns the path of the written file.
    """
    doc_namespace = f"https://oneport.co.in/sbom/{uuid.uuid4()}"

    packages_section = []
    relationships = []

    for name, version in packages:
        spdx_id = f"SPDXRef-{name.replace('-', '-').replace('_', '-')}"
        packages_section.append({
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": version,
            "downloadLocation": f"https://pypi.org/project/{name}/{version}/",
            "filesAnalyzed": False,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:pypi/{name}@{version}",
                }
            ],
        })
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": spdx_id,
        })

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "oneport-depcheck-sbom",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": _now_iso(),
            "creators": ["Tool: oneport-depcheck"],
        },
        "packages": packages_section,
        "relationships": relationships,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(spdx_doc, f, indent=2)

    return output_path


def generate_cyclonedx(packages: list[tuple[str, str]], output_path: str = "sbom.cyclonedx.json") -> str:
    """
    Generate a CycloneDX 1.4 JSON SBOM from a list of (name, version) tuples.
    Returns the path of the written file.
    """
    components = []

    for name, version in packages:
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}",
            "bom-ref": f"{name}@{version}",
        })

    cdx_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "tools": [{"name": "oneport-depcheck", "version": "0.2.0"}],
        },
        "components": components,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(cdx_doc, f, indent=2)

    return output_path