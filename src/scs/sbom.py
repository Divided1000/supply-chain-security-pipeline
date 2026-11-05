"""Control 1 — SBOM (Software Bill of Materials) generation.

An SBOM is an "ingredient list" for a piece of software: every component (library,
package, system lib) that goes into the artifact, with enough identity to look each one
up later. The classic use case: a new CVE drops in `log4j 2.14.1`; instead of guessing
whether you're affected, you query your SBOMs and get an instant, authoritative answer.

This module builds an SBOM in a **CycloneDX-style** JSON shape (CycloneDX and SPDX are
the two industry-standard SBOM formats). The real tool that does this by actually
inspecting an image's filesystem is `syft`; here we read the artifact's declared
manifest, which is the same idea at the source-manifest level.

Two identity details worth understanding:
  * **purl** (package URL) — a standard string like `pkg:pypi/flask@2.0.1` that uniquely
    and portably identifies a component across tools and ecosystems. Vulnerability
    scanners match on purl, so getting it right is what makes control 2 work.
  * **hash** — a SHA-256 over the component's identity, standing in for the integrity
    digest a real SBOM records for each resolved package.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class Component:
    name: str
    version: str
    ecosystem: str
    purl: str
    hash: str

    @staticmethod
    def from_dep(dep: dict) -> "Component":
        name = dep["name"]
        version = dep["version"]
        ecosystem = dep["ecosystem"]
        purl = build_purl(ecosystem, name, version)
        digest = hashlib.sha256(purl.encode()).hexdigest()
        return Component(name, version, ecosystem, purl, digest)


@dataclass
class SBOM:
    bom_format: str
    spec_version: str
    artifact_name: str
    artifact_version: str
    components: list[Component] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "bomFormat": self.bom_format,
            "specVersion": self.spec_version,
            "metadata": {
                "component": {
                    "name": self.artifact_name,
                    "version": self.artifact_version,
                }
            },
            "components": [asdict(c) for c in self.components],
        }

    def to_json(self) -> str:
        # sort_keys for deterministic output -> identical bytes every run (testable,
        # and critical later: we sign the SBOM, so its bytes must be stable).
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def purls(self) -> list[str]:
        return [c.purl for c in self.components]


# Maps our ecosystem names to the purl "type" token used by the purl spec.
_PURL_TYPE = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "system": "generic",
}


def build_purl(ecosystem: str, name: str, version: str) -> str:
    """Build a package URL (purl): pkg:<type>/<name>@<version>."""
    ptype = _PURL_TYPE.get(ecosystem, "generic")
    return f"pkg:{ptype}/{name}@{version}"


def generate_sbom(artifact_dir: str | Path) -> SBOM:
    """Read an artifact's manifest and produce its SBOM."""
    manifest_path = Path(artifact_dir) / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    components = [Component.from_dep(d) for d in manifest.get("dependencies", [])]
    return SBOM(
        bom_format="CycloneDX",
        spec_version="1.5",
        artifact_name=manifest["name"],
        artifact_version=manifest["version"],
        components=components,
    )


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Generate an SBOM for an artifact.")
    parser.add_argument("--artifact", default="sample-app")
    args = parser.parse_args()

    sbom = generate_sbom(args.artifact)
    print(sbom.to_json())
    print(f"\n# {len(sbom.components)} components catalogued for "
          f"{sbom.artifact_name}@{sbom.artifact_version}", flush=True)


if __name__ == "__main__":
    main()
