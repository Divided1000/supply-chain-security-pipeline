"""Control 2 — Vulnerability scanning against the SBOM.

Once we have an inventory (the SBOM), scanning is a join: for each component, ask the
vulnerability feed "are there known CVEs for this package, and does this version fall in
the affected range?" The answer drives the deny/allow decision later.

The two things that make this correct (and that trip people up):

  1. **Match on package identity, not fuzzy name.** We match on (ecosystem, package
     name) so `flask` in pypi can't collide with some `flask` in npm.

  2. **Version-range comparison, not equality.** A CVE affects a *range*
     (`introduced <= v < fixed`). "Is my version affected?" requires comparing version
     strings numerically, so `2.14.1 < 2.15.0` is True but `2.16.0 < 2.15.0` is False.
     A naive string compare gets this wrong (e.g. "2.9" > "2.15" lexically), so we parse
     versions into integer tuples. This is exactly the logic `trivy`/`grype` apply when
     they match an SBOM against the NVD/OSV feeds.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .sbom import SBOM

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


@dataclass
class Finding:
    cve_id: str
    package: str
    version: str
    severity: str
    cvss: float
    fixed_version: str
    summary: str

    def line(self) -> str:
        return (f"{self.severity.upper():8s} {self.cve_id:16s} "
                f"{self.package}@{self.version}  (fixed in {self.fixed_version})")


def parse_version(v: str) -> tuple:
    """Turn '1.1.1k' into a comparable tuple (1,1,1,'k').

    Numeric chunks compare as ints; a trailing non-numeric suffix (openssl's 'k')
    is kept as a string so 1.1.1k > 1.1.1. Good enough for semver-ish comparisons;
    real scanners use ecosystem-specific version algebra (PEP 440, semver, Maven).
    """
    parts: list = []
    for chunk in re.split(r"[.\-+]", v):
        m = re.match(r"^(\d+)([A-Za-z].*)?$", chunk)
        if m:
            parts.append(int(m.group(1)))
            if m.group(2):
                parts.append(m.group(2))
        elif chunk.isdigit():
            parts.append(int(chunk))
        elif chunk:
            parts.append(chunk)
    return tuple(parts)


def _cmp(a: str, b: str) -> int:
    """Return -1/0/1 comparing version a to b, tolerant of int/str tuple mixing."""
    ta, tb = parse_version(a), parse_version(b)
    for x, y in zip(ta, tb):
        if type(x) is not type(y):
            x, y = str(x), str(y)
        if x < y:
            return -1
        if x > y:
            return 1
    # shorter version is "less" (2.14 < 2.14.1)
    return (len(ta) > len(tb)) - (len(ta) < len(tb))


def is_affected(version: str, introduced: str, fixed: str) -> bool:
    """True if introduced <= version < fixed (the standard CVE range semantics)."""
    return _cmp(version, introduced) >= 0 and _cmp(version, fixed) < 0


def load_feed(path: str | Path) -> list[dict]:
    return json.loads(Path(path).read_text()).get("vulnerabilities", [])


def scan(sbom: SBOM, feed_path: str | Path) -> list[Finding]:
    feed = load_feed(feed_path)
    findings: list[Finding] = []
    for comp in sbom.components:
        for vuln in feed:
            if vuln["package"] != comp.name or vuln["ecosystem"] != comp.ecosystem:
                continue
            aff = vuln["affected"]
            if is_affected(comp.version, aff["introduced"], aff["fixed"]):
                findings.append(
                    Finding(
                        cve_id=vuln["id"],
                        package=comp.name,
                        version=comp.version,
                        severity=vuln["severity"],
                        cvss=vuln.get("cvss", 0.0),
                        fixed_version=aff["fixed"],
                        summary=vuln.get("summary", ""),
                    )
                )
    # highest severity first
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 0), f.cvss), reverse=True)
    return findings


def worst_severity(findings: list[Finding]) -> str:
    if not findings:
        return "none"
    return max(findings, key=lambda f: SEVERITY_RANK.get(f.severity, 0)).severity


def main() -> None:
    import argparse

    from .sbom import generate_sbom

    parser = argparse.ArgumentParser(description="Scan an artifact's SBOM for CVEs.")
    parser.add_argument("--artifact", default="sample-app")
    parser.add_argument("--feed", default="data/cve_feed.json")
    args = parser.parse_args()

    sbom = generate_sbom(args.artifact)
    findings = scan(sbom, args.feed)

    print(f"Scanned {len(sbom.components)} components against {args.feed}\n")
    if not findings:
        print("No known vulnerabilities.")
    else:
        for f in findings:
            print(f.line())
        print(f"\n{len(findings)} vulnerabilities; worst severity = "
              f"{worst_severity(findings).upper()}")


if __name__ == "__main__":
    main()
