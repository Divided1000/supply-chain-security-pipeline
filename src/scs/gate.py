"""Control 5 — Deny-by-default admission / verification gate.

The previous four controls produce *evidence*. The gate makes the *decision*: should this
artifact be allowed to run? The defining principle is **deny by default** — an artifact is
rejected unless it affirmatively passes every check. Silence, a missing signature, or an
unverifiable attestation all mean "no". This is the same posture as a cosign verification
policy or a Kyverno admission controller that refuses to admit an unsigned image.

The gate enforces five independent checks, and ALL must pass:

  1. Artifact signature valid        — the code is authentic and unchanged (control 3).
  2. SBOM signature valid            — the ingredient list is authentic and unchanged.
  3. Provenance valid                — the build record is authentic (control 4).
  4. Provenance bound to THIS artifact AND from a TRUSTED builder — stops an attacker
     reusing a real attestation for a different artifact, or self-attesting from an
     untrusted builder.
  5. No vulnerabilities at or above the severity threshold (control 2).

Each failure is recorded with a reason, so a rejection is explainable — an operator sees
*why* an artifact was blocked, not just that it was.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .provenance import SignedProvenance, verify_provenance, provenance_subject_digest
from .scan import Finding, SEVERITY_RANK
from .signing import Signature, verify_signature


@dataclass
class GateInput:
    artifact_digest: str
    sbom_bytes: bytes
    artifact_signature: Signature
    sbom_signature: Signature
    signed_provenance: SignedProvenance
    findings: list[Finding]


@dataclass
class GatePolicy:
    trusted_builders: tuple[str, ...] = ("scs-pipeline@local",)
    # block if any finding is at or above this severity
    max_allowed_severity: str = "high"   # i.e. reject "high" and "critical"

    def severity_blocks(self, severity: str) -> bool:
        return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK[self.max_allowed_severity]


@dataclass
class GateDecision:
    allowed: bool
    checks: list[tuple[str, bool, str]] = field(default_factory=list)  # (name, ok, detail)

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append((name, ok, detail))

    @property
    def reasons(self) -> list[str]:
        return [f"{name}: {detail}" for name, ok, detail in self.checks if not ok]

    def render(self) -> str:
        lines = [f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  — {detail}" if detail else "")
                 for name, ok, detail in self.checks]
        verdict = "ADMITTED" if self.allowed else "REJECTED"
        return "\n".join(lines) + f"\n\nGATE DECISION: {verdict}"


# builder id lives inside the signed provenance statement; pull it out to check trust
def _provenance_builder(signed: SignedProvenance) -> str:
    import json
    stmt = json.loads(signed.statement)
    return stmt.get("predicate", {}).get("runDetails", {}).get("builder", {}).get("id", "")


def evaluate(inp: GateInput, policy: GatePolicy | None = None) -> GateDecision:
    policy = policy or GatePolicy()
    d = GateDecision(allowed=False)

    # 1. artifact signature
    art_ok = verify_signature(inp.artifact_digest.encode(), inp.artifact_signature)
    d.add("artifact-signature", art_ok, "" if art_ok else "artifact signature invalid")

    # 2. sbom signature
    sbom_ok = verify_signature(inp.sbom_bytes, inp.sbom_signature)
    d.add("sbom-signature", sbom_ok, "" if sbom_ok else "SBOM signature invalid")

    # 3. provenance signature
    prov_ok = verify_provenance(inp.signed_provenance)
    d.add("provenance-signature", prov_ok, "" if prov_ok else "provenance signature invalid")

    # 4a. provenance bound to this exact artifact
    bound = prov_ok and provenance_subject_digest(inp.signed_provenance) == inp.artifact_digest
    d.add("provenance-binding", bound,
          "" if bound else "provenance subject digest != artifact digest")

    # 4b. builder is trusted
    builder = _provenance_builder(inp.signed_provenance)
    builder_ok = builder in policy.trusted_builders
    d.add("trusted-builder", builder_ok,
          "" if builder_ok else f"untrusted builder '{builder}'")

    # 5. vulnerability threshold
    blocking = [f for f in inp.findings if policy.severity_blocks(f.severity)]
    vuln_ok = not blocking
    d.add("vulnerability-threshold", vuln_ok,
          "" if vuln_ok else
          f"{len(blocking)} finding(s) >= {policy.max_allowed_severity}: "
          f"{', '.join(f.cve_id for f in blocking)}")

    # deny by default: allowed only if every check passed
    d.allowed = all(ok for _, ok, _ in d.checks)
    return d
