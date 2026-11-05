"""End-to-end supply-chain pipeline: build -> SBOM -> scan -> sign -> attest -> verify.

Runs all five controls on an artifact and prints a trust report ending in an admit/reject
decision from the gate. With --tamper, it modifies the artifact *after* signing to show
the gate catch it — the core demonstration that these controls actually defend something.

    python -m scs.pipeline --artifact sample-app
    python -m scs.pipeline --artifact sample-app --tamper
"""
from __future__ import annotations

import argparse

from .gate import GateInput, GatePolicy, evaluate
from .provenance import build_provenance, sign_provenance
from .sbom import generate_sbom
from .scan import scan, worst_severity
from .signing import (
    digest_artifact, digest_bytes, generate_keypair, sign_content,
)


def run(artifact: str, feed: str, tamper: bool = False,
        policy: GatePolicy | None = None):
    policy = policy or GatePolicy()

    # --- build phase: establish keys and produce evidence ---
    pub, priv = generate_keypair()

    # control 1: SBOM
    sbom = generate_sbom(artifact)
    sbom_bytes = sbom.to_json().encode()

    # control 2: scan
    findings = scan(sbom, feed)

    # control 3: sign the artifact digest and the SBOM
    artifact_digest = digest_artifact(artifact)
    art_sig = sign_content("artifact-digest", artifact_digest.encode(), priv, pub)
    sbom_sig = sign_content("sbom", sbom_bytes, priv, pub)

    # control 4: signed provenance, bound to the artifact digest
    prov = build_provenance(
        artifact_name=sbom.artifact_name,
        artifact_digest=artifact_digest,
        sbom_digest=digest_bytes(sbom_bytes),
    )
    signed_prov = sign_provenance(prov, priv, pub)

    # --- tamper: modify the artifact AFTER signing (attacker swaps the build) ---
    verified_digest = artifact_digest
    if tamper:
        # recompute the digest as if an attacker changed a file; signatures were made
        # over the ORIGINAL digest, so verification must now fail.
        verified_digest = digest_bytes(b"malicious-swapped-artifact")

    # control 5: the gate
    gate_input = GateInput(
        artifact_digest=verified_digest,
        sbom_bytes=sbom_bytes,
        artifact_signature=art_sig,
        sbom_signature=sbom_sig,
        signed_provenance=signed_prov,
        findings=findings,
    )
    decision = evaluate(gate_input, policy)
    return sbom, findings, decision


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the supply-chain pipeline.")
    parser.add_argument("--artifact", default="sample-app")
    parser.add_argument("--feed", default="data/cve_feed.json")
    parser.add_argument("--tamper", action="store_true",
                        help="modify the artifact after signing to show the gate reject it")
    parser.add_argument("--max-severity", default="high",
                        help="block findings at or above this severity")
    args = parser.parse_args()

    policy = GatePolicy(max_allowed_severity=args.max_severity)
    sbom, findings, decision = run(args.artifact, args.feed, args.tamper, policy)

    print("=" * 70)
    print(f"SUPPLY-CHAIN PIPELINE — {sbom.artifact_name}@{sbom.artifact_version}"
          + ("   [TAMPERED]" if args.tamper else ""))
    print("=" * 70)
    print(f"[1] SBOM        : {len(sbom.components)} components")
    print(f"[2] Scan        : {len(findings)} vuln(s), worst = {worst_severity(findings).upper()}")
    print(f"[3] Signing     : artifact + SBOM signed")
    print(f"[4] Provenance  : SLSA statement signed and bound to artifact digest")
    print(f"[5] Gate        :")
    for name, ok, detail in decision.checks:
        print(f"      {'PASS' if ok else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ""))
    print("-" * 70)
    print(f"DECISION: {'ADMITTED' if decision.allowed else 'REJECTED'}")
    if not decision.allowed:
        print("reasons:")
        for r in decision.reasons:
            print(f"  - {r}")
    raise SystemExit(0 if decision.allowed else 1)


if __name__ == "__main__":
    main()
