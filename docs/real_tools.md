# Real-Tool Mapping

This project implements each control from scratch so the mechanism is clear. In
production you would use the battle-tested tools below. This page maps each `scs` module
to the real command and notes what the real tool adds beyond the teaching version.

| Control | `scs` module | Production tool | Example command |
|---------|--------------|-----------------|-----------------|
| 1. SBOM | `sbom.py` | **syft** | `syft <image> -o cyclonedx-json > sbom.json` |
| 2. Vuln scan | `scan.py` | **trivy** / **grype** | `trivy image <image>` · `grype sbom:./sbom.json` |
| 3. Signing | `signing.py` | **cosign** (Sigstore) | `cosign sign <image>` · `cosign verify <image>` |
| 4. Provenance | `provenance.py` | **cosign attest** / SLSA GitHub generator | `cosign attest --predicate slsa.json --type slsaprovenance <image>` |
| 5. Verification gate | `gate.py` | **cosign policy** / **Kyverno** / **OPA Gatekeeper** | Kyverno `verifyImages` policy; `cosign verify --certificate-identity ...` |

## What the real tools add

**syft** — walks the actual image filesystem (OS packages + every language ecosystem),
not just a declared manifest. Emits CycloneDX or SPDX.

**trivy / grype** — ship and auto-update a real vulnerability database (NVD, OSV.dev,
GitHub Advisory DB, distro feeds) and apply ecosystem-correct version comparison (PEP 440,
semver, Maven, APK/DEB/RPM). They also detect misconfigurations and secrets.

**cosign / Sigstore** — the big leap is **keyless signing**: instead of managing a private
key, cosign ties the signature to an identity via OIDC (GitHub Actions, Google, etc.),
issues a short-lived certificate from **Fulcio**, and records the signature in the
**Rekor** public transparency log so it is independently auditable. Our from-scratch RSA
shows the signature math; Sigstore solves the much harder *key management and
revocability* problem around it.

**SLSA provenance** — a GitHub Actions reusable workflow (the SLSA generator) can emit
provenance signed by the build platform itself, which is what earns the higher SLSA levels
(the developer cannot forge it). Our `provenance.py` produces the same in-toto statement
shape, signed locally.

**Kyverno / OPA Gatekeeper** — run inside Kubernetes as admission controllers and reject a
`Pod`/`Deployment` at admission time unless its images satisfy the policy (signed by a
trusted identity, valid attestation, etc.). This is the production form of our `gate.py`,
and it connects directly to the Kyverno admission policy in my Kubernetes workload
security lab — that lab gates on pod *spec*; this gates on artifact *supply-chain trust*.

## Trying the real tools (optional)

The `scs` pipeline runs with zero external dependencies. If you install the real tools,
the same five steps look like:

```bash
# 1 + 2: SBOM and scan
syft myimage:latest -o cyclonedx-json > sbom.json
grype sbom:./sbom.json

# 3 + 4: sign and attest (keyless)
cosign sign myimage:latest
cosign attest --predicate slsa.json --type slsaprovenance myimage:latest

# 5: verify as a gate (fails closed)
cosign verify myimage:latest --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*'
```
