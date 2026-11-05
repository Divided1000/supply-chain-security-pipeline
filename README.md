# Supply-Chain Security Pipeline

A from-scratch implementation of the five controls that make a software artifact
**trustworthy end to end** — the same guarantees commercial tools like Sigstore/cosign,
syft, and Trivy provide, built here in plain Python so the *mechanism* is visible, not
hidden behind a CLI.

This is the problem [Chainguard](https://www.chainguard.dev/) exists to solve: when you
pull an image or install a package, you run code you didn't write, built by someone you
never met, shipped through infrastructure you don't control. A **supply-chain attack**
poisons one link in that chain so you run the attacker's code thinking it's legitimate
(SolarWinds 2020, Codecov, XZ Utils). The final artifact looks normal — nothing
downstream can tell it was tampered with. These five controls close that gap.

## The five controls

| # | Control | Question it answers | Real-world tool |
|---|---------|---------------------|-----------------|
| 1 | **SBOM** | What's actually inside this artifact? | `syft` |
| 2 | **Vuln scan** | Do any ingredients have known CVEs? | `trivy` / `grype` |
| 3 | **Signing** | Who built it, and has it changed since? | `cosign` / Sigstore |
| 4 | **Provenance** | Where did it come from and how was it built? | SLSA / in-toto |
| 5 | **Verification gate** | Should we allow this to run? | cosign policy / Kyverno |

The payoff is **control 5**: a deny-by-default gate that refuses to admit any artifact
that isn't signed, lacks trusted provenance, or carries critical vulnerabilities.

## Design: learn the mechanism, then the tooling

The core is implemented from scratch in Python using real cryptography (SHA-256 digests,
Ed25519 / HMAC signatures) so you can see exactly what each control does under the hood.
Alongside, [`docs/real_tools.md`](docs/real_tools.md) maps every step to the
industry-standard command (`syft`, `trivy`, `cosign`, `slsa`) you'd run in production.

Everything runs **offline and deterministically** — no external services, no network — so
it is reproducible and testable.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# run the whole pipeline on the sample artifact
python -m scs.pipeline --artifact sample-app

# see the gate reject a tampered artifact
python -m scs.pipeline --artifact sample-app --tamper

pytest -q
```

## Layout

```
src/scs/
  sbom.py         control 1 — build a CycloneDX-style SBOM
  scan.py         control 2 — match SBOM components to a CVE feed
  signing.py      control 3 — digital signatures over artifact + SBOM
  provenance.py   control 4 — SLSA-style signed build provenance
  gate.py         control 5 — deny-by-default verification policy
  pipeline.py     end-to-end runner + tamper demo
sample-app/       the mock artifact we build/scan/sign/verify
data/             sample CVE feed
docs/             concepts writeup + real-tool mapping
tests/
```

## Documentation

- [Concepts](docs/concepts.md) — the supply-chain problem and each control explained
- [Real tools](docs/real_tools.md) — the production command for each control
