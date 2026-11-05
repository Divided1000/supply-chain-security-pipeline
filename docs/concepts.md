# Concepts — Software Supply-Chain Security

A plain-language explanation of the problem and the five controls, written to be read
start to finish. The code in `src/scs/` implements each of these.

## The problem

When you `docker pull` an image or `pip install` a package, you run code you did not
write, built by people you never met, delivered through infrastructure you do not control.
A **software supply-chain attack** compromises one link in that chain so that you end up
running the attacker's code while believing it is legitimate.

Why it is so dangerous: the final artifact looks completely normal. Nothing downstream can
tell it was tampered with — unless the chain carries *evidence* that can be independently
verified. Real cases:

- **SolarWinds (2020)** — malicious code injected into the *build pipeline*, so the
  official, correctly-signed update shipped a backdoor to ~18,000 organizations.
- **Codecov (2021)** — a CI script was altered to exfiltrate secrets from everyone who ran it.
- **XZ Utils (2024)** — a long-con maintainer takeover planted a backdoor in a core Linux library.

The five controls below exist to make each link verifiable.

## Control 1 — SBOM: "What's inside?"

A **Software Bill of Materials** is an ingredient list: every component, with a version and
a portable identifier (**purl**, e.g. `pkg:pypi/flask@2.0.1`). You cannot secure what you
cannot see — the SBOM is the inventory every other control builds on. When a new CVE drops,
you answer "am I affected?" by querying SBOMs instead of guessing.

## Control 2 — Vulnerability scan: "Any known holes?"

Join each SBOM component against a vulnerability feed. The subtlety is **version-range
comparison**: a CVE affects a range (`introduced <= v < fixed`), so you must compare
versions *numerically* (2.9 is older than 2.15, even though "2.9" > "2.15" as text). A
component sitting exactly at its fixed version is safe. Getting this boundary right is the
difference between real coverage and false confidence.

## Control 3 — Signing: "Who made it, and has it changed?"

A **hash** proves integrity (bytes unchanged) but not authenticity — an attacker who edits
a file just recomputes the hash. A **digital signature** proves both: the signer uses a
**private** key; anyone verifies with the **public** key. Only the private-key holder could
produce a signature that verifies, so a tamper (changed bytes) or a forgery (wrong key)
both fail verification. This is the control that *would have* caught a post-build artifact
swap — if the consumer verified.

## Control 4 — Provenance: "Where did it come from and how was it built?"

A signature says the artifact is authentic; **provenance** says *how it came to be*. It is
a signed statement (SLSA / in-toto) recording the builder identity, source repo and commit,
and build inputs, cryptographically bound to the artifact's digest. This is the
SolarWinds-specific defense: the backdoor entered during the build, so a trustworthy record
of the build itself is what exposes it. SLSA levels (L1–L4) rank how tamper-resistant that
record is; the key jump is requiring the *build platform* to generate it, so a developer
cannot forge "this was built cleanly."

## Control 5 — Verification gate: "Should we run it?"

The gate turns evidence into a decision, and it is **deny-by-default**: an artifact is
rejected unless it affirmatively passes every check — valid artifact signature, valid SBOM
signature, valid provenance, provenance bound to *this* artifact from a *trusted* builder,
and no vulnerabilities above the severity threshold. A missing or unverifiable anything
means "no." Every rejection is explainable (it lists the failed checks), which is what
makes a gate usable in production rather than something people disable.

## The whole chain

```
build ─▶ SBOM (what's inside) ─▶ scan (known holes?) ─▶ sign (authentic?) ─▶
         attest (how built?) ─▶ GATE (deny by default) ─▶ run / reject
```

Each control answers one question an attacker hopes you never ask. Together they turn
"trust me" into "here is independently verifiable evidence" — which is exactly the
guarantee Chainguard ships with its hardened open-source builds.
