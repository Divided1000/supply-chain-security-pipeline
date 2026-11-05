"""Tests for all five supply-chain controls, with positive and negative cases."""
from scs.sbom import generate_sbom, build_purl
from scs.scan import scan, is_affected, parse_version, _cmp, worst_severity
from scs.signing import (
    generate_keypair, sign, verify, sign_content, verify_signature,
    digest_artifact, digest_bytes,
)
from scs.provenance import build_provenance, sign_provenance, verify_provenance, provenance_subject_digest
from scs.gate import GateInput, GatePolicy, evaluate
from scs.pipeline import run


# ---------------- control 1: SBOM ----------------

def test_sbom_lists_all_components(sample_app):
    sbom = generate_sbom(sample_app)
    assert len(sbom.components) == 6
    names = {c.name for c in sbom.components}
    assert {"flask", "log4j-core", "openssl"} <= names


def test_purl_format():
    assert build_purl("pypi", "flask", "2.0.1") == "pkg:pypi/flask@2.0.1"
    assert build_purl("system", "openssl", "1.1.1k") == "pkg:generic/openssl@1.1.1k"


def test_sbom_is_deterministic(sample_app):
    # byte-identical across runs — required because we sign it
    assert generate_sbom(sample_app).to_json() == generate_sbom(sample_app).to_json()


# ---------------- control 2: scan ----------------

def test_scan_flags_log4j(sample_app, feed):
    findings = scan(generate_sbom(sample_app), feed)
    cves = {f.cve_id for f in findings}
    assert "CVE-2021-44228" in cves       # Log4Shell
    assert worst_severity(findings) == "critical"


def test_scan_respects_fixed_version(sample_app, feed):
    # pyyaml 5.4.1, openssl 1.1.1k, lodash 4.17.21 are all AT their fix version -> safe
    findings = scan(generate_sbom(sample_app), feed)
    flagged = {f.package for f in findings}
    assert "pyyaml" not in flagged
    assert "openssl" not in flagged
    assert "lodash" not in flagged


def test_scan_ignores_packages_not_present(sample_app, feed):
    findings = scan(generate_sbom(sample_app), feed)
    assert "leftpad" not in {f.package for f in findings}


def test_patched_artifact_has_no_vulns(sample_app_patched, feed):
    findings = scan(generate_sbom(sample_app_patched), feed)
    assert findings == []


def test_version_comparison_is_numeric_not_lexical():
    # the classic bug: "2.9" > "2.15" as strings, but 2.9 < 2.15 numerically
    assert _cmp("2.9", "2.15") == -1
    assert parse_version("1.1.1k") > parse_version("1.1.1")


def test_is_affected_boundaries():
    assert is_affected("2.14.1", "2.0.0", "2.15.0") is True
    assert is_affected("2.15.0", "2.0.0", "2.15.0") is False   # fixed version is safe
    assert is_affected("1.9.0", "2.0.0", "2.15.0") is False    # below introduced


# ---------------- control 3: signing ----------------

def test_rsa_sign_verify_roundtrip():
    pub, priv = generate_keypair()
    msg = b"hello supply chain"
    sig = sign(msg, priv)
    assert verify(msg, sig, pub) is True


def test_rsa_detects_tamper():
    pub, priv = generate_keypair()
    sig = sign(b"original", priv)
    assert verify(b"tampered", sig, pub) is False


def test_attacker_key_cannot_forge():
    pub, _priv = generate_keypair()
    _atk_pub, atk_priv = generate_keypair()
    forged = sign(b"content", atk_priv)
    assert verify(b"content", forged, pub) is False


def test_sign_content_and_verify(sample_app):
    pub, priv = generate_keypair()
    digest = digest_artifact(sample_app).encode()
    sig = sign_content("artifact-digest", digest, priv, pub)
    assert verify_signature(digest, sig) is True
    assert verify_signature(b"different", sig) is False


# ---------------- control 4: provenance ----------------

def test_provenance_signs_and_verifies(sample_app):
    pub, priv = generate_keypair()
    ad = digest_artifact(sample_app)
    sd = digest_bytes(generate_sbom(sample_app).to_json().encode())
    signed = sign_provenance(build_provenance("sample-app", ad, sd), priv, pub)
    assert verify_provenance(signed) is True
    assert provenance_subject_digest(signed) == ad


def test_provenance_tamper_fails(sample_app):
    pub, priv = generate_keypair()
    ad = digest_artifact(sample_app)
    signed = sign_provenance(build_provenance("sample-app", ad, "x"), priv, pub)
    signed.statement = signed.statement.replace("sample-app", "evil-app")
    assert verify_provenance(signed) is False


# ---------------- control 5: gate + pipeline ----------------

def test_patched_artifact_is_admitted(sample_app_patched, feed):
    _sbom, _findings, decision = run(str(sample_app_patched), str(feed),
                                     policy=GatePolicy(max_allowed_severity="critical"))
    assert decision.allowed is True
    assert all(ok for _, ok, _ in decision.checks)


def test_vulnerable_artifact_is_rejected(sample_app, feed):
    _sbom, _findings, decision = run(str(sample_app), str(feed),
                                     policy=GatePolicy(max_allowed_severity="critical"))
    assert decision.allowed is False
    assert any("vulnerability-threshold" in r for r in decision.reasons)


def test_tamper_is_rejected(sample_app_patched, feed):
    # use the patched (vuln-free) artifact so the ONLY failure is tampering
    _sbom, _findings, decision = run(str(sample_app_patched), str(feed), tamper=True,
                                     policy=GatePolicy(max_allowed_severity="critical"))
    assert decision.allowed is False
    reasons = " ".join(decision.reasons)
    assert "artifact-signature" in reasons
    assert "provenance-binding" in reasons


def test_untrusted_builder_is_rejected(sample_app_patched, feed):
    # a policy that trusts a different builder than the pipeline uses
    policy = GatePolicy(trusted_builders=("some-other-builder",),
                        max_allowed_severity="critical")
    _sbom, _findings, decision = run(str(sample_app_patched), str(feed), policy=policy)
    assert decision.allowed is False
    assert any("trusted-builder" in r for r in decision.reasons)


def test_gate_is_deny_by_default():
    # an empty/garbage gate input must be rejected, never silently allowed
    pub, priv = generate_keypair()
    bad_sig = sign_content("artifact-digest", b"x", priv, pub)
    signed_prov = sign_provenance(build_provenance("a", "deadbeef", "x"), priv, pub)
    inp = GateInput(
        artifact_digest="not-the-signed-digest",
        sbom_bytes=b"{}",
        artifact_signature=bad_sig,
        sbom_signature=bad_sig,
        signed_provenance=signed_prov,
        findings=[],
    )
    decision = evaluate(inp)
    assert decision.allowed is False
