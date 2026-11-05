"""Control 3 — Digital signatures over the artifact and its SBOM.

This answers two questions an attacker hopes you never ask: **who produced this, and has
it changed since they produced it?** A SolarWinds-style tamper — swapping the artifact
after it was built but before you run it — is exactly what a signature catches, *if* the
consumer verifies it.

Two primitives, and the difference between them matters:

  * **Hash (digest)** — a one-way fingerprint of some bytes (SHA-256). Change one byte,
    the digest changes completely. A hash proves *integrity* ("these bytes are unchanged")
    but NOT *authenticity* — anyone can compute a hash, so an attacker who changes the
    file can just recompute the hash too.

  * **Digital signature** — the signer uses their **private** key to sign the digest;
    anyone can check it with the signer's **public** key. Only the holder of the private
    key could have produced a signature that verifies, so this proves *authenticity*
    (who) AND *integrity* (unchanged). An attacker who tampers the file cannot forge a
    valid signature without the private key.

We implement textbook **RSA** from scratch (stdlib only) so the mechanism is visible:
keygen (two primes -> modulus n, public exponent e, private exponent d), sign
(s = hash^d mod n), verify (hash == s^e mod n). This is deliberately educational — real
systems use padded RSA (PSS) or Ed25519 via a vetted library, and Sigstore/cosign add
*keyless* signing (short-lived certs tied to an OIDC identity, logged in a public
transparency log). Those tradeoffs are documented in docs/real_tools.md.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from pathlib import Path


# ---------------------------------------------------------------------------
# artifact / content digests
# ---------------------------------------------------------------------------

def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_artifact(artifact_dir: str | Path) -> str:
    """A single SHA-256 over all files in the artifact, in sorted path order.

    Sorting makes the digest deterministic regardless of filesystem ordering. Any change
    to any file (or the set of files) changes this digest — that is what the signature
    will protect.
    """
    artifact_dir = Path(artifact_dir)
    h = hashlib.sha256()
    for path in sorted(p for p in artifact_dir.rglob("*") if p.is_file()):
        h.update(path.relative_to(artifact_dir).as_posix().encode())
        h.update(b"\0")
        h.update(path.read_bytes())
    return h.hexdigest()


# ---------------------------------------------------------------------------
# textbook RSA  (educational; see module docstring)
# ---------------------------------------------------------------------------

@dataclass
class PublicKey:
    n: int
    e: int


@dataclass
class PrivateKey:
    n: int
    d: int


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1  # top & bottom bit set
        if _is_probable_prime(candidate):
            return candidate


def generate_keypair(bits: int = 512) -> tuple[PublicKey, PrivateKey]:
    """Generate an RSA keypair. 512 bits keeps the demo fast; NOT secure for real use
    (real RSA is >= 2048). The algorithm is identical at any size."""
    e = 65537
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e != 0:
            d = pow(e, -1, phi)  # modular inverse (Python 3.8+)
            return PublicKey(n, e), PrivateKey(n, d)


def _digest_to_int(message: bytes, n: int) -> int:
    """Hash the message to a fixed digest, interpret as an int < n (textbook RSA)."""
    h = hashlib.sha256(message).digest()
    return int.from_bytes(h, "big") % n


def sign(message: bytes, priv: PrivateKey) -> int:
    """Signature = (H(m))^d mod n. Requires the private key."""
    m = _digest_to_int(message, priv.n)
    return pow(m, priv.d, priv.n)


def verify(message: bytes, signature: int, pub: PublicKey) -> bool:
    """Valid iff (signature)^e mod n == H(m). Uses only the public key."""
    expected = _digest_to_int(message, pub.n)
    recovered = pow(signature, pub.e, pub.n)
    return recovered == expected


# ---------------------------------------------------------------------------
# signed-bundle helpers used by the pipeline
# ---------------------------------------------------------------------------

@dataclass
class Signature:
    """A signature plus the public key needed to verify it and what was signed."""
    subject: str          # what was signed, e.g. "artifact-digest" or "sbom"
    signed_digest: str    # the sha256 hex of the signed content (human-readable record)
    value: int            # the RSA signature integer
    public_key: PublicKey

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "signed_digest": self.signed_digest,
            "value": str(self.value),
            "public_key": {"n": str(self.public_key.n), "e": self.public_key.e},
        }

    @staticmethod
    def from_dict(d: dict) -> "Signature":
        pk = PublicKey(int(d["public_key"]["n"]), int(d["public_key"]["e"]))
        return Signature(d["subject"], d["signed_digest"], int(d["value"]), pk)


def sign_content(subject: str, content: bytes, priv: PrivateKey,
                 pub: PublicKey) -> Signature:
    return Signature(
        subject=subject,
        signed_digest=digest_bytes(content),
        value=sign(content, priv),
        public_key=pub,
    )


def verify_signature(content: bytes, sig: Signature) -> bool:
    """Verify both that the content matches the recorded digest AND the RSA signature."""
    if digest_bytes(content) != sig.signed_digest:
        return False
    return verify(content, sig.value, sig.public_key)


def main() -> None:
    import argparse
    from .sbom import generate_sbom

    parser = argparse.ArgumentParser(description="Sign an artifact and its SBOM.")
    parser.add_argument("--artifact", default="sample-app")
    args = parser.parse_args()

    pub, priv = generate_keypair()
    art_digest = digest_artifact(args.artifact)
    sbom_bytes = generate_sbom(args.artifact).to_json().encode()

    art_sig = sign_content("artifact-digest", art_digest.encode(), priv, pub)
    sbom_sig = sign_content("sbom", sbom_bytes, priv, pub)

    print(f"artifact digest : {art_digest}")
    print(f"artifact sig ok : {verify_signature(art_digest.encode(), art_sig)}")
    print(f"sbom sig ok     : {verify_signature(sbom_bytes, sbom_sig)}")

    # tamper demo: flip the artifact digest and re-verify
    tampered = ("0" + art_digest[1:]).encode()
    print(f"tampered sig ok : {verify_signature(tampered, art_sig)}  (expected False)")


if __name__ == "__main__":
    main()
