"""The mock application source. Its contents don't matter functionally — what matters
is that this file's bytes are part of the artifact we hash, sign, and verify. Changing
a single byte here should make signature verification fail (the tamper demo)."""


def handler(request):
    return {"status": "ok", "service": "sample-app", "version": "1.2.0"}
