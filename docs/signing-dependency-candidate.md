# Signing dependency candidate and primitive test evidence

Status: draft candidate, not release approval.

For the CPython 3.11/3.13 matrix, select cryptography 50.0.2 (2026-09-30),
cffi 2.1.1 (2026-08-03), and pycparser 3.0 (2026-01-21). Use exact
version pins and wheel-only installation in CI; run the unsigned tests first
and crypto tests separately without optional-provider skips. This initial
version lock is not yet a hash-locked dependency set. Final acceptance
requires verification of the exact published wheel hashes/provenance and
current advisories, including bundled OpenSSL and transitive dependencies.
Do not interpret this limited review as proof of absence of vulnerabilities.

Cryptography's changelog and security advisories were reviewed on 2026-11-24.
The 50.0.2 candidate is later than fixes for the published PKCS#7 oracle
(50.0.0), certificate chain blowup (49.0.0), and previously reported
non-contiguous buffer and bundled OpenSSL issues. The project only intends to
use Ed25519 and key serialization, not PKCS#7 or X.509 chain verification.
Cryptography 49+ removed Intel macOS and 32-bit Windows support; the current
matrix targets Linux x86-64, Windows x86-64 and Apple Silicon macOS.
Additional architecture support is not claimed. Actual wheel installation
and dependency checks on the runner must succeed before acceptance.

Sources:
- https://pypi.org/project/cryptography/50.0.2/
- https://cryptography.io/en/50.0.2/changelog/
- https://github.com/pyca/cryptography/security/advisories
- https://github.com/advisories/GHSA-g6cj-pr64-35w5
- https://github.com/advisories/GHSA-jwv3-5hgf-82ww
- https://pypi.org/project/cffi/2.1.1/
- https://cffi.readthedocs.io/en/stable/installation.html
- https://pypi.org/project/pycparser/3.0/
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners

## Known-answer fixture provenance

RFC 8032 section 7.1 TEST 1 supplies the public synthetic seed, public key
and empty-message signature. For a separate protocol vector, local
OpenSSL 3.5.5 generated the signature using pkeyutl -sign -rawin, with
the published RFC seed encoded in PKCS#8 DER (prefix
302e020100300506032b657004220420), and a message consisting of the
specified domain prefix followed by the exact CRLF-terminated manifest
bytes in tests_crypto/test_ed25519_primitives.py. OpenSSL pkeyutl
-verify -rawin returned "Signature Verified Successfully" for that
signature and the derived public key. The fixed expected signature is
recorded in the test. This is an independent tool path, not an independent
security audit, and OpenSSL may share implementation ancestry with PyCA.
The seed is public test data, not a real private key.

The new primitive module accepts an already loaded Ed25519 key and exact
manifest bytes. It has no CLI, PEM loading, passphrase handling, evidence
verification integration or schema validation. Its caller must enforce
the signed-manifest design and must not treat primitive verification as
proof of evidence consistency. No production signing feature is claimed.
