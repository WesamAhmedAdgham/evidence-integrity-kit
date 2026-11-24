# Signing dependency candidate and primitive test evidence

Status: draft candidate, not release approval.

For the CPython 3.11/3.13 matrix, select cryptography 50.0.2 (2026-09-30),
cffi 2.1.1 (2026-08-03), and pycparser 3.0 (2026-01-21). Use exact
version pins and wheel-only installation in CI; run the unsigned tests first
and crypto tests separately without optional-provider skips. The allowlist now pins SHA-256 hashes for the ten exact wheels observed
in successful signed CLI CI at 41b174c. Hash-enforced installation and pip check passed in all twelve native jobs
at 2cd3fb3; final acceptance still requires
independent review and current advisories, including bundled OpenSSL.
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

The primitive module accepts an already loaded Ed25519 key and exact
manifest bytes. It is integrated by the experimental signed CLI, which handles PEM loading,
passphrase input and manifest validation separately. Primitive verification
is not proof of evidence consistency. No production release is claimed.

## Exact wheel allowlist (2026-11-24)

The following filenames were observed in both native CI runs 45307799453 and
45307806168. SHA-256 values were transcribed from the exact wheel details on
PyPI release pages above; Cryptography values appear in PyPI-verified
publisher attestations for pyca/cryptography commit
fe12d283180ea89ceed622021242fddb31d27f84. CFFI and pycparser file metadata
reports non-Trusted-Publishing uploads; hash matching is not proof of publisher
security. No independent Sigstore verification or direct local wheel download
is claimed. CI now enforces hashes, wheel-only installation and reinstall.
Other wheel variants are deliberately not allowed.

| Filename | SHA-256 |
| --- | --- |
| `cryptography-50.0.2-cp311-abi3-win_amd64.whl` | `7afa5a6602a9f29af1f3a2965f831bae7c9d5d597b7cbb716d41ab3b7d89879c` |
| `cryptography-50.0.2-cp311-abi3-manylinux_2_34_x86_64.whl` | `9dab55f57c74c3cad24c323bacbbd04be4705ba6eb0d92e920b1fc4837ed5079` |
| `cryptography-50.0.2-cp311-abi3-macosx_11_0_arm64.whl` | `fa8f5efb344d6908a1ce62f4a24e2e5780f825d6f53f5f50ec5ffacac72936cb` |
| `cffi-2.1.1-cp311-cp311-win_amd64.whl` | `42f6930c31dc7f50732c9ae793c2786c7b6b044195967bbdde40bb9be81c4cc0` |
| `cffi-2.1.1-cp313-cp313-win_amd64.whl` | `1aa5645c30469b09530c4ebca77ebf8f17618293c58f8549cb1a543a50236e7d` |
| `cffi-2.1.1-cp311-cp311-manylinux2014_x86_64.manylinux_2_17_x86_64.whl` | `34e261f78cb6ceaaa36f42f2613f4380d94d9c759a9c73c769ee6e0247364632` |
| `cffi-2.1.1-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl` | `a931079504ecc49efed7744c476a5c343a92fabf66dec2db95edb1b2fdc770e2` |
| `cffi-2.1.1-cp311-cp311-macosx_11_0_arm64.whl` | `398aff33cee2767e3e781d2554c54bd0dff386bb437581e0d8011fde1a942ec1` |
| `cffi-2.1.1-cp313-cp313-macosx_11_0_arm64.whl` | `19ee6127ee34de7d83ce3d371ebc5ed91addbdcc39f9ab15ce4eb35a4e534971` |
| `pycparser-3.0-py3-none-any.whl` | `b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992` |


## Proposed point-validator dependency — not approved

PyNaCl 1.6.2, three pinned wheel hashes verified by byte hashing in PR #25 run 45464785795, with 72 evaluation/integration methods passed in run 45466885008. Upstream reports the bundled libsodium fix for CVE-2025-69277; independent publisher and patch provenance, review of current advisories and the final integration matrix remain required. This draft adds PyNaCl to the signing lock but does not approve it. OpenSSL 4.0.3 is still blocked. The point-validator release allowlist is empty.


## 2026-11-24 release qualification checkpoint

OpenSSL published four additional advisories on 2026-11-24 affecting 4.0.3 and listing fixes for 4.0.4: CVE-2026-84785 and CVE-2026-107494 (QUIC), CVE-2026-121482 (X.509 CRL processing), CVE-2026-84786 (DANE). See https://openssl-library.org/news/timeline/ and https://openssl-library.org/news/vulnerabilities-4.0/. These protocol/certificate paths are not used by the intended offline manifest CLI; this is a preliminary reachability assessment, not proof of non-applicability or approval of the binary. The official release timeline and PyPI https://pypi.org/project/cryptography/ still show OpenSSL 4.0.3 on the pinned cryptography 50.0.2 wheels; do not infer that a listed fix target is a published wheel. Retain the release block and both empty allowlists. Require independent advisory applicability, patch provenance and exact artifact review before approval.
