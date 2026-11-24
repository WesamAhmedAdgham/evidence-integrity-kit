# Cumulative release qualification — independent review required

This is an author-side AI-assisted review packet, not independent approval.
Baseline main: `85a6b7939ef0ae96d44999e2b7afcef85ae5a2a5` (PR #28 merged).
Last functionally qualified reconciled head: `f36424a6372d3fc9c51c4f29aa0a043117c1a195`; tree `c228f96027339b0b553a6706bf5f49a4244be8a5`.
Review the exact latest head of PR #26, including this packet revision, against main. The last reconciled head had 104 commits ahead, zero behind, 43 changed files. The revision of this packet changes documentation only; do not reuse earlier CI as exact-head acceptance. APFS is deferred to #22; experimental #25 infrastructure is excluded. Owner's independent-review waiver was limited to unsigned PR #28 and does not extend to this candidate.

## Reproducible evidence

| Stage | Run | Observed outcome |
| --- | --- | --- |
| PKCS#8 bounds and key format | 45390037499 | 1,346 passes, 214 skips, 0 failures |
| JSON resource bounds | 45421134451 | 1,400 passes, 214 skips, 0 failures after cancelled macOS retry |
| KDF provisioning | 45430965467 | 1,400 passes, 214 skips, 0 failures after macOS retries |
| Isolated validator | 45464785795 | 30 evaluation methods passed, 24 artifact digest checks; 13 distinct artifacts |
| Test-hook integration | 45466885008 | 72 evaluation methods passed, zero skips/failures |
| Direct runtime baseline | 45467589147 | 1,460 passes, 214 skips, 0 failures, six native jobs; 219 standard + 60 crypto methods each |

All six last-baseline functional job logs checked out merge `67c1c9e5dc1ccde7997361c007abcbc8e676c425`, identical tree to baseline. All 54 direct point-admission executions passed; native Btrfs positive/negative fixtures passed on both Linux runners. Platform skips are not native coverage on other platforms. Provider gate skipped on stacked PR; not approval. Retargeting #26 to main alone did not create a fresh workflow run at the observed checkpoint; this documentation revision is intended to trigger the full direct-main matrix. No result for the revised head is claimed.

## Review disposition checklist

| Area | Evidence available | Required independent disposition |
| --- | --- | --- |
| F01 / dependencies | Locked cryptography 50.0.2 / OpenSSL 4.0.3; PyNaCl 1.6.2 | Review current advisories, all artifact provenance and bundled binary identity; all three approval allowlists empty |
| F02 / Ed25519 | Canonical SPKI, maintained point validation, fail-closed direct tests | Review subgroup semantics, provider errors, trusted key model and exact wheel provenance |
| F03 / KDF | Bounded outer DER profile, passphrase limit, 600,000 iteration roundtrip | Independent parser differential review; decide legacy import vs stronger provisioning policy |
| F04–F06 / filesystem | Sampled mode, Windows NTFS guarded mode and Linux Btrfs snapshot native tests | Owner acceptance of residual TOCTOU and isolation requirements; no comprehensive guarantee |
| F07 / JSON | Structural and byte budgets, native regression | Review parser and compatibility, process-wide resource limitations |
| F08–F09 / control inputs | Sampled stable reads and terminal passphrase tests | Review trusted control storage, races and secret lifetime |
| F10 / provenance | Hash locks, actual wheel digest and installation evidence | Verify publisher attestations separately; hash matching is not publisher trust |
| F11 / documentation | Updated design and README | Check exact final code/docs consistency |
| F12 / protocol scope | Explicit signature, trust and replay boundaries | Accept limits on completeness, freshness and legal provenance |
| F13 / independence | Implementation-side evidence only | Independent reviewer signs off on exact final fixed head |

## Execution and acceptance

In a fresh venv install with `python -m pip install --require-hashes --only-binary=:all: -r requirements-signing.txt`, then `python -m pip check`, `python -m unittest discover -s tests -v`, and `python -m unittest discover -s tests_crypto -v`. Inspect actual native terminal and filesystem fixture results, not just green job summaries. Use synthetic inputs only. Review complete cumulative diff, production modules, CI workflows, lock, licenses and threat model. Verify exact tree identity of CI checkout and all final changes.

Record each finding ID, severity, exact commit, source, reproduction, impact, fix, independent retest and disposition. Explicitly distinguish author-side functional tests, independent audit, dependency approval and owner release authorization. No merge, tag or production release until all required gates are met. No provider allowlist entry merely on version or CI success.

## Exact artifact-bound release approval

The previous gate matched provider version strings only. This revision requires three independent, explicit allowlist matches: cryptography/OpenSSL, point-validator version, and SHA-256 of a canonical approval record containing the complete semantic lock (including every permitted wheel digest), the verified pip install report's exact wheel filenames/digests/versions for all four packages, and CPython implementation/major.minor, OS, architecture and reported provider versions. All three allowlists remain empty. CI passes the original installation report and lock to the gate, which revalidates report structure and installed distribution versions. Future review must record provenance, applicability, and exact artifact approval for every allowed environment and every lock artifact before adding any digest. An alternative wheel, transitive dependency, extra lock hash, or environment change invalidates an existing environment approval. A digest identifies evidence; it is not by itself a signature or independent approval.

The gate assumes a trusted CI runner, pip, installation report and local interpreter. It does not prove that arbitrary installed native code corresponds to the report, independently authenticate a publisher or establish patched binary identity. No runtime signing code, dependency pins, CI job names or main-target conditions changed. Test the exact revised candidate and require independent review of this policy before any allowlist entry. Run: `python -m tools.check_release_provider --report signing-install-report.json --lock requirements-signing.txt`. Current OpenSSL 4.0.3 remains blocked; all three explicit approvals remain mandatory.


## Current author-side signing-path review and remaining decisions

Historical direct-main run 45486557127 on the reconciled head: 225 standard + 60 crypto methods per environment, 1,496 passed, 214 platform skips, zero failures; both native Linux Btrfs positive and nested-bind-negative fixtures passed. Six mandatory release jobs rejected all three approval dimensions. See PR #26 comment 7144417234. Fresh review of exact source at that head (not an independent review or fresh local execution):

- `encrypted_key_profile.py:61–102` admits only bounded canonical outer DER; no default PRF, unsupported OIDs, nonminimal lengths, unbounded iteration count, trailing bytes, or oversized ciphertext. `signing_keys.py:100–118,144–149` rechecks the admitted DER before provider decryption; file path rejects unsupported outer profile before prompting. Existing regression coverage includes every truncated prefix and provider roundtrips at both iteration bounds. **F03 remains open for independent parser differential and owner approval of legacy 2,048–599,999 iteration import / short salts versus stronger provisioning.** No cryptographic inner parser proof is claimed.
- `signing_keys.py:22–82` enforces exact PEM/base64 and canonical RFC 8410 Ed25519 SPKI, checks the point with PyNaCl before generic PyCA parsing, rejects non-True results, checks type and canonical reserialization. Existing native point tests include mixed-order/noncanonical points, unavailable validator and valid generated keys. **F02 remains open for exact validator artifact and independent subgroup review.** No claim of a proven signature forgery or independent binary validation.
- `manifest_signatures.py:22–65` binds exact bytes to the fixed domain, enforces a 64-byte detached signature and lowercase canonical hex encoding with allowed final newline; `evidence_integrity.py:666–697` validates strict schema before signing, authenticates retained bytes before JSON or evidence I/O when verifying, reports trusted-key fingerprint and never falls back. Existing tests cover wrong key, tampering, schema violation, exact retained buffer and missing signature. **F12 remains an explicit protocol boundary:** trusted key distribution, replay/freshness, completeness and capture mode are not established by a signature alone.
- `evidence_integrity.py:574–603` bounds and samples control-file reads; `signing_keys.py:121–138` rejects redirected input and echo fallback, then checks UTF-8 byte size after collection. **F08/F09 remain conditional on trusted control storage and secret lifecycle;** no atomic control-file cohort, pre-allocation terminal input cap or Python memory zeroization. No new bypass observed in this source pass; no full filesystem review or additional execution claimed.
- `evidence_integrity.py:717–725` requires explicit protection selection for create/verify/verify-signed, unlike previous unsigned main CLI. Documented breaking change; callers must migrate. Native failures must not downgrade. Python API default remains sampled. Review/accept the migration and remaining threat boundaries before second merge. 

No production code, lock, workflow or approval allowlist changes in this packet revision. Next review separately covers Windows and Linux providers, trust and artifact evidence, and exact final documentation/behavior. Keep release blocked until independent review and explicit owner decisions are recorded. No release approval.
