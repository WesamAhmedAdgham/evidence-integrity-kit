# Release review packet — independent review required

Implementation baseline: `0a59fe012198e10666bb2cbcaf3f71852829a1d5` (PR #23).
Review the final exact commit, including any subsequent changes; this packet does not approve it.
This packet is an implementation-side review, not independent approval.
The release candidate is the exact head of this draft PR, not main.

## Evidence and reproducibility

- Compare cumulatively against main `5f1c01439e3d65a635a164507e92fcf8f68a695f`.
- Review every production module, native adapter, security design, dependency lock, CI workflow and test suite.
- Previous PR #23 baseline `c31002d8dea2bb960bd473ec05d4e2071cd8d951`: run 45390037499, six functional jobs, 1,346 passes, 214 platform skips, zero failures; tested merge tree matched candidate tree. Provider gate skipped, not approval.
- F07 baseline `0a59fe012198e10666bb2cbcaf3f71852829a1d5`: run 45421134451, five completed native jobs each with 218 standard and 51 crypto methods; 1,170 passes, 175 platform skips, zero test failures in completed jobs. macOS 3.13 cancelled; retry requested. Do not count the unfinished job or credit the new candidate with these historical results.
- PR #20 run 45323053884: all six provider-policy jobs failed. Require provider approval, exact final tree and full native matrix; no automatic release.
- In a fresh venv install using pip --require-hashes --only-binary=:all:
  -r requirements-signing.txt, run python -m pip check, then run
  python -m unittest discover -s tests -v and
  python -m unittest discover -s tests_crypto -v.
- Review the baseline native Windows console and POSIX PTY tests and rerun
  them on the final candidate. Mocked input is not evidence of real echo suppression.
- Verify PyPI artifact hashes/provenance against source records and current
  advisories; do not assume successful installation proves supply-chain safety.

## Review priorities and open limitations

1. Authentication: exact bytes, domain separator, canonical encoding, key
   type, strict schema, no fallback or filesystem access before authentication,
   exit codes, public-key trust and replay semantics.
2. Key handling: encrypted DER parser, resource-intensive KDF parameters,
   prompt behavior, errors and secret lifetime. Keys must be trusted local
   inputs; the strict outer KDF profile bounds admitted parameters, not total process resources. Review F02 public-key validity, F03 stronger provisioning policy versus legacy compatibility, and actual Windows console and POSIX PTY evidence.
3. Filesystem: POSIX directory moves after open, mount changes, Windows
   sampled-mode absolute path limitations, guarded native relative traversal, reparse mutations, special files, inode
   reuse, metadata collisions, path aliases, root ancestors, control-input
   races and multi-file consistency. Current checks are sampled mitigations;
   not comprehensive protection against a hostile mutable filesystem.
4. Snapshot prerequisite: externally trusted immutable snapshot or effective
   write/namespace exclusion is needed for point-in-time evidence. Guarded Windows and Btrfs modes enforce specific tested controls, not comprehensive isolation across arbitrary environments. Owner and independent reviewer must
   explicitly accept the bounded threat model or require further implementation.
5. Dependencies: ten exact hashes, no source builds, install fresh, review
   PyPI provenance, upstream versions and bundled OpenSSL, optional provider
   absence, no implicit upgrade.
6. CI and packaging: check all native logs and explained skips; validate
   unsigned compatibility, help/exit codes, no secrets, MIT license.

Record findings with ID, severity, exact commit, source location, reproduction,
impact, remediation, and independent retest result. An independent reviewer
must assess the final fixed commit and explicitly record residual risks.
The author cannot approve their own implementation as independent.
Do not mark audit, comprehensive TOCTOU protection, or release acceptance
complete solely because tests pass. No merge until owner gates are met.
