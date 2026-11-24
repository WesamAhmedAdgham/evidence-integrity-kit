# Release review packet — independent review required

Baseline: verified release-hardening candidate at 2cd3fb319e8ddc3989510c667ee4b60ea12c3a71.
This packet is an implementation-side review, not independent approval.
The release candidate is the exact head of this draft PR, not main.

## Evidence and reproducibility

- Read the cumulative diff from main 60654e8265650bf74626198ddd9692acddf8071e.
- Review the four production modules, security-and-signature-design.md,
  dependency allowlist and all tests. Inspect source, not only PR summaries.
- Verified baseline: 173 defined methods (129 standard, 44 crypto), 1844 passes,
  232 explained platform-specific skips, zero failures across 12 jobs
  (45308478164 and 45308486875). Hash-locked installation, pip check, POSIX PTY
  and real Windows console tests passed. See PR #17 for exact evidence.
- Follow-up candidate adds file/directory conflict preflight, root resolution
  error handling and eight regression methods (135 standard, 46 crypto).
  Its own exact-head CI and review are required; baseline counts do not prove it.
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
   inputs; 16 KiB does not bound KDF CPU/memory. Review actual Windows console and POSIX PTY evidence.
3. Filesystem: POSIX directory moves after open, mount changes, Windows
   absolute-path guard limitations, reparse mutations, special files, inode
   reuse, metadata collisions, path aliases, root ancestors, control-input
   races and multi-file consistency. Current checks are sampled mitigations;
   not comprehensive protection against a hostile mutable filesystem.
4. Snapshot prerequisite: externally trusted immutable snapshot or effective
   write/namespace exclusion is needed for point-in-time evidence. The tool
   cannot establish or attest this itself. Owner and independent reviewer must
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
