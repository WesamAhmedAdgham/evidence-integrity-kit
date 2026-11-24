# Consolidated release gate (2026-11-24)

Status: **development candidate, not approved for production or release.**
AI-assisted implementation-side review. This document is not independent
audit evidence or an owner sign-off.

## Codex audit remediation (2026-11-24)

Audited SHA: `e97eb72328a91266f72b88ee91dd3a0de0e4ad47`. Independent AI review (not human approval): NO-GO. Run 45310410001: 214 methods, 1,156 passes, 128 platform skips, zero functional failures; all six provider checks rejected the locked provider. Codex reproduced a real same-size Windows write with restored mtime after hashing that returned match. The final-sample race remains fundamentally outside the stable-tree model.

| Audit ID | Current remediation / residual requirement |
| --- | --- |
| EIKA-01 | Blocked: retain provider gate; obtain and review released patched artifacts. |
| EIKA-02 | Native Windows ChangeTime sampling plus audit-derived regression; exact-head native CI required. Not continuous exclusion. Demonstrate external immutable acquisition before point-in-time use. |
| EIKA-03 | Aggregate limits on entries, path components and characters before trie allocation; evidence bytes, I/O time and key KDF isolation remain external. |
| EIKA-04 | Provider check also runs on main pushes; owner must verify actual repository rules and publication controls. No auto-publishing. |
| EIKA-05 | Permission-denied fixtures explicitly classified, strict native CI mode; regressions required. |
| EIKA-06 | README separates unsigned interpreter requirement and signed wheel lock matrix. |
| EIKA-07 | Historical baseline separated from current audit; use latest exact-head CI and independent retest for acceptance. |

Operational acceptance procedure: acquire an externally trusted immutable collection or exclude all writers and namespace changes (including writable aliases) for the full acquisition and comparison interval. Document the filesystem, snapshot/ACL boundary, trusted root ancestors and control storage. Test independent writer and namespace-change attempts using synthetic files in the actual deployment environment; record denied attempts and unchanged digests, then obtain independent review. Never infer snapshot immutability from this CLI's success. Retain the verified snapshot and authenticated manifest in trusted custody if needed. This procedure is a requirement, not proof that a particular environment meets it.

## Historical baseline and cumulative review

- Published main: 60654e8265650bf74626198ddd9692acddf8071e.
- Native-verified consolidated baseline: 38a53a9c499041affc7f385b028ffc6a30ad1f2f.
- PR #20 run 45309934294: 205 methods, 1108 passes, 122 explained
  platform skips, zero failures in six native environments; all ten wheel
  hashes observed and linked OpenSSL 4.0.3 reported by every job.
- PR #19, run 45309485624: 193 test methods; 1040 passes and 118 explained
  platform skips across six native environments, zero failures.
- This consolidated candidate includes all preceding stacked changes and
  adds directory identity checks, unsupported-platform rejection, actual
  pip installation-report validation and runtime provider inventory.
  The subsequent delta adds actual POSIX opened-directory identity checks,
  a 128-component bound, and a fail-closed release-provider policy check.
  Verify the exact new commit and logs before recording any pass.
- Review the cumulative PR diff against main, not only the latest delta.
  License stays MIT; all test data must be synthetic.

## Implementation-side findings

| ID | Observation | Candidate disposition |
| --- | --- | --- |
| EIK-R01 | Earlier pathname checks could miss a changed ancestor when a nested directory and its file retain their identity. | Sample descendant directory identities before and after hashing and at batch completion. Native and cross-platform regression fixtures; exact-head CI required. |
| EIK-R02 | Unsupported OS families could fall back to unguarded evidence opens. | Reject unsupported evidence platforms; retain supported native paths. |
| EIK-R03 | Previously recorded wheel allowlist did not record the actual per-job installed archive hash and bundled provider version in a structured record. | CI requires pip report, approved URL host, exact wheel hash and installed versions; logs OpenSSL version. Not cryptographic publisher verification. |
| EIK-R04 | Library-level OpenSSL advisories postdate the pinned cryptography wheel build. | Open supply-chain acceptance blocker; see below. |
| EIK-R05 | Live hostile filesystem consistency cannot be certified by sampled identity/metadata checks. | Open threat-model acceptance blocker; external immutable snapshot or effective write and namespace exclusion required. |

## Supply-chain review

Upstream cryptography 50.0.2 changelog states that the Windows, macOS and
Linux wheels use OpenSSL 4.0.3. Confirm the actual linked version in each
CI job, not the system openssl executable. The OpenSSL advisories dated
10 and 17 November 2026 include vulnerabilities affecting the 4.0 branch
before 4.0.4, including CVE-2026-107493 (PEM X509_INFO stack handling),
CVE-2026-35190 (TLS Suite B), CVE-2026-124709 (QUIC server retention),
and CVE-2026-88823 (AES-GCM-SIV). These named paths are not directly invoked
by this CLI: the application decodes its PEM envelope into DER and uses
Ed25519 and PKCS#8/SPKI serialization, not TLS, QUIC or AES-GCM-SIV.
This is a limited application-level reachability observation, not a
verified full transitive call graph or a vulnerability exemption.
Do not claim the wheel is free of vulnerabilities or change pins merely
to an unverified version. Independently review all relevant advisories,
including the actual cryptographic provider, encrypted private-key
algorithms accepted by PyCA, and dependency provenance. Require patched
reviewed artifacts or explicit, independently reviewed applicability
and owner risk acceptance. Re-lock hashes and rerun native CI after any
dependency changes.

Sources reviewed:
- https://cryptography.io/en/50.0.2/changelog/
- https://github.com/pyca/cryptography/security/advisories
- https://openssl-library.org/news/timeline/
- https://openssl-library.org/news/vulnerabilities/

The exact wheel hash policy and successful prior native installs are
evidence of reproducibility, not independent publisher authentication.
The CI check must verify the actual install report for all three
distributions and log the linked provider. Independent provenance review
and current advisories for all dependencies remain open. As of 2026-11-24,
PyPI and the stable upstream changelog still identify 50.0.2 as the current
stable release. Do not substitute an unreleased or unreviewed build.

The separate `Signing provider release gate` job now installs the locked
wheels, verifies their installation report, and runs
`tools/check_release_provider.py`. It intentionally rejects OpenSSL 4.0.x
before 4.0.4 and denies every provider pair not explicitly reviewed and
allowlisted. The allowlist is empty pending independent review. This is a
visible CI policy check, not configured branch protection or independent
approval; repository owners must make it required before permitting release.
Functional CI remains separate and can succeed while the release gate fails.
See https://pypi.org/project/cryptography/ for upstream release status.

## Supported security boundary and operational acceptance

For trustworthy point-in-time evidence, the operator must supply a stable
local evidence tree obtained from an independently trusted immutable
snapshot or effective exclusion of writers and namespace mutations
throughout the operation. Use trusted root ancestors and control-file
storage, an independently distributed public key, and a trusted OS and
Python environment. Run without elevated privileges where feasible.
The program cannot prove any of these external prerequisites itself.
Use explicit signed verification where authenticity is required.

Residual risks: mount replacement, reverted namespace/content changes,
in-place reparse changes, identity reuse, timestamp precision, aliases
not represented by observed identity, post-check mutation, and resource
exhaustion (including expensive private-key KDF and filesystem latency).
Neither the hash nor signature establishes origin, completeness, freshness,
chain of custody, or an atomic snapshot. A read-only mount alone does not
necessarily prevent writes through other aliases. The owner and independent
reviewer must explicitly accept this scope, or demand further implementation.
Do not mark comprehensive TOCTOU protection achieved. Actual POSIX opened
ancestor handles are now compared to current pathnames during leaf opening;
this catches sampled descriptor/path divergence but does not prevent directory
moves, mount substitution, or changes reverted between checks.

## Independent reviewer handoff

Review the entire cumulative diff, production modules, protocol, all
filesystem guards, tests, actual wheel evidence and the security model.
Attempt adversarial but synthetic regression cases within the authorized
test environment. Record exact commit, severity, reproduction, impact,
fix and retest for each finding. Review the fixed commit independently.
Do not use passing tests or this implementation-side record as independent
approval. Do not publish real evidence, credentials, or private keys.

Final checklist:
- [ ] Exact cumulative candidate CI verified on all six supported environments.
- [ ] Review current advisories and actual provider; close EIK-R04.
- [ ] Independent artifact provenance review and dependency acceptance.
- [ ] Independent code/protocol and threat-model review; close findings.
- [ ] Owner accepts the bounded model or required additional controls are implemented and verified.
- [ ] Final cumulative CI on the accepted commit; verify MIT and provenance.
- [ ] Explicit release authorization, then merge/tag/publish as authorized.

No automatic merge or release is permitted by this checklist.
