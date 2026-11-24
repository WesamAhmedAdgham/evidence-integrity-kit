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

## Owner-observed interactive input regression

At `7e15309348bfb27c29c9ad886fd2848fabe3ebca`, the owner demonstrated with synthetic data that direct PyCA and EIK key loading and signature primitives work, while interactive getpass returned a single U+0016 (Ctrl+V) in two attempts and the exact intended passphrase in another. The CLI now rejects that literal control character before decryption, without echo, secret logging, stripping, or insecure fallback. Added mocked regression coverage and isolated native Windows console coverage. This is a fail-closed diagnostic improvement, not a universal clipboard/paste implementation. Exact-head CI and owner retest remain required. All existing release blockers remain in force.

## Owner-rejected residual TOCTOU risk — experimental Windows cohort

The owner did not accept the existing partial TOCTOU protection. EIK-R05/EIKA-02 remain open. The opt-in Windows deny-write mode is a bounded first implementation step: all listed file handles exclude ordinary write/delete sharing before hashing begins, same-handle native ChangeTime checks, retained descendant directory guards, whole-operation failure without weaker fallback, and a 256-component retained-handle budget. Native subprocess probes cover existing incompatible writers, writes and renames during hashing/final revalidation, and release on success/error. Require exact-head CI before crediting any results. The follow-up restricts guarded mode to a single local NTFS volume using handle-derived volume GUIDs, excludes ordinary conflicting directory write opens, and checks native leaf identity and attributes on the held handle. Native writable mapping, directory-write and volume scope regressions require exact-head CI. Guarded descendant opens now use actual NT RootDirectory-relative single-component opens with native no-follow type checks and relative edge revalidation; exact-head native CI required. Root acquisition and sampled pathname validation are still absolute. This does not provide a verified immutable namespace, POSIX enforcement, protection beyond the common handle interval, or comprehensive TOCTOU resistance. Further design and owner review required.

## Experimental Linux snapshot integration

The Linux x86-64 Btrfs candidate checks a trusted externally supplied snapshot UUID, actual root-owned read-only subvolume and descriptor-derived scope, strict openat2 traversal and same-object reads. Native synthetic fixture must verify ordinary writer denial, live-source mutation isolation, read-only bind mount rejection and mount crossing. No implicit privileged snapshot creation in the application. The macOS arm64 APFS candidate adds native descriptor statfs checks for snapshot/read-only/local/nodev flags, root mount owner, expected source, exact mounted root and matching descendant scope. Both providers require actual signed CLI fixture tests; macOS SDK ABI and synthetic APFS positive/negative fixture must pass. Independent acceptance remains open. Require exact-head CI and do not claim comprehensive TOCTOU closure.

## Reconciliation after unsigned-core merge

PR #21 was merged with all twelve required checks passing for the pinned unsigned-only payload. The six provider-named checks there reported NOT_APPLICABLE, never provider approval. This signed candidate restores the full hash-locked provider gate in those same contexts; the unsigned-only gate and its two test modules are intentionally retired here because they prohibit any signing modules. All common unsigned regression files match the merged main byte-for-byte. Retain the historical [scope record](unsigned-core-split.md) and Git history. The protected main ruleset remains active with no bypass actors. The owner deferred the final security review, not the final acceptance requirement.

Native APFS setup at 5cb4d35 failed before snapshot creation: hdiutil rejected `-format UDRW` without a source. Use the documented blank-image `-type UDIF` option; native positive and negative fixture remains mandatory. Verify the actual subsequent logs before claiming remediation.

## Historical native APFS capability blocker (deferred feature)

Exact run 45321827535 at ab73511934fac0a50df9dd86a9b7e278a9533076: both Darwin SDK ABI probes, blank APFS image creation, attach and synthetic population succeeded. Both native positive fixtures stopped at fs_snapshot_create with EPERM, despite sudo. The Darwin fs_snapshot_create(2) manual requires superuser privileges and an additional entitlement. This is a native fixture capability blocker; it is not proof that the APFS provider works or that EPERM alone identifies the exact missing entitlement. Do not disable SIP or security policy, use system-volume snapshots, or skip this positive requirement.

The next fixture revision exercises ordinary live and read-only APFS volume rejection before the privileged creation attempt, asserts the expected native scope rejection and no hashing, and preserves failure on creation denial. For positive acceptance use a disposable synthetic APFS snapshot provisioned by an authorized entitled tool in a trusted macOS arm64 test environment, then run the existing unprivileged check_apfs_fixture.py and check_snapshot_signed.py against the independently identified mount. Record exact commit, native ABI, source identity, isolation results, and signed verification. No positive native acceptance until reproduced. The full six-environment CI and OpenSSL release gate remain mandatory.

Reference: https://man.freebsd.org/cgi/man.cgi?query=fs_snapshot_create&sektion=2&manpath=macOS+26.7

## Guarded Windows root acquisition follow-up

Guarded mode no longer resolves the supplied root through junctions before acquisition. The candidate restricts the root to a bounded ordinary local drive-letter path, checks the actual anchor is a volume root, retains each ancestor via single-component native relative opens, and omits delete sharing throughout. Ancestors allow ordinary writes; the final evidence root denies writes. Reject reparse points and cross-volume scope, recheck native edges and sample current drive/root identity. Native tests for root junction rejection, ancestor rename exclusion and ambiguous root rejection are mandatory. This does not guarantee that metadata-only or privileged namespace changes are impossible. Exact-head verification and independent review remain required.

## Explicit CLI assurance selection

The candidate requires exactly one protection option for create, verify and verify-signed. An explicit --assume-stable-tree assertion selects compatibility sampling; its CLI report states isolation_verified=false. Absence or conflicting modes fails at argument parsing before control or evidence reads. This prevents accidental omission of the protection flag, not deliberate selection of an inappropriate mode. Native requests retain fail-closed behavior, and manifest/signature formats and the legacy Python API remain unchanged. Existing CLI tests explicitly select the stable-tree mode where appropriate; native tests retain native flags. Require exact-head verification and owner review.

## Release scope split — 2026-11-24

The native APFS feature is removed from the proposed first signed release, not marked as verified. Its complete implementation, source, native fixture and tests are preserved at 1d35d485b85aad4accdfda1ca86fa683a3039e77 and in the separate APFS development branch. The signed candidate exposes only explicit sampled/external-isolation, Windows local NTFS guarded and Linux Btrfs snapshot modes. macOS remains supported for sampled checks against externally isolated evidence, not native snapshot capability. The release scope test checks absent APFS runtime/fixture files and rejection of its former flag before control/evidence I/O. The mandatory APFS positive and negative fixture remains in the deferred feature branch and must pass before reintroduction. The six functional contexts, Windows and Linux native fixtures, and all six full cryptographic provider contexts remain mandatory. This is a scope reduction, not a security acceptance or a permission workaround. Owner's residual risk rejection, independent review, operational isolation and provider acceptance remain open.

## Historical baseline and cumulative review

- Original published baseline: 60654e8265650bf74626198ddd9692acddf8071e.
- Current merged unsigned-core baseline: 5f1c01439e3d65a635a164507e92fcf8f68a695f (PR #21, owner-authorized incremental merge; not a production approval).
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
mandatory CI policy check under the active main ruleset 27955931, not independent
approval. Do not relax or replace it for the signed candidate.
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

## Bounded encrypted private-key preflight (proposed follow-up)

The private-key KDF resource concern in EIKA-03 is partially addressed by a strict outer encrypted PKCS#8 DER profile checked before prompting or invoking the decryption provider. Only PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC is supported, with a bounded canonical iteration count (2,048 to 1,000,000), salt (8–64 bytes), optional exact 32-byte key length, IV (16 bytes), and block-aligned ciphertext (16–4,096 bytes). Unknown algorithms and trailing/noncanonical DER are rejected. The provider still decrypts and validates the inner key. This deliberately narrows accepted key formats; exact locked-provider round trips on all six environments and independent parser review are required before integration. The lower limit preserves existing provider-generated key compatibility, not password-strength assurance. External evidence I/O and process-resource isolation remain required. No provider approval or release authorization follows from this change.

### Key-admission follow-up

PR #23 exact earlier head `7e3565431b11bc79eba55d015b43f6e3dec5cd05`, run 45323815050: all six functional logs reviewed, 206 standard + 50 crypto tests per environment (1,536 total, 1,322 passed, 214 platform-specific skips, zero functional failures), native Linux fixture passed on both runners. All six jobs reported OpenSSL 4.0.3; the release-provider job was skipped because this stacked PR targets a development branch rather than main. No provider acceptance. The follow-up restricts public input to canonical 44-byte Ed25519 SPKI before invoking generic provider parsing, bounds passphrases to 1,024 bytes before decryption, adds exhaustive prefix truncation checks and real provider decryption/signing tests at both iteration limits using synthetic keys. The interactive limit applies after getpass returns, not to terminal allocation. The fixed profile and compatibility changes require independent review and exact-head native CI. PyPI and stable upstream changelog still list cryptography 50.0.2 / OpenSSL 4.0.3 at this checkpoint (2026-11-24); no lock or provider approval change.


## F07 JSON resource-budget follow-up

Development-only remediation: limit JSON nesting to 64 and structural tokens to 65,536 before decoding. Preserve the existing byte cap, strict decoder, signed authentication ordering and schema/path checks. Local isolated decoder tests passed 9 methods including 10,000 seeded generated documents; two legacy excessive-nesting message checks also passed. No full local suite or native CI result claimed for this change. Require cumulative native CI and independent review before accepting F07; remaining process-resource limits and compatibility restrictions are explicit. No provider gate change or release approval.


## F02 draft runtime integration (not approved)

Evaluation PR #25 exact head 96b734e15cda27873e17ac0211cc2b5cf44b5cca, run 45466885008: all six evaluation jobs completed with 12 methods each, 72 passed, zero skips/failures, including the seven CLI hook integration methods. Earlier run 45464785795 verified actual wheel bytes (24 checks across 13 distinct artifacts) and native point-admission cases. The draft runtime candidate is based on PR #24, not the evaluation branch. It uses lazy PyNaCl validation before generic public-key parsing and adds nine direct runtime tests (no loader hook). Its signing lock adds only the three evaluated wheel hashes; unsigned execution stays stdlib-only. The release gate additionally requires explicit independent point-validator approval; both allowlists remain empty. No independent publisher attestation, OpenSSL approval, final CI or merge authorization is claimed.


## 2026-11-24 release qualification checkpoint

OpenSSL published four additional advisories on 2026-11-24 affecting 4.0.3 and listing fixes for 4.0.4: CVE-2026-84785 and CVE-2026-107494 (QUIC), CVE-2026-121482 (X.509 CRL processing), CVE-2026-84786 (DANE). See https://openssl-library.org/news/timeline/ and https://openssl-library.org/news/vulnerabilities-4.0/. These protocol/certificate paths are not used by the intended offline manifest CLI; this is a preliminary reachability assessment, not proof of non-applicability or approval of the binary. The official release timeline and PyPI https://pypi.org/project/cryptography/ still show OpenSSL 4.0.3 on the pinned cryptography 50.0.2 wheels; do not infer that a listed fix target is a published wheel. Retain the release block and both empty allowlists. Require independent advisory applicability, patch provenance and exact artifact review before approval.

PR #26 now targets main as a draft for cumulative qualification only; no merge. Prior functional baseline dde5594422a478b643ad4c5fc548f34ac736e38f, run 45467589147, 1,460 passes, 214 platform skips, zero failures, six native environments; the tested tree matched the baseline. Retargeting alone did not produce a new run at the time of inspection. This documentation-only revision triggers fresh CI against main and requires inspecting actual provider job results. No new CI result or independent review is claimed.

## Exact artifact-bound release approval

The previous gate matched provider version strings only. This revision requires three independent, explicit allowlist matches: cryptography/OpenSSL, point-validator version, and SHA-256 of a canonical approval record containing the complete semantic lock (including every permitted wheel digest), the verified pip install report's exact wheel filenames/digests/versions for all four packages, and CPython implementation/major.minor, OS, architecture and reported provider versions. All three allowlists remain empty. CI passes the original installation report and lock to the gate, which revalidates report structure and installed distribution versions. Future review must record provenance, applicability, and exact artifact approval for every allowed environment and every lock artifact before adding any digest. An alternative wheel, transitive dependency, extra lock hash, or environment change invalidates an existing environment approval. A digest identifies evidence; it is not by itself a signature or independent approval.

The gate assumes a trusted CI runner, pip, installation report and local interpreter. It does not prove that arbitrary installed native code corresponds to the report, independently authenticate a publisher or establish patched binary identity. No runtime signing code, dependency pins, CI job names or main-target conditions changed. Test the exact revised candidate and require independent review of this policy before any allowlist entry. Run: `python -m tools.check_release_provider --report signing-install-report.json --lock requirements-signing.txt`. Current OpenSSL 4.0.3 remains blocked; both library and environment approval remain mandatory.
