# Security model and signed-manifest v1 design

Status: **implemented experimental protocol; independent review and release approval pending**.
Reviewed candidate baseline: a9b92e90afe62d654d1302f8a3fe357c40619da4.
This design is AI-assisted; it is not a security audit or a release approval.
The commands below are implemented on the development candidate, not approved for production use.

## 1. Scope and trust boundaries

Evidence Integrity Kit checks explicitly listed file bytes against SHA-256
digests. A match is not a claim that a collection is exhaustive, legally
admissible, authentic in origin, or captured at a specific time. A valid
signature authenticates manifest bytes relative to a trusted signing key,
not the original evidence collection process.

Trusted prerequisites: the operator, executable and Python environment,
cryptographic provider, OS/kernel, filesystem metadata and access controls,
resolved root and ancestors, and an independently obtained public key.
For point-in-time consistency, require an externally trusted immutable snapshot
or effective exclusion of all writers and namespace changes for the entire
capture or verification operation. The CLI cannot create, attest or enforce
that prerequisite on arbitrary filesystems. Keep input manifests, signatures,
keys and output in a separate trusted directory, not in untrusted evidence.
Run without administrative/root privilege unless an external process requires it.

Treat manifest bytes and listed names, file contents, and signatures as
untrusted data. Reject detected filesystem anomalies rather than continue
with a success result. An attacker may supply malformed inputs, path traversal,
aliases, or replace content between operations; an unprivileged concurrent
writer can also cause observable changes during an operation. The current
checks mitigate tested race cases but **do not make a hostile live filesystem
a supported security boundary**. An attacker who controls the trusted root
ancestors, kernel, filesystem implementation, verifier, signing key or trusted
public key is outside the guarantee. Denial of service, mount replacement,
in-place reparse mutation, inode reuse, reverted changes and post-check
mutation are residual risks, not accepted as solved by passing unit tests.

| Threat | Current or proposed control | Remaining constraint |
| --- | --- | --- |
| Malformed manifest or ambiguous JSON | Bounded read, duplicate-key rejection, structural preflight | Does not bound all CPU, memory or filesystem latency |
| Path traversal and aliases | Portable lexical policy, collision checks, lstat, single-link rule | Not an exhaustive filesystem alias detector |
| POSIX substituted links and root | Descriptor-relative no-follow opening, persistent root, sampled identity | Ancestors above resolved root, mount and directory moves remain possible |
| Windows substituted links and root | Native directory/leaf guards, no delete sharing, reparse and identity checks | Not NT RootDirectory-relative traversal; reparse changes between samples remain possible |
| File changes during read | Sampled identity and metadata checks | Same-size, reverted or metadata-indistinguishable changes may evade detection |
| Earlier file changes during a batch | Final pathname metadata revalidation | Sequential checks are not an atomic snapshot |
| Manifest forgery or alteration | Detached Ed25519 signature | Requires a genuinely trusted public key |
| Signature stripping / downgrade | Separate fail-closed signed-verification command | Caller must enforce signed mode; unsigned mode does not authenticate |
| Replay of a previously valid manifest | No automatic freshness or revocation claim | External retention, identity, timestamp and revocation policy needed |
| Key theft or key substitution | Encrypted private key, trusted public-key distribution | Compromised key invalidates trust; no automatic recovery |

Do not silently broaden the supported threat model. Stronger active-adversary
containment or snapshot guarantees require a separately designed and tested
mechanism, or an externally enforced isolation prerequisite. Reviewers must
explicitly evaluate whether these boundaries satisfy the intended use case.
The owner's comprehensive TOCTOU gate remains open until that decision and
any required remediation are recorded.

## 2. Signature protocol

Use standard Pure Ed25519 as specified in RFC 8032, through the maintained
PyCA cryptography implementation. Do not implement curve arithmetic,
signature parsing, custom key derivation, or an algorithm negotiation layer.
This is not Ed25519ph or Ed25519ctx.

Signed message M is the concatenation of:

1. Fixed ASCII bytes "Evidence Integrity Kit signed manifest v1" followed by
   one NUL byte (0x00).
2. The exact bounded manifest file bytes, with no decoding, normalization,
   reserialization, whitespace stripping or newline conversion.

The fixed domain prefix separates this application's message type from other
uses of the same primitive. Use a dedicated signing key even with this prefix.
Use the library's Ed25519 sign(M) and verify(signature, M) directly, not an
extra SHA-256 digest of M. Evidence content digests remain SHA-256.

The detached signature file represents exactly 64 signature bytes as 128
lowercase ASCII hexadecimal characters, followed by either no newline, one
LF, or one CRLF. Reject all other forms, including leading whitespace, BOM,
uppercase, multiple lines, extra bytes, malformed hex and wrong length.
Bound the signature read to 130 bytes (plus one overflow byte).
The signed manifest remains a v1 SHA-256 JSON manifest, at most 4 MiB.
Changing any byte of the manifest, including line endings, invalidates the
signature. The signature has no embedded key, algorithm selector, filename,
URL or certificate. It does not grant trust to any adjacent key file.

Public keys: one Ed25519 SubjectPublicKeyInfo PEM block, maximum 16 KiB,
loaded by the library and checked for the exact Ed25519 key type. Reject
additional PEM blocks, unrelated prefix/suffix data, private keys and
unsupported key types. No automatic key discovery or network lookup.
Display SHA-256 of the 32-byte raw public key as a fingerprint in authenticated
verification output. A fingerprint aids comparison; it does not establish trust.

Private keys: one encrypted PKCS#8 PEM block, maximum 16 KiB, exact Ed25519
key type. Require an interactive non-echoing passphrase prompt; fail if the
terminal cannot securely accept the passphrase, rather than fall back to
echoing input. Never accept the password in argv, environment, repository
fixtures or logs; avoid printing key bytes or exception details containing
sensitive material. Use established local key-management tooling to generate
and protect keys, with restrictive permissions/ACLs and backups. No automatic
key generation, persistent key cache, key upload or recovery in the initial
scope. Python cannot guarantee secret memory zeroization.

The crypto dependency is optional for ordinary unsigned operations. Choose a
supported, security-reviewed version and reproducible pinned dependency set
before implementation; CI must exercise actual signature operations on all
supported OS/Python combinations with the dependency installed. Test the
absence of the dependency separately. Runtime remains offline; missing or
unsupported crypto must fail closed, never degrade to unsigned verification.

## 3. Command semantics

    python evidence_integrity.py sign --manifest manifest.json --private-key signer.pem
    python evidence_integrity.py verify-signed --root evidence --manifest manifest.json --signature manifest.sig --public-key trusted.pem

The first command prints the detached hex signature to stdout on success.
Users may save stdout in a trusted location using a byte/ASCII-preserving
redirection mechanism; document shell caveats, especially Windows PowerShell.
Do not overwrite the manifest or private key. No automatic writes to evidence.
Signing attests only to the supplied validated manifest bytes, not to the
current evidence files; the operator must verify the manifest and collection
before signing. No signature on malformed or unsupported manifests.

The second command requires all three explicit manifest, signature and public
key paths, verifies the signature over the exact single-read byte buffer
**before JSON parsing or evidence I/O**, then decodes and validates that same
buffer and verifies the listed evidence. No reopening the manifest for parsing.
Reject invalid signatures, wrong keys, unsupported algorithms, malformed
signed content, missing inputs or dependency failures with exit 2 and no
success report. A valid signature with mismatching/inaccessible evidence uses
exit 1 and a per-file report. Success requires both valid signature and
matching evidence. Add a signed-mode authentication object with the fixed
protocol identifier, verified=true and trusted key fingerprint; no claim of
verified evidence when only signature verification has succeeded.

Keep existing create/verify commands and their unsigned JSON contract intact.
Do not automatically try unsigned mode if a signature is absent or invalid.
Unsigned verify may check only hashes; documentation must require callers
that need authentication to invoke verify-signed explicitly. Signed mode
accepts only the defined v1 manifest keys (version, algorithm, files;
path and sha256 in each entry), exact integer version and supported digest
algorithm; reject unknown fields instead of granting unintended meaning.
Share structural preflight between signing and verification without touching
evidence during signing or before all entries pass validation.

Refactor the existing bounded manifest read into a reusable bytes reader and
a separate strict JSON decoder. Preserve identity/stability checks and
existing regression cases. Signature and key files also need bounded binary
reads, regular-file checks and sampled identity/stability checks. Use trusted
locations for all control inputs; the public key is a trust anchor, not
adversary-selected data. Do not claim special-file protection beyond actual
native tests. Do not read a substituted manifest again after signature
verification. For signed operations, no parser or evidence access on failed
cryptographic authentication.

## 4. Acceptance and independent review checklist

Before implementing, review the byte-level protocol and trust assumptions;
decide how the optional dependency will be pinned, obtained and tested.
Before merge, test at minimum:

- RFC 8032 known-answer primitive test and a fixed, independently generated
  protocol-specific vector; verify both signature and exact message bytes.
- Valid sign/verify across all supported environments, Unicode manifest names,
  CRLF/LF, binary evidence, and deterministic signature for a fixed key/message.
- One-byte changes, whitespace/newline changes, wrong key, missing or invalid
  signature, malformed hex, invalid length, trailing data and BOM.
- Signature stripping, missing dependency, wrong key type, malformed/oversize
  PEM, encrypted-key wrong password, noninteractive passphrase rejection,
  no secret logging and no unsigned fallback.
- Invalid JSON/duplicate keys, unsupported manifest version, unknown fields,
  path traversal and malformed entries even when correctly signed.
- Failed authentication must not call JSON decoding or evidence hashing;
  confirm verification and parsing use the same bytes despite file replacement.
- Signed valid manifest with altered/missing evidence, correct exit codes,
  preserved result order, and no change to the unsigned interface.
- Bounded read and cleanup regressions for every new control input; native
  Linux/macOS/Windows CI with platform-specific skips justified, no silent
  crypto skip; synthetic keys only, never a production key.

Threat model review must address all residual race classes explicitly. If
stronger handle-relative guarantees or snapshot enforcement are required,
implement and verify them before release rather than mark this design as
sufficient by assertion. The independent reviewer must be separate from the
implementation, review the exact final candidate commit, source, dependency
selection, protocol, threat model and reproducible test evidence, and record
findings and their disposition. CI and AI self-review are not independent
audit evidence. Close known defects with verified fixes, obtain review on the
resulting commit, and run final cumulative cross-platform regression before
merging. No merge solely because this proposal exists.

## References

- RFC 8032, section 5.1 and test vectors section 7.1:
  https://www.rfc-editor.org/rfc/rfc8032.html
- PyCA cryptography Ed25519 API:
  https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
- PyCA cryptography key serialization:
  https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
- Existing PRs #1–#11 and their native CI evidence in this repository.
