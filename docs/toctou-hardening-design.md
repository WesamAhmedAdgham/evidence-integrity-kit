# TOCTOU hardening design — owner acceptance pending

Status: development design; not a claim of comprehensive resistance. The owner rejected the previous residual TOCTOU risk. Neither passing regression tests nor an opt-in mode closes that decision.

## Assurance levels and trust boundary

| Level | Required invariant | Current disposition |
|---|---|---|
| Sampled live tree | Observe changes at documented samples; no atomicity | Existing compatibility mode |
| Windows guarded cohort | All listed leaf objects simultaneously held with read-only sharing, native identity/metadata checks | Experimental implementation; native verification required |
| Stable capture / snapshot | Independently enforced immutability of content and relevant namespace for the entire comparison interval | Experimental Btrfs and APFS providers |

A protected interval starts only after its complete guard set is acquired. An integrity report describes those observed bytes, not the current state indefinitely after release. The relevant adversary is an ordinary concurrent process with access to the evidence tree, not a compromised OS, kernel driver, raw disk writer or unrestricted administrator. Control files and key trust remain separate. Never infer origin, freshness or completeness from a signature.

## Platform design requirements

Windows: existing guarded cohort excludes ordinary write/delete opens of listed leaves and retains directory handles, with a bounded total handle count. Existing writable handles must fail acquisition. The strengthened candidate excludes ordinary conflicting write opens of guarded directories, requires local NTFS volume GUID scope, and samples native leaf identity and attributes on the retained handle. Native writable mapping and directory-write probes are required. Guarded descendants now use single-component NT RootDirectory-relative opens with FILE_OPEN_REPARSE_POINT and native type checks, without absolute fallback. Native junction/symlink and UTF-16 regressions required. The follow-up pins the drive-volume root and every ancestor using native relative opens, rejecting reparse points and cross-volume paths; ancestor handles omit delete sharing but permit unrelated writes. The drive mapping and current root name are sampled. Native ancestor rename denial and root junction rejection require exact-head CI. Evaluate metadata-only access, reparse state mutation and mount changes before claiming a stronger namespace guarantee. The user-mode API contract is documented at https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntcreatefile; this implementation does not rely on undocumented combinations of OBJ_DONT_REPARSE flags. Do not silently substitute sampled mode for a failed guarded request.

POSIX (Linux/macOS): ordinary read-only file descriptors do not block other writers; flock/fcntl advisory locks do not enforce exclusion against non-cooperating processes. A read-only bind mount is insufficient if the same backing files remain writable by another mount or handle. Evaluate trusted read-only snapshots supplied by the platform/storage provider (for example Linux filesystem snapshots or APFS snapshots) and separate capability validation. Do not implement a fake snapshot by copying a live directory: acquisition itself can race. Do not use elevated privileges or create system snapshots implicitly. A portable snapshot interface must define trusted provisioning, backing-store identity, mounted snapshot lifetime, capability rejection and cleanup. Linux x86-64 candidate checks independently supplied root-owned Btrfs snapshot UUID, subvolume-level read-only state, actual descriptor subvolume/mount identity and strict openat2 traversal. Native synthetic loopback snapshot fixture is mandatory on Linux CI. Trust in provisioning, storage, kernel, procfs and mount namespace remains external. macOS arm64 candidate requires a real administrator-mounted APFS snapshot (native fstatfs type, MNT_LOCAL, MNT_RDONLY, MNT_NODEV and MNT_SNAPSHOT), descriptor filesystem and mount identity, an independently supplied exact mount source, and native positive/negative fixture. Descriptor-relative traversal checks each directory and leaf before hashing; unlike Linux openat2 this is not an atomic no-cross-mount syscall. The trusted namespace assumption remains. A generic read-only mount or disk image is not a snapshot claim. No automatic downgrade.

## Acceptance matrix

1. Acquire every listed guard before any hashing; fail atomically on existing incompatible writer, missing file, alias or handle budget exhaustion.
2. Independent native process probes: ordinary write and rename before first hash, between hashes and after the final per-file check but before release. Verify original bytes unchanged; verify release on every success/error path.
3. Native namespace tests: rename/delete/reparse substitution of root, descendant and leaf, preexisting write-capable directory handles, mount or ancestor substitution. Distinguish prevention from sampled detection and explicitly state unsupported cases.
4. Snapshot provider tests: reject mutable backing storage, untrusted providers, stale/changed mount identity, inconsistent acquisition and unsupported OS; demonstrate independent writer denial or immutable snapshot semantics.
5. CLI tests: explicit mode selection, no fallback, no success report on acquisition error; signed verification authenticates before evidence acquisition. Retain existing wire format and default compatibility behavior until explicitly reviewed.
6. Run exact-head six-environment CI, inspect logs, retest owner deployment with synthetic fixtures, and obtain independent review and owner acceptance. The separate cryptographic provider gate remains required.

Native APFS positive fixture provisioning is currently blocked by EPERM at fs_snapshot_create under sudo (run 45321827535). The Darwin API requires a separate entitlement. A normal read-only volume cannot stand in for a snapshot. Keep native negative checks separate, and obtain a trusted disposable snapshot via an authorized provisioning environment without altering system protection. Native positive tests remain mandatory.

Do not claim comprehensive TOCTOU closure from a successful guarded Windows cohort. The release remains NO-GO until all applicable requirements and review are resolved.
