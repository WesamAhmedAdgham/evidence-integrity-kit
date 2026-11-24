# Evidence Integrity Kit

Offline Python CLI for generating and checking SHA-256 manifests of explicitly listed evidence files. This unsigned-core development candidate uses Python standard-library modules only; it does not include the separate Ed25519 signing implementation or the experimental protected filesystem modes in PR #20.

## Requirements

Python 3.11 or later on supported Windows and POSIX systems. The native test matrix targets CPython 3.11 and 3.13. No third-party Python packages are required. Runtime operations make no network calls.

## Usage

```sh
python evidence_integrity.py create --root ./evidence scan.json notes.txt > manifest.json
python evidence_integrity.py verify --root ./evidence --manifest manifest.json
```

Keep the manifest in separate trusted storage. Never redirect output into an input file. On Windows use redirection that preserves ASCII/UTF-8 rather than UTF-16. Exit 0 means all listed digests match (or create succeeded); exit 1 means at least one mismatch or evidence error; exit 2 means invalid input or an operational failure.

## Validation and bounds

- Regular UTF-8 manifests up to 4 MiB; reject duplicate JSON keys, non-finite numbers and excessive nesting. Compare sampled control-input identity, size, timestamps and byte count before decoding.
- Validate every listed path and digest before accessing evidence. Reject traversal, Windows device names, forbidden characters, Unicode/casefold path conflicts, duplicate names and file/directory conflicts. Preserve original spellings.
- Maximum 10,000 entries, 32,768 aggregate components, 262,144 aggregate Unicode path characters, 128 components per path. These are preflight bounds, not limits on total evidence bytes or elapsed time.
- Reject detected reparse points, symbolic links, multiply linked files and sampled identity aliases. Use native root/descendant guards on Windows and descriptor-relative opening on POSIX. Compare metadata before/after bounded hashing and during final batch revalidation; on Windows additionally sample native ChangeTime to detect certain restored-mtime modifications.
- The stricter lexical policy intentionally rejects some previously accepted paths on case-sensitive systems. Invalid structure exits 2 before evidence access.

## Security model and limits

Unsigned verification does **not** authenticate the manifest or establish authorship, time, collection completeness or legal chain of custody. Use an independently trusted stable local collection or externally enforced immutable snapshot/writer and namespace exclusion. This tool does not create or certify a snapshot. Sampled change detection does not prevent all concurrent changes; files may change after the final sample, and hostile live-tree TOCTOU protection is not established. The owner has not accepted this residual risk for the final production release. This candidate is not an approval to use it for live hostile evidence, nor a claim that the separate TOCTOU hardening is complete. Use synthetic data only in public examples and issues.

## Tests

```sh
python -m unittest discover -s tests -v
```

Native CI requires platform-appropriate fixtures. The split needs its own exact-head test results. The proposed scope-aware CI retains the twelve required contexts: exact unsigned payload validation explicitly reports signing-provider NOT APPLICABLE, never provider approval. Unknown or signing payload fails closed in this workflow. The signed development branch retains the full provider gate. Review of the policy and candidate remains required. See [split review record](docs/unsigned-core-split.md).

## Status and provenance

AI-assisted development, extracted from the public repository's own cumulative development branch, not from a private codebase. Published baseline 0.1.0 remains unchanged until the separate PR is approved. No independent audit or production approval claimed.

## Contributing

Use synthetic evidence, include reproducible steps, Python and OS versions, and never publish confidential evidence, credentials or personal data.

## License

MIT. See [LICENSE](LICENSE).
