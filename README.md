# Evidence Integrity Kit

A small, offline Python CLI for generating and verifying SHA-256 manifests for explicitly selected evidence files. Intended for reproducible security assessments, software test artifacts and research records. No third-party dependencies or network calls.

## Requirements

Python 3.11 or later. Python 3.12 or later is recommended on Windows for junction detection.

## Example

```sh
python evidence_integrity.py create --root ./evidence scan.json notes.txt > manifest.json
python evidence_integrity.py verify --root ./evidence --manifest manifest.json
```

Run `create` on a trusted, stable evidence directory. Keep the resulting manifest in a separate trusted location. The command prints JSON and does not write into the evidence directory. `verify` checks the listed files and produces a JSON report. Exit codes: `0` success, `1` mismatch or inaccessible listed evidence, `2` invalid input or operational error.

Manifest JSON must not contain duplicate object keys (including nested keys) or the non-standard constants `NaN`, `Infinity`, and `-Infinity`. These inputs are rejected with exit code `2` before evidence hashing. This validation does not authenticate the manifest.

## Security model and limits

This tool verifies content against a supplied manifest; it does not authenticate the manifest, prove authorship, establish chain of custody, or prove that the directory contains no additional files. It checks explicit relative paths and rejects traversal and detected symbolic links (and junctions on supported Python versions). It is not a sandbox and is not designed to withstand concurrent hostile filesystem changes. Use a trusted, stable local directory and keep manifests separate from untrusted evidence. Manifest paths may themselves be sensitive; inspect before sharing. Never publish actual client evidence or private manifests.

## Tests

```sh
python -m unittest discover -s tests -v
```

## Status

Initial experimental implementation (0.1.0), developed with AI assistance. Not extracted from a private codebase. Thirteen unit tests passed in a local Linux environment before publication. No adoption, Windows validation or independent security audit is claimed. Review before production use.

## Contributing

Bug reports and improvements are welcome. Use synthetic evidence only in issues, examples and tests. Include reproducible steps, Python version and operating system. Do not disclose confidential evidence, credentials or personal data.

## License

MIT. See [LICENSE](LICENSE).
