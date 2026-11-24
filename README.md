# Evidence Integrity Kit

A small, offline Python CLI for generating and verifying SHA-256 manifests for explicitly selected evidence files. Intended for reproducible security assessments, software test artifacts and research records. No third-party dependencies or network calls.

## Requirements

Python 3.11 or later.

## Example

```sh
python evidence_integrity.py create --root ./evidence scan.json notes.txt > manifest.json
python evidence_integrity.py verify --root ./evidence --manifest manifest.json
```

Run `create` on a trusted, stable evidence directory. Keep the resulting manifest in a separate trusted location. The command prints JSON and does not write into the evidence directory. `verify` checks the listed files and produces a JSON report. Exit codes: `0` success, `1` mismatch or inaccessible listed evidence, `2` invalid input or operational error.

Manifest JSON must not contain duplicate object keys (including nested keys) or the non-standard constants `NaN`, `Infinity`, and `-Infinity`. These inputs are rejected with exit code `2` before evidence hashing. Excessive JSON nesting beyond the decoder limit is also rejected with exit code `2` rather than an unhandled traceback. This validation does not authenticate the manifest.

Manifest input must be a regular UTF-8 file of at most 4 MiB (4,194,304 bytes, including whitespace). The reader requests at most one byte beyond this limit and rejects oversize input before JSON parsing. Detected directories and special files such as FIFOs are rejected before opening. The CLI `create` command also rejects serialized output that would exceed the limit using conservative CRLF newline accounting; split large file lists into multiple manifests. This bounds the input read, not total memory, runtime, verification-report size or evidence-file size. Use stable local files; concurrent replacement between checks and opening is outside this tool's security model.

Verification validates the structure of every manifest entry (object type, path string, lowercase SHA-256 digest, portable relative path syntax, and exact duplicate path names) before resolving or hashing any listed evidence file. Malformed entries produce exit code `2` without evidence hashing. After structural validation, filesystem errors and mismatches remain per-file results (exit `1`); report order follows manifest order.

Path names use a conservative cross-platform lexical policy: `/` separates nonempty components. Dot and parent components, trailing ASCII spaces/dots, Windows-reserved device names (including extensions), Windows-forbidden punctuation, ASCII control characters 0–31 and unpaired surrogate code points are rejected on every OS. Both create and verify validate the complete path list before evidence resolution or hashing. This intentionally rejects some previously accepted POSIX filenames; invalid lexical paths now produce exit code `2` instead of a per-file error in verify. Rename incompatible files before creating a new manifest; do not silently rewrite existing evidence paths. This is not a guarantee of portability: filesystem-specific limits, filesystem aliases (including hard links and short names), and concurrent changes remain outside this lexical check.

Both create and verify also reject conflicting spellings of any listed path component under the same parent when they share a conservative Unicode comparison key (NFC, casefold, NFC). This includes directory prefixes, even when the leaf filenames differ. The original spelling is preserved; no path is automatically renamed. This policy can reject distinct files on case-sensitive filesystems and is not an exact model of any particular filesystem's case or normalization rules. It detects collisions among listed paths only, not all aliases or unlisted directory entries. Rejections occur before evidence file resolution or hashing (exit code `2`).

Evidence files must report exactly one hard link (`st_nlink == 1`) at the time of the file check. A file with additional hard links is rejected, including aliases not listed in the manifest and aliases elsewhere on the same filesystem. An unavailable or zero link count is not accepted. This intentionally conservative rule rejects even legitimate multiply linked files: if appropriate, use independent copies in a trusted evidence directory rather than modifying originals. The affected file is not hashed; create exits `2`, while verify records a per-file error (exit `1`). Identical content in independent files remains supported. The rule depends on trustworthy filesystem metadata and is not a proof of origin, a general alias detector, or protection against concurrent link changes. It does not apply to the manifest file itself.

## Security model and limits

This tool verifies content against a supplied manifest; it does not authenticate the manifest, prove authorship, establish chain of custody, or prove that the directory contains no additional files. It checks explicit relative paths and rejects traversal and symbolic links, junctions and other reparse points when exposed by `lstat()` on each listed path component below the resolved evidence root. Junction detection does not require `Path.is_junction()` (introduced in Python 3.12). Some Windows reparse types may be resolved by the operating system rather than exposed by `lstat()`; this is not a guarantee that all reparse points are detected. The explicitly supplied root is resolved before checking its descendants. It is not a sandbox and is not designed to withstand concurrent hostile filesystem changes. Use a trusted, stable local directory and keep manifests separate from untrusted evidence. Manifest paths may themselves be sensitive; inspect before sharing. Never publish actual client evidence or private manifests.

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
