# Diagnostic provenance review (evaluation only)

This job is not a release gate or independent security approval. It runs in a separate read-only CI runner on the evaluation PR, downloads but never imports or installs the candidate artifacts, checks all 13 exact wheel byte digests, and attempts publisher verification against the independently identified upstream repositories pyca/cryptography and pyca/pynacl. Missing or failed attestations produce a nonzero result; cffi/pycparser require alternative provenance evidence and explicit independent review.

The official PyPI verifier is pinned at pypi-attestations 0.0.32, but its transitive dependencies are not independently hash-locked or approved; the job records the installation report and package versions to expose this limitation. Its output is diagnostic only. A reviewer must bootstrap their own verified toolchain and independently authenticate the expected publisher identity/workflow and build provenance. A publish attestation is not proof of the bundled library's patched binary identity. No result changes the candidate provider allowlists. Do not merge evaluation infrastructure into main.

References: https://docs.pypi.org/attestations/consuming-attestations/ ; https://docs.pypi.org/api/integrity/ ; https://github.com/pyca/cryptography ; https://github.com/pyca/pynacl .
