"""Release-only gate for the signing dependency.

Passing functional tests is not release acceptance. This gate is intentionally
closed until the actual linked provider and wheel set have been reviewed.
It neither changes the runtime signing API nor certifies independent approval.
"""
import json
import re
import sys
from importlib.metadata import version

# No reviewed patched wheel set is currently accepted. Never add an entry
# merely because its version is newer: record independent provenance and
# applicability review, update the wheel lock and rerun the native matrix.
APPROVED_PROVIDERS = frozenset()
# Independent wheel/provenance and embedded libsodium review required.
APPROVED_POINT_VALIDATORS = frozenset()


def provider_status(crypto_version, openssl_text):
    match = re.fullmatch(r'OpenSSL (\d+)\.(\d+)\.(\d+)(?:\s+.*)?', openssl_text)
    if match is None:
        return False, 'Unrecognized provider version; review required'
    provider = tuple(int(part) for part in match.groups())
    if provider[:2] == (4, 0) and provider[2] < 4:
        return False, 'OpenSSL 4.0 before 4.0.4: November 2026 advisories remain unresolved'
    if (crypto_version, openssl_text) not in APPROVED_PROVIDERS:
        return False, 'Exact signing provider is not release-approved'
    return True, 'Provider pair is on the reviewed release allowlist'


def validator_status(validator_version):
    if validator_version not in APPROVED_POINT_VALIDATORS:
        return False, 'Exact point-validation provider is not release-approved'
    return True, 'Point-validation provider is on the reviewed release allowlist'


def main():
    from cryptography.hazmat.backends.openssl.backend import backend

    crypto_version = version('cryptography')
    openssl_text = backend.openssl_version_text()
    approved, reason = provider_status(crypto_version, openssl_text)
    validator_version = version('PyNaCl')
    validator_approved, validator_reason = validator_status(validator_version)
    print(json.dumps({'cryptography': crypto_version, 'openssl': openssl_text,
                      'pynacl': validator_version,
                      'provider_release_gate_passed': approved and validator_approved,
                      'reason': reason, 'validator_reason': validator_reason},
                     sort_keys=True))
    return 0 if approved and validator_approved else 1


if __name__ == '__main__':
    sys.exit(main())
