"""Release-only gate for the signing dependency.

Passing functional tests is not release acceptance. This gate is intentionally
closed until the actual linked provider and wheel set have been reviewed.
It neither changes the runtime signing API nor certifies independent approval.
"""
import argparse
import hashlib
import json
import platform
import re
import sys
from importlib.metadata import version
from pathlib import Path

from tools.verify_signing_environment import load_lock, verify_report

# No reviewed patched wheel set is currently accepted. Never add an entry
# merely because its version is newer: record independent provenance and
# applicability review, update the wheel lock and rerun the native matrix.
APPROVED_PROVIDERS = frozenset()
# Independent wheel/provenance and embedded libsodium review required.
APPROVED_POINT_VALIDATORS = frozenset()
# SHA-256 of the canonical, independently reviewed environment record below.
# This binds the full lock and exact observed wheel set, not just versions.
# A digest is an identifier, not evidence of independent approval on its own.
APPROVED_ENVIRONMENTS = frozenset()


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


def approval_record(pins, observed, runtime):
    """Canonical policy identity for verified pip report and trusted CI metadata."""
    return {
        'schema': 1,
        'lock': {name: {'version': pin[0], 'sha256': sorted(pin[1])}
                 for name, pin in sorted(pins.items())},
        'wheels': observed,
        'runtime': runtime,
    }


def approval_digest(record):
    raw = json.dumps(record, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False).encode('ascii')
    return hashlib.sha256(raw).hexdigest()


def release_decision(pins, observed, runtime):
    """All three explicit approvals must pass; a newer version is insufficient."""
    approved, reason = provider_status(runtime['cryptography'], runtime['openssl'])
    validator_approved, validator_reason = validator_status(runtime['pynacl'])
    record = approval_record(pins, observed, runtime)
    digest = approval_digest(record)
    environment_approved = digest in APPROVED_ENVIRONMENTS
    return {
        'cryptography': runtime['cryptography'],
        'openssl': runtime['openssl'],
        'pynacl': runtime['pynacl'],
        'provider_release_gate_passed': approved and validator_approved and environment_approved,
        'reason': reason,
        'validator_reason': validator_reason,
        'environment_reason': ('Exact environment artifact record is release-approved'
                               if environment_approved else
                               'Exact environment artifact record is not release-approved'),
        'environment_approval_sha256': digest,
        'environment_approval_record': record,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--lock', required=True, type=Path)
    args = parser.parse_args(argv)
    pins = load_lock(args.lock)
    observed = verify_report(json.loads(args.report.read_text(encoding='utf-8')), pins)
    for name, (expected, _) in pins.items():
        if version(name) != expected:
            raise ValueError('Installed distribution version does not match lock')
    from cryptography.hazmat.backends.openssl.backend import backend

    runtime = {
        'python_implementation': platform.python_implementation(),
        'python_major_minor': f'{sys.version_info.major}.{sys.version_info.minor}',
        'system': platform.system(),
        'machine': platform.machine(),
        'cryptography': version('cryptography'),
        'openssl': backend.openssl_version_text(),
        'pynacl': version('PyNaCl'),
    }
    decision = release_decision(pins, observed, runtime)
    print(json.dumps(decision, sort_keys=True))
    return 0 if decision['provider_release_gate_passed'] else 1

if __name__ == '__main__':
    sys.exit(main())
