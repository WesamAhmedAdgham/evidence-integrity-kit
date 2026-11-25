"""Fail-closed scope gate for the explicitly reviewed unsigned extraction.

A provider is not approved by this program. Only the exact unsigned payload
may report provider NOT APPLICABLE. Signed/unknown payloads must use full
provider policy; this unsigned workflow cannot approve them.
"""
import json
import subprocess
import sys

# Git blob IDs of the proposed unsigned-only F14/F15 backport.
# Exact scope pinning is not independent review or merge authorization.
EXPECTED_BLOBS = {
    ".gitignore": "98dbeb43997e0d3f65ee193a2f0f895debc6a1f6",
    "LICENSE": "f48ae1e496f52c718e4baea15028b15ef67171ac",
    "evidence_integrity.py": "595b97a8629bed83d36754ba145473f21097ab5d",
    "tests/native_fixture_support.py": "d23a2547371088d9674ecdd846e874880139ff17",
    "tests/test_audit_remediation.py": "218c157990272dee872129aedec1ebf6dd4d5c19",
    "tests/test_bounded_evidence.py": "1e25cdab681ea92e947c1ef962c4f7a9e483a381",
    "tests/test_control_read_consistency.py": "0df26c3ce3c891ae7a6cfb50d2f6e284dafeb8e6",
    "tests/test_descriptor_cleanup.py": "bd12ee33d2bd338b54baa3d2d4c2938b253a7bbf",
    "tests/test_directory_chain.py": "aea41461f8ecb8c6a82f1d9a51edffd8ebe318d8",
    "tests/test_evidence_integrity.py": "81c620338c358c990a10e1d88ec84c33d1db896b",
    "tests/test_file_identity.py": "1663a8ce76d3c7fdbe7ecfc38081a6cf6f40dd23",
    "tests/test_file_stability.py": "1848a18f519a7765bc132afab1c68e9ab81ba658",
    "tests/test_handle_traversal.py": "3097eb4dc2e805980f28e0341144073172021754",
    "tests/test_hard_links.py": "fb88d1b0bba997c8d9f2364eac22bb171a6f514b",
    "tests/test_manifest_foundation.py": "04b9a1ae1bbc73cab461b50e7175a65e4f4c4f6e",
    "tests/test_manifest_io.py": "00f302071c37a496eb31dbd3118f07a40096d45c",
    "tests/test_manifest_json.py": "bebe0abf99553bcdfea881dcd4000cc56f2134ea",
    "tests/test_json_structure_budget.py": "d4431d5e34e6fb2132df66eb7e0b3bd32e1fdefe",
    "tests/test_manifest_open.py": "8cbbb7bb1fff539fa1cc40e8a959b0a0fee3053d",
    "tests/test_manifest_preflight.py": "05f393c894a1b2cfc319b0c6197dc27e1bc41c78",
    "tests/test_manifest_stability.py": "0b52d99eb411dcba2d2b1bb36bdd4039b9278324",
    "tests/test_multi_file_consistency.py": "99fdbea948ad34b70756623cb7ab35e04f44cb01",
    "tests/test_path_collisions.py": "f87335e4f7e0636d98ac44ecb96ed896f33b7d73",
    "tests/test_portable_paths.py": "86edbd53a961b4d5c1bc933fd7ed6345e04bbc2d",
    "tests/test_posix_open_identity.py": "9b23565b224159b02c5e8a6f35f6684b48ed3d28",
    "tests/test_post_hash_path.py": "9f69dbc1628aaaab1f30854f05ee37b7742932e1",
    "tests/test_release_preflight.py": "5ec9a8739f0956e2b86b44a8e35553341d4bea2c",
    "tests/test_root_lifetime.py": "89ae67d83ffa74f06afe2519c3e9d4ddbc6f89df",
    "tests/test_safe_open.py": "a3ab687871878b1ceaef99694542697d46ddd383",
    "tests/test_sample_gap.py": "df75cc65d05e72faeec2c84420f5293c391a617c",
    "tests/test_unsigned_scope.py": "353726008b7401f56eb08bba5d84d06862ee3dbc",
    "tests/test_windows_descendant_open.py": "befc1424033475bb149c7fca410afc8030424a99",
    "tests/test_windows_junctions.py": "5999480f76a57c3a699be52119b0612d5bdb45f6",
    "tests/test_windows_root_lifetime.py": "650bf299cf16f738a10d5505993d8d60a8d7320f",
    "windows_root.py": "cd6b85e0574d02e282670cde4e825a252def7054"
}
POLICY_PATHS = frozenset((
    '.github/workflows/tests.yml', 'README.md', 'docs/unsigned-core-split.md',
    'tools/check_unsigned_scope.py', 'tests/test_unsigned_scope_gate.py',
))


def tracked_index():
    raw = subprocess.check_output(['git', 'ls-files', '--stage', '-z'])
    entries = {}
    for record in raw.split(b'\x00'):
        if not record:
            continue
        header, path = record.split(b'\t', 1)
        mode, blob, stage = header.decode('ascii').split()
        name = path.decode('utf-8')
        if mode != '100644' or stage != '0' or name in entries:
            raise ValueError('Unexpected tracked file mode or index stage')
        entries[name] = blob
    return entries


def check_scope(entries):
    if set(entries) != set(EXPECTED_BLOBS) | POLICY_PATHS:
        raise ValueError('Unknown or signed payload: full review/provider policy required')
    if any(entries[path] != blob for path, blob in EXPECTED_BLOBS.items()):
        raise ValueError('Unsigned payload differs from pinned extraction; review required')


def main():
    try:
        check_scope(tracked_index())
        # Run in a fresh checkout before executing any project tests. Reject
        # unexpected working tree changes and untracked files, even ignored.
        if subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--']).returncode != 0:
            raise ValueError('Working tree differs from checked commit')
        if subprocess.check_output(['git', 'ls-files', '--others', '-z']):
            raise ValueError('Unexpected untracked files in scope-check checkout')
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(json.dumps({'scope_check_passed': False, 'reason': str(error)}))
        return 1
    print(json.dumps({'scope_check_passed': True, 'scope': 'pinned-unsigned-core',
                      'signing_provider': 'NOT_APPLICABLE',
                      'provider_release_gate_passed': None}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
