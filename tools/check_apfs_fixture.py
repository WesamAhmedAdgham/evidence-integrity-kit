"""Unprivileged actual APFS snapshot tests on a disposable image."""
import errno
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import evidence_integrity as kit


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def rejected(operation, reason=None):
    try:
        operation()
    except (ValueError, OSError) as error:
        if reason is not None:
            require(reason in str(error), f'Unexpected rejection: {error}')
        return
    raise AssertionError('Expected APFS snapshot operation rejection')


root, source, expected = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
require(os.geteuid() != 0, 'Fixture must run unprivileged')
if len(sys.argv) == 5:
    from unittest.mock import patch
    mode = sys.argv[4]
    require(mode in ('--ordinary-readonly', '--ordinary-live'), 'Unknown fixture mode')
    readonly = bool(os.statvfs(root).f_flag & os.ST_RDONLY)
    require(readonly == (mode == '--ordinary-readonly'), 'Unexpected fixture read-only state')
    require((root / 'nested/a').read_bytes() == b'AAAA', 'Fixture evidence missing')
    with patch.object(kit.hashlib, 'file_digest') as digest:
        rejected(lambda: kit.generate(root, ['nested/a'], apfs_source=expected),
                 'requires a local read-only nodev snapshot mount')
        require(not digest.called, 'Ordinary APFS volume reached hashing')
    print(f'APFS native fixture: {mode[2:]} rejected before hashing PASS')
    raise SystemExit(0)
names = ['nested/a', 'b']
manifest = kit.generate(root, names, apfs_source=expected)
require(manifest == kit.generate(root, names), 'Manifest wire format changed')
report = kit.verify(root, manifest, apfs_source=expected)
require(report['ok'] and report['protection']['snapshot_source'] == expected, 'APFS snapshot verification failed')
live = subprocess.run([sys.executable, '-c',
    "import sys; from pathlib import Path; Path(sys.argv[1]).write_bytes(b'ZZZZ')",
    str(source / 'nested/a')], capture_output=True, timeout=15)
require(live.returncode == 0, 'Live-source control writer failed')
for operation in ("p.write_bytes(b'ZZZZ')", "p.rename(p.with_name('moved'))"):
    code = ("import errno,sys; from pathlib import Path\np=Path(sys.argv[1])\ntry: " + operation +
            "\nexcept OSError as e: sys.exit(0 if e.errno==errno.EROFS else 2)\nsys.exit(3)")
    result = subprocess.run([sys.executable, '-c', code, str(root / 'nested/a')],
                            capture_output=True, timeout=15)
    require(result.returncode == 0, 'APFS snapshot write/rename not denied with EROFS')
require((root / 'nested/a').read_bytes() == b'AAAA', 'APFS snapshot bytes changed')
require(kit.verify(root, manifest, apfs_source=expected)['ok'], 'APFS snapshot changed')
rejected(lambda: kit.generate(root, names, apfs_source='wrong@/dev/disk99s1'))
rejected(lambda: kit.generate(source, names, apfs_source=expected))
rejected(lambda: kit.generate(root / 'nested', ['a'], apfs_source=expected))
rejected(lambda: kit.generate(root, ['alias'], apfs_source=expected))
bad = json.loads(json.dumps(manifest))
bad['files'][0]['sha256'] = '0' * 64
require(not kit.verify(root, bad, apfs_source=expected)['ok'], 'Mismatch accepted')
print('APFS native fixture: snapshot verification, live-source mutation isolation, write/rename denial, wrong source/subroot/symlink rejection PASS')
