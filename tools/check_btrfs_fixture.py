"""Required native CI probes, run unprivileged against an isolated Btrfs image."""
import errno
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import evidence_integrity as kit


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def rejected(operation, pattern=None):
    try:
        operation()
    except (ValueError, OSError) as error:
        if pattern is not None:
            require(pattern in str(error), str(error))
        return
    raise AssertionError('Expected snapshot operation rejection')


def main():
    root, source, mutable_bind, expected, other = sys.argv[1:]
    root, source, mutable_bind = map(Path, (root, source, mutable_bind))
    require(os.geteuid() != 0, 'Fixture must run unprivileged')
    names = ['nested/a', 'b']
    manifest = kit.generate(root, names, snapshot_uuid=expected)
    require(manifest == kit.generate(root, names), 'Manifest wire format changed')
    require(kit.verify(root, manifest, snapshot_uuid=expected)['ok'], 'Snapshot verification failed')
    live = subprocess.run([sys.executable, '-c',
        "import sys; from pathlib import Path; Path(sys.argv[1]).write_bytes(b'ZZZZ')",
        str(source / 'nested/a')], capture_output=True, timeout=15)
    require(live.returncode == 0, 'Live-source control writer failed')
    for operation in ("p.write_bytes(b'ZZZZ')", "p.rename(p.with_name('moved'))"):
        code = ("import errno,sys; from pathlib import Path\np=Path(sys.argv[1])\ntry: " + operation +
                "\nexcept OSError as e: sys.exit(0 if e.errno==errno.EROFS else 2)\nsys.exit(3)")
        denied = subprocess.run([sys.executable, '-c', code, str(root / 'nested/a')],
                                capture_output=True, timeout=15)
        require(denied.returncode == 0, 'Snapshot write/rename not rejected with EROFS')
    require((root / 'nested/a').read_bytes() == b'AAAA', 'Snapshot bytes changed')
    import fcntl, struct
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            fcntl.ioctl(fd, 0x4008941a, struct.pack('=Q', 0))
        except OSError as error:
            require(error.errno in (errno.EPERM, errno.EACCES, errno.EROFS), 'Unexpected flag error')
        else:
            raise AssertionError('Unprivileged process changed snapshot flags')
    finally:
        os.close(fd)
    require(kit.verify(root, manifest, snapshot_uuid=expected)['ok'], 'Snapshot changed after writer')
    rejected(lambda: kit.generate(root, names, snapshot_uuid=other), 'UUID does not match')
    rejected(lambda: kit.generate(source, names, snapshot_uuid=expected), 'not read-only')
    rejected(lambda: kit.generate(mutable_bind, names, snapshot_uuid=other), 'not read-only')
    rejected(lambda: kit.generate(root, ['alias'], snapshot_uuid=expected))
    wrong = json.loads(json.dumps(manifest))
    wrong['files'][0]['sha256'] = '0' * 64
    require(not kit.verify(root, wrong, snapshot_uuid=expected)['ok'], 'Mismatch accepted')
    print('Btrfs native fixture: immutable snapshot, live-source control, writer/rename/property denial, UUID and read-only-bind rejection PASS')


if __name__ == '__main__':
    if sys.argv[1] == '--mount-crossing':
        root, expected = Path(sys.argv[2]), sys.argv[3]
        with patch.object(kit.hashlib, 'file_digest') as digest:
            rejected(lambda: kit.generate(root, ['nested/a'], snapshot_uuid=expected))
            require(not digest.called, 'Cross-mount path reached hashing')
        print('Btrfs native fixture: real nested bind mount rejected before hashing PASS')
    else:
        main()
