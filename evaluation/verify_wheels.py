"""Evaluation-only independent digest check of downloaded artifacts."""
import hashlib
from pathlib import Path
from tools.verify_signing_environment import load_lock

PINS = load_lock(Path('evaluation/requirements-validator.txt'))
SODIUM = {
    'pynacl-1.6.2-cp38-abi3-win_amd64.whl',
    'pynacl-1.6.2-cp38-abi3-manylinux_2_34_x86_64.whl',
    'pynacl-1.6.2-cp38-abi3-macosx_10_10_universal2.whl',
}


def main():
    seen = set()
    for path in sorted(Path('validator-wheelhouse').iterdir()):
        name, version, *_ = path.name.split('-')
        name = name.lower()
        if not path.is_file() or path.suffix != '.whl' or name in seen or name not in PINS:
            raise ValueError('Unexpected downloaded artifact')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if version != PINS[name][0] or digest not in PINS[name][1]:
            raise ValueError('Wheel digest or version mismatch')
        if name == 'pynacl' and path.name not in SODIUM:
            raise ValueError('Unexpected PyNaCl wheel')
        seen.add(name)
        print(f'{path.name} sha256={digest}')
    if seen != set(PINS):
        raise ValueError('Incomplete evaluation wheelhouse')


if __name__ == '__main__':
    main()
