"""Check the exact diagnostic verifier installation report; no approval implied."""
import importlib.metadata
import json
from pathlib import Path
import re
from tools.verify_signing_environment import load_lock, verify_report


def canonical(name):
    return re.sub(r'[-_.]+', '-', name.lower())


def main():
    pins = load_lock(Path('evaluation/requirements-provenance.txt'))
    report = json.loads(Path('verifier-install-report.json').read_text(encoding='utf-8'))
    # pip distribution metadata may use underscores or hyphens.
    for item in report['install']:
        item['metadata']['name'] = canonical(item['metadata']['name'])
    observed = verify_report(report, pins)
    for name, (version, _) in pins.items():
        if importlib.metadata.version(name) != version:
            raise ValueError('Diagnostic installed version differs from lock')
    print(json.dumps({'diagnostic_verifier_wheels': observed, 'release_approval': False},
                     sort_keys=True))


if __name__ == '__main__':
    main()
