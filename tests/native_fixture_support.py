"""Native capability handling; CI requires the actual applicable fixtures."""
import errno
import os
import subprocess


def unavailable(case, capability, exc):
    message = f'Native fixture capability unavailable: {capability}: {exc}'
    if os.environ.get('EIK_REQUIRE_NATIVE_FIXTURES') == '1':
        case.fail(message)
    case.skipTest(message)


def link_fixture(case, capability, operation):
    try:
        operation()
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM, errno.ENOSYS, errno.ENOTSUP) or getattr(exc, 'winerror', None) in (5, 50, 1314):
            unavailable(case, capability, exc)
        raise


def junction_fixture(case, alias, target):
    result = subprocess.run(
        ['cmd.exe', '/d', '/c', 'mklink', '/J', str(alias), str(target)],
        capture_output=True, timeout=15)
    if result.returncode:
        output = result.stdout + result.stderr
        if b'access is denied' in output.lower() or b'privilege' in output.lower():
            unavailable(case, 'junction', repr(output))
        case.fail(f'Unexpected junction fixture error: {output!r}')
