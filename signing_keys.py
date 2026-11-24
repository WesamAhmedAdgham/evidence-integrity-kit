"""Bounded Ed25519 key loading for explicit signed-manifest operations."""
import base64
import binascii
import getpass
import hashlib
import re
import sys
import warnings

from encrypted_key_profile import validate_encrypted_key_profile
from evidence_integrity import read_control_bytes
from manifest_signatures import provider

MAX_KEY_BYTES = 16 * 1024
PUBLIC_LABEL = b'PUBLIC KEY'
PRIVATE_LABEL = b'ENCRYPTED PRIVATE KEY'


def pem_payload(raw, label):
    """Accept one exact PEM envelope; delegate DER/key parsing to PyCA."""
    if type(raw) is not bytes or len(raw) > MAX_KEY_BYTES:
        raise ValueError('Invalid key file size or type')
    normalized = raw.replace(b'\r\n', b'\n')
    if normalized.endswith(b'\n'):
        normalized = normalized[:-1]
    lines = normalized.split(b'\n')
    if (len(lines) < 3 or lines[0] != b'-----BEGIN ' + label + b'-----' or
            lines[-1] != b'-----END ' + label + b'-----' or
            any(not re.fullmatch(rb'[A-Za-z0-9+/=]+', line) for line in lines[1:-1])):
        raise ValueError('Invalid key PEM envelope')
    encoded = b''.join(lines[1:-1])
    try:
        der = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError('Invalid key PEM encoding') from None
    if not der or base64.b64encode(der) != encoded:
        raise ValueError('Invalid key PEM encoding')
    return der


def serialization_provider():
    ed25519, _, unsupported = provider()
    try:
        from cryptography.hazmat.primitives import serialization
    except (ImportError, OSError):
        raise ValueError('Key serialization provider unavailable') from None
    return ed25519, serialization, unsupported


def load_public_key(raw):
    der = pem_payload(raw, PUBLIC_LABEL)
    ed25519, serialization, unsupported = serialization_provider()
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, TypeError, unsupported):
        raise ValueError('Invalid or unsupported public key') from None
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError('Ed25519 public key required')
    # Require the exact canonical SPKI encoding, not another accepted container
    # or a DER object with ignored trailing data.
    if key.public_bytes(serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo) != der:
        raise ValueError('Public key must be canonical Ed25519 SPKI')
    return key


def public_key_fingerprint(key):
    ed25519, serialization, _ = serialization_provider()
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError('Ed25519 public key required')
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def _load_encrypted_private_der(der, password):
    if type(password) is not bytes or not password:
        raise ValueError('Nonempty private key passphrase required')
    validate_encrypted_key_profile(der)
    ed25519, serialization, unsupported = serialization_provider()
    try:
        key = serialization.load_der_private_key(der, password=password)
    except (ValueError, TypeError, unsupported):
        # A password on unencrypted DER is also rejected by the provider.
        # Do not expose parser errors, key bytes or passphrases.
        raise ValueError('Unable to unlock encrypted private key') from None
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError('Ed25519 private key required')
    return key


def load_private_key(raw, password):
    """Internal API; callers must obtain passwords securely."""
    return _load_encrypted_private_der(pem_payload(raw, PRIVATE_LABEL), password)


def prompt_passphrase():
    """Refuse redirected input and getpass's echoing fallback."""
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError('Interactive non-echoing terminal required for signing')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            password = getpass.getpass('Private key passphrase: ', stream=sys.stderr)
        if not password:
            raise ValueError('Nonempty private key passphrase required')
        # Windows getpass may return Ctrl+V as literal U+0016 rather
        # than pasted text. Never strip it or try an altered passphrase.
        if '\x16' in password:
            raise ValueError('Unexpected paste control character in passphrase; type it manually or use a terminal paste command that inserts text')
        return password.encode('utf-8')
    except (getpass.GetPassWarning, EOFError, OSError, UnicodeError, KeyboardInterrupt):
        raise ValueError('Secure private key passphrase input failed') from None


def read_public_key(path):
    return load_public_key(read_control_bytes(path, limit=MAX_KEY_BYTES, label='Public key'))


def read_private_key(path):
    raw = read_control_bytes(path, limit=MAX_KEY_BYTES, label='Private key')
    der = pem_payload(raw, PRIVATE_LABEL)
    validate_encrypted_key_profile(der)  # Reject excessive KDF work before prompting.
    serialization_provider()  # Fail on missing dependency before prompting.
    return _load_encrypted_private_der(der, prompt_passphrase())
