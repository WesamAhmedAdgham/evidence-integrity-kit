"""Detached Ed25519 manifest protocol primitives, not a complete signing CLI."""
import re

from evidence_integrity import MAX_MANIFEST_BYTES

DOMAIN = b'Evidence Integrity Kit signed manifest v1\x00'
SIGNATURE_BYTES = 64
MAX_SIGNATURE_FILE_BYTES = 130
SIGNATURE_HEX = re.compile(rb'[0-9a-f]{128}(?:\r\n|\n)?')


def provider():
    """Load optional crypto only for explicit signature operations."""
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except (ImportError, OSError) as exc:
        raise ValueError('Ed25519 provider unavailable; install reviewed signing dependencies') from exc
    return ed25519, InvalidSignature, UnsupportedAlgorithm


def signed_message(raw):
    if type(raw) is not bytes or len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError('Invalid manifest byte buffer')
    return DOMAIN + raw


def encode_signature(signature):
    if type(signature) is not bytes or len(signature) != SIGNATURE_BYTES:
        raise ValueError('Invalid Ed25519 signature length or type')
    return signature.hex().encode('ascii') + b'\n'


def decode_signature(raw):
    if type(raw) is not bytes or len(raw) > MAX_SIGNATURE_FILE_BYTES or not SIGNATURE_HEX.fullmatch(raw):
        raise ValueError('Invalid detached signature encoding')
    return bytes.fromhex(raw[:128].decode('ascii'))


def sign_manifest_bytes(raw, private_key):
    """Sign exact bytes with an already loaded Ed25519 key; caller validates schema."""
    message = signed_message(raw)
    ed25519, _, unsupported = provider()
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError('Ed25519 private key required')
    try:
        signature = private_key.sign(message)
    except unsupported as exc:
        raise ValueError('Ed25519 signing unavailable') from exc
    return encode_signature(signature)


def verify_manifest_signature(raw, signature_file, public_key):
    """Raise on authentication failure; never decode JSON or read evidence."""
    message = signed_message(raw)
    signature = decode_signature(signature_file)
    ed25519, invalid, unsupported = provider()
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError('Ed25519 public key required')
    try:
        public_key.verify(signature, message)
    except invalid as exc:
        raise ValueError('Manifest signature invalid') from exc
    except unsupported as exc:
        raise ValueError('Ed25519 verification unavailable') from exc
