"""Evaluation-only prototype of F02 key admission; never imported by runtime."""
import signing_keys as keys

_BASE_LOAD = keys.load_public_key


def _validator():
    from nacl.bindings import crypto_core_ed25519_is_valid_point
    return crypto_core_ed25519_is_valid_point


def load_public_key(raw):
    """Require canonical SPKI and validated point before existing provider parsing."""
    der = keys.pem_payload(raw, keys.PUBLIC_LABEL)
    prefix = keys.ED25519_SPKI_PREFIX
    if len(der) != len(prefix) + 32 or not der.startswith(prefix):
        raise ValueError('Ed25519 public key required in canonical SPKI encoding')
    try:
        accepted = _validator()(der[len(prefix):])
    except (ImportError, OSError, RuntimeError, ValueError, TypeError) as exc:
        raise ValueError('Ed25519 point validation unavailable') from exc
    if accepted is not True:
        raise ValueError('Invalid Ed25519 public point')
    return _BASE_LOAD(raw)
