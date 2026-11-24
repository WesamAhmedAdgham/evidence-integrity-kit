"""Strict, bounded outer PKCS#8 encrypted-key profile; no cryptographic parsing.

The provider still decrypts and validates the actual private key. This parser
only admits a small DER grammar before the provider can start expensive work.
"""
MAX_ITERATIONS = 1_000_000
MIN_ITERATIONS = 2_048
PBES2 = bytes.fromhex('2a864886f70d01050d')
PBKDF2 = bytes.fromhex('2a864886f70d01050c')
HMAC_SHA256 = bytes.fromhex('2a864886f70d0209')
AES256_CBC = bytes.fromhex('60864801650304012a')


class _DER:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def peek(self):
        return self.data[self.pos] if self.pos < len(self.data) else None

    def take(self, tag):
        p = self.pos
        data = self.data
        if p + 2 > len(data) or data[p] != tag:
            raise ValueError('Invalid DER tag')
        length = data[p + 1]
        p += 2
        if length >= 128:
            count = length & 127
            if count not in (1, 2) or p + count > len(data) or data[p] == 0:
                raise ValueError('Invalid DER length')
            length = int.from_bytes(data[p:p + count], 'big')
            p += count
            if length < 128:
                raise ValueError('Nonminimal DER length')
        if p + length > len(data):
            raise ValueError('Truncated DER value')
        self.pos = p + length
        return data[p:self.pos]

    def sequence(self):
        return _DER(self.take(0x30))

    def integer(self):
        raw = self.take(0x02)
        if (not 1 <= len(raw) <= 4 or raw[0] & 128 or
                (len(raw) > 1 and raw[0] == 0 and not raw[1] & 128)):
            raise ValueError('Invalid positive DER integer')
        return int.from_bytes(raw, 'big')

    def oid(self, expected):
        if self.take(0x06) != expected:
            raise ValueError('Unsupported algorithm')

    def end(self):
        if self.pos != len(self.data):
            raise ValueError('Unexpected trailing DER data')


def validate_encrypted_key_profile(der):
    """Allow only PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC with bounded work."""
    try:
        if type(der) is not bytes or not 1 <= len(der) <= 16 * 1024:
            raise ValueError('Invalid input')
        outer = _DER(der)
        info = outer.sequence()
        outer.end()
        algorithm = info.sequence()
        algorithm.oid(PBES2)
        params = algorithm.sequence()
        algorithm.end()
        kdf = params.sequence()
        kdf.oid(PBKDF2)
        pbkdf = kdf.sequence()
        kdf.end()
        salt = pbkdf.take(0x04)
        if not 8 <= len(salt) <= 64:
            raise ValueError('Unsupported salt size')
        iterations = pbkdf.integer()
        if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
            raise ValueError('Unsupported iteration count')
        if pbkdf.peek() == 0x02 and pbkdf.integer() != 32:
            raise ValueError('Unsupported key length')
        prf = pbkdf.sequence()
        prf.oid(HMAC_SHA256)
        if prf.peek() == 0x05 and prf.take(0x05) != b'':
            raise ValueError('Invalid NULL')
        prf.end()
        pbkdf.end()
        cipher = params.sequence()
        cipher.oid(AES256_CBC)
        if len(cipher.take(0x04)) != 16:
            raise ValueError('Invalid IV size')
        cipher.end()
        params.end()
        ciphertext = info.take(0x04)
        if not 16 <= len(ciphertext) <= 4096 or len(ciphertext) % 16:
            raise ValueError('Unsupported ciphertext size')
        info.end()
    except ValueError:
        raise ValueError('Unable to unlock encrypted private key: unsupported or unbounded PKCS#8 profile') from None
