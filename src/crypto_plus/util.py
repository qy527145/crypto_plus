from base64 import b64decode

from cryptography.hazmat.primitives import serialization


def load_key(key_bytes: bytes | str, password: str | None = None):
    if isinstance(key_bytes, str):
        key_bytes = b64decode(key_bytes)

    try:
        return serialization.load_pem_private_key(key_bytes, password)
    except ValueError:
        pass
    try:
        return serialization.load_pem_public_key(key_bytes)
    except ValueError:
        pass
    try:
        return serialization.load_der_private_key(key_bytes, password)
    except ValueError:
        pass
    try:
        return serialization.load_der_public_key(key_bytes)
    except ValueError:
        pass
