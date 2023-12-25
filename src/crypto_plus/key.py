import functools
from base64 import b64decode
from os.path import exists

from Crypto.PublicKey import DSA
from Crypto.PublicKey import ECC
from Crypto.PublicKey import RSA
from Crypto.PublicKey.DSA import DsaKey
from Crypto.PublicKey.ECC import EccKey
from Crypto.PublicKey.RSA import RsaKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import Certificate
from cryptography.x509 import load_pem_x509_certificate


def loads_key(key_bytes: bytes | str, password: bytes | None = None):
    if isinstance(key_bytes, str):
        if key_bytes.startswith("-----"):
            key_bytes = key_bytes.encode()
        else:
            try:
                key_bytes = b64decode(key_bytes)
            except:  # noqa
                key_bytes = key_bytes.encode()

    try:
        return serialization.load_pem_private_key(key_bytes, password)
    except Exception:
        pass
    try:
        return serialization.load_pem_public_key(key_bytes)
    except Exception:
        pass
    try:
        return serialization.load_der_private_key(key_bytes, password)
    except Exception:
        pass
    try:
        return serialization.load_der_public_key(key_bytes)
    except Exception:
        pass
    try:
        return serialization.load_ssh_private_key(key_bytes, password)
    except Exception:
        pass
    try:
        return serialization.load_ssh_public_key(key_bytes)
    except Exception:
        pass
    try:
        return serialization.load_ssh_public_key(key_bytes)
    except Exception:
        pass
    try:
        return load_pem_x509_certificate(key_bytes)
    except Exception:
        pass
    raise Exception('无法加载密钥，密钥格式或密码错误')


def dumps_key(key: RsaKey | DsaKey | EccKey, key_format="PEM"):
    return key.export_key(format=key_format)


def load_key(key_path: str, password: bytes | None = None):
    if not exists(key_path):
        raise Exception(f"{key_path} not found")
    with open(key_path, "rb") as f:
        return loads_key(f.read())


def dump_key(key: RsaKey | DsaKey | EccKey, path="rsa.key", key_format="PEM"):
    with open(path, "wb") as key_file:
        data = key.export_key(format=key_format)
        if isinstance(data, str):
            data = data.encode()
        key_file.write(data)


class KeyPair:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key


@functools.singledispatch
def construct_keypair(key, *args, **kwargs) -> KeyPair:
    raise NotImplementedError(f"Not implemented type: {type(key)}")


@construct_keypair.register(rsa.RSAPrivateKey)
def _(key: rsa.RSAPrivateKey):
    private_key = RSA.construct(
        (
            key.private_numbers().public_numbers.n,
            key.private_numbers().public_numbers.e,
            key.private_numbers().d,
            key.private_numbers().p,
            key.private_numbers().q,
        )
    )
    private_key.public_key()
    public_key = private_key.public_key()
    assert private_key.size_in_bytes() > 11, "密钥太短"
    return KeyPair(private_key, public_key)


@construct_keypair.register(rsa.RSAPublicKey)
def _(key: rsa.RSAPublicKey):
    public_key = RSA.construct(
        (
            key.public_numbers().n,
            key.public_numbers().e,
        )
    )
    return KeyPair(None, public_key)


@construct_keypair.register(dsa.DSAPrivateKey)
def _(key: dsa.DSAPrivateKey):
    private_numbers = key.private_numbers()
    private_key = DSA.construct(
        (
            private_numbers.public_numbers.y,
            private_numbers.public_numbers.parameter_numbers.g,
            private_numbers.public_numbers.parameter_numbers.p,
            private_numbers.public_numbers.parameter_numbers.q,
            private_numbers.x,
        )
    )
    public_key = private_key.public_key()
    return KeyPair(private_key, public_key)


@construct_keypair.register(dsa.DSAPublicKey)
def _(key: dsa.DSAPublicKey):
    public_key = DSA.construct(
        (
            key.public_numbers().y,
            key.public_numbers().parameter_numbers.g,
            key.public_numbers().parameter_numbers.p,
            key.public_numbers().parameter_numbers.q,
        )
    )
    return KeyPair(None, public_key)


@construct_keypair.register(ec.EllipticCurvePrivateKey)
def _(key: ec.EllipticCurvePrivateKey):
    private_key: ECC.EccKey = ECC.construct(
        curve=key.curve.name,
        d=key.private_numbers().private_value,
        point_x=key.private_numbers().public_numbers.x,
        point_y=key.private_numbers().public_numbers.y,
    )
    public_key = private_key.public_key()
    return KeyPair(private_key, public_key)


@construct_keypair.register(ec.EllipticCurvePublicKey)
def _(key: ec.EllipticCurvePublicKey):
    public_key = ECC.construct(
        curve=key.curve.name,
        point_x=key.public_numbers().x,
        point_y=key.public_numbers().y,
    )
    return KeyPair(None, public_key)


@construct_keypair.register(Certificate)
def _(key: Certificate):
    return construct_keypair(key.public_key())
