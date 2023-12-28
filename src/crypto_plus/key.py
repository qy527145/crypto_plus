from __future__ import annotations

import functools
from base64 import b64decode
from os.path import exists
from typing import TYPE_CHECKING

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

if TYPE_CHECKING:
    from typing import Optional
    from typing import Union


def loads_key(
    key_bytes: "Union[bytes, str]", password: "Optional[bytes]" = None
):
    if isinstance(key_bytes, str):
        if key_bytes.startswith("-----"):
            key_bytes = key_bytes.encode()
        else:
            try:
                key_bytes = b64decode(key_bytes)
            except Exception:
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
    raise Exception("无法加载密钥，密钥格式或密码错误")


def dumps_key(
    key: "Union[RsaKey , DsaKey , EccKey]", key_format="PEM"
) -> "Union[bytes, str]":
    return key.export_key(format=key_format)


def load_key(key_path: str, password: "Optional[bytes]" = None):
    if not exists(key_path):
        raise Exception(f"{key_path} not found")
    with open(key_path, "rb") as f:
        return loads_key(f.read())


def dump_key(
    key: "Union[RsaKey , DsaKey , EccKey]", path="rsa.key", key_format="PEM"
):
    with open(path, "wb") as key_file:
        data = key.export_key(format=key_format)
        if isinstance(data, str):
            data = data.encode()
        key_file.write(data)


class KeyPair:
    def __init__(self, private_key, public_key):
        self.private_key: """Union[
            rsa.RSAPrivateKey,
            dsa.DSAPrivateKey,
            ec.EllipticCurvePrivateKey,
            Certificate,
            RsaKey,
            DsaKey,
            EccKey,
        ]""" = private_key
        self.public_key: """Union[
            rsa.RSAPublicKey,
            dsa.DSAPublicKey,
            ec.EllipticCurvePublicKey,
            RsaKey,
            DsaKey,
            EccKey,
        ]""" = public_key


@functools.singledispatch
def construct_keypair(key, *args, **kwargs) -> "KeyPair":
    raise NotImplementedError(f"Not implemented type: {type(key)}")


@construct_keypair.register(rsa.RSAPrivateKey)
def _(key: "rsa.RSAPrivateKey") -> "KeyPair":
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
def _(key: "rsa.RSAPublicKey") -> "KeyPair":
    public_key = RSA.construct(
        (
            key.public_numbers().n,
            key.public_numbers().e,
        )
    )
    return KeyPair(None, public_key)


@construct_keypair.register(dsa.DSAPrivateKey)
def _(key: "dsa.DSAPrivateKey") -> "KeyPair":
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
def _(key: "dsa.DSAPublicKey") -> "KeyPair":
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
def _(key: "ec.EllipticCurvePrivateKey") -> "KeyPair":
    private_key: ECC.EccKey = ECC.construct(
        curve=key.curve.name,
        d=key.private_numbers().private_value,
        point_x=key.private_numbers().public_numbers.x,
        point_y=key.private_numbers().public_numbers.y,
    )
    public_key = private_key.public_key()
    return KeyPair(private_key, public_key)


@construct_keypair.register(ec.EllipticCurvePublicKey)
def _(key: "ec.EllipticCurvePublicKey") -> "KeyPair":
    public_key = ECC.construct(
        curve=key.curve.name,
        point_x=key.public_numbers().x,
        point_y=key.public_numbers().y,
    )
    return KeyPair(None, public_key)


@construct_keypair.register(Certificate)
def _(key: "Certificate") -> "KeyPair":
    return construct_keypair(key.public_key())
