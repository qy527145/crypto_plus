import functools
from abc import abstractmethod
from typing import Union

from Crypto import Hash
from Crypto.PublicKey.DSA import DsaKey
from Crypto.PublicKey.ECC import EccKey
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature import DSS
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signature

from crypto_plus.base import Base


class BaseSignature(Base):
    @abstractmethod
    def sign(self, message: bytes, **kwargs) -> bytes:
        pass

    @abstractmethod
    def verify(self, message: bytes, signature: bytes, **kwargs) -> bool:
        pass


@functools.singledispatch
def sign_by_key(key, *args, **kwargs) -> bytes:
    raise NotImplementedError(f"Not implemented type: {type(key)}")


@sign_by_key.register(RsaKey)
def _(key: "RsaKey", message, hash_algorithm="SHA256", **kwargs) -> bytes:
    hash_algorithm = getattr(Hash, hash_algorithm)
    hashed_message = hash_algorithm.new(message)
    signer = PKCS1_v1_5_Signature.new(key)
    signature = signer.sign(hashed_message)
    return signature


@sign_by_key.register(DsaKey)
@sign_by_key.register(EccKey)
def _(
    key: Union[DsaKey, EccKey],
    message,
    hash_algorithm="SHA256",
    random_k=True,
    binary=False,
    **kwargs,
) -> bytes:
    mode = "fips-186-3" if random_k else "deterministic-rfc6979"
    encoding = "binary" if binary else "der"
    hash_algorithm = getattr(Hash, hash_algorithm)
    hashed_message = hash_algorithm.new(message)
    signer = DSS.new(key, mode, encoding=encoding)
    signature = signer.sign(hashed_message)
    return signature


@functools.singledispatch
def verify_by_key(
    key, message: bytes, signature: bytes, *args, **kwargs
) -> bool:
    raise NotImplementedError(f"Not implemented type: {type(key)}")


@verify_by_key.register(RsaKey)
def _(
    key: "RsaKey",
    message: bytes,
    signature: bytes,
    hash_algorithm="SHA256",
    **kwargs,
) -> bool:
    hash_algorithm = getattr(Hash, hash_algorithm)
    hashed_message = hash_algorithm.new(message)
    verifier = PKCS1_v1_5_Signature.new(key)
    return verifier.verify(hashed_message, signature)


@verify_by_key.register(DsaKey)
@verify_by_key.register(EccKey)
def _(
    key: "DsaKey",
    message: bytes,
    signature: bytes,
    hash_algorithm="SHA256",
    random_k=True,
    binary=False,
    **kwargs,
) -> bool:
    mode = "fips-186-3" if random_k else "deterministic-rfc6979"
    encoding = "binary" if binary else "der"
    hash_algorithm = getattr(Hash, hash_algorithm)
    hashed_message = hash_algorithm.new(message)
    verifier = DSS.new(key, mode, encoding=encoding)
    try:
        verifier.verify(hashed_message, signature)
    except ValueError:
        return False
    return True
