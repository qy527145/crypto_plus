import functools
from abc import abstractmethod

from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.PublicKey.DSA import DsaKey
from Crypto.PublicKey.ECC import EccKey
from Crypto.PublicKey.RSA import RsaKey

from crypto_plus.base import Base


class BaseCrypto(Base):
    @abstractmethod
    def encrypt(self, message):
        pass

    @abstractmethod
    def decrypt(self, message):
        pass


@functools.singledispatch
def encrypt_by_key(*args, **kwargs):
    raise NotImplementedError("Not implemented")


@encrypt_by_key.register(RsaKey)
def _(key: RsaKey, message, **kwargs):
    if not message:
        return b""
    cipher = PKCS1_v1_5_Cipher.new(key)
    seg = key.size_in_bytes() - 11
    res = []
    for i in range(1 + (len(message) - 1) // seg):
        res.append(cipher.encrypt(message[i * seg : (i + 1) * seg]))
    return b"".join(res)


@encrypt_by_key.register(DsaKey)
@encrypt_by_key.register(EccKey)
def _(key: DsaKey | EccKey, message, **kwargs):
    pass


@functools.singledispatch
def decrypt_by_key(*args, **kwargs):
    raise NotImplementedError("Not implemented")


@decrypt_by_key.register(RsaKey)
def _(key: RsaKey, message, **kwargs):
    cipher = PKCS1_v1_5_Cipher.new(key)
    seg = key.size_in_bytes()
    res = []
    for i in range(1 + (len(message) - 1) // seg):
        res.append(cipher.decrypt(message[i * seg : (i + 1) * seg], None))
    return b"".join(res)


@decrypt_by_key.register(DsaKey)
@decrypt_by_key.register(EccKey)
def _(key: DsaKey | EccKey, message, **kwargs):
    pass
