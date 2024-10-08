import functools
import random
from abc import abstractmethod
from typing import Union

from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Math.Numbers import Integer
from Crypto.PublicKey.DSA import DsaKey
from Crypto.PublicKey.ECC import EccKey
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import long_to_bytes

from crypto_plus.base import Base


def fast_pow(base: Union[Integer, int], exponent: int, p: int, q: int):
    # 加速模幂运算
    # return pow(base, exponent, p * q)
    # 扩展辗转相除（比pow快3倍左右）
    n = p * q
    mp = pow(base, exponent % (p - 1), p)
    mq = pow(base, exponent % (q - 1), q)
    return (mq * p * pow(p, -1, q) % n + mp * q * pow(q, -1, p) % n) % n


def fast_pow_factor(key: RsaKey):
    n = key.n
    e = key.e
    # d = key.d
    p = key.p
    q = key.q
    u = key.u
    dp = key.dp
    dq = key.dq
    _p = p * pow(p, -1, q) % n
    _q = q * pow(q, -1, p) % n
    r = random.randint(1, n)
    _r = fast_pow(r, -1, p, q)

    def _fast_pow1(base: Union[Integer, int]):
        cp = base * fast_pow(r, e, p, q) % n
        m1 = pow(cp, dp, p)
        m2 = pow(cp, dq, q)
        h = ((m2 - m1) * u) % q
        mp = h * p + m1
        return (mp * _r) % key.n

    def _fast_pow2(base: int):
        return _fast_pow1(Integer(base))

    def _fast_pow3(base: Union[Integer, int]):
        mp = pow(base, dp, p)
        mq = pow(base, dq, q)
        return (mq * _p % n + mp * _q % n) % n

    def _fast_pow4(base: int):
        return _fast_pow3(Integer(base))

    return _fast_pow4


class BaseCrypto(Base):
    @abstractmethod
    def encrypt(self, message: bytes):
        pass

    @abstractmethod
    def decrypt(self, message: bytes):
        pass


@functools.singledispatch
def encrypt_by_key(key, message: bytes, *args, **kwargs):
    raise NotImplementedError(f"Not implemented type: {type(key)}")


@encrypt_by_key.register(RsaKey)
def _(key: RsaKey, message: bytes, **kwargs):
    pad = 8
    max_segment_len = key.size_in_bytes() - pad - 3
    padding_mode = kwargs.get("padding_mode", 1)
    res = []
    if key.has_private():
        # 私钥加密（不建议）
        _fast_pow = fast_pow_factor(key)
        for i in range(1 + (len(message) - 1) // max_segment_len):
            # 分段加密
            plaintext_part = message[
                i * max_segment_len : (i + 1) * max_segment_len
            ]
            pad_len = key.size_in_bytes() - len(plaintext_part) - 3
            # 填充后加密
            if padding_mode == 0:
                # 00填充
                plaintext_part_padding = bytes_to_long(
                    bytes.fromhex(
                        f'0000{"00" * pad_len}00{plaintext_part.hex()}'
                    )
                )
            elif padding_mode == 1:
                # ff填充
                plaintext_part_padding = bytes_to_long(
                    bytes.fromhex(
                        f'0001{"ff" * pad_len}00{plaintext_part.hex()}'
                    )
                )
            else:
                # 随机填充
                # 生成范围在1到255之间的随机数，确保非零字节
                rand_pads = bytearray(pad_len)
                for j in range(pad_len):
                    rand_pads[j] = random.randint(1, 255)

                plaintext_part_padding = bytes_to_long(
                    # bytes.fromhex(f'0001{"ff" * pad_len}00{plaintext_part.hex()}')
                    bytes.fromhex(
                        f"0002{rand_pads.hex()}00{plaintext_part.hex()}"
                    )
                )
            ciphertext_part = _fast_pow(plaintext_part_padding)

            # encrypt_data = encrypt_data.to_bytes(1 + encrypt_data.bit_length() // 8)
            ciphertext_part = ciphertext_part.to_bytes(
                key.public_key().size_in_bytes()
            )
            res.append(ciphertext_part)
    else:
        cipher = PKCS1_v1_5_Cipher.new(key)
        for i in range(1 + (len(message) - 1) // max_segment_len):
            res.append(
                cipher.encrypt(
                    message[i * max_segment_len : (i + 1) * max_segment_len]
                )
            )
    return b"".join(res)


@encrypt_by_key.register(DsaKey)
@encrypt_by_key.register(EccKey)
def _(key: Union[DsaKey, EccKey], message: bytes, **kwargs):
    raise NotImplementedError(f"Not implemented type: {type(key)}")


@functools.singledispatch
def decrypt_by_key(key, message, *args, **kwargs):
    raise NotImplementedError(f"Not implemented type: {type(key)}")


@decrypt_by_key.register(RsaKey)
def _(key: RsaKey, message: bytes, **kwargs):
    seg_len = key.size_in_bytes()
    pad = 8
    max_segment_len = seg_len - pad - 3
    res = []
    if key.has_private():
        cipher = PKCS1_v1_5_Cipher.new(key)
        for i in range(1 + (len(message) - 1) // seg_len):
            res.append(
                cipher.decrypt(message[i * seg_len : (i + 1) * seg_len], None)
            )
    else:
        # 公钥解密（不建议）
        for i in range(1 + (len(message) - 1) // seg_len):
            ciphertext_part = message[i * seg_len : (i + 1) * seg_len]
            # 分段解密
            plaintext_part = long_to_bytes(
                pow(bytes_to_long(ciphertext_part), key.e, key.n),
                key.size_in_bytes(),
            )
            # 去除填充字节
            if plaintext_part[1] in [1, 2]:
                plaintext_part = plaintext_part[
                    plaintext_part.find(b"\x00", 10) + 1 :
                ]
            elif plaintext_part[1] == 0:
                plaintext_part = plaintext_part.lstrip(b"\x00")
                for ch in plaintext_part:
                    if not 32 <= ch <= 126:
                        # 存在非可见字符就尝试补全误删的00前缀
                        if len(
                            plaintext_part
                        ) < max_segment_len and not message.endswith(
                            ciphertext_part
                        ):
                            plaintext_part = (
                                b"\x00"
                                * (max_segment_len - len(plaintext_part))
                                + plaintext_part
                            )
                        break
            else:
                plaintext_part = plaintext_part.lstrip(b"\x00")
            res.append(plaintext_part)
    return b"".join(res)


@decrypt_by_key.register(DsaKey)
@decrypt_by_key.register(EccKey)
def _(key: Union[DsaKey, EccKey], message: bytes, **kwargs):
    raise NotImplementedError(f"Not implemented type: {type(key)}")
