import datetime
from typing import Optional
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import Certificate
from cryptography.x509 import CertificateBuilder
from cryptography.x509 import Name
from cryptography.x509 import NameAttribute
from cryptography.x509 import random_serial_number
from cryptography.x509.oid import NameOID

from crypto_plus.encrypt import BaseCrypto
from crypto_plus.encrypt import decrypt_by_key
from crypto_plus.encrypt import encrypt_by_key
from crypto_plus.key import KeyPair
from crypto_plus.key import construct_keypair
from crypto_plus.key import dump_key
from crypto_plus.key import dumps_key
from crypto_plus.key import load_key
from crypto_plus.key import loads_key
from crypto_plus.sign import BaseSignature
from crypto_plus.sign import sign_by_key
from crypto_plus.sign import verify_by_key


class CryptoPlus(BaseCrypto, BaseSignature):
    def __init__(
        self,
        key: Union[
            rsa.RSAPrivateKey,
            rsa.RSAPublicKey,
            dsa.DSAPrivateKey,
            dsa.DSAPublicKey,
            ec.EllipticCurvePrivateKey,
            ec.EllipticCurvePublicKey,
        ],
    ):
        super().__init__()
        self.key = key
        if hasattr(key, "public_key"):
            self.raw_keypair = KeyPair(key, key.public_key())
        else:
            self.raw_keypair = KeyPair(None, key)
        self.keypair = construct_keypair(key)

    @property
    def public_key(self):
        return self.keypair.public_key

    @property
    def private_key(self):
        return self.keypair.private_key

    @property
    def raw_public_key(self):
        return self.raw_keypair.public_key

    @property
    def raw_private_key(self):
        return self.raw_keypair.private_key

    # RSA
    @classmethod
    def generate_rsa(cls, nbits=4096, public_exponent=65537) -> "CryptoPlus":
        key = rsa.generate_private_key(public_exponent, nbits)
        return cls(key)

    @classmethod
    def construct_rsa(
        cls,
        *,
        e=65537,
        d: Optional[int] = None,
        n: Optional[int] = None,
        p: Optional[int] = None,
        q: Optional[int] = None,
    ) -> "CryptoPlus":
        if not p or not q:
            p, q = rsa.rsa_recover_prime_factors(n, e, d)
        if not d or not n:
            n = p * q
            d = pow(e, -1, (p - 1) * (q - 1))
        key = rsa.RSAPrivateNumbers(
            p,
            q,
            d,
            d % (p - 1),
            d % (q - 1),
            pow(q, -1, p),
            rsa.RSAPublicNumbers(e, n),
        ).private_key()
        return cls(key)

    # DSA
    @classmethod
    def generate_dsa(cls, nbits=3072) -> "CryptoPlus":
        key = dsa.generate_private_key(nbits)
        return cls(key)

    # ECDSA
    @classmethod
    def generate_ecdsa(
        cls, curve: ec.EllipticCurve = ec.SECP256R1
    ) -> "CryptoPlus":
        key = ec.generate_private_key(curve)
        return cls(key)

    def dump(
        self,
        key_path="key.pem",
        pub_key_path="key_pub.pem",
        key_format="PEM",
    ):
        if self.private_key:
            dump_key(self.private_key, key_path, key_format)
        dump_key(self.public_key, pub_key_path, key_format)

    def dumps(self, key_format="PEM"):
        private_key = None
        if self.private_key:
            private_key = dumps_key(self.private_key, key_format)
        public_key = dumps_key(self.public_key, key_format)
        return private_key, public_key

    @classmethod
    def load(cls, key_path="key.pem", password=None) -> "CryptoPlus":
        return cls(load_key(key_path, password))

    @classmethod
    def loads(cls, key: Union[bytes, str], password=None) -> "CryptoPlus":
        return cls(loads_key(key, password))

    def dump_cert(
        self,
        subject_name: str,
        issuer_name: str,
        days=36500,
        cert_path="cert.crt",
    ):
        with open(cert_path, "wb") as f:
            f.write(self.dumps_cert(subject_name, issuer_name, days=days))

    def dumps_cert(self, subject_name="", issuer_name="", days=36500) -> bytes:
        if isinstance(self.raw_private_key, Certificate):
            return self.raw_private_key.public_bytes(serialization.Encoding.PEM)
        if not self.private_key:
            raise Exception("私钥缺失")
        today = datetime.datetime.today()
        one_day = datetime.timedelta(days=1)
        time_range = datetime.timedelta(days=days)
        start_time = today - one_day
        end_time = today + time_range

        builder = CertificateBuilder()
        builder = builder.subject_name(
            Name(
                [
                    NameAttribute(NameOID.COMMON_NAME, subject_name),
                ]
            )
        )
        builder = builder.issuer_name(
            Name(
                [
                    NameAttribute(NameOID.COMMON_NAME, issuer_name),
                ]
            )
        )
        builder = builder.not_valid_before(start_time)
        builder = builder.not_valid_after(end_time)
        builder = builder.serial_number(random_serial_number())
        builder = builder.public_key(self.raw_public_key)
        certificate = builder.sign(
            private_key=self.raw_private_key, algorithm=hashes.SHA256()
        )
        return certificate.public_bytes(serialization.Encoding.PEM)

    # 非常规方法
    def encrypt_by_private_key(self, message: bytes) -> bytes:
        if not message:
            return b""
        if not self.private_key:
            raise Exception("私钥缺失")
        return encrypt_by_key(self.private_key, message)

    def decrypt_by_public_key(self, message: bytes) -> bytes:
        if not message:
            return b""
        return decrypt_by_key(self.public_key, message)

    # 常规方法
    def encrypt(self, message: bytes) -> bytes:
        if not message:
            return b""
        return encrypt_by_key(self.public_key, message)

    def decrypt(self, message: bytes) -> bytes:
        if not message:
            return b""
        if not self.private_key:
            raise Exception("私钥缺失")
        return decrypt_by_key(self.private_key, message)

    def sign(
        self,
        message: bytes,
        hash_algorithm="SHA256",
        random_k=True,
        binary=False,
    ) -> bytes:
        if not self.private_key:
            raise Exception("私钥缺失")
        return sign_by_key(
            self.private_key,
            message,
            hash_algorithm=hash_algorithm,
            random_k=random_k,
            binary=binary,
        )

    def verify(
        self,
        message: bytes,
        signature: bytes,
        hash_algorithm="SHA256",
        random_k=True,
        binary=False,
    ) -> bool:
        return verify_by_key(
            self.public_key,
            message,
            signature,
            hash_algorithm=hash_algorithm,
            random_k=random_k,
            binary=binary,
        )
