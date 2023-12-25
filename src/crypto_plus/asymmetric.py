import datetime
from os.path import exists

from Crypto import Hash
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.PublicKey import DSA
from Crypto.PublicKey import ECC
from Crypto.PublicKey import RSA
from Crypto.Signature import DSS
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import Certificate
from cryptography.x509 import CertificateBuilder
from cryptography.x509 import Name
from cryptography.x509 import NameAttribute
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509 import random_serial_number
from cryptography.x509.oid import NameOID

from crypto_plus.base import BaseCrypto
from crypto_plus.base import BaseSignature
from crypto_plus.util import load_key


class RSACrypto(BaseCrypto, BaseSignature):
    def __init__(self, key: rsa.RSAPrivateKey | rsa.RSAPublicKey):
        super().__init__()
        if isinstance(key, rsa.RSAPrivateKey):
            self.key = key  # 使用openssl加速
            self.private_key = RSA.construct(
                (
                    key.private_numbers().public_numbers.n,
                    key.private_numbers().public_numbers.e,
                    key.private_numbers().d,
                    key.private_numbers().p,
                    key.private_numbers().q,
                )
            )
            self.public_key = self.private_key.public_key()
            assert self.private_key.size_in_bytes() > 11, "密钥太短"
        elif isinstance(key, rsa.RSAPublicKey):
            self.key = None
            self.private_key = None
            self.public_key = RSA.construct(
                (
                    key.public_numbers().n,
                    key.public_numbers().e,
                )
            )
        else:
            raise Exception("参数错误，无法构造对象")

    @classmethod
    def generate(cls, nbits=4096, public_exponent=65537) -> "RSACrypto":
        key = rsa.generate_private_key(public_exponent, nbits)
        return cls(key)

    @classmethod
    def create(
        cls,
        *,
        e=65537,
        d: int | None = None,
        n: int | None = None,
        p: int | None = None,
        q: int | None = None,
    ) -> "RSACrypto":
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

    def dump(
        self,
        key_path="rsa.key",
        pub_key_path="rsa_pub.key",
        key_format="PEM",
    ):
        self.dump_private_key(key_path, key_format)
        self.dump_public_key(pub_key_path, key_format)

    def dump_private_key(self, path="rsa.key", key_format="PEM"):
        if not self.private_key:
            return
        RSACrypto.dump_key(self.private_key, path, key_format)

    def dump_public_key(self, path="rsa_pub.key", key_format="PEM"):
        RSACrypto.dump_key(self.public_key, path, key_format)

    @staticmethod
    def dump_key(key: RSA.RsaKey, path="rsa.key", key_format="PEM"):
        with open(path, "wb") as key_file:
            data = key.export_key(format=key_format)
            if isinstance(data, str):
                data = data.encode()
            key_file.write(data)

    @classmethod
    def load(cls, key_path="rsa.key", password=None) -> "RSACrypto":
        if not exists(key_path):
            raise Exception(f"{key_path} not found")
        with open(key_path, "rb") as key_file:
            return cls(load_key(key_file.read(), password))

    @staticmethod
    def load_private_key(path="rsa.key", password=None):
        if not exists(path):
            raise Exception(f"{path} not found")
        with open(path, "rb") as key_file:
            return serialization.load_pem_private_key(key_file.read(), password)

    @staticmethod
    def load_public_key(path="rsa_pub.key"):
        if not exists(path):
            raise Exception(f"{path} not found")
        with open(path, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())

    @staticmethod
    def generate_cert(
        key: rsa.RSAPrivateKey, subject_name, issuer_name, days=36500
    ) -> Certificate:
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
        builder = builder.public_key(key.public_key())

        return builder.sign(private_key=key, algorithm=hashes.SHA256())

    @staticmethod
    def dump_cert(certificate: Certificate, path="rsa.crt"):
        with open(path, "wb") as cert_file:
            cert_file.write(RSACrypto.export_cert(certificate))

    @staticmethod
    def export_cert(certificate):
        return certificate.public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def load_cert(path="rsa.crt"):
        if not exists(path):
            raise Exception(f"{path} not found")
        with open(path, "rb") as cert_file:
            return load_pem_x509_certificate(cert_file.read())

    # 常规方法
    def encrypt(self, message):
        if not message:
            return b""
        cipher = PKCS1_v1_5_Cipher.new(self.public_key)
        seg = self.public_key.size_in_bytes() - 11
        res = []
        for i in range(1 + (len(message) - 1) // seg):
            res.append(cipher.encrypt(message[i * seg : (i + 1) * seg]))
        return b"".join(res)

    def decrypt(self, message):
        if not message:
            return b""
        if not self.private_key:
            raise Exception("私钥缺失")
        cipher = PKCS1_v1_5_Cipher.new(self.private_key)
        seg = self.private_key.size_in_bytes()
        res = []
        for i in range(1 + (len(message) - 1) // seg):
            res.append(cipher.decrypt(message[i * seg : (i + 1) * seg], None))
        return b"".join(res)

    def sign(self, message, hash_algorithm="SHA256"):
        if not self.private_key:
            raise Exception("私钥缺失")
        hash_algorithm = getattr(Hash, hash_algorithm)
        hashed_message = hash_algorithm.new(message)
        signer = PKCS1_v1_5_Signature.new(self.private_key)
        signature = signer.sign(hashed_message)
        return signature

    def verify(self, message, signature, hash_algorithm="SHA256"):
        hash_algorithm = getattr(Hash, hash_algorithm)
        hashed_message = hash_algorithm.new(message)
        verifier = PKCS1_v1_5_Signature.new(self.public_key)
        return verifier.verify(hashed_message, signature)


class DSASignature(BaseSignature):
    def __init__(
        self,
        key: dsa.DSAPrivateKey
        | dsa.DSAPublicKey
        | ec.EllipticCurvePrivateKey
        | ec.EllipticCurvePublicKey,
    ):
        super().__init__()
        if isinstance(key, dsa.DSAPrivateKey):
            self.key: dsa.DSAPrivateKey = key
            private_numbers = key.private_numbers()
            self.private_key = DSA.construct(
                (
                    private_numbers.public_numbers.y,
                    private_numbers.public_numbers.parameter_numbers.g,
                    private_numbers.public_numbers.parameter_numbers.p,
                    private_numbers.public_numbers.parameter_numbers.q,
                    private_numbers.x,
                )
            )
            self.public_key = self.private_key.public_key()
        elif isinstance(key, dsa.DSAPublicKey):
            self.key: dsa.DSAPublicKey = key
            self.private_key: DSA.DsaKey | None = None
            self.public_key = DSA.construct(
                (
                    key.public_numbers().y,
                    key.public_numbers().parameter_numbers.g,
                    key.public_numbers().parameter_numbers.p,
                    key.public_numbers().parameter_numbers.q,
                )
            )
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            self.key: ec.EllipticCurvePrivateKey = key
            self.private_key: ECC.EccKey = ECC.construct(
                curve=key.curve.name,
                d=key.private_numbers().private_value,
                point_x=key.private_numbers().public_numbers.x,
                point_y=key.private_numbers().public_numbers.y,
            )
            self.public_key = self.private_key.public_key()
        elif isinstance(key, ec.EllipticCurvePublicKey):
            self.key: ec.EllipticCurvePublicKey = key
            self.private_key = None
            self.public_key = ECC.construct(
                curve=key.curve.name,
                point_x=key.public_numbers().x,
                point_y=key.public_numbers().y,
            )
        else:
            raise Exception("参数错误，无法构造对象")

    @classmethod
    def generate(
        cls, nbits=3072, ecc=False, curve: ec.EllipticCurve = ec.SECP256R1
    ) -> "DSASignature":
        if not ecc:
            key = dsa.generate_private_key(nbits)
        else:
            key = ec.generate_private_key(curve)
        return cls(key)

    @classmethod
    def generate_ecc(cls, curve: ec.EllipticCurve = ec.SECP256R1) -> "DSASignature":
        key = ec.generate_private_key(curve)
        return cls(key)

    def dump(
        self,
        key_path="dsa.key",
        pub_key_path="dsa_pub.key",
        key_format="PEM",
    ):
        self.dump_private_key(key_path, key_format)
        self.dump_public_key(pub_key_path, key_format)

    def dump_private_key(self, path="dsa.key", key_format="PEM"):
        if not self.has_private:
            return
        DSASignature.dump_key(self.private_key, path, key_format)

    def dump_public_key(self, path="dsa_pub.key", key_format="PEM"):
        DSASignature.dump_key(self.public_key, path, key_format)

    @staticmethod
    def dump_key(key: DSA.DsaKey | ECC.EccKey, path="dsa.key", key_format="PEM"):
        with open(path, "wb") as key_file:
            data = key.export_key(format=key_format)
            if isinstance(data, str):
                data = data.encode()
            key_file.write(data)

    @classmethod
    def load(cls, key_path="dsa.key", password=None) -> "DSASignature":
        if not exists(key_path):
            raise Exception(f"{key_path} not found")
        with open(key_path, "rb") as key_file:
            return cls(load_key(key_file.read(), password))

    def sign(
        self,
        message,
        hash_algorithm="SHA256",
        random_k=True,
        binary=False,
    ):
        mode = "fips-186-3" if random_k else "deterministic-rfc6979"
        encoding = "binary" if binary else "der"
        if not self.private_key:
            raise Exception("私钥缺失")
        hash_algorithm = getattr(Hash, hash_algorithm)
        hashed_message = hash_algorithm.new(message)
        signer = DSS.new(self.private_key, mode, encoding=encoding)
        signature = signer.sign(hashed_message)
        return signature

    def verify(
        self,
        message,
        signature,
        hash_algorithm="SHA256",
        random_k=True,
        binary=False,
    ):
        mode = "fips-186-3" if random_k else "deterministic-rfc6979"
        encoding = "binary" if binary else "der"
        hash_algorithm = getattr(Hash, hash_algorithm)
        hashed_message = hash_algorithm.new(message)
        verifier = DSS.new(self.public_key, mode, encoding=encoding)
        try:
            verifier.verify(hashed_message, signature)
        except ValueError:
            return False
        return True
