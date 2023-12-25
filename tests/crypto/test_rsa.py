import os
import random

import pytest

from crypto_plus.asymmetric import CryptoPlus


@pytest.fixture(
    scope="session",
    autouse=True,
    params=[
        CryptoPlus.generate_rsa(),
        CryptoPlus.generate_rsa(3072),
    ],
)
def rsa(request):
    yield request.param
    os.system("del /q *.pem")
    os.system("del /q *.key")
    os.system("del /q *.crt")


def test_encrypt(rsa):
    plaintext = random.randbytes(10)
    secret = rsa.encrypt(plaintext)
    assert plaintext == rsa.decrypt(secret), plaintext


def test_sign(rsa):
    msg = random.randbytes(10)
    assert rsa.verify(msg, rsa.sign(msg)), msg


def test_dump(rsa):
    rsa.dump(
        key_path="rsa.key",
        pub_key_path="rsa_pub.key",
    )
    pri = CryptoPlus.load("rsa.key")
    pub = CryptoPlus.load("rsa_pub.key")
    plaintext = random.randbytes(10)
    secret = pub.encrypt(plaintext)
    assert plaintext == pri.decrypt(secret), plaintext
    msg = random.randbytes(10)
    assert pub.verify(msg, pri.sign(msg)), msg


def test_cert(rsa: CryptoPlus):
    plaintext = random.randbytes(10)
    rsa.dump_cert("aaa", "bbb")
    assert rsa.decrypt(CryptoPlus.load("cert.crt").encrypt(plaintext)) == plaintext
