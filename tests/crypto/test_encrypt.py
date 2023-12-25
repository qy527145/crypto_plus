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
def obj(request):
    yield request.param
    os.system("del /q *.pem")
    os.system("del /q *.key")
    os.system("del /q *.crt")


def test_encrypt(obj):
    plaintext = random.randbytes(10)
    secret = obj.encrypt(plaintext)
    assert plaintext == obj.decrypt(secret), plaintext


def test_dump(obj):
    obj.dump(
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


def test_cert(obj: CryptoPlus):
    plaintext = random.randbytes(10)
    obj.dump_cert("aaa", "bbb")
    assert obj.decrypt(CryptoPlus.load("cert.crt").encrypt(plaintext)) == plaintext
