import os
import random

import pytest

from crypto_plus.asymmetric import RSACrypto


@pytest.fixture(
    scope="session",
    autouse=True,
    params=[
        RSACrypto.generate(),
        RSACrypto.generate(3072),
    ],
)
def rsa(request):
    yield request.param
    os.system("del *.key")


def test_encrypt(rsa):
    plaintext = random.randbytes(10)
    secret = rsa.encrypt(plaintext)
    assert plaintext == rsa.decrypt(secret), plaintext


def test_sign(rsa):
    msg = random.randbytes(10)
    assert rsa.verify(msg, rsa.sign(msg)), msg


def test_dump(rsa):
    rsa.dump()
    pri = RSACrypto.load("rsa.key")
    pub = RSACrypto.load("rsa_pub.key")
    plaintext = random.randbytes(10)
    secret = pub.encrypt(plaintext)
    assert plaintext == pri.decrypt(secret), plaintext
    msg = random.randbytes(10)
    assert pub.verify(msg, pri.sign(msg)), msg
