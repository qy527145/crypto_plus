import os
import random

import pytest
from crypto_plus import CryptoPlus


@pytest.fixture(
    scope="session",
    autouse=True,
    params=[
        CryptoPlus.generate_rsa(1024),
        CryptoPlus.generate_rsa(2048),
        CryptoPlus.generate_rsa(3072),
        CryptoPlus.generate_rsa(),
    ],
)
def obj(request):
    yield request.param
    os.system("del /q *.pem")
    os.system("del /q *.key")
    os.system("del /q *.crt")


@pytest.fixture(
    scope="module",
    autouse=True,
    params=[
        random.randbytes(10),
        random.randbytes(10**4),
    ],
)
def plaintext(request):
    yield request.param


def test_encrypt(obj: CryptoPlus, plaintext: bytes):
    ciphertext = obj.encrypt(plaintext)
    assert plaintext == obj.decrypt(ciphertext), plaintext


def test_encrypt2(obj: CryptoPlus, plaintext: bytes):
    secret = obj.encrypt_by_private_key(plaintext)
    assert plaintext == obj.decrypt_by_public_key(secret), plaintext


def test_encrypt3(obj: CryptoPlus, plaintext: bytes):
    secret = obj.encrypt_by_private_key(plaintext)
    assert plaintext == CryptoPlus.construct_rsa(
        n=obj.public_key.n
    ).decrypt_by_public_key(secret), plaintext


def test_encrypt4(obj: CryptoPlus, plaintext: bytes):
    secret = obj.encrypt_by_private_key(plaintext, 0)
    assert plaintext == obj.decrypt_by_public_key(secret), plaintext


def test_encrypt5(obj: CryptoPlus, plaintext: bytes):
    secret = obj.encrypt_by_private_key(plaintext, 2)
    assert plaintext == obj.decrypt_by_public_key(secret), plaintext
