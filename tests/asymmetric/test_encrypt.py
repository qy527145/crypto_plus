import os
import random

import pytest
from crypto_plus import CryptoPlus
from crypto_plus.encrypt import decrypt_by_key
from crypto_plus.encrypt import encrypt_by_key


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
    secret = encrypt_by_key(obj.private_key, plaintext)
    assert plaintext == decrypt_by_key(obj.public_key, secret), plaintext
