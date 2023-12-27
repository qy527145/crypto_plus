import os
import random

import pytest
from crypto_plus.asymmetric import CryptoPlus


@pytest.fixture(
    scope="session",
    autouse=True,
    params=[
        CryptoPlus.generate_rsa(),
        CryptoPlus.generate_dsa(),
        CryptoPlus.generate_ecdsa(),
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


def test_sign(obj: CryptoPlus, plaintext: bytes):
    assert obj.verify(plaintext, obj.sign(plaintext)), plaintext
