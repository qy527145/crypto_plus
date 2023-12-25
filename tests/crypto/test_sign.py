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


def test_sign(obj: CryptoPlus):
    msg = random.randbytes(10)
    assert obj.verify(msg, obj.sign(msg)), msg
