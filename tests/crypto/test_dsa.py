import random
from os import system

import pytest

from crypto_plus.asymmetric import DSASignature
from crypto_plus.util import load_key


@pytest.fixture(
    scope="session",
    autouse=True,
    params=[
        DSASignature.generate(),
        DSASignature.generate_ecc(),
    ],
)
def dsa(request):
    yield request.param
    system("del *.key")


def test_sign(dsa):
    msg = random.randbytes(10)
    assert dsa.verify(msg, dsa.sign(msg)), msg


def test_dump(dsa):
    dsa.dump()
    pri = DSASignature.load("dsa.key")
    pub = DSASignature.load("dsa_pub.key")
    msg = random.randbytes(10)
    assert pub.verify(msg, pri.sign(msg)), msg


def test_load(dsa):
    key = "MIIBSwIBADCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoEFgIUNYsbkapILzW8VhfGrU4eHo6/Dqw="
    pri = DSASignature(load_key(key))
    pri.dump()
    assert (
        pri.public_key.export_key()
        == DSASignature.load("dsa_pub.key").public_key.export_key()
    )
