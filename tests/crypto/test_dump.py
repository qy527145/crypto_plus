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


def test_dump(obj: CryptoPlus):
    obj.dump(
        key_path="dsa.key",
        pub_key_path="dsa_pub.key",
    )
    pri = CryptoPlus.load("dsa.key")
    pub = CryptoPlus.load("dsa_pub.key")
    msg = random.randbytes(10)
    assert pub.verify(msg, pri.sign(msg)), msg


def test_cert(obj: CryptoPlus):
    plaintext = random.randbytes(10)
    obj.dump_cert("aaa", "bbb")
    assert CryptoPlus.load("cert.crt").verify(plaintext, obj.sign(plaintext))


def test_load():
    key = "MIIBSwIBADCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoEFgIUNYsbkapILzW8VhfGrU4eHo6/Dqw="
    pri = CryptoPlus.loads(key)
    pri.dump(
        key_path="dsa.key",
        pub_key_path="dsa_pub.key",
    )
    assert (
        pri.public_key.export_key()
        == CryptoPlus.load("dsa_pub.key").public_key.export_key()
    )
