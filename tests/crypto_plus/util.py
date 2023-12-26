import random

_inst = random.Random()


def randbytes(n):
    return _inst.getrandbits(n * 8).to_bytes(n, "little")


randint = random.randint
randrange = random.randrange
