import time
from functools import wraps

# import gmpy2


def timer(loop=100000):
    def outer(func):
        @wraps(func)
        def inner(*args, **kwargs):
            res = None
            start = time.perf_counter()

            # Call the actual function
            for _ in range(loop):
                res = func(*args, **kwargs)

            duration = time.perf_counter() - start
            print(f"[{inner.__name__}] took {duration * 1000} ms")
            return res

        return inner

    return outer


def gcd1(a, b):
    if b == 0:
        return 1, 0, a
    x, y, g = gcd1(b, a % b)
    return y, x - (a // b) * y, g


def gcd2(a, b):
    a1, b1 = 1, 0
    a2, b2 = 0, 1
    a3, b3 = a, b
    while b3 != 0:
        c = a3 // b3
        a1, b1 = b1, a1 - b1 * c
        a2, b2 = b2, a2 - b2 * c
        a3, b3 = b3, a3 - b3 * c
    return a1, a2, a3


@timer()
def inverse1(u, v):
    x, y, g = gcd1(u, v)
    assert g == 1
    return x % v


@timer()
def inverse2(u, v):
    x, y, g = gcd2(u, v)
    assert g == 1
    return x % v


@timer()
def inverse3(u, v):
    u1, v1 = 1, 0
    u3, v3 = u, v
    while v3 > 0:
        q = u3 // v3
        u1, v1 = v1, u1 - v1 * q
        u3, v3 = v3, u3 - v3 * q
    return u1 % v


if __name__ == "__main__":
    m, n = 3212312312243123452451, 4567513242341235123123543568
    # x, y, g = gcd(m, n)
    # print(x * m + y * n, g)
    # print(gcd(m, n))
    # print(inverse1(m, n))
    # print(inverse2(m, n))
    # print(inverse3(m, n))
    print(gcd2(15, 9))
    # m = gmpy2.mpz(str(m))
    # n = gmpy2.mpz(str(n))
    # print(inverse1(m, n))
    # print(inverse2(m, n))
    # print(inverse3(m, n))
