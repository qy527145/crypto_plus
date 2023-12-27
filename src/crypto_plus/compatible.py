import builtins
import functools
import random
import sys


def limit_times(times=1):
    remaining_times = times

    def wrapper(f):
        @functools.wraps(f)
        def inner(*args, **kwargs):
            nonlocal remaining_times
            if remaining_times > 0:
                remaining_times -= 1
                res = f(*args, **kwargs)
                return res
            return

        return inner

    return wrapper


def patch(min_version, patch_target, name: "str"):
    has_old = hasattr(patch_target, name)
    old = getattr(patch_target, name, None)

    @limit_times()
    def unpatch():
        if has_old:
            setattr(patch_target, name, old)
        else:
            delattr(patch_target, name)

    @limit_times()
    def wrapper(f):
        @functools.wraps(f)
        def inner(*args, **kwargs):
            return f(*args, __old=old, **kwargs)

        if sys.version_info[:2] < min_version:
            setattr(patch_target, name, inner)
            inner._unpatch = unpatch

        return inner

    return wrapper


def inverse(u, v):
    if v == 0:
        raise ZeroDivisionError("Modulus cannot be zero")
    if v < 0:
        raise ValueError("Modulus cannot be negative")

    u3, v3 = u, v
    u1, v1 = 1, 0
    while v3 > 0:
        q = u3 // v3
        u1, v1 = v1, u1 - v1 * q
        u3, v3 = v3, u3 - v3 * q
    if u3 != 1:
        raise ValueError("No inverse value can be computed")
    while u1 < 0:
        u1 = u1 + v
    return u1


@patch((3, 8), builtins, "pow")
def patch_pow(*args, __old):
    if len(args) == 3 and args[1] < 0:
        base, exponent, modulus = args
        return __old(inverse(base, modulus), -exponent, modulus)  # noqa
    else:
        return __old(*args)


_inst = random.Random()


@patch((3, 9), random, "randbytes")
def patch_randbytes(n, __old):
    return _inst.getrandbits(n * 8).to_bytes(n, "little")
