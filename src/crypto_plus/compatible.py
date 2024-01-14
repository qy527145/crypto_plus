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


def condition(cond):
    def wrapper(f):
        @functools.wraps(f)
        def inner(*args, **kwargs):
            if cond:
                return f(*args, **kwargs)

        return inner

    return wrapper


def execute_once_now(*args, **kwargs):
    def wrapper(f):
        @limit_times()
        @functools.wraps(f)
        def inner(*args1, **kwargs1):
            return f(*args1, **kwargs1)

        inner(*args, **kwargs)

        return inner

    return wrapper


def patch(min_version, /, *, target=None, module=None, name=None):
    if target is not None:
        module = __import__(target.__module__)
        name = target.__name__
        has_old = True
        old = target
    else:
        has_old = hasattr(module, name)
        old = getattr(module, name, None)

    @limit_times()
    def unpatch():
        if has_old:
            setattr(module, name, old)
        else:
            delattr(module, name)

    @limit_times()
    def wrapper(f):
        @functools.wraps(f)
        def inner(*args, **kwargs):
            return f(*args, __old=old, **kwargs)

        if sys.version_info[:2] < min_version:
            setattr(module, name, inner)
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


@patch((3, 8), target=pow)
def new_pow(*args, __old):
    if len(args) == 3 and args[1] < 0:
        base, exponent, modulus = args
        return __old(inverse(base, modulus), -exponent, modulus)
    else:
        return __old(*args)


_inst = random.Random()


@patch((3, 9), module=random, name="randbytes")
def new_randbytes(n, __old):
    return _inst.getrandbits(n * 8).to_bytes(n, "little")


@execute_once_now()
@condition(sys.version_info[:2] < (3, 7))
def suppress_cryptography_warnings():
    import warnings

    warnings.filterwarnings(
        "ignore", message="Python 3.6 is no longer supported"
    )
