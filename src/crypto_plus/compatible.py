import builtins
import functools
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


@limit_times()
def _pow_monkey_patch():
    old_pow = builtins.pow

    def new_pow(*args):
        if len(args) == 3 and args[1] < 0:
            base, exponent, modulus = args
            return pow(inverse(base, modulus), -exponent, modulus)  # noqa
        else:
            return old_pow(*args)

    builtins.pow = new_pow


if sys.version_info[:2] < (3, 8):
    _pow_monkey_patch()
