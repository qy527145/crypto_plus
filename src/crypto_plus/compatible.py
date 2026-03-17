import functools
import random
import sys


def limit_times(times=1):
    """
    一个装饰器，用于限制函数的调用次数。

    参数:
        times (int): 函数最多可以被调用的次数。

    返回:
        function: 一个包装后的函数，强制执行调用次数限制。
    """
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
    """
    一个装饰器，根据给定条件有选择地执行函数。

    参数:
        cond (bool): 要评估的条件。

    返回:
        function: 一个包装后的函数，仅在条件为 True 时执行。
    """

    def wrapper(f):
        @functools.wraps(f)
        def inner(*args, **kwargs):
            if cond:
                return f(*args, **kwargs)

        return inner

    return wrapper


def execute_once_now(*args, **kwargs):
    """
    一个装饰器，立即执行函数并限制其未来的调用次数为一次。

    参数:
        *args: 函数的定位参数。
        **kwargs: 函数的关键字参数。

    返回:
        function: 一个包装后的函数，立即执行并限制未来调用次数。
    """

    def wrapper(f):
        @limit_times()
        @functools.wraps(f)
        def inner(*args1, **kwargs1):
            return f(*args1, **kwargs1)

        inner(*args, **kwargs)

        return inner

    return wrapper


def patch(
    min_version,
    # /, *,
    target=None,
    module=None,
    name=None,
):
    """
    一个装饰器，根据 Python 版本对函数或方法进行补丁。

    参数:
        min_version (tuple): 应用补丁所需的最低 Python 版本。
        target (function, optional): 要补丁的目标函数。
        module (module, optional): 包含要补丁函数的模块。
        name (str, optional): 要补丁函数的名称。

    返回:
        function: 一个包装后的函数，应用补丁。
    """
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
        """
        恢复原始函数或方法。
        """
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


def inverse(a, b):
    """
    计算一个数的模逆。

    参数:
        a (int): 要计算模逆的数。
        b (int): 模数。

    返回:
        int: a 模 b 的模逆。
    """
    a1, b1 = 1, 0
    # a2, b2 = 0, 1
    a3, b3 = a, b
    while b3 != 0:
        c = a3 // b3
        a1, b1 = b1, a1 - b1 * c
        # a2, b2 = b2, a2 - b2 * c
        a3, b3 = b3, a3 - b3 * c
    # return a1, a2, a3
    return a1 % b


@patch((3, 8), target=pow)
def new_pow(*args, __old):
    """
    内置 pow 函数的补丁版本，用于处理负指数。

    参数:
        *args: pow 函数的参数。
        __old (function): 原始 pow 函数。

    返回:
        int: 补丁后的 pow 函数结果。
    """
    if len(args) == 3 and args[1] < 0:
        base, exponent, modulus = args
        return __old(inverse(base, modulus), -exponent, modulus)
    else:
        return __old(*args)


_inst = random.Random()


@patch((3, 9), module=random, name="randbytes")
def new_randbytes(n, __old):
    """
    random.randbytes 函数的补丁版本，适用于 Python 版本 < 3.9。

    参数:
        n (int): 要生成的字节数。
        __old (function): 原始 randbytes 函数。

    返回:
        bytes: 生成的随机字节。
    """
    return _inst.getrandbits(n * 8).to_bytes(n, "little")


@execute_once_now()
@condition(sys.version_info[:2] < (3, 7))
def suppress_cryptography_warnings():
    """
    对于 Python 版本 < 3.7，抑制加密库的警告。
    """
    import warnings

    warnings.filterwarnings(
        "ignore", message="Python 3.6 is no longer supported"
    )
